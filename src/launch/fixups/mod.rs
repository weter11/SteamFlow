use anyhow::{Context, Result};
use rhai::{Engine, Scope};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixupResult {
    pub extra_env: HashMap<String, String>,
    pub extra_dll_overrides: Vec<String>,
    pub actions_log: Vec<String>,
    pub extra_launch_args: Vec<String>,
    pub registry: Vec<RegOp>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegOp {
    pub path: String,
    pub key: String,
    pub kind: RegKind,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegKind {
    Dword,
    String,
}

#[derive(Debug, Clone)]
pub struct FixupContext {
    pub app_id: u32,
    pub app_name: String,
    pub install_dir: String,
    pub wineprefix: String,
    pub target_architecture: String,
    pub result: FixupResult,
}

impl FixupContext {
    pub fn new(app_id: u32, app_name: String, install_dir: String, wineprefix: String, target_architecture: String) -> Self {
        Self { app_id, app_name, install_dir, wineprefix, target_architecture, result: FixupResult::default() }
    }
    pub fn set_env(&mut self, key: &str, value: &str) { self.result.extra_env.insert(key.to_string(), value.to_string()); }
    pub fn remove_env(&mut self, key: &str) { self.result.extra_env.remove(key); }
    pub fn add_dll_override(&mut self, fragment: &str) { self.result.extra_dll_overrides.push(fragment.to_string()); }
    pub fn add_launch_arg(&mut self, arg: &str) { self.result.extra_launch_args.push(arg.to_string()); }
    pub fn log(&mut self, message: &str) { self.result.actions_log.push(message.to_string()); }

    /// Translate a protonfixes-style override type into a WINEDLLOVERRIDES fragment.
    ///   "builtin"         -> dll=b
    ///   "native"          -> dll=n
    ///   "native,builtin"  -> dll=n,b
    ///   "builtin,native"  -> dll=b,n
    ///   ""                -> dll=  (disable override, load builtin default)
    /// Anything else is passed through verbatim (raw fragment like "d3d9=n,b").
    pub fn override_dll(&mut self, dll_name: &str, override_type: &str) {
        let mode = match override_type {
            "builtin" => "b",
            "native" => "n",
            "native,builtin" | "n,b" => "n,b",
            "builtin,native" | "b,n" => "b,n",
            "" => "",
            other => other,
        };
        self.add_dll_override(&format!("{dll_name}={mode}"));
    }

    pub fn disable_dll(&mut self, dll_name: &str) {
        self.override_dll(dll_name, "");
    }

    /// Convenience shorthand mirroring protonfixes' `util.disable_nvapi()`:
    /// disables both nvapi shims and turns off DXVK's NVAPI integration.
    pub fn disable_nvapi(&mut self) {
        self.disable_dll("nvapi");
        self.disable_dll("nvapi64");
        self.set_env("DXVK_ENABLE_NVAPI", "0");
    }

    pub fn set_reg_dword(&mut self, path: &str, key: &str, val: i64) {
        self.result.registry.push(RegOp { path: path.to_string(), key: key.to_string(), kind: RegKind::Dword, value: val.to_string() });
    }

    pub fn set_reg_string(&mut self, path: &str, key: &str, val: &str) {
        self.result.registry.push(RegOp { path: path.to_string(), key: key.to_string(), kind: RegKind::String, value: val.to_string() });
    }
}

pub const SEED_SCRIPTS: &[(&str, &str)] = &[
    ("227300.rhai", include_str!("seed_scripts/227300.rhai")),
    ("359550.rhai", include_str!("seed_scripts/359550.rhai")),
    ("271590.rhai", include_str!("seed_scripts/271590.rhai")),
    ("1151640.rhai", include_str!("seed_scripts/1151640.rhai")),
];

pub fn fixups_dir() -> Result<PathBuf> { Ok(crate::config::config_dir()?.join("fixups")) }

pub fn seed_default_fixups() -> Result<()> {
    let dir = fixups_dir()?;
    std::fs::create_dir_all(&dir)?;
    for (name, body) in SEED_SCRIPTS {
        let path = dir.join(name);
        if !path.exists() { std::fs::write(path, body)?; }
    }
    Ok(())
}

type SharedCtx = Arc<Mutex<FixupContext>>;

fn engine_for(shared: &SharedCtx) -> Engine {
    let mut engine = Engine::new();
    engine.register_type::<SharedCtx>();
    let shared_getters = Arc::clone(shared);

    // Context getters — callable both as ctx.app_id (method) and app_id() (free).
    // Rhai passes the registered type (SharedCtx) as the getter receiver, so no capture is needed.
    engine.register_get("app_id", |ctx: &mut SharedCtx| ctx.lock().unwrap().app_id as i64);
    engine.register_get("app_name", |ctx: &mut SharedCtx| ctx.lock().unwrap().app_name.clone());
    engine.register_get("install_dir", |ctx: &mut SharedCtx| ctx.lock().unwrap().install_dir.clone());
    engine.register_get("wineprefix", |ctx: &mut SharedCtx| ctx.lock().unwrap().wineprefix.clone());
    engine.register_get("target_architecture", |ctx: &mut SharedCtx| ctx.lock().unwrap().target_architecture.clone());

    // Free-function style (protonfixes translation standard): set_env("K","v")
    macro_rules! free_fn {
        ($name:literal, $method:ident, $($arg:ident : $ty:ty),*) => {
            let shared = Arc::clone(&shared_getters);
            engine.register_fn($name, move |$($arg: $ty),*| {
                let mut ctx = shared.lock().unwrap();
                ctx.$method($($arg),*);
            });
        };
    }
    free_fn!("set_env", set_env, key: &str, val: &str);
    free_fn!("remove_env", remove_env, key: &str);
    free_fn!("add_dll_override", add_dll_override, fragment: &str);
    free_fn!("override_dll", override_dll, dll_name: &str, override_type: &str);
    free_fn!("disable_dll", disable_dll, dll_name: &str);
    engine.register_fn("disable_nvapi", {
        let shared = Arc::clone(&shared_getters);
        move || shared.lock().unwrap().disable_nvapi()
    });
    free_fn!("add_launch_arg", add_launch_arg, arg: &str);
    free_fn!("set_reg_dword", set_reg_dword, path: &str, key: &str, val: i64);
    free_fn!("set_reg_string", set_reg_string, path: &str, key: &str, val: &str);
    free_fn!("log", log, message: &str);

    // Method-style (backward compat with existing fixups): ctx.set_env("K","v")
    engine.register_fn("set_env", |ctx: &mut SharedCtx, key: &str, val: &str| ctx.lock().unwrap().set_env(key, val));
    engine.register_fn("remove_env", |ctx: &mut SharedCtx, key: &str| ctx.lock().unwrap().remove_env(key));
    engine.register_fn("add_dll_override", |ctx: &mut SharedCtx, fragment: &str| ctx.lock().unwrap().add_dll_override(fragment));
    engine.register_fn("override_dll", |ctx: &mut SharedCtx, dll_name: &str, override_type: &str| ctx.lock().unwrap().override_dll(dll_name, override_type));
    engine.register_fn("disable_dll", |ctx: &mut SharedCtx, dll_name: &str| ctx.lock().unwrap().disable_dll(dll_name));
    engine.register_fn("disable_nvapi", |ctx: &mut SharedCtx| ctx.lock().unwrap().disable_nvapi());
    engine.register_fn("add_launch_arg", |ctx: &mut SharedCtx, arg: &str| ctx.lock().unwrap().add_launch_arg(arg));
    engine.register_fn("set_reg_dword", |ctx: &mut SharedCtx, path: &str, key: &str, val: i64| ctx.lock().unwrap().set_reg_dword(path, key, val));
    engine.register_fn("set_reg_string", |ctx: &mut SharedCtx, path: &str, key: &str, val: &str| ctx.lock().unwrap().set_reg_string(path, key, val));
    engine.register_fn("log", |ctx: &mut SharedCtx, message: &str| ctx.lock().unwrap().log(message));

    engine
}

pub fn run_fixup_script(path: &Path, ctx: FixupContext) -> Result<FixupResult> {
    let script = std::fs::read_to_string(path).with_context(|| format!("reading fixup script {}", path.display()))?;
    let shared: SharedCtx = Arc::new(Mutex::new(ctx));
    let mut scope = Scope::new();
    scope.push("ctx", Arc::clone(&shared));
    let engine = engine_for(&shared);
    // Rhai evaluation is synchronous and scripts are tiny per-launch config snippets, so this
    // intentionally runs inline in the async pipeline rather than offloading to a blocking pool.
    engine.eval_with_scope::<()>(&mut scope, &script)?;
    let final_ctx = match Arc::try_unwrap(shared) {
        Ok(mutex) => mutex.into_inner().unwrap_or_else(|poison| poison.into_inner()),
        Err(arc) => arc.lock().unwrap_or_else(|poison| poison.into_inner()).clone(),
    };
    Ok(final_ctx.result)
}

pub fn load_and_run_fixup(app_id: u32, ctx: FixupContext) -> Result<Option<(String, FixupResult)>> {
    seed_default_fixups()?;
    let path = fixups_dir()?.join(format!("{}.rhai", app_id));
    if !path.exists() { return Ok(None); }
    let result = run_fixup_script(&path, ctx)?;
    Ok(Some((path.file_name().unwrap().to_string_lossy().to_string(), result)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> FixupContext {
        FixupContext::new(883710, "Resident Evil 2".into(), "/g".into(), "/p".into(), "x86_64".into())
    }

    #[test]
    fn seed_scripts_execute() {
        for (name, body) in SEED_SCRIPTS {
            let mut p = std::env::temp_dir();
            p.push(format!("steamflow_{}", name));
            std::fs::write(&p, body).unwrap();
            let res = run_fixup_script(&p, ctx()).unwrap();
            assert!(!res.extra_env.is_empty() || !res.extra_dll_overrides.is_empty());
            assert!(!res.actions_log.is_empty());
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn malformed_errors_without_panic() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.rhai");
        std::fs::write(&p, "let = ;").unwrap();
        assert!(run_fixup_script(&p, ctx()).is_err());
    }

    #[test]
    fn free_function_set_env() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.rhai");
        std::fs::write(&p, "set_env(\"FOO\", \"bar\");").unwrap();
        let res = run_fixup_script(&p, ctx()).unwrap();
        assert_eq!(res.extra_env.get("FOO").map(|s| s.as_str()), Some("bar"));
    }

    #[test]
    fn free_function_remove_env() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.rhai");
        std::fs::write(&p, "set_env(\"FOO\", \"bar\"); remove_env(\"FOO\");").unwrap();
        let res = run_fixup_script(&p, ctx()).unwrap();
        assert!(!res.extra_env.contains_key("FOO"));
    }

    #[test]
    fn free_function_override_dll_translations() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.rhai");
        std::fs::write(&p, r#"
            override_dll("x3daudio1_7", "native,builtin");
            override_dll("d3dcompiler_46", "native,builtin");
            override_dll("amd_ags_x64", "builtin");
            disable_dll("nvapi");
        "#).unwrap();
        let res = run_fixup_script(&p, ctx()).unwrap();
        let ov = &res.extra_dll_overrides;
        assert!(ov.contains(&"x3daudio1_7=n,b".to_string()), "got {ov:?}");
        assert!(ov.contains(&"d3dcompiler_46=n,b".to_string()), "got {ov:?}");
        assert!(ov.contains(&"amd_ags_x64=b".to_string()), "got {ov:?}");
        assert!(ov.contains(&"nvapi=".to_string()), "got {ov:?}");
    }

    #[test]
    fn free_function_disable_nvapi() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.rhai");
        std::fs::write(&p, "disable_nvapi();").unwrap();
        let res = run_fixup_script(&p, ctx()).unwrap();
        assert!(res.extra_dll_overrides.contains(&"nvapi=".to_string()));
        assert!(res.extra_dll_overrides.contains(&"nvapi64=".to_string()));
        assert_eq!(res.extra_env.get("DXVK_ENABLE_NVAPI").map(|s| s.as_str()), Some("0"));
    }

    #[test]
    fn free_function_add_launch_arg() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.rhai");
        std::fs::write(&p, "add_launch_arg(\"-ignoredifferentvideocard\");").unwrap();
        let res = run_fixup_script(&p, ctx()).unwrap();
        assert_eq!(res.extra_launch_args, vec!["-ignoredifferentvideocard".to_string()]);
    }

    #[test]
    fn free_function_registry_ops() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.rhai");
        // Note: Rhai string literals need doubled backslashes for registry paths.
        std::fs::write(&p, r#"
            set_reg_dword("HKCU\\Software\\Valve\\Steam", "D3D12", 1);
            set_reg_string("HKCU\\Software\\Valve\\Steam", "Name", "Test");
        "#).unwrap();
        let res = run_fixup_script(&p, ctx()).unwrap();
        assert_eq!(res.registry.len(), 2);
        assert_eq!(res.registry[0].kind, RegKind::Dword);
        assert_eq!(res.registry[0].value, "1");
        assert_eq!(res.registry[1].kind, RegKind::String);
        assert_eq!(res.registry[1].value, "Test");
    }

    #[test]
    fn method_style_still_works() {
        // Backward compat: ctx.set_env(...) must still work alongside free functions.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.rhai");
        std::fs::write(&p, "ctx.set_env(\"OLD\", \"style\"); set_env(\"NEW\", \"style\");").unwrap();
        let res = run_fixup_script(&p, ctx()).unwrap();
        assert_eq!(res.extra_env.get("OLD").map(|s| s.as_str()), Some("style"));
        assert_eq!(res.extra_env.get("NEW").map(|s| s.as_str()), Some("style"));
    }
}
