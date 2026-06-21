use anyhow::{Context, Result};
use rhai::{Engine, Scope};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixupResult {
    pub extra_env: HashMap<String, String>,
    pub extra_dll_overrides: Vec<String>,
    pub actions_log: Vec<String>,
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
    pub fn add_dll_override(&mut self, fragment: &str) { self.result.extra_dll_overrides.push(fragment.to_string()); }
    pub fn log(&mut self, message: &str) { self.result.actions_log.push(message.to_string()); }
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

fn engine() -> Engine {
    let mut engine = Engine::new();
    engine.register_type::<FixupContext>();
    engine.register_get("app_id", |ctx: &mut FixupContext| ctx.app_id as i64);
    engine.register_get("app_name", |ctx: &mut FixupContext| ctx.app_name.clone());
    engine.register_get("install_dir", |ctx: &mut FixupContext| ctx.install_dir.clone());
    engine.register_get("wineprefix", |ctx: &mut FixupContext| ctx.wineprefix.clone());
    engine.register_get("target_architecture", |ctx: &mut FixupContext| ctx.target_architecture.clone());
    engine.register_fn("set_env", FixupContext::set_env);
    engine.register_fn("add_dll_override", FixupContext::add_dll_override);
    engine.register_fn("log", FixupContext::log);
    engine
}

pub fn run_fixup_script(path: &Path, mut ctx: FixupContext) -> Result<FixupResult> {
    let script = std::fs::read_to_string(path).with_context(|| format!("reading fixup script {}", path.display()))?;
    let mut scope = Scope::new();
    scope.push("ctx", ctx.clone());
    // Rhai evaluation is synchronous and scripts are tiny per-launch config snippets, so this
    // intentionally runs inline in the async pipeline rather than offloading to a blocking pool.
    engine().eval_with_scope::<()>(&mut scope, &script)?;
    ctx = scope.get_value::<FixupContext>("ctx").unwrap_or(ctx);
    Ok(ctx.result)
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
    #[test]
    fn seed_scripts_execute() {
        for (name, body) in SEED_SCRIPTS {
            let mut p = std::env::temp_dir(); p.push(format!("steamflow_{}", name));
            std::fs::write(&p, body).unwrap();
            let res = run_fixup_script(&p, FixupContext::new(1,"Game".into(),"/g".into(),"/p".into(),"x86_64".into())).unwrap();
            assert!(!res.extra_env.is_empty() || !res.extra_dll_overrides.is_empty());
            assert!(!res.actions_log.is_empty());
            let _ = std::fs::remove_file(p);
        }
    }
    #[test]
    fn malformed_errors_without_panic() {
        let dir = tempfile::tempdir().unwrap(); let p = dir.path().join("bad.rhai");
        std::fs::write(&p, "let = ;").unwrap();
        assert!(run_fixup_script(&p, FixupContext::new(1,"Game".into(),"/g".into(),"/p".into(),"x86".into())).is_err());
    }
}
