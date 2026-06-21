use std::collections::HashMap;
use std::path::PathBuf;
use rhai::{Engine, Scope, CustomType};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FixupResult {
    pub extra_env: HashMap<String, String>,
    pub extra_dll_overrides: Vec<String>,
    pub actions_log: Vec<String>,
}

#[derive(Clone, CustomType)]
pub struct FixupContext {
    pub app_id: u32,
    pub app_name: String,
    pub install_dir: String,
    pub wineprefix: String,
    pub target_architecture: String,

    #[rhai_type(skip)]
    pub result: std::sync::Arc<std::sync::Mutex<FixupResult>>,
}

impl FixupContext {
    pub fn set_env(&mut self, key: String, value: String) {
        let mut res = self.result.lock().unwrap();
        res.extra_env.insert(key, value);
    }

    pub fn add_dll_override(&mut self, fragment: String) {
        let mut res = self.result.lock().unwrap();
        res.extra_dll_overrides.push(fragment);
    }

    pub fn log(&mut self, message: String) {
        let mut res = self.result.lock().unwrap();
        res.actions_log.push(message);
    }
}

pub fn run_fixup_script(
    app_id: u32,
    app_name: String,
    install_dir: PathBuf,
    wineprefix: PathBuf,
    target_architecture: String,
) -> anyhow::Result<Option<FixupResult>> {
    let config_dir = crate::config::config_dir()?;
    let fixups_dir = config_dir.join("fixups");
    let script_path = fixups_dir.join(format!("{}.rhai", app_id));

    if !script_path.exists() {
        return Ok(None);
    }

    let script = std::fs::read_to_string(&script_path)?;
    execute_script(script, app_id, app_name, install_dir, wineprefix, target_architecture)
}

fn execute_script(
    script: String,
    app_id: u32,
    app_name: String,
    install_dir: PathBuf,
    wineprefix: PathBuf,
    target_architecture: String,
) -> anyhow::Result<Option<FixupResult>> {
    let mut engine = Engine::new();

    engine.build_type::<FixupContext>();
    engine.register_fn("set_env", FixupContext::set_env);
    engine.register_fn("add_dll_override", FixupContext::add_dll_override);
    engine.register_fn("log", FixupContext::log);

    let result = std::sync::Arc::new(std::sync::Mutex::new(FixupResult::default()));
    let context = FixupContext {
        app_id,
        app_name,
        install_dir: install_dir.to_string_lossy().to_string(),
        wineprefix: wineprefix.to_string_lossy().to_string(),
        target_architecture,
        result: result.clone(),
    };

    let mut scope = Scope::new();
    scope.push("ctx", context);

    if let Err(e) = engine.run_with_scope(&mut scope, &script) {
        tracing::error!("Error running fixup script for AppID {}: {}", app_id, e);
        return Ok(None);
    }

    let final_result = result.lock().unwrap().clone();
    Ok(Some(final_result))
}

pub fn seed_default_fixups() -> anyhow::Result<()> {
    let config_dir = crate::config::config_dir()?;
    let fixups_dir = config_dir.join("fixups");
    std::fs::create_dir_all(&fixups_dir)?;

    let seed_scripts = [
        (409710, include_str!("seeds/409710.rhai")), // BioShock Remastered
        (22300, include_str!("seeds/22300.rhai")),  // Fallout 3
        (22370, include_str!("seeds/22370.rhai")),  // Fallout: New Vegas
        (72850, include_str!("seeds/72850.rhai")),  // Skyrim
    ];

    for (app_id, content) in seed_scripts {
        let path = fixups_dir.join(format!("{}.rhai", app_id));
        if !path.exists() {
            std::fs::write(path, content)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_script_success() {
        let script = r#"
            ctx.log("Starting fixup");
            ctx.set_env("PBA_DISABLE_CRASHHANDLER", "1");
            ctx.add_dll_override("d3d9=n,b");
            ctx.log("Fixup complete");
        "#.to_string();

        let res = execute_script(
            script,
            123,
            "Test Game".to_string(),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp/pfx"),
            "x86_64".to_string(),
        ).unwrap().unwrap();

        assert_eq!(res.extra_env.get("PBA_DISABLE_CRASHHANDLER").unwrap(), "1");
        assert_eq!(res.extra_dll_overrides[0], "d3d9=n,b");
        assert_eq!(res.actions_log[0], "Starting fixup");
        assert_eq!(res.actions_log[1], "Fixup complete");
    }

    #[test]
    fn test_execute_script_malformed() {
        let script = r#"
            this is not rhai script
        "#.to_string();

        let res = execute_script(
            script,
            123,
            "Test Game".to_string(),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp/pfx"),
            "x86_64".to_string(),
        ).unwrap();

        assert!(res.is_none());
    }
}
