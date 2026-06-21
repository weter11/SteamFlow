use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext, LaunchError, LaunchErrorKind};
use std::collections::HashMap;
use std::path::PathBuf;

pub struct ResolveGameFixupsStage;

#[async_trait]
impl PipelineStage for ResolveGameFixupsStage {
    fn name(&self) -> &str { "ResolveGameFixups" }

    async fn execute(&self, ctx: &mut PipelineContext) -> std::result::Result<(), LaunchError> {
        let config = ctx.launcher_config.as_ref().ok_or_else(|| LaunchError::new(LaunchErrorKind::Validation, "launcher_config missing"))?;
        let app = ctx.app.as_ref().ok_or_else(|| LaunchError::new(LaunchErrorKind::Validation, "app missing"))?;
        let library_root = PathBuf::from(&config.steam_library_path);
        let proton = if let Some(forced) = config.game_configs.get(&ctx.app_id).and_then(|c| c.forced_proton_version.as_ref()) {
            forced.as_str()
        } else {
            ctx.proton_path.as_deref().filter(|p| !p.is_empty()).unwrap_or(config.proton_version.as_str())
        };
        let runner = crate::utils::resolve_runner(proton, &library_root);
        match crate::utils::classify_runner(&runner) {
            crate::utils::RunnerKind::Unknown => return Err(LaunchError::new(LaunchErrorKind::Runner, format!("Unknown game runner: {}", runner.display()))),
            crate::utils::RunnerKind::Proton { has_protonfixes: true, .. } => {
                ctx.fixup_result = None;
                ctx.fixup_script_name = None;
                ctx.verification.protonfixes_routed = true;
                if let Some(logger) = &ctx.logger { let _ = logger.info("protonfixes_routed", "Using Proton bundled protonfixes via proton run".into(), Some(self.name().into()), HashMap::new()); }
            }
            _ => {
                ctx.verification.protonfixes_routed = false;
                let store: crate::models::UserConfigStore = ctx.user_config.as_ref().map(|c| { let mut s = HashMap::new(); s.insert(ctx.app_id, c.clone()); s }).unwrap_or_default().into();
                let wineprefix = crate::utils::steam_wineprefix_for_game(config, ctx.app_id, &store);
                let install_dir = app.install_path.clone().unwrap_or_default();
                let arch = match ctx.target_architecture { crate::models::ExecutableArchitecture::X86 => "x86", _ => "x86_64" };
                let fctx = crate::launch::fixups::FixupContext::new(ctx.app_id, app.name.clone(), install_dir, wineprefix.to_string_lossy().to_string(), arch.into());
                match crate::launch::fixups::load_and_run_fixup(ctx.app_id, fctx) {
                    Ok(Some((name, result))) => {
                        ctx.verification.rhai_fixup_applied = Some(name.clone());
                        ctx.fixup_script_name = Some(name);
                        ctx.fixup_result = Some(result);
                    }
                    Ok(None) => { ctx.fixup_result = None; ctx.fixup_script_name = None; }
                    Err(e) => {
                        if let Some(logger) = &ctx.logger {
                            let mut m = HashMap::new(); m.insert("app_id".into(), ctx.app_id.to_string()); m.insert("error".into(), e.to_string());
                            let _ = logger.error("fixup_script_error", "Rhai fixup failed; continuing without fixup".into(), Some(self.name().into()), m);
                        }
                        ctx.fixup_result = Some(crate::launch::fixups::FixupResult::default());
                    }
                }
            }
        }
        Ok(())
    }
}
