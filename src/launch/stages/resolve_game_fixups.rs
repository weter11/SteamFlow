use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext, LaunchError, LaunchErrorKind};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
                // Use the EFFECTIVE prefix mode so registry fixups target the
                // same prefix the launch uses (runner-mismatch guard).
                let configured_mode = ctx.user_config.as_ref()
                    .map(|c| c.steam_prefix_mode.clone())
                    .unwrap_or(config.steam_prefix_mode.clone());
                let effective_mode = crate::infra::runners::wine_tkg::effective_prefix_mode_impl(
                    configured_mode,
                    &config.steam_runtime_runner,
                    proton,
                    &library_root,
                );
                let wineprefix = crate::utils::steam_wineprefix_for_game(config, ctx.app_id, &store, Some(effective_mode));
                let install_dir = app.install_path.clone().unwrap_or_default();
                let arch = match ctx.target_architecture { crate::models::ExecutableArchitecture::X86 => "x86", _ => "x86_64" };
                let fctx = crate::launch::fixups::FixupContext::new(ctx.app_id, app.name.clone(), install_dir, wineprefix.to_string_lossy().to_string(), arch.into());
                match crate::launch::fixups::load_and_run_fixup(ctx.app_id, fctx) {
                    Ok(Some((name, result))) => {
                        if !result.registry.is_empty() {
                            if let Err(e) = apply_registry_ops(&runner, &wineprefix, &result.registry, name.as_str(), ctx) {
                                if let Some(logger) = &ctx.logger {
                                    let mut m = HashMap::new(); m.insert("app_id".into(), ctx.app_id.to_string()); m.insert("error".into(), e.to_string());
                                    let _ = logger.error("fixup_registry_warning", "Registry fixup failed; continuing launch".into(), Some(self.name().into()), m);
                                }
                            }
                        }
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


/// Apply fixup registry operations inline (Q1 decision): run `wine reg.exe add`
/// against the prefix right after the Rhai script executes, before the game spawns.
/// Non-zero `reg.exe` exits log a warning but do NOT halt the launch.
fn apply_registry_ops(
    runner: &Path,
    wineprefix: &Path,
    ops: &[crate::launch::fixups::RegOp],
    script_name: &str,
    ctx: &PipelineContext,
) -> std::result::Result<(), LaunchError> {
    use crate::launch::fixups::RegKind;
    let wine_bin = crate::utils::build_bare_wine_command(runner)
        .map_err(|e| LaunchError::new(LaunchErrorKind::Runner, format!("registry fixup: cannot resolve wine for runner {}", runner.display())).with_source(e))?
        .get_program()
        .to_owned();
    for op in ops {
        let (reg_type, value) = match op.kind {
            RegKind::Dword => ("REG_DWORD", op.value.clone()),
            RegKind::String => ("REG_SZ", op.value.clone()),
        };
        let mut reg = std::process::Command::new(&wine_bin);
        reg.env("WINEPREFIX", wineprefix);
        reg.arg("reg.exe").arg("add").arg(&op.path)
            .arg("/v").arg(&op.key)
            .arg("/t").arg(reg_type)
            .arg("/d").arg(&value)
            .arg("/f");
        let out = reg.output()
            .map_err(|e| LaunchError::new(LaunchErrorKind::Process, format!("registry fixup: failed to run reg.exe for {}\\{}", op.path, op.key)).with_source(anyhow::Error::from(e)))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            if let Some(logger) = &ctx.logger {
                let mut m = HashMap::new();
                m.insert("app_id".into(), ctx.app_id.to_string());
                m.insert("script".into(), script_name.to_string());
                m.insert("reg_path".into(), format!("{}\\{}", op.path, op.key));
                m.insert("stderr".into(), stderr);
                let _ = logger.error("fixup_registry_warning", "reg.exe exited non-zero; continuing launch".into(), Some("ResolveGameFixups".into()), m);
            }
        } else if let Some(logger) = &ctx.logger {
            let mut m = HashMap::new();
            m.insert("app_id".into(), ctx.app_id.to_string());
            m.insert("reg_path".into(), format!("{}\\{}", op.path, op.key));
            m.insert("value".into(), value);
            let _ = logger.info("fixup_registry_applied", "Applied registry fixup".into(), Some("ResolveGameFixups".into()), m);
        }
    }
    Ok(())
}
