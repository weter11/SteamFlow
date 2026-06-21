use crate::launch::pipeline::{PipelineStage, PipelineContext, LaunchError, LaunchErrorKind};
use async_trait::async_trait;
use crate::utils::classify_runner;

pub struct ResolveGameFixupsStage;

#[async_trait]
impl PipelineStage for ResolveGameFixupsStage {
    fn name(&self) -> &str { "ResolveGameFixups" }

    async fn execute(&self, ctx: &mut PipelineContext) -> Result<(), LaunchError> {
        let library_root = std::path::PathBuf::from(
            ctx.launcher_config.as_ref()
                .map(|c| c.steam_library_path.clone())
                .unwrap_or_default()
        );

        let proton = if let Some(forced) = ctx.launcher_config.as_ref()
            .and_then(|c| c.game_configs.get(&ctx.app_id))
            .and_then(|c| c.forced_proton_version.as_ref())
        {
            forced.as_str()
        } else {
            ctx.proton_path.as_deref()
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| ctx.launcher_config.as_ref().map(|c| c.proton_version.as_str()).unwrap_or("Proton - Experimental"))
        };

        let active_runner_path = crate::utils::resolve_runner(proton, &library_root);
        let kind = classify_runner(&active_runner_path);

        match kind {
            crate::utils::RunnerKind::Proton { has_protonfixes, .. } if has_protonfixes => {
                tracing::info!("Proton runner with bundled fixes detected. Skipping Rhai fixups.");
                ctx.verification.protonfixes_routed = true;
                ctx.fixup_result = None;
            }
            crate::utils::RunnerKind::PlainWine { .. } | crate::utils::RunnerKind::Proton { .. } => {
                tracing::info!("Plain Wine or Proton without bundled fixes detected. Running Rhai fixups.");
                ctx.verification.protonfixes_routed = false;

                let app_name = ctx.app.as_ref().map(|a| a.name.clone()).unwrap_or_default();
                let install_dir = ctx.resolved_install_dir.clone().unwrap_or_default();

                let config = ctx.launcher_config.as_ref().ok_or_else(|| {
                    LaunchError::new(LaunchErrorKind::Validation, "Launcher config missing in ResolveGameFixupsStage")
                })?;

                let wineprefix = crate::utils::steam_wineprefix_for_game(
                    config,
                    ctx.app_id,
                    &ctx.user_config.as_ref().map(|c| {
                        let mut store = std::collections::HashMap::new();
                        store.insert(ctx.app_id, c.clone());
                        store
                    }).unwrap_or_default().into()
                );
                let arch = format!("{:?}", ctx.target_architecture).to_lowercase();

                match crate::launch::fixups::run_fixup_script(
                    ctx.app_id,
                    app_name,
                    install_dir,
                    wineprefix,
                    arch,
                ) {
                    Ok(Some(res)) => {
                        tracing::info!("Rhai fixup applied for AppID {}", ctx.app_id);
                        ctx.verification.rhai_fixup_applied = Some(ctx.app_id.to_string());
                        ctx.fixup_result = Some(res);
                    }
                    Ok(None) => {
                        tracing::info!("No Rhai fixup found or applied for AppID {}", ctx.app_id);
                        ctx.fixup_result = None;
                    }
                    Err(e) => {
                        tracing::error!("Error running Rhai fixup for AppID {}: {}", ctx.app_id, e);
                        ctx.fixup_result = None;
                    }
                }
            }
            crate::utils::RunnerKind::Unknown => {
                return Err(LaunchError::new(
                    LaunchErrorKind::Runner,
                    format!("Failed to classify runner at {}", active_runner_path.display())
                ));
            }
        }

        Ok(())
    }
}
