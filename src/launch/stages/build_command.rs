use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext, LaunchError, LaunchErrorKind};

pub struct BuildCommandStage;

#[async_trait]
impl PipelineStage for BuildCommandStage {
    fn name(&self) -> &str { "BuildCommand" }
    async fn execute(&self, ctx: &mut PipelineContext) -> std::result::Result<(), LaunchError> {
        use crate::infra::runners::LaunchContext;

        if let Some(runner) = &ctx.runner {
            let runner_ctx = LaunchContext {
                app: ctx.app.as_ref()
                    .ok_or_else(|| LaunchError::new(LaunchErrorKind::Validation, "app missing"))?.clone(),
                launch_info: ctx.launch_info.as_ref()
                    .ok_or_else(|| LaunchError::new(LaunchErrorKind::Validation, "launch_info missing"))?.clone(),
                launcher_config: ctx.launcher_config.as_ref()
                    .ok_or_else(|| LaunchError::new(LaunchErrorKind::Validation, "launcher_config missing"))?.clone(),
                user_config: ctx.user_config.clone(),
                proton_path: ctx.proton_path.clone(),
                target_architecture: ctx.target_architecture,
                dll_resolutions: ctx.dll_resolutions.clone(),
                verification_ptr: &mut ctx.verification as *mut _,
            };
            let mut spec = runner.build_command(&runner_ctx).await?;

            // umu-launcher integration
            let use_umu = ctx.user_config.as_ref()
                .and_then(|c| c.use_umu)
                .unwrap_or(ctx.launcher_config.as_ref().map(|c| c.use_umu).unwrap_or(false));

            if use_umu {
                if let Some(logger) = &ctx.logger {
                    let _ = logger.info("umu_intercept", "Intercepting command for umu-run wrapping".to_string(), Some("BuildCommand".to_string()), std::collections::HashMap::new());
                }

                // Ensure umu-run is available
                if let Err(e) = std::process::Command::new("umu-run").arg("--version").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status() {
                    return Err(LaunchError::new(LaunchErrorKind::Environment, format!("umu-run not found in PATH: {}", e)));
                }

                let game_id = ctx.app_id.to_string();
                let proton_path = ctx.proton_path.as_ref()
                    .ok_or_else(|| LaunchError::new(LaunchErrorKind::Environment, "proton_path missing for umu-run"))?;

                // Construct new umu-run command
                let mut umu_args = vec![
                    spec.program.to_string_lossy().to_string(),
                ];
                umu_args.extend(spec.args);

                spec.program = std::path::PathBuf::from("umu-run");
                spec.args = umu_args;
                spec.env.insert("GAMEID".to_string(), game_id);
                spec.env.insert("PROTONPATH".to_string(), proton_path.clone());
            }

            ctx.command_spec = Some(spec);
        }
        Ok(())
    }
}
