use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext};

pub struct SpawnProcessStage;

#[async_trait]
impl PipelineStage for SpawnProcessStage {
    fn name(&self) -> &str { "SpawnProcess" }
    async fn execute(&self, ctx: &mut PipelineContext) -> Result<()> {
        if let Some(runner) = &ctx.runner {
            if let Some(spec) = &ctx.command_spec {
                if let Some(logger) = &ctx.logger {
                    let mut metadata = std::collections::HashMap::new();
                    metadata.insert("program".to_string(), spec.program.to_string_lossy().to_string());
                    metadata.insert("args".to_string(), spec.args.join(" "));
                    for (k, v) in &spec.env {
                        metadata.insert(format!("env:{}", k), v.clone());
                    }
                    let _ = logger.info("process_spawn_attempt", "Attempting to spawn process via runner".to_string(), Some("SpawnProcess".to_string()), metadata);
                }

                let child = runner.launch(spec)?;
                ctx.child = Some(child);
            }
        } else {
            // Legacy/Native fallback if no runner resolved
            let app = ctx.app.as_ref().context("app missing")?;
            let launch_info = ctx.launch_info.as_ref().context("launch_info missing")?;
            let launcher_config = ctx.launcher_config.as_ref().context("launcher_config missing")?;

            // For now, we use the legacy path for NativeLinux until NativeRunner is implemented
            let client = crate::steam_client::SteamClient::new()?;
            let child = client.internal_legacy_launch_adhoc(
                app,
                launch_info,
                ctx.proton_path.as_deref(),
                launcher_config,
                ctx.user_config.as_ref()
            )?;
            ctx.child = Some(child);
        }
        Ok(())
    }
}
