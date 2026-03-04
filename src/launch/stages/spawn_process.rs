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
            let child = client.spawn_game_process_legacy(
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
