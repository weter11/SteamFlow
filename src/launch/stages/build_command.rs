use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext};

pub struct BuildCommandStage;

#[async_trait]
impl PipelineStage for BuildCommandStage {
    fn name(&self) -> &str { "BuildCommand" }
    async fn execute(&self, ctx: &mut PipelineContext) -> Result<()> {
        use crate::infra::runners::LaunchContext;

        if let Some(runner) = &ctx.runner {
            let runner_ctx = LaunchContext {
                app: ctx.app.as_ref().context("app missing")?.clone(),
                launch_info: ctx.launch_info.as_ref().context("launch_info missing")?.clone(),
                launcher_config: ctx.launcher_config.as_ref().context("launcher_config missing")?.clone(),
                user_config: ctx.user_config.clone(),
                proton_path: ctx.proton_path.clone(),
            };
            let spec = runner.build_command(&runner_ctx)?;
            ctx.command_spec = Some(spec);
        }
        Ok(())
    }
}
