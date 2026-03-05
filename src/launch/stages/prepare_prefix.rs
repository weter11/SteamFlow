use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext, LaunchError, LaunchErrorKind};

pub struct PreparePrefixStage;

#[async_trait]
impl PipelineStage for PreparePrefixStage {
    fn name(&self) -> &str { "PreparePrefix" }
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
            };
            runner.prepare_prefix(&runner_ctx).await?;
        }
        Ok(())
    }
}
