use anyhow::Result;
use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext};

pub struct ResolveComponentsStage;

#[async_trait]
impl PipelineStage for ResolveComponentsStage {
    fn name(&self) -> &str { "ResolveComponents" }
    async fn execute(&self, ctx: &mut PipelineContext) -> Result<()> {
        use crate::infra::runners::WineTkgRunner;
        use crate::steam_client::LaunchTarget;

        if ctx.runner.is_none() {
            if let Some(info) = &ctx.launch_info {
                match info.target {
                    LaunchTarget::NativeLinux => {
                        // Native runner not yet implemented in infra/runners
                    }
                    LaunchTarget::WindowsProton => {
                        ctx.runner = Some(Box::new(WineTkgRunner));
                    }
                }
            }
        }
        Ok(())
    }
}
