use anyhow::{Result, bail};
use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext};

pub struct ResolveProfileStage;

#[async_trait]
impl PipelineStage for ResolveProfileStage {
    fn name(&self) -> &str { "ResolveProfile" }
    async fn execute(&self, ctx: &mut PipelineContext) -> Result<()> {
        if ctx.launch_info.is_none() {
            bail!("LaunchInfo missing in ResolveProfileStage");
        }
        Ok(())
    }
}
