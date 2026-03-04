use anyhow::{Result, bail};
use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext};

pub struct ResolveGameStage;

#[async_trait]
impl PipelineStage for ResolveGameStage {
    fn name(&self) -> &str { "ResolveGame" }
    async fn execute(&self, ctx: &mut PipelineContext) -> Result<()> {
        if ctx.app.is_none() {
            // In the future, we might resolve the app here if only app_id is provided
            bail!("App context missing in ResolveGameStage");
        }
        Ok(())
    }
}
