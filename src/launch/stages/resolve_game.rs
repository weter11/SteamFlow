use anyhow::Result;
use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext};

pub struct ResolveGameStage;

#[async_trait]
impl PipelineStage for ResolveGameStage {
    fn name(&self) -> &str { "ResolveGame" }
    async fn execute(&self, _ctx: &mut PipelineContext) -> Result<()> {
        // TODO: Day 2 Logic migration
        Ok(())
    }
}
