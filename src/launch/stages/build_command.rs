use anyhow::Result;
use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext};

pub struct BuildCommandStage;

#[async_trait]
impl PipelineStage for BuildCommandStage {
    fn name(&self) -> &str { "BuildCommand" }
    async fn execute(&self, _ctx: &mut PipelineContext) -> Result<()> {
        // TODO: Day 2 Logic migration
        Ok(())
    }
}
