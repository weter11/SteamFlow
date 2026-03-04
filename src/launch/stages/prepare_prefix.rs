use anyhow::Result;
use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext};

pub struct PreparePrefixStage;

#[async_trait]
impl PipelineStage for PreparePrefixStage {
    fn name(&self) -> &str { "PreparePrefix" }
    async fn execute(&self, _ctx: &mut PipelineContext) -> Result<()> {
        // TODO: Day 2 Logic migration
        Ok(())
    }
}
