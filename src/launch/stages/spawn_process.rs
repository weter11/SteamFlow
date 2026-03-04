use anyhow::Result;
use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext};

pub struct SpawnProcessStage;

#[async_trait]
impl PipelineStage for SpawnProcessStage {
    fn name(&self) -> &str { "SpawnProcess" }
    async fn execute(&self, _ctx: &mut PipelineContext) -> Result<()> {
        // TODO: Day 2 Logic migration
        Ok(())
    }
}
