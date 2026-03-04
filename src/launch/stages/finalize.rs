use anyhow::Result;
use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext};

pub struct FinalizeStage;

#[async_trait]
impl PipelineStage for FinalizeStage {
    fn name(&self) -> &str { "Finalize" }
    async fn execute(&self, _ctx: &mut PipelineContext) -> Result<()> {
        Ok(())
    }
}
