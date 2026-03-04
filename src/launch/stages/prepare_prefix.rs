use crate::launch::pipeline::{PipelineContext, PipelineError, PipelineStage};
use async_trait::async_trait;

#[derive(Default)]
pub struct PreparePrefixStage;

#[async_trait]
impl PipelineStage for PreparePrefixStage {
    fn name(&self) -> &str {
        "PreparePrefix"
    }

    async fn run(&self, _ctx: &mut PipelineContext) -> Result<(), PipelineError> {
        // TODO: Implement prefix preparation
        Ok(())
    }
}
