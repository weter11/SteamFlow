use crate::launch::pipeline::{PipelineContext, PipelineError, PipelineStage};
use async_trait::async_trait;

#[derive(Default)]
pub struct FinalizeStage;

#[async_trait]
impl PipelineStage for FinalizeStage {
    fn name(&self) -> &str {
        "Finalize"
    }

    async fn run(&self, _ctx: &mut PipelineContext) -> Result<(), PipelineError> {
        // TODO: Implement finalization
        Ok(())
    }
}
