use crate::launch::pipeline::{PipelineContext, PipelineError, PipelineStage};
use async_trait::async_trait;

#[derive(Default)]
pub struct ResolveGameStage;

#[async_trait]
impl PipelineStage for ResolveGameStage {
    fn name(&self) -> &str {
        "ResolveGame"
    }

    async fn run(&self, _ctx: &mut PipelineContext) -> Result<(), PipelineError> {
        // TODO: Implement game resolution
        Ok(())
    }
}
