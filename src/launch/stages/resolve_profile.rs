use crate::launch::pipeline::{PipelineContext, PipelineError, PipelineStage};
use async_trait::async_trait;

#[derive(Default)]
pub struct ResolveProfileStage;

#[async_trait]
impl PipelineStage for ResolveProfileStage {
    fn name(&self) -> &str {
        "ResolveProfile"
    }

    async fn run(&self, _ctx: &mut PipelineContext) -> Result<(), PipelineError> {
        // TODO: Implement profile resolution
        Ok(())
    }
}
