use crate::launch::pipeline::{PipelineContext, PipelineError, PipelineStage};
use async_trait::async_trait;

#[derive(Default)]
pub struct ResolveComponentsStage;

#[async_trait]
impl PipelineStage for ResolveComponentsStage {
    fn name(&self) -> &str {
        "ResolveComponents"
    }

    async fn run(&self, _ctx: &mut PipelineContext) -> Result<(), PipelineError> {
        // TODO: Implement components resolution
        Ok(())
    }
}
