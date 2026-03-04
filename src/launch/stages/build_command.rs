use crate::launch::pipeline::{PipelineContext, PipelineError, PipelineStage};
use async_trait::async_trait;

#[derive(Default)]
pub struct BuildCommandStage;

#[async_trait]
impl PipelineStage for BuildCommandStage {
    fn name(&self) -> &str {
        "BuildCommand"
    }

    async fn run(&self, _ctx: &mut PipelineContext) -> Result<(), PipelineError> {
        // TODO: Implement command building
        Ok(())
    }
}
