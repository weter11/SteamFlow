use crate::launch::pipeline::{PipelineContext, PipelineError, PipelineStage};
use async_trait::async_trait;

#[derive(Default)]
pub struct BuildEnvironmentStage;

#[async_trait]
impl PipelineStage for BuildEnvironmentStage {
    fn name(&self) -> &str {
        "BuildEnvironment"
    }

    async fn run(&self, _ctx: &mut PipelineContext) -> Result<(), PipelineError> {
        // TODO: Implement environment building
        Ok(())
    }
}
