use crate::launch::pipeline::{PipelineContext, PipelineError, PipelineStage};
use async_trait::async_trait;

#[derive(Default)]
pub struct SpawnProcessStage;

#[async_trait]
impl PipelineStage for SpawnProcessStage {
    fn name(&self) -> &str {
        "SpawnProcess"
    }

    async fn run(&self, _ctx: &mut PipelineContext) -> Result<(), PipelineError> {
        // TODO: Implement process spawning
        Ok(())
    }
}
