use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext, LaunchError};

pub struct BuildEnvironmentStage;

#[async_trait]
impl PipelineStage for BuildEnvironmentStage {
    fn name(&self) -> &str { "BuildEnvironment" }
    async fn execute(&self, _ctx: &mut PipelineContext) -> std::result::Result<(), LaunchError> {
        // Environment is built inside Runner::build_env(). This stage exists for
        // future expansion (e.g. pre-launch Steam readiness gate, DX12 detection).
        Ok(())
    }
}
