use anyhow::Result;
use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext};

pub struct BuildEnvironmentStage;

#[async_trait]
impl PipelineStage for BuildEnvironmentStage {
    fn name(&self) -> &str { "BuildEnvironment" }
    async fn execute(&self, _ctx: &mut PipelineContext) -> Result<()> {
        // Currently build_env is called internally by build_command in Runner
        Ok(())
    }
}
