use std::fmt;
use anyhow::Result;
use async_trait::async_trait;

use crate::models::{LibraryGame, UserAppConfig};
use crate::config::LauncherConfig;
use crate::steam_client::LaunchInfo;
use crate::infra::runners::{Runner, CommandSpec};

pub struct PipelineContext {
    pub app_id: u32,
    pub app: Option<LibraryGame>,
    pub launch_info: Option<LaunchInfo>,
    pub launcher_config: Option<LauncherConfig>,
    pub user_config: Option<UserAppConfig>,
    pub proton_path: Option<String>,

    pub runner: Option<Box<dyn Runner>>,
    pub command_spec: Option<CommandSpec>,
    pub child: Option<std::process::Child>,
}

impl PipelineContext {
    pub fn new(app_id: u32) -> Self {
        Self {
            app_id,
            app: None,
            launch_info: None,
            launcher_config: None,
            user_config: None,
            proton_path: None,
            runner: None,
            command_spec: None,
            child: None,
        }
    }
}

#[derive(Debug)]
pub struct PipelineError {
    pub stage_name: String,
    pub inner: anyhow::Error,
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pipeline failed at stage '{}': {}", self.stage_name, self.inner)
    }
}

impl std::error::Error for PipelineError {}

#[async_trait]
pub trait PipelineStage: Send + Sync {
    fn name(&self) -> &str;
    async fn execute(&self, ctx: &mut PipelineContext) -> Result<()>;
}

pub struct LaunchPipeline {
    stages: Vec<Box<dyn PipelineStage>>,
}

impl LaunchPipeline {
    pub fn new() -> Self {
        Self { stages: Vec::new() }
    }

    pub fn add_stage(&mut self, stage: Box<dyn PipelineStage>) {
        self.stages.push(stage);
    }

    pub fn with_default_stages() -> Self {
        let mut pipeline = Self::new();
        pipeline.add_stage(Box::new(crate::launch::stages::resolve_game::ResolveGameStage));
        pipeline.add_stage(Box::new(crate::launch::stages::resolve_profile::ResolveProfileStage));
        pipeline.add_stage(Box::new(crate::launch::stages::resolve_components::ResolveComponentsStage));
        pipeline.add_stage(Box::new(crate::launch::stages::prepare_prefix::PreparePrefixStage));
        pipeline.add_stage(Box::new(crate::launch::stages::build_environment::BuildEnvironmentStage));
        pipeline.add_stage(Box::new(crate::launch::stages::build_command::BuildCommandStage));
        pipeline.add_stage(Box::new(crate::launch::stages::spawn_process::SpawnProcessStage));
        pipeline.add_stage(Box::new(crate::launch::stages::finalize::FinalizeStage));
        pipeline
    }

    pub async fn run(&self, ctx: &mut PipelineContext) -> std::result::Result<(), PipelineError> {
        for stage in &self.stages {
            if let Err(e) = stage.execute(ctx).await {
                return Err(PipelineError {
                    stage_name: stage.name().to_string(),
                    inner: e,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SuccessStage(&'static str);
    #[async_trait]
    impl PipelineStage for SuccessStage {
        fn name(&self) -> &str { self.0 }
        async fn execute(&self, _ctx: &mut PipelineContext) -> Result<()> { Ok(()) }
    }

    struct FailStage(&'static str);
    #[async_trait]
    impl PipelineStage for FailStage {
        fn name(&self) -> &str { self.0 }
        async fn execute(&self, _ctx: &mut PipelineContext) -> Result<()> {
            Err(anyhow::anyhow!("failure"))
        }
    }

    #[tokio::test]
    async fn test_pipeline_order_and_success() {
        let mut pipeline = LaunchPipeline::new();
        pipeline.add_stage(Box::new(SuccessStage("stage1")));
        pipeline.add_stage(Box::new(SuccessStage("stage2")));

        let mut ctx = PipelineContext::new(0);
        assert!(pipeline.run(&mut ctx).await.is_ok());
    }

    #[tokio::test]
    async fn test_pipeline_short_circuit() {
        let mut pipeline = LaunchPipeline::new();
        pipeline.add_stage(Box::new(FailStage("stage1")));
        pipeline.add_stage(Box::new(SuccessStage("stage2")));

        let mut ctx = PipelineContext::new(0);
        let res = pipeline.run(&mut ctx).await;

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.stage_name, "stage1");
    }

    #[tokio::test]
    async fn test_pipeline_returned_error_context() {
        let mut pipeline = LaunchPipeline::new();
        pipeline.add_stage(Box::new(SuccessStage("stage1")));
        pipeline.add_stage(Box::new(FailStage("stage2")));

        let mut ctx = PipelineContext::new(0);
        let res = pipeline.run(&mut ctx).await;

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.stage_name, "stage2");
        assert_eq!(err.inner.to_string(), "failure");
    }
}
