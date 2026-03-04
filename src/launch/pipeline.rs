use thiserror::Error;
use async_trait::async_trait;

#[derive(Error, Debug)]
pub enum PipelineError {
    #[error("Stage '{stage_name}' failed: {message}")]
    StageFailed {
        stage_name: String,
        message: String,
    },
}

#[derive(Debug, Default)]
pub struct PipelineContext {
    pub app_id: u32,
    // TODO: Add fields for game, profile, components, etc.
}

#[async_trait]
pub trait PipelineStage: Send + Sync {
    fn name(&self) -> &str;
    async fn run(&self, ctx: &mut PipelineContext) -> Result<(), PipelineError>;
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

    pub async fn execute(&self, ctx: &mut PipelineContext) -> Result<(), PipelineError> {
        for stage in &self.stages {
            stage.run(ctx).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    struct TestStage {
        name: String,
        executed_order: Arc<Mutex<Vec<String>>>,
        fail: bool,
    }

    #[async_trait]
    impl PipelineStage for TestStage {
        fn name(&self) -> &str {
            &self.name
        }

        async fn run(&self, _ctx: &mut PipelineContext) -> Result<(), PipelineError> {
            if self.fail {
                return Err(PipelineError::StageFailed {
                    stage_name: self.name.clone(),
                    message: "Induced failure".to_string(),
                });
            }
            self.executed_order.lock().await.push(self.name.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_pipeline_deterministic_order() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut pipeline = LaunchPipeline::new();

        pipeline.add_stage(Box::new(TestStage {
            name: "Stage1".to_string(),
            executed_order: order.clone(),
            fail: false,
        }));
        pipeline.add_stage(Box::new(TestStage {
            name: "Stage2".to_string(),
            executed_order: order.clone(),
            fail: false,
        }));

        let mut ctx = PipelineContext::default();
        pipeline.execute(&mut ctx).await.unwrap();

        let final_order = order.lock().await;
        assert_eq!(final_order.len(), 2);
        assert_eq!(final_order[0], "Stage1");
        assert_eq!(final_order[1], "Stage2");
    }

    #[tokio::test]
    async fn test_pipeline_short_circuits_on_error() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut pipeline = LaunchPipeline::new();

        pipeline.add_stage(Box::new(TestStage {
            name: "Stage1".to_string(),
            executed_order: order.clone(),
            fail: true,
        }));
        pipeline.add_stage(Box::new(TestStage {
            name: "Stage2".to_string(),
            executed_order: order.clone(),
            fail: false,
        }));

        let mut ctx = PipelineContext::default();
        let result = pipeline.execute(&mut ctx).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            PipelineError::StageFailed { stage_name, .. } => assert_eq!(stage_name, "Stage1"),
        }

        let final_order = order.lock().await;
        assert_eq!(final_order.len(), 0);
    }
}
