use std::fmt;
use async_trait::async_trait;

use std::collections::HashMap;
use crate::models::{LibraryGame, UserAppConfig};
use crate::config::LauncherConfig;
use crate::steam_client::LaunchInfo;
use crate::infra::runners::{Runner, CommandSpec};
use crate::infra::logging::{LaunchSession, EventLogger};

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

    pub session: Option<LaunchSession>,
    pub logger: Option<EventLogger>,
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
            session: None,
            logger: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LaunchErrorKind {
    Validation,      // Missing app context, invalid app id
    Environment,     // Missing proton path, config issues
    Permission,      // Failed to create dir, set permissions
    Runner,          // Runner prepare_prefix/build_command failed
    GameData,        // appmanifest not found, executable not found
    Process,         // Failed to spawn process
    Dependency,      // Missing MangoHud, etc.
    Unknown,
}

impl fmt::Display for LaunchErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Validation => "Validation",
            Self::Environment => "Environment",
            Self::Permission => "Permission",
            Self::Runner => "Runner",
            Self::GameData => "Game Data",
            Self::Process => "Process",
            Self::Dependency => "Dependency",
            Self::Unknown => "Unknown",
        };
        write!(f, "{}", s)
    }
}

impl LaunchErrorKind {
    pub fn remediation_hint(&self) -> &'static str {
        match self {
            Self::Validation => "Check if the game is correctly imported.",
            Self::Environment => "Verify your Global Settings and Compatibility Layer path.",
            Self::Permission => "Check filesystem permissions for the library and prefix folders.",
            Self::Runner => "Try a different Proton/Wine version.",
            Self::GameData => "Verify integrity of game files or reinstall the game.",
            Self::Process => "Ensure no other instance of the game is running.",
            Self::Dependency => "Install missing system dependencies.",
            Self::Unknown => "Check the detailed logs for more information.",
        }
    }
}

#[derive(Debug)]
pub struct LaunchError {
    pub kind: LaunchErrorKind,
    pub message: String,
    pub context: HashMap<String, String>,
    pub source: Option<anyhow::Error>,
}

impl LaunchError {
    pub fn new(kind: LaunchErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            context: HashMap::new(),
            source: None,
        }
    }

    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    pub fn with_source(mut self, source: anyhow::Error) -> Self {
        self.source = Some(source);
        self
    }
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} - {}", self.kind, self.message, self.kind.remediation_hint())
    }
}

impl std::error::Error for LaunchError {}

pub fn map_anyhow_error(err: anyhow::Error) -> LaunchError {
    let msg = err.to_string();
    if msg.contains("Permission denied") || msg.contains("EACCES") {
        LaunchError::new(LaunchErrorKind::Permission, msg).with_source(err)
    } else if msg.contains("not found") || msg.contains("No such file or directory") {
        LaunchError::new(LaunchErrorKind::GameData, msg).with_source(err)
    } else if msg.contains("proton") || msg.contains("compatibility layer") {
        LaunchError::new(LaunchErrorKind::Runner, msg).with_source(err)
    } else {
        LaunchError::new(LaunchErrorKind::Unknown, msg).with_source(err)
    }
}

#[derive(Debug)]
pub struct PipelineError {
    pub stage_name: String,
    pub inner: LaunchError,
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
    async fn execute(&self, ctx: &mut PipelineContext) -> std::result::Result<(), LaunchError>;
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
        if let Some(logger) = &ctx.logger {
            let mut metadata = HashMap::new();
            metadata.insert("app_id".to_string(), ctx.app_id.to_string());
            if let Some(app) = &ctx.app {
                metadata.insert("app_name".to_string(), app.name.clone());
            }
            let _ = logger.info("launch_start", "Starting launch pipeline".to_string(), None, metadata);
        }

        for stage in &self.stages {
            let stage_name = stage.name().to_string();
            if let Some(logger) = &ctx.logger {
                let _ = logger.info("stage_start", format!("Starting stage: {}", stage_name), Some(stage_name.clone()), HashMap::new());
            }

            let start_time = std::time::Instant::now();
            if let Err(e) = stage.execute(ctx).await {
                let duration = start_time.elapsed().as_millis();
                if let Some(logger) = &ctx.logger {
                    let mut metadata = HashMap::new();
                    metadata.insert("error_kind".to_string(), e.kind.to_string());
                    metadata.insert("error_message".to_string(), e.message.clone());
                    metadata.insert("duration_ms".to_string(), duration.to_string());
                    for (k, v) in &e.context {
                        metadata.insert(format!("error_ctx_{}", k), v.clone());
                    }
                    let _ = logger.error("stage_failure", format!("Stage failed: {}", stage_name), Some(stage_name.clone()), metadata.clone());

                    let _ = logger.error("launch_end", "Launch failed".to_string(), None, metadata);
                }

                return Err(PipelineError {
                    stage_name,
                    inner: e,
                });
            }

            let duration = start_time.elapsed().as_millis();
            if let Some(logger) = &ctx.logger {
                let mut metadata = HashMap::new();
                metadata.insert("duration_ms".to_string(), duration.to_string());
                let _ = logger.info("stage_success", format!("Stage succeeded: {}", stage_name), Some(stage_name.clone()), metadata);
            }
        }

        if let Some(logger) = &ctx.logger {
            let _ = logger.info("launch_end", "Launch successful".to_string(), None, HashMap::new());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    struct SuccessStage(&'static str);
    #[async_trait]
    impl PipelineStage for SuccessStage {
        fn name(&self) -> &str { self.0 }
        async fn execute(&self, _ctx: &mut PipelineContext) -> std::result::Result<(), LaunchError> { Ok(()) }
    }

    struct FailStage(&'static str);
    #[async_trait]
    impl PipelineStage for FailStage {
        fn name(&self) -> &str { self.0 }
        async fn execute(&self, _ctx: &mut PipelineContext) -> std::result::Result<(), LaunchError> {
            Err(LaunchError::new(LaunchErrorKind::Unknown, "failure"))
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
        assert!(err.inner.to_string().contains("failure"));
    }

    #[test]
    fn test_map_anyhow_error() {
        let err = anyhow::anyhow!("Permission denied: /tmp/pfx");
        let mapped = map_anyhow_error(err);
        assert_eq!(mapped.kind, LaunchErrorKind::Permission);

        let err = anyhow::anyhow!("file not found");
        let mapped = map_anyhow_error(err);
        assert_eq!(mapped.kind, LaunchErrorKind::GameData);

        let err = anyhow::anyhow!("random error");
        let mapped = map_anyhow_error(err);
        assert_eq!(mapped.kind, LaunchErrorKind::Unknown);
    }

    #[tokio::test]
    async fn test_pipeline_logging() {
        let mut pipeline = LaunchPipeline::new();
        pipeline.add_stage(Box::new(SuccessStage("test_stage")));

        let tmp = tempdir().unwrap();
        let session = LaunchSession::new(tmp.path());
        let logger = EventLogger::new(&session).unwrap();

        let mut ctx = PipelineContext::new(123);
        ctx.logger = Some(logger);

        pipeline.run(&mut ctx).await.unwrap();

        let content = std::fs::read_to_string(session.event_log_path()).unwrap();
        assert!(content.contains("launch_start"));
        assert!(content.contains("stage_start"));
        assert!(content.contains("test_stage"));
        assert!(content.contains("stage_success"));
        assert!(content.contains("launch_end"));
    }

    #[tokio::test]
    async fn test_pipeline_structured_error_logging() {
        let mut pipeline = LaunchPipeline::new();
        pipeline.add_stage(Box::new(FailStage("fail_stage")));

        let tmp = tempdir().unwrap();
        let session = LaunchSession::new(tmp.path());
        let logger = EventLogger::new(&session).unwrap();

        let mut ctx = PipelineContext::new(456);
        ctx.logger = Some(logger);

        let _ = pipeline.run(&mut ctx).await;

        let content = std::fs::read_to_string(session.event_log_path()).unwrap();
        assert!(content.contains("stage_failure"));
        assert!(content.contains("fail_stage"));
        assert!(content.contains("error_kind"));
        assert!(content.contains("Unknown"));
        assert!(content.contains("failure"));
    }
}
