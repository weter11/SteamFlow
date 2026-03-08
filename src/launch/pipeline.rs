use std::fmt;
use async_trait::async_trait;

use std::collections::HashMap;
use crate::models::{LibraryGame, UserAppConfig};
use crate::config::LauncherConfig;
use crate::steam_client::LaunchInfo;
use crate::infra::runners::{Runner, CommandSpec};
use crate::infra::logging::{LaunchSession, EventLogger};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompatibilityWarning {
    pub code: String,
    pub message: String,
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct DuplicateInstanceInfo {
    pub detected: bool,
    pub source: String, // "lockfile" | "pid" | "guard" | "none"
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct GraphicsStackInfo {
    pub graphics_stack_expected: String,           // e.g. "DXVK v2.3, VKD3D-Proton v2.10"
    pub graphics_stack_evidence: Vec<String>,      // e.g. ["DXVK: v2.3.1"]
    pub graphics_stack_confidence: String,         // "low" | "medium" | "high"
    pub override_policy: String,                   // e.g. "Native-only"
    pub dll_providers: HashMap<String, String>,    // e.g. {"d3d11": "Runner", "d3d9": "GameLocal"}
    pub target_process_arch: crate::utils::Architecture,
}

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
    pub warnings: Vec<CompatibilityWarning>,
    pub graphics_stack: GraphicsStackInfo,
    pub dll_resolutions: Vec<crate::launch::dll_provider_resolver::DllResolution>,
    pub target_process_arch: crate::utils::Architecture,
    pub effective_dll_bindings: HashMap<String, crate::launch::dll_provider_resolver::DllResolution>,
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
            warnings: Vec::new(),
            graphics_stack: GraphicsStackInfo::default(),
            dll_resolutions: Vec::new(),
            target_process_arch: crate::utils::Architecture::Unknown,
            effective_dll_bindings: HashMap::new(),
        }
    }

    pub fn add_warning(&mut self, code: impl Into<String>, message: impl Into<String>) {
        let warning = CompatibilityWarning {
            code: code.into(),
            message: message.into(),
            context: HashMap::new(),
        };

        if let Some(logger) = &self.logger {
            let mut metadata = HashMap::new();
            metadata.insert("warning_code".to_string(), warning.code.clone());
            metadata.insert("warning_message".to_string(), warning.message.clone());
            let _ = logger.log(crate::infra::logging::LogLevel::Warn, "compatibility_warning", warning.message.clone(), None, metadata);
        }

        self.warnings.push(warning);
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
            Self::Process => "Check if the game is already running or if files are locked.",
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
    if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
        return map_io_error(io_err, None);
    }

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

pub fn map_io_error(err: &std::io::Error, dup_info: Option<&DuplicateInstanceInfo>) -> LaunchError {
    use std::io::ErrorKind;

    let kind = match err.kind() {
        ErrorKind::NotFound => LaunchErrorKind::GameData,
        ErrorKind::PermissionDenied => LaunchErrorKind::Permission,
        ErrorKind::InvalidInput => LaunchErrorKind::Validation,
        ErrorKind::AlreadyExists => LaunchErrorKind::Process,
        _ => LaunchErrorKind::Process,
    };

    let mut message = match err.kind() {
        ErrorKind::NotFound => "The game executable or runner was not found.".to_string(),
        ErrorKind::PermissionDenied => "Access denied while attempting to start the game. Check file permissions.".to_string(),
        ErrorKind::InvalidInput => "Invalid launch configuration or malformed path.".to_string(),
        ErrorKind::AlreadyExists => "A lock file or another instance of the game was detected.".to_string(),
        _ => format!("Process spawn failed: {}", err),
    };

    // ONLY show duplicate instance hint if explicitly detected or AlreadyExists kind
    let err_str = err.to_string();
    let lock_msg = "Game files are locked by another process. Ensure no other instance is running.";

    if let Some(info) = dup_info {
        if info.detected {
            message = lock_msg.to_string();
        }
    } else if err.kind() == ErrorKind::AlreadyExists || err_str.contains("locked") || err_str.contains("Resource busy") {
        message = lock_msg.to_string();
    }

    let mut launch_err = LaunchError::new(kind, message)
        .with_context("io_kind", format!("{:?}", err.kind()));

    if let Some(code) = err.raw_os_error() {
        launch_err = launch_err.with_context("os_errno", code.to_string());
    }

    if let Some(info) = dup_info {
        launch_err = launch_err.with_context("duplicate_instance_detected", info.detected.to_string());
        launch_err = launch_err.with_context("duplicate_detection_source", info.source.clone());
    } else {
        launch_err = launch_err.with_context("duplicate_instance_detected", "false");
        launch_err = launch_err.with_context("duplicate_detection_source", "none");
    }

    launch_err
}

pub fn detect_duplicate_instance(ctx: &PipelineContext) -> DuplicateInstanceInfo {
    // 1. Check for explicit lockfile in the game directory or prefix
    if let Some(spec) = &ctx.command_spec {
        if let Some(cwd) = &spec.cwd {
            let lockfile = cwd.join(".steamflow_launch.lock");
            if lockfile.exists() {
                return DuplicateInstanceInfo {
                    detected: true,
                    source: "lockfile".to_string(),
                };
            }
        }
    }

    // 2. Check for tracked PID if we had a mechanism to store it
    // For now, check if steam.pid exists in the prefix (if applicable)
    if let Some(spec) = &ctx.command_spec {
        if let Some(prefix) = spec.env.get("WINEPREFIX") {
            let pid_path = std::path::Path::new(prefix).join("steam.pid");
            if pid_path.exists() {
                 // Note: Ideally we'd check if the PID is still alive,
                 // but existence of the file in WINEPREFIX is a strong hint.
                 return DuplicateInstanceInfo {
                     detected: true,
                     source: "pid".to_string(),
                 };
            }
        }
    }

    DuplicateInstanceInfo {
        detected: false,
        source: "none".to_string(),
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
    validators: Vec<Box<dyn crate::launch::validators::LaunchValidator>>,
}

impl LaunchPipeline {
    pub fn new() -> Self {
        Self {
            stages: Vec::new(),
            validators: Vec::new(),
        }
    }

    pub fn add_stage(&mut self, stage: Box<dyn PipelineStage>) {
        self.stages.push(stage);
    }

    pub fn add_validator(&mut self, validator: Box<dyn crate::launch::validators::LaunchValidator>) {
        self.validators.push(validator);
    }

    pub fn with_default_stages() -> Self {
        let mut pipeline = Self::new();
        pipeline.add_stage(Box::new(crate::launch::stages::resolve_game::ResolveGameStage));
        pipeline.add_stage(Box::new(crate::launch::stages::resolve_profile::ResolveProfileStage));
        pipeline.add_stage(Box::new(crate::launch::stages::resolve_components::ResolveComponentsStage));
        pipeline.add_stage(Box::new(crate::launch::stages::resolve_dll_providers::ResolveDllProvidersStage));
        pipeline.add_stage(Box::new(crate::launch::stages::prepare_prefix::PreparePrefixStage));
        pipeline.add_stage(Box::new(crate::launch::stages::build_environment::BuildEnvironmentStage));
        pipeline.add_stage(Box::new(crate::launch::stages::build_command::BuildCommandStage));
        pipeline.add_stage(Box::new(crate::launch::stages::preflight::PreflightStage));
        pipeline.add_stage(Box::new(crate::launch::stages::spawn_process::SpawnProcessStage));
        pipeline.add_stage(Box::new(crate::launch::stages::finalize::FinalizeStage));

        pipeline.add_validator(Box::new(crate::launch::validators::overrides::OverrideConflictValidator));

        pipeline
    }

    pub async fn run(&self, ctx: &mut PipelineContext) -> std::result::Result<(), PipelineError> {
        // Record expected stack info before starting
        self.populate_expected_graphics_stack(ctx);

        use crate::infra::logging::LaunchResult;

        let total_start = std::time::Instant::now();
        let mut stage_durations = HashMap::new();
        let mut failing_stage = None;

        if let Some(logger) = &ctx.logger {
            let mut metadata = HashMap::new();
            metadata.insert("app_id".to_string(), ctx.app_id.to_string());
            if let Some(app) = &ctx.app {
                metadata.insert("app_name".to_string(), app.name.clone());
            }
            let _ = logger.info("launch_start", "Starting launch pipeline".to_string(), None, metadata);
        }

        let mut final_result = LaunchResult::Success;

        // Run validators before starting stages
        for validator in &self.validators {
            validator.validate(ctx);
        }

        for stage in &self.stages {
            let stage_name = stage.name().to_string();
            if let Some(logger) = &ctx.logger {
                let _ = logger.info("stage_start", format!("Starting stage: {}", stage_name), Some(stage_name.clone()), HashMap::new());
            }

            let start_time = std::time::Instant::now();
            let res = stage.execute(ctx).await;
            let duration = start_time.elapsed().as_millis();
            stage_durations.insert(stage_name.clone(), duration);

            if let Err(e) = res {
                failing_stage = Some(stage_name.clone());
                final_result = LaunchResult::Failure;

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

                self.write_summary_if_possible(ctx, final_result, failing_stage, total_start.elapsed().as_millis(), stage_durations.clone());

                return Err(PipelineError {
                    stage_name,
                    inner: e,
                });
            }

            if let Some(logger) = &ctx.logger {
                let mut metadata = HashMap::new();
                metadata.insert("duration_ms".to_string(), duration.to_string());
                let _ = logger.info("stage_success", format!("Stage succeeded: {}", stage_name), Some(stage_name.clone()), metadata);
            }
        }

        if let Some(logger) = &ctx.logger {
            let _ = logger.info("launch_end", "Launch successful".to_string(), None, HashMap::new());
        }

        // After stages are complete (or failed), scan logs for evidence
        self.record_dll_provider_diagnostics(ctx);
        self.scan_logs_for_graphics_evidence(ctx);

        self.write_summary_if_possible(ctx, final_result, failing_stage, total_start.elapsed().as_millis(), stage_durations);

        Ok(())
    }

    fn populate_expected_graphics_stack(&self, ctx: &mut PipelineContext) {
        if let Some(config) = &ctx.user_config {
            let mut expected = Vec::new();
            if config.graphics_layers.dxvk_enabled {
                expected.push("DXVK");
            }
            if config.graphics_layers.vkd3d_proton_enabled {
                expected.push("VKD3D-Proton");
            }
            if config.graphics_layers.vkd3d_enabled {
                expected.push("VKD3D");
            }

            let policy = format!("{:?}", config.graphics_layers.graphics_backend_policy);
            if expected.is_empty() {
                ctx.graphics_stack.graphics_stack_expected = format!("WineD3D (Baseline) [Policy: {}]", policy);
                ctx.graphics_stack.override_policy = "Builtin-only".to_string();
            } else {
                ctx.graphics_stack.graphics_stack_expected = format!("{} [Policy: {}]", expected.join(", "), policy);
                ctx.graphics_stack.override_policy = "Native-preferred".to_string();
            }
        }
    }

    fn record_dll_provider_diagnostics(&self, ctx: &mut PipelineContext) {
        for res in &ctx.dll_resolutions {
            ctx.graphics_stack.dll_providers.insert(res.name.clone(), format!("{:?}", res.chosen_provider));
        }
    }

    fn scan_logs_for_graphics_evidence(&self, ctx: &mut PipelineContext) {
        if let Some(session) = &ctx.session {
            let stderr_path = session.stderr_path();
            if stderr_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&stderr_path) {
                    for line in content.lines() {
                        if let Some(evidence) = crate::infra::logging::classify_graphics_evidence(line) {
                            if !ctx.graphics_stack.graphics_stack_evidence.contains(&evidence) {
                                ctx.graphics_stack.graphics_stack_evidence.push(evidence);
                            }
                        }
                    }
                }
            }

            // Update confidence based on evidence vs expectation
            if ctx.graphics_stack.graphics_stack_evidence.is_empty() {
                ctx.graphics_stack.graphics_stack_confidence = "low".to_string();
            } else {
                let has_expected = if ctx.user_config.as_ref().map(|c| c.graphics_layers.dxvk_enabled).unwrap_or(false) {
                    ctx.graphics_stack.graphics_stack_evidence.iter().any(|e| e.contains("DXVK"))
                } else {
                    true
                };

                if has_expected {
                    ctx.graphics_stack.graphics_stack_confidence = "high".to_string();
                } else {
                    ctx.graphics_stack.graphics_stack_confidence = "medium".to_string();
                }
            }
        }
    }

    fn write_summary_if_possible(
        &self,
        ctx: &mut PipelineContext,
        result: crate::infra::logging::LaunchResult,
        failing_stage: Option<String>,
        total_duration_ms: u128,
        stage_durations_ms: HashMap<String, u128>,
    ) {
        if let Some(session) = &ctx.session {
            let bindings_path = session.log_dir.join("effective_dll_bindings.json");
            if let Ok(content) = serde_json::to_string_pretty(&ctx.effective_dll_bindings) {
                 let _ = std::fs::write(bindings_path, content);
            }
        }

        let (sanity_warnings, env_snapshot) = if let Some(spec) = &ctx.command_spec {
            let runner_name = ctx
                .runner
                .as_ref()
                .map(|r| r.name().to_string())
                .unwrap_or_else(|| "Unknown".to_string());

            let warnings = crate::infra::logging::check_environment_sanity(
                &spec.env,
                &runner_name,
                ctx.user_config.as_ref(),
            );

            let env_snapshot = crate::infra::logging::EffectiveEnv {
                runner_name,
                profile_id: ctx.launch_info.as_ref().map(|l| l.id.clone()),
                profile_name: ctx.launch_info.as_ref().map(|l| l.description.clone()),
                wine_dll_overrides: spec.env.get("WINEDLLOVERRIDES").cloned(),
                env_vars: spec.env.clone(),
            };

            (warnings, Some(env_snapshot))
        } else {
            (Vec::new(), None)
        };

        for warning in sanity_warnings {
            ctx.add_warning(warning.code, warning.message);
        }

        if let Some(session) = &ctx.session {
            if let Some(env) = env_snapshot {
                let _ = session.write_effective_env(&env);
                let _ = session.write_effective_env_txt(&env.env_vars);
            }
            if let Some(spec) = &ctx.command_spec {
                let _ = session.write_command_artifact(spec);
            }
            let _ = session.write_dll_resolution_artifact(&ctx.dll_resolutions);
        }

        if let Some(session) = &ctx.session {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let summary = crate::infra::logging::LaunchSummary {
                session_id: session.id.to_string(),
                app_id: ctx.app_id,
                app_name: ctx.app.as_ref().map(|a| a.name.clone()),
                runner_name: ctx.runner.as_ref().map(|r| r.name().to_string()),
                result,
                failing_stage,
                total_duration_ms,
                stage_durations_ms,
                timestamp,
                target_process_arch: ctx.target_process_arch.to_string(),
                warnings: ctx.warnings.clone(),
                graphics_stack: Some(ctx.graphics_stack.clone()),
            };

            let _ = session.write_summary(&summary);
        }
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

    #[test]
    fn test_graphics_stack_info_arch_serialization() {
        let mut info = GraphicsStackInfo::default();
        info.target_process_arch = crate::utils::Architecture::X86_64;
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"target_process_arch\":\"x64\""));
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

    #[test]
    fn test_map_io_error_not_found() {
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let mapped = map_io_error(&err, None);
        assert_eq!(mapped.kind, LaunchErrorKind::GameData);
        assert!(mapped.message.contains("not found"));
        assert_eq!(mapped.context.get("io_kind").unwrap(), "NotFound");
    }

    #[test]
    fn test_map_io_error_permission_denied() {
        let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let mapped = map_io_error(&err, None);
        assert_eq!(mapped.kind, LaunchErrorKind::Permission);
        assert!(mapped.message.contains("Access denied"));
    }

    #[test]
    fn test_map_io_error_lock_detected() {
        // Simulating a "Resource busy" or "locked" error which often maps to 'Other' or 'WouldBlock' in std::io
        let err = std::io::Error::new(std::io::ErrorKind::Other, "file is locked by another process");
        let mapped = map_io_error(&err, None);
        assert_eq!(mapped.kind, LaunchErrorKind::Process);
        assert!(mapped.message.contains("locked by another process"));
    }

    #[test]
    fn test_map_io_error_with_explicit_dup_info() {
        let err = std::io::Error::new(std::io::ErrorKind::Other, "generic error");
        let info = DuplicateInstanceInfo {
            detected: true,
            source: "lockfile".to_string(),
        };
        let mapped = map_io_error(&err, Some(&info));
        assert_eq!(mapped.kind, LaunchErrorKind::Process);
        assert!(mapped.message.contains("Ensure no other instance is running"));
        assert_eq!(mapped.context.get("duplicate_instance_detected").unwrap(), "true");
        assert_eq!(mapped.context.get("duplicate_detection_source").unwrap(), "lockfile");
    }

    #[test]
    fn test_detect_duplicate_instance_lockfile() {
        let tmp = tempfile::tempdir().unwrap();
        let lockfile = tmp.path().join(".steamflow_launch.lock");
        std::fs::write(&lockfile, "").unwrap();

        let mut ctx = PipelineContext::new(123);
        let mut spec = CommandSpec::default();
        spec.cwd = Some(tmp.path().to_path_buf());
        ctx.command_spec = Some(spec);

        let info = detect_duplicate_instance(&ctx);
        assert!(info.detected);
        assert_eq!(info.source, "lockfile");
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
