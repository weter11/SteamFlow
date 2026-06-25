use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use tempfile::tempdir;

use crate::launch::pipeline::{PipelineContext, LaunchPipeline, LaunchError, LaunchErrorKind};
use crate::infra::logging::{LaunchSession, EventLogger};
use crate::infra::runners::{Runner, CommandSpec, LaunchContext};

struct MockRunner {
    exit_immediately: bool,
}

#[async_trait]
impl Runner for MockRunner {
    fn name(&self) -> &str { "MockRunner" }
    async fn prepare_prefix(&self, _ctx: &LaunchContext) -> Result<(), LaunchError> { Ok(()) }
    async fn build_env(&self, _ctx: &LaunchContext) -> Result<HashMap<String, String>, LaunchError> { Ok(HashMap::new()) }
    async fn build_command(&self, _ctx: &LaunchContext) -> Result<CommandSpec, LaunchError> { Ok(CommandSpec::default()) }
    fn launch(&self, _spec: &CommandSpec) -> Result<Child, LaunchError> {
        let cmd = if self.exit_immediately {
            "exit 0"
        } else {
            "sleep 10"
        };
        Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| LaunchError::new(LaunchErrorKind::Process, e.to_string()))
    }
}


#[tokio::test]
async fn test_launch_verification_early_exit() {
    let mut pipeline = LaunchPipeline::new();
    pipeline.add_stage(Box::new(crate::launch::stages::spawn_process::SpawnProcessStage));

    let tmp = tempdir().unwrap();
    let session = LaunchSession::new(tmp.path());
    let logger = EventLogger::new(&session).unwrap();

    let mut ctx = PipelineContext::new(123);
    ctx.logger = Some(logger);
    ctx.session = Some(session);
    ctx.runner = Some(Box::new(MockRunner { exit_immediately: true }));
    ctx.command_spec = Some(CommandSpec {
        program: PathBuf::from("sh"),
        args: vec!["-c".to_string(), "exit 0".to_string()],
        ..Default::default()
    });

    let _ = pipeline.run(&mut ctx).await;

    assert_eq!(ctx.verification.status, "failed_after_spawn");
    assert!(ctx.verification.process_lifetime_ms.is_some());
    assert_eq!(ctx.verification.exit_code, Some(0));

    // Check summary for failure
    let summary_path = ctx.session.as_ref().unwrap().summary_path();
    let summary_content = std::fs::read_to_string(summary_path).unwrap();
    assert!(summary_content.contains("\"result\": \"Failure\""));
    assert!(summary_content.contains("\"status\": \"failed_after_spawn\""));
}

#[tokio::test]
async fn test_launch_verification_success() {
    let mut pipeline = LaunchPipeline::new();
    pipeline.add_stage(Box::new(crate::launch::stages::spawn_process::SpawnProcessStage));

    let tmp = tempdir().unwrap();
    let session = LaunchSession::new(tmp.path());
    let logger = EventLogger::new(&session).unwrap();

    let mut ctx = PipelineContext::new(123);
    ctx.logger = Some(logger);
    ctx.session = Some(session);
    ctx.runner = Some(Box::new(MockRunner { exit_immediately: false }));
    ctx.command_spec = Some(CommandSpec {
        program: PathBuf::from("sh"),
        args: vec!["-c".to_string(), "sleep 10".to_string()],
        ..Default::default()
    });

    let _ = pipeline.run(&mut ctx).await;

    assert_eq!(ctx.verification.status, "verified");
    assert!(ctx.verification.process_lifetime_ms.is_some());

    // Check summary for success
    let summary_path = ctx.session.as_ref().unwrap().summary_path();
    let summary_content = std::fs::read_to_string(summary_path).unwrap();
    assert!(summary_content.contains("\"result\": \"Success\""));
    assert!(summary_content.contains("\"status\": \"verified\""));

    // Cleanup the sleep process
    if let Some(mut child) = ctx.child.take() {
        let _ = child.kill();
    }
}

#[tokio::test]
async fn test_background_steam_grace_period_failure() {
    use crate::infra::runners::wine_tkg::WineTkgRunner;
    use crate::config::LauncherConfig;
    use crate::models::{LibraryGame, UserAppConfig, SteamRuntimePolicy};
    use crate::steam_client::{LaunchInfo, LaunchTarget};
    use std::fs;

    let tmp = tempdir().unwrap();

    // Mock HOME for get_master_steam_config
    let old_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", tmp.path());

    let root_dir = tmp.path().join(".config/SteamFlow/master_steam_prefix");
    let wine_prefix = root_dir.join("pfx");
    let steam_exe_path = wine_prefix.join("drive_c/Program Files (x86)/Steam/steam.exe");
    fs::create_dir_all(steam_exe_path.parent().unwrap()).unwrap();
    fs::write(&steam_exe_path, "").unwrap();

    let lib = tmp.path().join("library");
    fs::create_dir_all(&lib).unwrap();

    // Setup a fake runner that exits quickly
    let runner_dir = tmp.path().join("fake_runner");
    fs::create_dir_all(runner_dir.join("bin")).unwrap();
    let wine_path = runner_dir.join("bin/wine64");

    // Create a script that acts as wine64:
    // It should create the signal file and then exit.
    #[cfg(unix)]
    {
        // We want it to be alive when checked in the loop (T=1s),
        // but dead when checked in grace period (T=1s + 2s = 3s).
        fs::write(&wine_path, "#!/bin/sh\ntouch \"$WINEPREFIX/config.vdf\"\nsleep 2\nexit 1\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&wine_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&wine_path, perms).unwrap();
    }

    let mut config = LauncherConfig::default();
    config.steam_library_path = lib.to_string_lossy().to_string();
    config.steam_runtime_runner = runner_dir.clone();

    let mut user_config = UserAppConfig::default();
    user_config.use_steam_runtime = true;
    user_config.steam_runtime_policy = SteamRuntimePolicy::Enabled;

    let app = LibraryGame {
        app_id: 123,
        name: "Test".to_string(),
        install_path: Some(tmp.path().to_string_lossy().to_string()),
        is_installed: true,
        playtime_forever_minutes: None,
        active_branch: "public".to_string(),
        update_available: false,
        update_queued: false,
        local_manifest_ids: HashMap::new(),
    };

    // We need to set up the master prefix env so get_master_steam_config find it
    // But get_master_steam_config uses crate::config::config_dir()
    // We can't easily mock config_dir() without changing global state or using a mock.
    // However, WineTkgRunner::prepare_prefix calls get_master_steam_config().

    // For this test, we want to verify the logic in prepare_prefix.
    // We'll use a WineTkgRunner and call prepare_prefix directly.

    let mut verification = crate::infra::logging::LaunchVerification::default();
    let ctx = LaunchContext {
        app,
        launch_info: LaunchInfo {
            app_id: 123,
            id: "0".into(),
            description: "Test".into(),
            executable: "test.exe".into(),
            arguments: "".into(),
            workingdir: None,
            target: LaunchTarget::WindowsProton,
        },
        launcher_config: config,
        user_config: Some(user_config),
        proton_path: Some(runner_dir.to_string_lossy().to_string()),
        target_architecture: crate::models::ExecutableArchitecture::X86_64,
        dll_resolutions: Vec::new(),
        fixup_result: None,
        verification_ptr: &mut verification as *mut _,
    };

    // We need to make sure get_master_steam_config returns something we can control
    // or just make sure the directories it expects exist.
    // get_master_steam_config uses ~/.config/SteamFlow/master_steam_prefix
    // This is hard to override in a unit test without env vars.

    // Let's see if we can use a mock instead of real WineTkgRunner for the pipeline,
    // but the task asked to verify the new grace-check specifically.

    // Actually, I can just test the logic by calling prepare_prefix and mocking the environment.
    // But prepare_prefix is quite integrated.

    // Alternative: verify that the error message is what we expect when it fails.

    let runner = WineTkgRunner;
    let result = runner.prepare_prefix(&ctx).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind, LaunchErrorKind::Process);
    assert!(err.message.contains("indicates a corrupted Windows Steam install"));

    assert_eq!(verification.steam_runtime_milestone, "steam_process_exited_early");

    if let Some(h) = old_home {
        std::env::set_var("HOME", h);
    }
}
