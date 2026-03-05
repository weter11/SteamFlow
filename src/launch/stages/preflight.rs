use std::path::Path;
use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext, LaunchError, LaunchErrorKind};

pub struct PreflightStage;

#[async_trait]
impl PipelineStage for PreflightStage {
    fn name(&self) -> &str { "Preflight" }

    async fn execute(&self, ctx: &mut PipelineContext) -> std::result::Result<(), LaunchError> {
        let spec = ctx.command_spec.as_ref()
            .ok_or_else(|| LaunchError::new(LaunchErrorKind::Validation, "[Preflight] Command specification missing"))?;

        // 1. Verify runner binary
        let runner_path = &spec.program;
        if !runner_path.exists() {
            return Err(LaunchError::new(LaunchErrorKind::Runner, format!("[Preflight] Runner binary not found: {}", runner_path.display()))
                .with_context("runner_path", runner_path.to_string_lossy()));
        }
        if !runner_path.is_file() {
            return Err(LaunchError::new(LaunchErrorKind::Runner, format!("[Preflight] Runner path is not a file: {}", runner_path.display()))
                .with_context("runner_path", runner_path.to_string_lossy()));
        }

        // 2. Verify target game executable
        // Heuristic: for Wine/Proton runners, the game exe is usually the first argument
        if let Some(game_exe) = spec.args.first() {
            let game_exe_path = Path::new(game_exe);
            // Only check if it looks like an absolute path or relative to CWD
            if game_exe_path.is_absolute() || (game_exe_path.components().count() > 1 && !game_exe.starts_with('-')) {
                 if !game_exe_path.exists() {
                     // Try relative to install dir if we have it
                     let mut resolved = false;
                     if let Some(app) = &ctx.app {
                         if let Some(install_path) = &app.install_path {
                             let alt_path = Path::new(install_path).join(game_exe.replace('\\', "/"));
                             if alt_path.exists() && alt_path.is_file() {
                                 resolved = true;
                             }
                         }
                     }

                     if !resolved {
                         return Err(LaunchError::new(LaunchErrorKind::GameData, format!("[Preflight] Game executable not found: {}", game_exe))
                            .with_context("game_exe", game_exe.to_string()));
                     }
                 } else if !game_exe_path.is_file() {
                      return Err(LaunchError::new(LaunchErrorKind::GameData, format!("[Preflight] Game executable is not a file: {}", game_exe))
                        .with_context("game_exe", game_exe.to_string()));
                 }
            }
        }

        // 3. Verify working directory
        if let Some(cwd) = &spec.cwd {
            if !cwd.exists() {
                return Err(LaunchError::new(LaunchErrorKind::Environment, format!("[Preflight] Working directory does not exist: {}", cwd.display()))
                    .with_context("cwd", cwd.to_string_lossy()));
            }
            if !cwd.is_dir() {
                return Err(LaunchError::new(LaunchErrorKind::Environment, format!("[Preflight] Working directory is not a directory: {}", cwd.display()))
                    .with_context("cwd", cwd.to_string_lossy()));
            }
        }

        // 4. Verify WINEPREFIX if present in env
        if let Some(prefix) = spec.env.get("WINEPREFIX") {
            let prefix_path = Path::new(prefix);
            if !prefix_path.exists() {
                return Err(LaunchError::new(LaunchErrorKind::Environment, format!("[Preflight] WINEPREFIX does not exist: {}", prefix))
                    .with_context("wineprefix", prefix));
            }
            if !prefix_path.is_dir() {
                return Err(LaunchError::new(LaunchErrorKind::Environment, format!("[Preflight] WINEPREFIX is not a directory: {}", prefix))
                    .with_context("wineprefix", prefix));
            }
        }

        // 5. Check runner executability (Unix specific)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(runner_path) {
                if metadata.is_file() && metadata.permissions().mode() & 0o111 == 0 {
                    return Err(LaunchError::new(LaunchErrorKind::Permission, format!("[Preflight] Runner binary is not executable: {}", runner_path.display()))
                        .with_context("runner_path", runner_path.to_string_lossy()));
                }
            }
        }

        // 6. Architecture Hint & Context
        if let Some(logger) = &ctx.logger {
            let mut metadata = std::collections::HashMap::new();
            metadata.insert("runner_path".to_string(), runner_path.to_string_lossy().to_string());

            // Try to guess arch from executable name or launch info
            let arch_hint = if runner_path.to_string_lossy().contains("64") {
                "x64"
            } else {
                "x86/Unknown"
            };
            metadata.insert("arch_hint".to_string(), arch_hint.to_string());

            let _ = logger.info("preflight_report", "Preflight validation successful".to_string(), Some("Preflight".to_string()), metadata);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::runners::CommandSpec;
    use tempfile::tempdir;
    use std::fs;

    #[tokio::test]
    async fn test_preflight_missing_exe() {
        let mut ctx = PipelineContext::new(123);
        let mut spec = CommandSpec::default();
        spec.program = Path::new("/tmp/nonexistent_exe_12345").to_path_buf();
        ctx.command_spec = Some(spec);

        let stage = PreflightStage;
        let res = stage.execute(&mut ctx).await;

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.message.contains("not found"));
        assert!(err.message.contains("[Preflight]"));
    }

    #[tokio::test]
    async fn test_preflight_missing_cwd() {
        let tmp = tempdir().unwrap();
        let exe = tmp.path().join("game.exe");
        fs::write(&exe, "dummy").unwrap();

        let mut ctx = PipelineContext::new(123);
        let mut spec = CommandSpec::default();
        spec.program = exe;
        spec.cwd = Some(tmp.path().join("missing_dir"));
        ctx.command_spec = Some(spec);

        let stage = PreflightStage;
        let res = stage.execute(&mut ctx).await;

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.message.contains("Working directory does not exist"));
    }

    #[tokio::test]
    async fn test_preflight_missing_prefix() {
        let tmp = tempdir().unwrap();
        let exe = tmp.path().join("game.exe");
        fs::write(&exe, "dummy").unwrap();

        let mut ctx = PipelineContext::new(123);
        let mut spec = CommandSpec::default();
        spec.program = exe;
        spec.env.insert("WINEPREFIX".to_string(), tmp.path().join("missing_pfx").to_string_lossy().to_string());
        ctx.command_spec = Some(spec);

        let stage = PreflightStage;
        let res = stage.execute(&mut ctx).await;

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.message.contains("WINEPREFIX does not exist"));
    }

    #[tokio::test]
    async fn test_preflight_is_not_directory() {
        let tmp = tempdir().unwrap();
        let exe = tmp.path().join("game.exe");
        fs::write(&exe, "dummy").unwrap();
        let not_a_dir = tmp.path().join("not_a_dir");
        fs::write(&not_a_dir, "dummy").unwrap();

        let mut ctx = PipelineContext::new(123);
        let mut spec = CommandSpec::default();
        spec.program = exe;
        spec.cwd = Some(not_a_dir);
        ctx.command_spec = Some(spec);

        let stage = PreflightStage;
        let res = stage.execute(&mut ctx).await;

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.message.contains("is not a directory"));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_preflight_not_executable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempdir().unwrap();
        let exe = tmp.path().join("game.exe");
        fs::write(&exe, "dummy").unwrap();
        let mut perms = fs::metadata(&exe).unwrap().permissions();
        perms.set_mode(0o644); // Not executable
        fs::set_permissions(&exe, perms).unwrap();

        let mut ctx = PipelineContext::new(123);
        let mut spec = CommandSpec::default();
        spec.program = exe;
        ctx.command_spec = Some(spec);

        let stage = PreflightStage;
        let res = stage.execute(&mut ctx).await;

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.message.contains("is not executable"));
    }
}
