//! Diagnostic capture utilities for Steam Runtime installation and repair.
//!
//! This module provides a way to capture Wine traces and process output
//! during the Master Steam installation flow. It is triggered by setting
//! the `STEAMFLOW_DIAGNOSE_INSTALL=1` environment variable.
//!
//! Configuration is loaded from `~/.config/SteamFlow/debug_parameters.json`.

use std::process::{Command, Stdio};
use std::fs::File;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;
use anyhow::{Result, Context};
use crate::config::config_dir;

#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
struct DebugParameters {
    #[serde(default = "default_winedebug")]
    winedebug: String,
}

fn default_winedebug() -> String {
    "err+all,warn+module,warn+loaddll,+setupapi".to_string()
}

impl Default for DebugParameters {
    fn default() -> Self {
        Self {
            winedebug: default_winedebug(),
        }
    }
}

fn load_debug_parameters() -> DebugParameters {
    let config_path = match config_dir() {
        Ok(dir) => dir.join("debug_parameters.json"),
        Err(_) => return DebugParameters::default(),
    };

    if !config_path.exists() {
        return DebugParameters::default();
    }

    match std::fs::read_to_string(&config_path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(params) => params,
            Err(e) => {
                tracing::warn!("Failed to parse debug_parameters.json: {}. Using defaults.", e);
                DebugParameters::default()
            }
        },
        Err(e) => {
            tracing::warn!("Failed to read debug_parameters.json: {}. Using defaults.", e);
            DebugParameters::default()
        }
    }
}

/// Applies diagnostic capture to the given command if opt-in flag is set.
///
/// Behavior:
/// - Checks `STEAMFLOW_DIAGNOSE_INSTALL`. If not "1", returns `Ok(None)`.
/// - Replaces `WINEDEBUG` with values from `debug_parameters.json`.
/// - Redirects stdout and stderr to `logs/install_diagnose_<timestamp>.log`.
///
/// NOTE: Callers must call this function LAST, after setting their own env vars,
/// as this function replaces existing WINEDEBUG settings.
pub fn apply_install_diagnostics(cmd: &mut Command) -> Result<Option<PathBuf>> {
    if std::env::var("STEAMFLOW_DIAGNOSE_INSTALL").unwrap_or_default() != "1" {
        return Ok(None);
    }

    let params = load_debug_parameters();
    let timestamp = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let log_dir = config_dir()?.join("logs");
    std::fs::create_dir_all(&log_dir).context("failed to create logs directory")?;

    let log_path = log_dir.join(format!("install_diagnose_{}.log", timestamp));
    tracing::info!("Diagnostic capture active. Logging to: {}", log_path.display());

    let log_file = File::create(&log_path)
        .context(format!("failed to create log file at {}", log_path.display()))?;

    cmd.env("WINEDEBUG", &params.winedebug);

    let log_file_clone = log_file.try_clone()?;
    cmd.stdout(Stdio::from(log_file));
    cmd.stderr(Stdio::from(log_file_clone));

    Ok(Some(log_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn test_default_parameters() {
        let params = DebugParameters::default();
        assert_eq!(params.winedebug, "err+all,warn+module,warn+loaddll,+setupapi");
    }

    #[test]
    fn test_parsing_valid_json() {
        let json = r#"{"winedebug": "+process,+setupapi"}"#;
        let params: DebugParameters = serde_json::from_str(json).unwrap();
        assert_eq!(params.winedebug, "+process,+setupapi");
    }

    #[test]
    fn test_fallback_on_malformed_json() {
        let tmp = tempdir().unwrap();
        let config_path = tmp.path().join("debug_parameters.json");

        // Non-existent file
        let params = load_debug_parameters_from_path(&config_path);
        assert_eq!(params, DebugParameters::default());

        // Malformed JSON
        std::fs::write(&config_path, "not json").unwrap();
        let params = load_debug_parameters_from_path(&config_path);
        assert_eq!(params, DebugParameters::default());
    }

    fn load_debug_parameters_from_path(path: &Path) -> DebugParameters {
        if !path.exists() {
            return DebugParameters::default();
        }
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_else(|_| DebugParameters::default()),
            Err(_) => DebugParameters::default(),
        }
    }

    #[test]
    fn test_apply_diagnostics_gating() {
        let mut cmd = Command::new("ls");
        cmd.env("WINEDEBUG", "original");

        // Flag NOT set
        env::remove_var("STEAMFLOW_DIAGNOSE_INSTALL");
        let res = apply_install_diagnostics(&mut cmd).unwrap();
        assert!(res.is_none());

        let envs: std::collections::HashMap<_, _> = cmd.get_envs().collect();
        assert_eq!(envs.get(std::ffi::OsStr::new("WINEDEBUG")).unwrap().unwrap(), "original");
    }
}
