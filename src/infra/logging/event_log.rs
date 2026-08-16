use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use anyhow::Result;
use crate::infra::logging::LaunchSession;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub timestamp: u64,
    pub level: LogLevel,
    pub event_type: String,
    pub message: String,
    pub stage: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

pub struct EventLogger {
    file_path: PathBuf,
}

impl EventLogger {
    pub fn new(session: &LaunchSession) -> Result<Self> {
        std::fs::create_dir_all(&session.log_dir)?;
        let file_path = session.event_log_path();
        Ok(Self { file_path })
    }

    pub fn log(&self, level: LogLevel, event_type: &str, message: String, stage: Option<String>, metadata: HashMap<String, String>) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let redacted_metadata = redact_metadata(metadata);

        let event = LogEvent {
            timestamp,
            level,
            event_type: event_type.to_string(),
            message,
            stage,
            metadata: redacted_metadata,
        };

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)?;

        let mut line = serde_json::to_string(&event)?;
        line.push('\n');
        file.write_all(line.as_bytes())?;

        Ok(())
    }

    pub fn info(&self, event_type: &str, message: String, stage: Option<String>, metadata: HashMap<String, String>) -> Result<()> {
        self.log(LogLevel::Info, event_type, message, stage, metadata)
    }

    pub fn error(&self, event_type: &str, message: String, stage: Option<String>, metadata: HashMap<String, String>) -> Result<()> {
        self.log(LogLevel::Error, event_type, message, stage, metadata)
    }
}

fn redact_metadata(mut metadata: HashMap<String, String>) -> HashMap<String, String> {
    let sensitive_keys = ["STEAM_TOKEN", "STEAM_PASSWORD", "TOKEN", "PASSWORD", "REFRESH_TOKEN"];
    for (key, value) in metadata.iter_mut() {
        let upper_key = key.to_uppercase();
        if sensitive_keys.iter().any(|&sk| upper_key.contains(sk)) {
            *value = "[REDACTED]".to_string();
        }
    }
    metadata
}

/// Durable, launch-session-independent record of a manifest resolution for an
/// install/update operation. Appended as one JSON line to
/// `{config_dir}/logs/install_events.jsonl` so a later diagnosis can tell a
/// wrong-branch request from a wrong manifest picked out of the right appinfo
/// — even when no launch session directory exists for that operation.
pub fn log_install_manifest_resolution(
    appid: u32,
    branch: &str,
    changenumber: Option<u32>,
    manifests: &HashMap<u64, u64>,
) -> Result<()> {
    let dir = crate::config::config_dir()?.join("logs");
    log_install_manifest_resolution_to(&dir, appid, branch, changenumber, manifests)
}

/// Path-taking variant of [`log_install_manifest_resolution`], separated out
/// so tests can write to a temp dir without touching `$HOME`.
pub(crate) fn log_install_manifest_resolution_to(
    dir: &std::path::Path,
    appid: u32,
    branch: &str,
    changenumber: Option<u32>,
    manifests: &HashMap<u64, u64>,
) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join("install_events.jsonl");

    let mut metadata = HashMap::new();
    metadata.insert("appid".to_string(), appid.to_string());
    metadata.insert("active_branch".to_string(), branch.to_string());
    if let Some(change) = changenumber {
        metadata.insert("appinfo_changenumber".to_string(), change.to_string());
    }
    let manifests_str = manifests
        .iter()
        .map(|(depot, gid)| format!("{depot}:{gid}"))
        .collect::<Vec<_>>()
        .join(",");
    metadata.insert("resolved_manifests".to_string(), manifests_str);

    let event = LogEvent {
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        level: LogLevel::Info,
        event_type: "install_manifest_resolution".to_string(),
        message: format!(
            "resolved {} depot manifests for app {appid} on branch {branch}",
            manifests.len()
        ),
        stage: Some("manifest_resolution".to_string()),
        metadata: redact_metadata(metadata),
    };

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let mut line = serde_json::to_string(&event)?;
    line.push('\n');
    file.write_all(line.as_bytes())?;
    Ok(())
}
