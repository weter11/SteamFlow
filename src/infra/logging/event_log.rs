use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use anyhow::Result;
use crate::infra::logging::LaunchSession;

#[derive(Debug, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogEvent {
    pub timestamp: u64,
    pub level: LogLevel,
    pub message: String,
    pub stage: Option<String>,
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

    pub fn log(&self, level: LogLevel, message: String, stage: Option<String>) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let event = LogEvent {
            timestamp,
            level,
            message,
            stage,
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
}
