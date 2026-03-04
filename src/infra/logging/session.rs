use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LaunchSessionId(String);

impl LaunchSessionId {
    pub fn generate() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();
        let random: u32 = rand::random();
        Self(format!("{}-{:08x}", now, random))
    }
}

impl std::fmt::Display for LaunchSessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LaunchSummary {
    pub session_id: String,
    pub app_id: u32,
    pub app_name: Option<String>,
    pub runner_name: Option<String>,
    pub result: LaunchResult,
    pub failing_stage: Option<String>,
    pub total_duration_ms: u128,
    pub stage_durations_ms: HashMap<String, u128>,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum LaunchResult {
    Success,
    Failure,
}

pub struct LaunchSession {
    pub id: LaunchSessionId,
    pub created_at: SystemTime,
    pub log_dir: PathBuf,
}

impl LaunchSession {
    pub fn new(base_log_dir: &Path) -> Self {
        let id = LaunchSessionId::generate();
        let created_at = SystemTime::now();
        let log_dir = base_log_dir.join(id.to_string());

        Self {
            id,
            created_at,
            log_dir,
        }
    }

    pub fn event_log_path(&self) -> PathBuf {
        self.log_dir.join("events.jsonl")
    }

    pub fn summary_path(&self) -> PathBuf {
        self.log_dir.join("summary.json")
    }

    pub fn stdout_path(&self) -> PathBuf {
        self.log_dir.join("stdout.log")
    }

    pub fn stderr_path(&self) -> PathBuf {
        self.log_dir.join("stderr.log")
    }

    pub fn write_summary(&self, summary: &LaunchSummary) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.log_dir)?;
        let content = serde_json::to_string_pretty(summary)?;
        std::fs::write(self.summary_path(), content)?;
        Ok(())
    }
}
