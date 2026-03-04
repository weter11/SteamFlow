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

    pub fn stdout_path(&self) -> PathBuf {
        self.log_dir.join("stdout.log")
    }

    pub fn stderr_path(&self) -> PathBuf {
        self.log_dir.join("stderr.log")
    }
}
