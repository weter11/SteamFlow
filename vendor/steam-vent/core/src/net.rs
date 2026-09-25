use std::{borrow::Cow, fmt::Display};

/// A unique (per-session) identifier that links request-response pairs
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct JobId(pub(crate) u64);

impl JobId {
    pub fn new(id: u64) -> Self {
        JobId(id)
    }

    pub fn id(&self) -> u64 {
        self.0
    }
}

impl Default for JobId {
    fn default() -> Self {
        JobId::NONE
    }
}

impl Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Job({})", self.0)
    }
}

impl JobId {
    pub const NONE: JobId = JobId(u64::MAX);
}

/// A non-validated steam id
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct RawSteamId(pub(crate) u64);

impl RawSteamId {
    pub fn new(id: u64) -> Self {
        RawSteamId(id)
    }

    pub fn id(&self) -> u64 {
        self.0
    }
}

impl Default for RawSteamId {
    fn default() -> Self {
        RawSteamId::NONE
    }
}

impl RawSteamId {
    pub const NONE: RawSteamId = RawSteamId(0);
}

/// The header send with every message
#[derive(Debug, Clone)]
pub struct NetMessageHeader {
    pub source_job_id: JobId,
    pub target_job_id: JobId,
    pub steam_id: RawSteamId,
    pub session_id: i32,
    pub target_job_name: Option<Cow<'static, str>>,
    pub result: Option<i32>,
    pub source_app_id: Option<u32>,
}

impl Default for NetMessageHeader {
    fn default() -> Self {
        Self {
            source_job_id: JobId::default(),
            target_job_id: JobId::default(),
            steam_id: RawSteamId::default(),
            session_id: 0,
            target_job_name: None,
            result: None,
            source_app_id: None,
        }
    }
}
