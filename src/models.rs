use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionState {
    pub account_name: Option<String>,
    pub steam_id: Option<u64>,
    pub refresh_token: Option<String>,
    pub client_instance_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnedGame {
    pub app_id: u32,
    pub name: String,
    pub playtime_forever_minutes: u32,
    #[serde(default)]
    pub local_manifest_ids: HashMap<u64, u64>,
    #[serde(default)]
    pub update_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub steam_id: u64,
    pub account_name: String,
    pub game_count: usize,
    pub is_online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalGame {
    pub app_id: u32,
    pub name: String,
    pub install_dir: PathBuf,
    pub proton_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameModel {
    pub app_id: u32,
    pub name: String,
    pub playtime_forever_minutes: Option<u32>,
    pub install_dir: Option<PathBuf>,
    pub proton_version: Option<String>,
    pub image_cache_path: Option<PathBuf>,
}

impl GameModel {
    pub fn installed(&self) -> bool {
        self.install_dir.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryGame {
    pub app_id: u32,
    pub name: String,
    pub playtime_forever_minutes: Option<u32>,
    pub is_installed: bool,
    pub install_path: Option<String>,
    #[serde(default)]
    pub local_manifest_ids: HashMap<u64, u64>,
    #[serde(default)]
    pub update_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GameLibrary {
    pub games: Vec<LibraryGame>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryFilter {
    All,
    Installed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SteamGuardReq {
    EmailCode { domain_hint: String },
    DeviceCode,
    DeviceConfirmation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadProgressState {
    Queued,
    Downloading,
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadProgress {
    pub state: DownloadProgressState,
    pub bytes_downloaded: u64,
    pub total_bytes: u64,
    pub current_file: String,
}
