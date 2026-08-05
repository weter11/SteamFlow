use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default, Copy)]
pub enum RunnerSource {
    #[default]
    Official,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum SteamPrefixMode {
    #[default]
    Shared, // use master_steam_prefix WINEPREFIX directly
    PerGame, // copy/symlink Steam into game's own compatdata prefix
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum SteamRuntimePolicy {
    #[default]
    Auto,
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LaunchMode {
    #[default]
    DirectWine,
    SteamAppLaunch,
    SteamProtocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamLaunchConfig {
    #[serde(default)]
    pub no_browser: bool, // legacy storage: true disables CEF/steamwebhelper
    #[serde(default)]
    pub no_friends_ui: bool, // legacy storage: true disables the friends list
    #[serde(default)]
    pub no_overlay: bool, // legacy storage: true disables the in-game overlay
    #[serde(default)]
    pub no_chat_ui: bool, // legacy storage: true disables chat popups
}

pub fn default_true() -> bool {
    true
}

impl Default for SteamLaunchConfig {
    fn default() -> Self {
        Self {
            no_browser: false,
            no_friends_ui: false,
            no_overlay: false,
            no_chat_ui: false,
        }
    }
}

impl SteamLaunchConfig {
    /// Global default for client-management operations (Manage / Repair /
    /// Reinstall / Backup / Restore): everything alive — the web helper must
    /// survive so the client can log in and show its UI.
    pub fn all_alive() -> Self {
        Self {
            no_browser: false,
            no_friends_ui: false,
            no_overlay: false,
            no_chat_ui: false,
        }
    }
}

pub fn default_steam_launch_config_alive() -> SteamLaunchConfig {
    SteamLaunchConfig::all_alive()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum D3D7BackendPolicy {
    #[default]
    Auto,
    WineD3D,
    D7VK,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum GraphicsBackendPolicy {
    #[default]
    Auto,
    WineD3D,
    DXVK,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum D3D12ProviderPolicy {
    #[default]
    Auto,
    Vkd3dProton,
    Vkd3dWine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphicsLayerConfig {
    #[serde(default)]
    pub dxvk_enabled: bool,
    #[serde(default)]
    pub vkd3d_proton_enabled: bool,
    #[serde(default)]
    pub vkd3d_enabled: bool,
    #[serde(default = "default_true")]
    pub nvapi_enabled: bool,
    #[serde(default)]
    pub graphics_backend_policy: GraphicsBackendPolicy,
    #[serde(default)]
    pub d3d7_policy: D3D7BackendPolicy,
    #[serde(default)]
    pub d3d12_policy: D3D12ProviderPolicy,
    #[serde(default)]
    pub use_symlinks_in_prefix: bool,
    #[serde(default)]
    pub custom_dxvk_path: Option<PathBuf>,
    #[serde(default)]
    pub custom_vkd3d_path: Option<PathBuf>,
    #[serde(default)]
    pub custom_vkd3d_proton_path: Option<PathBuf>,
    #[serde(default)]
    pub force_wined3d: bool,
}

impl Default for GraphicsLayerConfig {
    fn default() -> Self {
        Self {
            dxvk_enabled: false,
            vkd3d_proton_enabled: false,
            vkd3d_enabled: false,
            nvapi_enabled: true,
            graphics_backend_policy: GraphicsBackendPolicy::Auto,
            d3d7_policy: D3D7BackendPolicy::Auto,
            d3d12_policy: D3D12ProviderPolicy::Auto,
            use_symlinks_in_prefix: false,
            custom_dxvk_path: None,
            custom_vkd3d_path: None,
            custom_vkd3d_proton_path: None,
            force_wined3d: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAppConfig {
    pub launch_options: String,                 // e.g. "-novid -console"
    pub env_variables: HashMap<String, String>, // e.g. {"MANGOHUD": "1"}
    pub use_steam_runtime: bool,                // DEPRECATED: use steam_runtime_policy instead
    #[serde(default)]
    pub steam_runtime_policy: SteamRuntimePolicy,
    #[serde(default)]
    pub steam_prefix_mode: SteamPrefixMode,
    #[serde(default)]
    pub launch_mode: LaunchMode,
    #[serde(default)]
    pub steam_launch_config: SteamLaunchConfig,
    #[serde(default)]
    pub graphics_layers: GraphicsLayerConfig,
    #[serde(default)]
    pub gpu_preference: Option<String>,
    pub hidden: bool,   // Future use
    pub favorite: bool, // Future use

    /// Per-game flag: this game requires Windows Steam to be running for Steam API access.
    /// Shown as informational indicator — does not override the global `Use Windows Steam Runtime` setting.
    #[serde(default)]
    pub requires_steam_api: bool,

    /// Per-game option: suppress Steam overlay for DX12 games where it causes black screens.
    #[serde(default)]
    pub dx12_suppress_overlay: bool,

    /// Per-game override for the Compatibility Layer (runner) used to launch this game.
    /// When set, this runner is used instead of the global proton_version setting.
    /// Does not affect the Steam Runtime runner used for Windows Steam background.
    #[serde(default)]
    pub game_runner: Option<String>,
}

pub type UserConfigStore = HashMap<u32, UserAppConfig>;

impl Default for UserAppConfig {
    fn default() -> Self {
        Self {
            launch_options: String::new(),
            env_variables: HashMap::new(),
            use_steam_runtime: false,
            steam_runtime_policy: SteamRuntimePolicy::Auto,
            steam_prefix_mode: SteamPrefixMode::Shared,
            launch_mode: LaunchMode::DirectWine,
            steam_launch_config: SteamLaunchConfig::default(),
            graphics_layers: GraphicsLayerConfig::default(),
            gpu_preference: None,
            hidden: false,
            favorite: false,
            requires_steam_api: false,
            dx12_suppress_overlay: false,
            game_runner: None,
        }
    }
}

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
    #[serde(default = "default_branch")]
    pub active_branch: String,
}

fn default_branch() -> String {
    "public".to_string()
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
    #[serde(default)]
    pub update_queued: bool,
    #[serde(default = "default_branch")]
    pub active_branch: String,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ExecutableArchitecture {
    #[default]
    Unknown,
    X86,
    X86_64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DepotPlatform {
    Linux,
    Windows,
}

pub struct ManifestSelection {
    pub app_id: u32,
    pub depot_id: u32,
    pub manifest_id: u64,
    pub appinfo_vdf: String,
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
    Verifying,
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

#[derive(Clone)]
pub struct DownloadState {
    pub is_downloading: bool,
    pub is_paused: bool,
    pub app_id: u32,
    pub app_name: String,
    pub total_bytes: u64,
    pub downloaded_bytes: u64,
    pub status_text: String,
    pub abort_signal: Arc<AtomicBool>,
    pub operation_controller: steam_cdn::OperationController,
}

impl Default for DownloadState {
    fn default() -> Self {
        Self {
            is_downloading: false,
            is_paused: false,
            app_id: 0,
            app_name: String::new(),
            total_bytes: 0,
            downloaded_bytes: 0,
            status_text: String::new(),
            abort_signal: Arc::new(AtomicBool::new(false)),
            operation_controller: steam_cdn::OperationController::new(),
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct AppInfoRoot {
    #[serde(default)]
    pub appinfo: Option<AppInfoNode>,
    #[serde(default)]
    pub common: Option<CommonNode>,
    #[serde(default)]
    pub depots: HashMap<String, DepotNode>,
    #[serde(default)]
    pub branches: HashMap<String, BranchNode>,
    #[serde(default)]
    pub config: Option<ConfigNode>,
}

#[derive(Debug, serde::Deserialize)]
pub struct AppInfoNode {
    #[serde(default)]
    pub common: Option<CommonNode>,
    #[serde(default)]
    pub depots: HashMap<String, DepotNode>,
    #[serde(default)]
    pub branches: HashMap<String, BranchNode>,
    #[serde(default)]
    pub config: Option<ConfigNode>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ConfigNode {
    #[serde(default)]
    pub launch: HashMap<String, ProductLaunchEntry>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ProductLaunchEntry {
    #[serde(default)]
    pub executable: Option<String>,
    #[serde(default)]
    pub arguments: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub oslist: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct CommonNode {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub dlc: HashMap<String, String>,
    #[serde(default)]
    pub installdir: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct DepotNode {
    #[serde(default)]
    pub config: Option<DepotConfig>,
    #[serde(default)]
    pub manifests: Option<DepotManifests>,
    #[serde(flatten)]
    pub _other: HashMap<String, serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
pub struct BranchNode {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub pwdrequired: Option<String>,
    #[serde(default)]
    pub buildid: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct DepotConfig {
    #[serde(default)]
    pub oslist: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct DepotManifests {
    #[serde(default)]
    pub public: Option<String>,
}
