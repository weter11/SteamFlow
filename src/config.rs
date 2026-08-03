use crate::models::{LaunchMode, OwnedGame, RunnerSource, SessionState, SteamPrefixMode, UserConfigStore};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct GameConfig {
    pub forced_proton_version: Option<String>,
    pub platform_preference: Option<String>,
}

/// Dev-only configuration loaded from `~/.config/SteamFlow/debug.json`.
///
/// Not exposed in the UI — this is a debugging facility for developers.
/// The `env` map is applied as the final (highest-priority) overlay onto
/// every game launch environment, so keys here win over per-game env
/// variables and built-in debug defaults.
///
/// Example file:
/// ```json
/// {
///   "env": {
///     "VKD3D_DEBUG": "info",
///     "DXVK_LOG_LEVEL": "info",
///     "WINEDEBUG": "+mfplat,+wg_transform,+gstreamer",
///     "GST_DEBUG": "2",
///     "GST_DEBUG_NO_COLOR": "1"
///   }
/// }
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DebugConfig {
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// Loads `debug.json` from the SteamFlow config dir.
///
/// - Missing file -> empty [`DebugConfig`] (no-op).
/// - Malformed JSON -> logs a warning to stderr and returns empty config;
///   a broken debug file must never break a game launch.
pub fn load_debug_config() -> DebugConfig {
    let Ok(dir) = config_dir() else {
        return DebugConfig::default();
    };
    let path = dir.join("debug.json");
    if !path.exists() {
        return DebugConfig::default();
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<DebugConfig>(&content) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!(
                    "[debug.json] failed to parse {}: {e}; ignoring debug config",
                    path.display()
                );
                DebugConfig::default()
            }
        },
        Err(e) => {
            eprintln!(
                "[debug.json] failed to read {}: {e}; ignoring debug config",
                path.display()
            );
            DebugConfig::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LauncherConfig {
    pub steam_library_path: String,
    pub proton_version: String,
    #[serde(default)]
    pub steam_runtime_runner: PathBuf,
    #[serde(default)]
    pub steam_runtime_runner_source: RunnerSource,
    #[serde(default)]
    pub steam_prefix_mode: SteamPrefixMode,
    #[serde(default)]
    pub launch_mode: LaunchMode,
    pub enable_cloud_sync: bool,
    #[serde(default)]
    pub use_shared_compat_data: bool,
    #[serde(default = "crate::models::default_true")]
    pub windows_steam_discovery_enabled: bool,
    /// When enabled (default), the Windows Steam client is pinned to skip its in-client
    /// self-updater. Under Proton-based runners Steam's updater downloads a fresh client
    /// that then fails the in-place rename (rename ...steamwebhelper.exe -> .old returns
    /// ERROR_ACCESS_DENIED) and the launch aborts before connecting. Disabling the
    /// self-update keeps the known-good client in place. wine-tkg does not trigger the
    /// update and works either way, but leaving this on is safe for it too.
    #[serde(default = "crate::models::default_true")]
    pub skip_steam_self_update: bool,
    /// Global Steam-launch feature toggles used by client-management operations
    /// (Manage / Repair / Reinstall / Backup / Restore). Defaults to
    /// `all_alive()` — steamwebhelper must survive these operations so the
    /// client can log in and render its UI. The per-game `SteamLaunchConfig`
    /// still controls game launches.
    #[serde(default = "crate::models::default_steam_launch_config_alive")]
    pub steam_launch_config: crate::models::SteamLaunchConfig,
    #[serde(default)]
    pub preferred_launch_options: HashMap<u32, String>,
    #[serde(default)]
    pub game_configs: HashMap<u32, GameConfig>,
}

impl LauncherConfig {
    pub async fn load() -> Result<Self> {
        load_launcher_config().await
    }

    pub async fn save(&self) -> Result<()> {
        save_launcher_config(self).await
    }
}

impl Default for LauncherConfig {
    fn default() -> Self {
        let steam_library_path = detect_steam_path()
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
                format!("{home}/Games/SteamFlow")
            });

        Self {
            steam_library_path,
            proton_version: "Proton - Experimental".to_string(),
            steam_runtime_runner: PathBuf::new(),
            steam_runtime_runner_source: RunnerSource::default(),
            steam_prefix_mode: SteamPrefixMode::default(),
            launch_mode: LaunchMode::default(),
            enable_cloud_sync: true,
            use_shared_compat_data: false,
            windows_steam_discovery_enabled: true,
            skip_steam_self_update: true,
            steam_launch_config: crate::models::SteamLaunchConfig::all_alive(),
            preferred_launch_options: HashMap::new(),
            game_configs: HashMap::new(),
        }
    }
}

pub fn detect_steam_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let candidates = [PathBuf::from(r"C:\Program Files (x86)\Steam")];
        return candidates.into_iter().find(|path| path.exists());
    }

    #[cfg(not(target_os = "windows"))]
    {
        let home = std::env::var("HOME").ok()?;
        let candidates = [
            PathBuf::from(&home).join(".steam/steam"),
            PathBuf::from(&home).join(".local/share/Steam"),
            PathBuf::from(&home).join(".steam/root"),
        ];
        candidates.into_iter().find(|path| path.exists())
    }
}

/// Returns the Steam install root that contains `compatibilitytools.d` and
/// `steamapps/common` (where Steam SDK shims such as libsteam_api.so live).
/// On Linux this is typically ~/.local/share/Steam (with ~/.steam/steam often a
/// symlink to it). Best-effort fallback source when a game's own Steam SDK shim
/// is missing or corrupt and must be repaired from another location.
pub fn get_steam_root_hint() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let candidates = [
        PathBuf::from(&home).join(".local/share/Steam"),
        PathBuf::from(&home).join(".steam/steam"),
        PathBuf::from(&home).join(".steam/root"),
    ];
    for c in &candidates {
        if c.join("compatibilitytools.d").is_dir() || c.join("steamapps/common").is_dir() {
            return Some(c.clone());
        }
    }
    candidates.into_iter().find(|p| p.exists())
}

pub fn config_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config/SteamFlow"))
}

pub async fn ensure_config_dirs() -> Result<()> {
    let config = config_dir()?;
    fs::create_dir_all(&config).await?;
    let images = opensteam_image_cache_dir()?;
    fs::create_dir_all(&images).await?;
    Ok(())
}

pub fn opensteam_image_cache_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("images"))
}

pub fn data_dir() -> Result<PathBuf> {
    config_dir()  // or use XDG_DATA_HOME if you want proper separation
}

pub async fn load_session() -> Result<SessionState> {
    let session_path = config_dir()?.join("session.json");
    if !session_path.exists() {
        return Ok(SessionState::default());
    }

    let raw = fs::read_to_string(&session_path)
        .await
        .with_context(|| format!("failed reading {}", session_path.display()))?;
    let state = serde_json::from_str(&raw)
        .with_context(|| format!("failed parsing {}", session_path.display()))?;
    Ok(state)
}

pub async fn save_session(session: &SessionState) -> Result<()> {
    let config = config_dir()?;
    fs::create_dir_all(&config)
        .await
        .with_context(|| format!("failed creating {}", config.display()))?;

    let session_path = config.join("session.json");
    let body = serde_json::to_string_pretty(session)?;
    fs::write(&session_path, body)
        .await
        .with_context(|| format!("failed writing {}", session_path.display()))?;

    Ok(())
}

pub async fn delete_session() -> Result<()> {
    let session_path = config_dir()?.join("session.json");
    if session_path.exists() {
        fs::remove_file(session_path).await?;
    }
    Ok(())
}

pub async fn load_launcher_config() -> Result<LauncherConfig> {
    let path = config_dir()?.join("config.json");
    if !path.exists() {
        let mut config = LauncherConfig::default();
        if let Some(detected) = detect_steam_path() {
            config.steam_library_path = detected.to_string_lossy().to_string();
        }
        return Ok(config);
    }

    let raw = fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed reading {}", path.display()))?;
    let parsed = serde_json::from_str::<LauncherConfig>(&raw)
        .with_context(|| format!("failed parsing {}", path.display()))?;
    Ok(parsed)
}

pub async fn save_launcher_config(config: &LauncherConfig) -> Result<()> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed creating {}", dir.display()))?;

    let path = dir.join("config.json");
    let body = serde_json::to_string_pretty(config)?;
    fs::write(&path, body)
        .await
        .with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

pub fn library_cache_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("library_cache.json"))
}

pub async fn save_library_cache(owned_games: &[OwnedGame]) -> Result<()> {
    let dir = data_dir()?;
    fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed creating {}", dir.display()))?;

    let path = library_cache_path()?;
    let body = serde_json::to_string_pretty(owned_games)?;
    fs::write(&path, body)
        .await
        .with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

pub async fn load_library_cache() -> Result<Vec<OwnedGame>> {
    let path = library_cache_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }

    let raw = fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed reading {}", path.display()))?;
    let cached = serde_json::from_str::<Vec<OwnedGame>>(&raw)
        .with_context(|| format!("failed parsing {}", path.display()))?;
    Ok(cached)
}

pub async fn load_user_configs() -> Result<UserConfigStore> {
    let path = config_dir()?.join("user_apps.json");
    if !path.exists() {
        return Ok(UserConfigStore::new());
    }

    let raw = fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed reading {}", path.display()))?;
    let parsed = serde_json::from_str::<UserConfigStore>(&raw)
        .with_context(|| format!("failed parsing {}", path.display()))?;
    Ok(parsed)
}

pub async fn save_user_configs(configs: &UserConfigStore) -> Result<()> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed creating {}", dir.display()))?;

    let path = dir.join("user_apps.json");
    let body = serde_json::to_string_pretty(configs)?;
    fs::write(&path, body)
        .await
        .with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}
