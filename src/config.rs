use crate::models::{OwnedGame, SessionState, UserConfigStore};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LauncherConfig {
    pub steam_library_path: String,
    pub proton_version: String,
    pub enable_cloud_sync: bool,
    #[serde(default)]
    pub use_shared_compat_data: bool,
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
            proton_version: "experimental".to_string(),
            enable_cloud_sync: true,
            use_shared_compat_data: false,
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

pub fn config_dir() -> Result<PathBuf> {
    Ok(PathBuf::from("./config/SteamFlow"))
}

pub fn data_dir() -> Result<PathBuf> {
    Ok(PathBuf::from("./config/SteamFlow"))
}

pub async fn ensure_config_dirs() -> Result<()> {
    let config = config_dir()?;
    fs::create_dir_all(&config).await?;
    let images = opensteam_image_cache_dir()?;
    fs::create_dir_all(&images).await?;
    let secrets = secrets_dir()?;
    fs::create_dir_all(&secrets).await?;
    Ok(())
}

pub fn opensteam_image_cache_dir() -> Result<PathBuf> {
    Ok(PathBuf::from("./config/SteamFlow/images"))
}

pub fn secrets_dir() -> Result<PathBuf> {
    Ok(PathBuf::from("./config/SteamFlow/secrets"))
}

pub fn absolute_path(path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        let cwd = std::env::current_dir().with_context(|| "failed to get current directory")?;
        Ok(cwd.join(path))
    }
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
