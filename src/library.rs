use crate::config::{detect_steam_path, load_launcher_config};
use crate::models::{GameLibrary, GameModel, LibraryGame, LocalGame, OwnedGame};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;

#[derive(Debug, Deserialize)]
struct LibraryFoldersFile {
    #[serde(default)]
    libraryfolders: HashMap<String, LibraryFolderRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum LibraryFolderRecord {
    LegacyPath(String),
    Detailed {
        path: Option<String>,
        #[serde(flatten)]
        _other: HashMap<String, serde_json::Value>,
    },
    Ignore(#[allow(dead_code)] HashMap<String, serde_json::Value>),
}

#[derive(Debug, Clone)]
pub struct InstalledAppInfo {
    pub install_path: PathBuf,
    pub active_branch: String,
    pub name: Option<String>,
}

pub async fn find_local_games() -> Result<Vec<LocalGame>> {
    let installed_info = scan_installed_app_info().await?;
    let mut all_games = Vec::new();

    for (app_id, info) in installed_info {
        all_games.push(LocalGame {
            app_id,
            name: info.name.unwrap_or_else(|| format!("App {app_id}")),
            install_dir: info.install_path,
            proton_version: None,
            active_branch: info.active_branch,
        });
    }

    Ok(all_games)
}

pub async fn scan_installed_app_info() -> Result<HashMap<u32, InstalledAppInfo>> {
    let config_path = load_launcher_config().await.ok().and_then(|cfg| {
        let p = PathBuf::from(cfg.steam_library_path);
        if p.join("steamapps").exists() || p.join("Steam").join("steamapps").exists() {
            Some(p)
        } else {
            None
        }
    });

    let root = config_path
        .or_else(detect_steam_path)
        .unwrap_or_else(default_steam_root);
    println!("Scanning Library Root: {:?}", root);
    scan_library_info(&root).await
}

pub async fn scan_installed_app_paths() -> Result<HashMap<u32, String>> {
    let info_map = scan_installed_app_info().await?;
    Ok(info_map
        .into_iter()
        .map(|(appid, info)| (appid, info.install_path.to_string_lossy().to_string()))
        .collect())
}

pub async fn scan_installed_app_paths_pathbuf() -> Result<HashMap<u32, PathBuf>> {
    let info_map = scan_installed_app_info().await?;
    Ok(info_map
        .into_iter()
        .map(|(appid, info)| (appid, info.install_path))
        .collect())
}

pub async fn scan_library_info(root_path: &Path) -> Result<HashMap<u32, InstalledAppInfo>> {
    let mut installed = HashMap::new();
    let mut libraries = vec![root_path.to_path_buf()];

    let library_folders_path = root_path.join("steamapps").join("libraryfolders.vdf");
    let extra_libraries = parse_library_folders(library_folders_path)
        .await
        .unwrap_or_else(|e| {
            println!("Warning: Could not parse libraryfolders.vdf: {}", e);
            Vec::new()
        });
    libraries.extend(extra_libraries);

    libraries.sort();
    libraries.dedup();

    for library_root in libraries {
        let steamapps = library_root.join("steamapps");
        if !steamapps.exists() {
            continue;
        }

        let mut dir = fs::read_dir(&steamapps)
            .await
            .with_context(|| format!("failed to read {}", steamapps.display()))?;

        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if !is_app_manifest(&path) {
                continue;
            }

            match parse_app_manifest_info(&path).await {
                Ok(Some((app_id, info))) => {
                    installed.insert(app_id, info);
                }
                Ok(None) => {}
                Err(e) => println!("Skipping bad manifest {:?}: {}", path, e),
            }
        }
    }

    Ok(installed)
}

fn default_steam_root() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(program_files_x86) = std::env::var("PROGRAMFILES(X86)") {
            return PathBuf::from(program_files_x86).join("Steam");
        }
        if let Ok(program_files) = std::env::var("PROGRAMFILES") {
            return PathBuf::from(program_files).join("Steam");
        }
        return PathBuf::from(r"C:\Program Files (x86)\Steam");
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Some(detected) = detect_steam_path() {
            return detected;
        }
        directories::BaseDirs::new()
            .map(|d| d.home_dir().to_path_buf())
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "~".to_string()))
            })
            .join(".steam/steam")
    }
}

fn is_app_manifest(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };

    name.starts_with("appmanifest_") && name.ends_with(".acf")
}

pub async fn parse_library_folders(path: PathBuf) -> Result<Vec<PathBuf>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let raw = fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed reading {}", path.display()))?;

    let parsed = keyvalues_serde::from_str::<LibraryFoldersFile>(&raw)
        .context("failed to parse libraryfolders.vdf with keyvalues-serde")?;

    let mut libraries = Vec::new();
    for (key, value) in parsed.libraryfolders {
        if !key.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }

        match value {
            LibraryFolderRecord::LegacyPath(p) if !p.is_empty() => libraries.push(PathBuf::from(p)),
            LibraryFolderRecord::Detailed { path: Some(p), .. } if !p.is_empty() => {
                libraries.push(PathBuf::from(p))
            }
            _ => {}
        }
    }

    libraries.sort();
    libraries.dedup();
    Ok(libraries)
}

async fn parse_app_manifest_info(path: &Path) -> Result<Option<(u32, InstalledAppInfo)>> {
    let raw = fs::read_to_string(path)
        .await
        .with_context(|| format!("failed reading {}", path.display()))?;

    let mut app_id = None;
    let mut install_dir_name = None;
    let mut name = None;
    let mut active_branch = "public".to_string();

    let mut in_user_config = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        let parts = extract_quoted_values(trimmed);

        if parts.len() == 1 && parts[0].eq_ignore_ascii_case("userconfig") {
            in_user_config = true;
            continue;
        }

        if trimmed == "{" || trimmed == "}" {
            if trimmed == "}" && in_user_config {
                in_user_config = false;
            }
            continue;
        }

        if parts.len() >= 2 {
            let key = parts[0].to_lowercase();
            let value = &parts[1];

            if !in_user_config {
                if key == "appid" {
                    app_id = value.parse::<u32>().ok();
                } else if key == "installdir" {
                    install_dir_name = Some(value.to_string());
                } else if key == "name" {
                    name = Some(value.to_string());
                }
            } else if key == "betakey" {
                if !value.trim().is_empty() {
                    active_branch = value.to_string();
                }
            }
        }
    }

    match (app_id, install_dir_name) {
        (Some(id), Some(dir)) => {
            let install_path = path
                .parent()
                .map(|p| p.join("common").join(dir))
                .unwrap_or_default();
            Ok(Some((
                id,
                InstalledAppInfo {
                    install_path,
                    active_branch,
                    name,
                },
            )))
        }
        _ => Ok(None),
    }
}

fn extract_quoted_values(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_quote = false;
    let mut current = String::new();
    for ch in line.chars() {
        if ch == '"' {
            if in_quote {
                out.push(current.clone());
                current.clear();
            }
            in_quote = !in_quote;
            continue;
        }
        if in_quote {
            current.push(ch);
        }
    }
    out
}

pub fn build_game_library(
    owned: Vec<OwnedGame>,
    installed_info: HashMap<u32, InstalledAppInfo>,
) -> GameLibrary {
    let mut games = Vec::new();

    for owned_game in owned {
        let info = installed_info.get(&owned_game.app_id);
        let install_path = info.map(|i| i.install_path.to_string_lossy().to_string());
        let active_branch = info
            .map(|i| i.active_branch.clone())
            .unwrap_or_else(|| "public".to_string());

        games.push(LibraryGame {
            app_id: owned_game.app_id,
            name: owned_game.name,
            playtime_forever_minutes: Some(owned_game.playtime_forever_minutes),
            is_installed: install_path.is_some(),
            install_path,
            local_manifest_ids: owned_game.local_manifest_ids,
            update_available: owned_game.update_available,
            update_queued: false,
            active_branch,
        });
    }

    for (app_id, info) in installed_info {
        if games.iter().any(|g| g.app_id == app_id) {
            continue;
        }

        games.push(LibraryGame {
            app_id,
            name: info.name.unwrap_or_else(|| format!("App {app_id}")),
            playtime_forever_minutes: None,
            is_installed: true,
            install_path: Some(info.install_path.to_string_lossy().to_string()),
            local_manifest_ids: HashMap::new(),
            update_available: false,
            update_queued: false,
            active_branch: info.active_branch,
        });
    }

    games.sort_by(|a, b| a.name.cmp(&b.name));
    GameLibrary { games }
}

pub fn merge_games(owned: Vec<OwnedGame>, installed: Vec<LocalGame>) -> Vec<GameModel> {
    let mut merged: HashMap<u32, GameModel> = HashMap::new();

    for game in owned {
        merged.insert(
            game.app_id,
            GameModel {
                app_id: game.app_id,
                name: game.name,
                playtime_forever_minutes: Some(game.playtime_forever_minutes),
                install_dir: None,
                proton_version: None,
                image_cache_path: None,
            },
        );
    }

    for local in installed {
        merged
            .entry(local.app_id)
            .and_modify(|existing| {
                existing.install_dir = Some(local.install_dir.clone());
                existing.proton_version = local.proton_version.clone();
                if existing.name.trim().is_empty() {
                    existing.name = local.name.clone();
                }
            })
            .or_insert(GameModel {
                app_id: local.app_id,
                name: local.name,
                playtime_forever_minutes: None,
                install_dir: Some(local.install_dir),
                proton_version: local.proton_version,
                image_cache_path: None,
            });
    }

    let mut games: Vec<GameModel> = merged.into_values().collect();
    games.sort_by(|a, b| a.name.cmp(&b.name));
    games
}
