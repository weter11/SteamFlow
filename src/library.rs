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


pub async fn find_local_games() -> Result<Vec<LocalGame>> {
    let installed_paths = scan_installed_app_paths().await?;
    let mut all_games = Vec::new();

    for (app_id, install_path) in installed_paths {
        all_games.push(LocalGame {
            app_id,
            name: format!("App {app_id}"),
            install_dir: PathBuf::from(install_path),
            proton_version: None,
        });
    }

    Ok(all_games)
}

pub async fn scan_installed_app_paths() -> Result<HashMap<u32, String>> {
    let path_map = scan_installed_app_paths_pathbuf().await?;
    Ok(path_map
        .into_iter()
        .map(|(appid, path)| (appid, path.to_string_lossy().to_string()))
        .collect())
}

pub async fn scan_installed_app_paths_pathbuf() -> Result<HashMap<u32, PathBuf>> {
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
    scan_library(&root).await
}

pub async fn scan_library(root_path: &Path) -> Result<HashMap<u32, PathBuf>> {
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

            match parse_app_manifest_install_path(&path).await {
                Ok(Some((app_id, install_dir))) => {
                    installed.insert(app_id, install_dir);
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

async fn parse_app_manifest_install_path(path: &Path) -> Result<Option<(u32, PathBuf)>> {
    let raw = fs::read_to_string(path)
        .await
        .with_context(|| format!("failed reading {}", path.display()))?;

    let mut app_id = None;
    let mut install_dir_name = None;

    for line in raw.lines() {
        let parts = extract_quoted_values(line.trim());
        if parts.len() >= 2 {
            let key = parts[0].to_lowercase();
            let value = &parts[1];

            if key == "appid" {
                app_id = value.parse::<u32>().ok();
            } else if key == "installdir" {
                install_dir_name = Some(value.to_string());
            }
        }

        if app_id.is_some() && install_dir_name.is_some() {
            break;
        }
    }

    match (app_id, install_dir_name) {
        (Some(id), Some(dir)) => {
            let install_dir = path
                .parent()
                .map(|p| p.join("common").join(dir))
                .unwrap_or_default();
            Ok(Some((id, install_dir)))
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
    installed_paths: HashMap<u32, String>,
) -> GameLibrary {
    let mut games = Vec::new();

    for owned_game in owned {
        let install_path = installed_paths.get(&owned_game.app_id).cloned();
        games.push(LibraryGame {
            app_id: owned_game.app_id,
            name: owned_game.name,
            playtime_forever_minutes: Some(owned_game.playtime_forever_minutes),
            is_installed: install_path.is_some(),
            install_path,
            local_manifest_ids: owned_game.local_manifest_ids,
            update_available: owned_game.update_available,
        });
    }

    for (app_id, install_path) in installed_paths {
        if games.iter().any(|g| g.app_id == app_id) {
            continue;
        }

        games.push(LibraryGame {
            app_id,
            name: format!("App {app_id}"),
            playtime_forever_minutes: None,
            is_installed: true,
            install_path: Some(install_path),
            local_manifest_ids: HashMap::new(),
            update_available: false,
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
