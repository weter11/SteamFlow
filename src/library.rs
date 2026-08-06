use crate::config::{detect_steam_path, load_launcher_config};
use crate::models::{GameLibrary, GameModel, LibraryGame, LocalGame, OwnedGame};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use steam_vdf_parser::parse_text;
use tokio::fs;

#[derive(Debug, Clone)]
pub struct InstalledAppInfo {
    pub install_path: PathBuf,
    pub active_branch: String,
    pub name: Option<String>,
    /// Manifest `"type"` field ("game", "mod", "tool", "application", …).
    /// Parsed for transparency/auditing only — no type-based filtering is
    /// applied: standalone Steam mods (e.g. Portal: Revolution, AppID 601300)
    /// and free community mods must appear alongside native titles.
    pub app_type: Option<String>,
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
    let config = load_launcher_config().await.ok();
    let config_path = config.as_ref().and_then(|cfg| {
        let p = PathBuf::from(&cfg.steam_library_path);
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
    let mut installed = scan_library_info(&root).await?;

    if let Some(cfg) = config {
        if cfg.windows_steam_discovery_enabled {
            let master_steam = crate::utils::get_master_steam_config();
            if master_steam.wine_prefix.exists() {
                println!("Scanning Windows Steam Root: {:?}", master_steam.wine_prefix);
                // Windows Steam layout is drive_c/Program Files (x86)/Steam
                let windows_steam_root = master_steam.wine_prefix.join("drive_c/Program Files (x86)/Steam");
                if windows_steam_root.exists() {
                    let windows_installed = scan_library_info(&windows_steam_root).await.unwrap_or_default();
                    for (app_id, info) in windows_installed {
                        // Prefer native/standard Linux Steam if duplicate
                        installed.entry(app_id).or_insert(info);
                    }
                }
            }
        }
    }

    Ok(installed)
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

/// Synchronous variant of [`parse_library_folders`] for call sites that are
/// not inside an async context (e.g. client-side VDF registration while Steam
/// is stopped).
/// Extracts a quoted string token from a VDF line fragment (first `"..."`).
fn extract_vdf_path_token(line: &str) -> Option<String> {
    let first = line.find('"')?;
    let rest = &line[first + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Resilient `libraryfolders.vdf` parser.
///
/// Steam rewrites this file on client exit, and a half-written / malformed
/// entry (e.g. a library index line like `"1` with a missing closing quote)
/// makes keyvalues-serde hard-fail ("Failed parsing VDF text") — which
/// previously produced spurious warnings and, worse, silently dropped ALL
/// extra library folders. This line-scanner extracts every `"path"` value
/// directly (same approach as the ACF parser) and tolerates malformed lines.
pub fn parse_library_folders_sync(path: PathBuf) -> Result<Vec<PathBuf>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("failed reading {}", path.display()))?;

    let mut libraries = Vec::new();

    // `"path"` only ever appears inside a library-folder block, so no block
    // tracking is needed — scan every line for the key directly. This also
    // tolerates a malformed block header (`"1` missing its closing quote).
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("\"path\"") {
            if let Some(value) = extract_vdf_path_token(rest.trim_start()) {
                if !value.is_empty() {
                    libraries.push(PathBuf::from(value));
                }
            }
        }
    }

    libraries.sort();
    libraries.dedup();
    Ok(libraries)
}

pub async fn parse_library_folders(path: PathBuf) -> Result<Vec<PathBuf>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let raw = fs::read(&path)
        .await
        .with_context(|| format!("failed reading {}", path.display()))?;

    let raw = std::str::from_utf8(&raw)
        .context("libraryfolders.vdf is not UTF-8 text VDF")?;
    let parsed = parse_text(raw).context("failed to parse libraryfolders.vdf")?;

    let mut libraries = Vec::new();
    let Some(libraryfolders) = parsed.get_obj(&[]) else {
        return Ok(libraries);
    };
    for (key, value) in libraryfolders.iter() {
        if !key.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }

        let path = value
            .as_str()
            .or_else(|| value.get_str(&["path"]));
        if let Some(path) = path.filter(|path| !path.is_empty()) {
            libraries.push(PathBuf::from(path));
        }
    }

    libraries.sort();
    libraries.dedup();
    Ok(libraries)
}

async fn parse_app_manifest_info(path: &Path) -> Result<Option<(u32, InstalledAppInfo)>> {
    let raw = fs::read(path)
        .await
        .with_context(|| format!("failed reading {}", path.display()))?;
    parse_app_manifest_info_sync(&raw, path)
}

/// Synchronous core of [`parse_app_manifest_info`] (mirrors the
/// `parse_library_folders_sync` pattern) so the parser logic can be unit-tested
/// without tokio. NO filtering by `"type"` is applied here — mod/tool/application
/// manifests are all accepted, the same way Steam itself lists them.
fn parse_app_manifest_info_sync(
    raw: &[u8],
    path: &Path,
) -> Result<Option<(u32, InstalledAppInfo)>> {
    let raw = std::str::from_utf8(raw)
        .with_context(|| format!("{} is not UTF-8 text VDF", path.display()))?;
    let parsed = parse_text(raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    let app_id = parsed.get_str(&["appid"]).and_then(|value| value.parse().ok());
    let install_dir_name = parsed.get_str(&["installdir"]);
    let name = parsed.get_str(&["name"]).map(str::to_owned);
    let active_branch = parsed
        .get_str(&["UserConfig", "betakey"])
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("public")
        .to_owned();
    let app_type = parsed.get_str(&["type"]).map(str::to_owned);

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
                    app_type,
                },
            )))
        }
        _ => Ok(None),
    }
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

#[cfg(test)]
mod library_folders_parser_tests {
    use super::*;

    fn write_tmp(content: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "steamflow_lf_test_{}_{}.vdf",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn parses_valid_vdf() {
        let p = write_tmp(
            "\"libraryfolders\"\n{\n\t\"0\"\n\t{\n\t\t\"path\"\t\t\"/home/user/.local/share/Steam\"\n\t\t\"label\"\t\t\"\"\n\t\t\"apps\"\n\t\t{\n\t\t}\n\t}\n}\n",
        );
        let libs = parse_library_folders_sync(p.clone()).unwrap();
        assert_eq!(libs, vec![std::path::PathBuf::from("/home/user/.local/share/Steam")]);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn tolerates_malformed_library_index() {
        // Real-world case: Steam rewrites this file on exit and can leave a
        // library index like `"1` with a missing closing quote. keyvalues-serde
        // hard-fails on that ("Failed parsing VDF text"); the scanner must not.
        let p = write_tmp(
            "\"libraryfolders\"\n{\n\t\"0\"\n\t{\n\t\t\"path\"\t\t\"C:\\Program Files (x86)\\Steam\"\n\t\t\"apps\"\n\t\t{\n\t\t}\n\t}\n\t\"1\n\t{\n\t\t\"path\"\t\t\"Z:\\home\\wer\\.local\\share\\Steam\"\n\t\t\"apps\"\n\t\t{\n\t\t\t\"883710\"\t\t\"0\"\n\t\t}\n\t}\n}\n",
        );
        let libs = parse_library_folders_sync(p.clone()).unwrap();
        assert_eq!(
            libs,
            vec![
                std::path::PathBuf::from("C:\\Program Files (x86)\\Steam"),
                std::path::PathBuf::from("Z:\\home\\wer\\.local\\share\\Steam"),
            ]
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn missing_file_returns_empty() {
        let p = std::env::temp_dir().join("steamflow_lf_nonexistent_does_not_exist.vdf");
        let libs = parse_library_folders_sync(p).unwrap();
        assert!(libs.is_empty());
    }

    #[test]
    fn includes_mod_type_manifests() {
        // Standalone Steam mod (Portal: Revolution, AppID 601300) appmanifest
        // shape: "type" "mod" must NOT be filtered out by the library scanner.
        let acf = "appmanifest_601300.acf";
        let path = std::env::temp_dir().join(acf);
        let content = "\"AppState\"\n{\n\t\"appid\"\t\t\"601300\"\n\t\"type\"\t\t\"mod\"\n\t\"name\"\t\t\"Portal Revolution\"\n\t\"installdir\"\t\"Portal Revolution\"\n\t\"StateFlags\"\t\t\"4\"\n}\n";
        std::fs::write(&path, content).unwrap();

        let parsed = parse_app_manifest_info_sync(content.as_bytes(), &path).unwrap();
        let _ = std::fs::remove_file(&path);

        let (app_id, info) = parsed.expect("mod manifest must be indexed, not filtered");
        assert_eq!(app_id, 601300);
        assert_eq!(info.name.as_deref(), Some("Portal Revolution"));
        assert_eq!(info.app_type.as_deref(), Some("mod"));
        assert!(info.install_path.ends_with("common/Portal Revolution"));
    }

    #[test]
    fn includes_plain_game_manifests() {
        let acf = "appmanifest_883710_test.acf";
        let path = std::env::temp_dir().join(acf);
        let content = "\"AppState\"\n{\n\t\"appid\"\t\t\"883710\"\n\t\"type\"\t\t\"game\"\n\t\"name\"\t\t\"Resident Evil 2\"\n\t\"installdir\"\t\"RESIDENT EVIL 2\"\n}\n";
        std::fs::write(&path, content).unwrap();

        let parsed = parse_app_manifest_info_sync(content.as_bytes(), &path).unwrap();
        let _ = std::fs::remove_file(&path);

        let (app_id, info) = parsed.unwrap();
        assert_eq!(app_id, 883710);
        assert_eq!(info.app_type.as_deref(), Some("game"));
    }
}
