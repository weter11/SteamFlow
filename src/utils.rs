use std::path::PathBuf;
use crate::config::{config_dir, secrets_dir};
use anyhow::Result;

/// Ensures the Windows Steam installer exists in the runtimes directory.
/// If missing, it downloads it from Steam's official CDN.
pub async fn download_windows_steam_client() -> Result<PathBuf> {
    let runtimes_dir = config_dir()?.join("runtimes");
    tokio::fs::create_dir_all(&runtimes_dir).await?;
    let target_path = runtimes_dir.join("SteamSetup.exe");

    if target_path.exists() {
        if let Ok(metadata) = tokio::fs::metadata(&target_path).await {
            if metadata.len() > 0 {
                tracing::info!("Using cached SteamSetup.exe at {}", target_path.display());
                return Ok(target_path);
            }
        }
    }

    tracing::info!("Downloading SteamSetup.exe...");
    let url = "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe";
    let response = reqwest::get(url).await?;
    let bytes = response.bytes().await?;

    if bytes.is_empty() {
        return Err(anyhow::anyhow!("Downloaded SteamSetup.exe is empty"));
    }

    tokio::fs::write(&target_path, &bytes).await?;
    tracing::info!("Saved SteamSetup.exe to {}", target_path.display());

    Ok(target_path)
}

/// Searches for the highest version of Proton installed on the system.
/// Checks official Steam paths and SteamFlow's custom compatibility tools directory.
pub fn get_proton_runner() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let mut search_paths = vec![
        PathBuf::from(&home).join(".steam/steam/steamapps/common"),
        PathBuf::from(&home).join(".local/share/Steam/steamapps/common"),
    ];

    if let Ok(cfg_dir) = config_dir() {
        search_paths.push(cfg_dir.join("compatibilitytools.d"));
    }

    let mut candidates = Vec::new();

    for path in search_paths {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        // Look for directories that likely contain Proton
                        if name.contains("Proton") {
                            let proton_exe = entry.path().join("proton");
                            if proton_exe.exists() {
                                candidates.push((name, proton_exe));
                            }
                        }
                    }
                }
            }
        }
    }

    // Sort by version number (descending)
    candidates.sort_by(|a, b| {
        let v1 = extract_version(&a.0);
        let v2 = extract_version(&b.0);
        v2.partial_cmp(&v1).unwrap_or(std::cmp::Ordering::Equal)
    });

    if let Some((name, path)) = candidates.first() {
        tracing::info!("Selected Proton runner: {} at {}", name, path.display());
        return Some(path.clone());
    }

    None
}

fn extract_version(name: &str) -> f32 {
    let mut v_str = String::new();
    let mut started = false;
    let mut dot_count = 0;
    for c in name.chars() {
        if c.is_ascii_digit() {
            v_str.push(c);
            started = true;
        } else if (c == '.' || c == '-') && started && dot_count == 0 {
            v_str.push('.');
            dot_count += 1;
        } else if started {
            break;
        }
    }
    v_str.parse::<f32>().unwrap_or(0.0)
}

/// Harvests Steam credentials from a specific Proton prefix and stores them in a central cache.
pub async fn harvest_credentials(prefix_path: &PathBuf) -> Result<()> {
    let steam_root = prefix_path.join("drive_c/Program Files (x86)/Steam");
    let loginusers_vdf = steam_root.join("config/loginusers.vdf");

    if !loginusers_vdf.exists() {
        return Ok(());
    }

    let content = tokio::fs::read_to_string(&loginusers_vdf).await?;
    if !content.contains("\"RememberPassword\"\t\t\"1\"") && !content.contains("\"RememberPassword\" \"1\"") {
        tracing::info!("RememberPassword not set in loginusers.vdf, skipping credential harvest.");
        return Ok(());
    }

    let secrets = secrets_dir()?;
    tokio::fs::create_dir_all(&secrets).await?;

    // Copy config files
    let config_src = steam_root.join("config");
    let config_dst = secrets.join("config");
    tokio::fs::create_dir_all(&config_dst).await?;

    let files_to_copy = ["config.vdf", "loginusers.vdf"];
    for file in files_to_copy {
        let src = config_src.join(file);
        if src.exists() {
            tokio::fs::copy(&src, config_dst.join(file)).await?;
        }
    }

    // Copy ssfn* files
    if let Ok(mut entries) = tokio::fs::read_dir(&steam_root).await {
        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name.starts_with("ssfn") {
                tokio::fs::copy(entry.path(), secrets.join(file_name)).await?;
            }
        }
    }

    tracing::info!("Steam credentials harvested successfully to {}", secrets.display());
    Ok(())
}

/// Injects cached Steam credentials into a specific Proton prefix.
/// Returns true if credentials were injected.
pub async fn inject_credentials(prefix_path: &PathBuf) -> Result<bool> {
    let secrets = secrets_dir()?;
    if !secrets.exists() {
        return Ok(false);
    }

    let steam_root = prefix_path.join("drive_c/Program Files (x86)/Steam");
    if !steam_root.exists() {
        return Ok(false);
    }

    let mut injected = false;

    // Inject config files
    let config_src = secrets.join("config");
    let config_dst = steam_root.join("config");
    if config_src.exists() {
        tokio::fs::create_dir_all(&config_dst).await?;
        let files_to_copy = ["config.vdf", "loginusers.vdf"];
        for file in files_to_copy {
            let src = config_src.join(file);
            if src.exists() {
                tokio::fs::copy(&src, config_dst.join(file)).await?;
                injected = true;
            }
        }
    }

    // Inject ssfn* files
    if let Ok(mut entries) = tokio::fs::read_dir(&secrets).await {
        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name.starts_with("ssfn") {
                tokio::fs::copy(entry.path(), steam_root.join(file_name)).await?;
                injected = true;
            }
        }
    }

    if injected {
        tracing::info!("Steam credentials injected into {}", steam_root.display());
    }

    Ok(injected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_version() {
        assert_eq!(extract_version("Proton 9.0"), 9.0);
        assert_eq!(extract_version("Proton 8.0-5"), 8.0);
        assert_eq!(extract_version("GE-Proton9-1"), 9.1);
        assert_eq!(extract_version("Proton Experimental"), 0.0);
        assert_eq!(extract_version("Proton-8.4"), 8.4);
    }
}
