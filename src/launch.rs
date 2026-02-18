use std::path::PathBuf;
use crate::config::{config_dir, absolute_path};
use crate::utils::download_windows_steam_client;
use anyhow::{anyhow, Result, Context};

/// Installs the "Ghost Steam" client into a specific Proton prefix for a game.
/// This avoids dependency conflicts by giving each game its own minimal Steam installation.
pub async fn install_ghost_steam_in_prefix(game_id: u32, _proton_path: PathBuf) -> Result<PathBuf> {
    let base_dir = absolute_path(config_dir()?)?;
    let compat_data_path = base_dir.join("steamapps/compatdata").join(game_id.to_string());
    let prefix_path = compat_data_path.join("pfx");

    // Expected path to steam.exe inside the Proton prefix
    let steam_exe_path = prefix_path
        .join("drive_c")
        .join("Program Files (x86)")
        .join("Steam")
        .join("steam.exe");

    if steam_exe_path.exists() {
        tracing::info!(appid = game_id, "Ghost Steam already installed at {}", steam_exe_path.display());
        return Ok(steam_exe_path);
    }

    tracing::info!(appid = game_id, "Installing Ghost Steam into prefix...");

    // 1. Ensure the installer is cached
    let installer_path = absolute_path(download_windows_steam_client().await
        .context("Failed to ensure Steam installer is cached")?)?;

    // 2. Ensure compatdata directory exists
    tokio::fs::create_dir_all(&compat_data_path).await
        .context("Failed to create compatdata directory")?;

    // 3. Manual Installation (Extract from SteamSetup.exe and sanitize stubs)
    let steam_dir = prefix_path.join("drive_c/Program Files (x86)/Steam");
    tokio::fs::create_dir_all(&steam_dir).await
        .context("Failed to create Steam directory in prefix")?;

    // Step A: Sanitize the Prefix (Remove Proton's stubs)
    let stubs = ["steam.exe", "lsteamclient.dll", "tier0_s.dll", "vstdlib_s.dll"];
    for stub in stubs {
        let path = steam_dir.join(stub);
        if path.exists() {
            tracing::info!(appid = game_id, stub = stub, "Removing built-in stub");
            let _ = tokio::fs::remove_file(&path).await;
        }
    }

    // Step B: Extract the Real Client from SteamSetup.exe
    tracing::info!(appid = game_id, "Extracting real Steam client from installer...");

    // We use a blocking task for ZIP extraction to avoid blocking the async executor
    let installer_path_clone = installer_path.clone();
    let steam_dir_clone = steam_dir.clone();

    tokio::task::spawn_blocking(move || -> Result<()> {
        let file = std::fs::File::open(&installer_path_clone)
            .context("Failed to open SteamSetup.exe")?;
        let mut archive = zip::ZipArchive::new(file)
            .context("Failed to open SteamSetup.exe as ZIP archive (NSIS might not be ZIP-compatible or file is corrupt)")?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let outpath = match file.enclosed_name() {
                Some(path) => steam_dir_clone.join(path),
                None => continue,
            };

            if file.name().ends_with('/') {
                std::fs::create_dir_all(&outpath)?;
            } else {
                if let Some(p) = outpath.parent() {
                    if !p.exists() {
                        std::fs::create_dir_all(p)?;
                    }
                }
                let mut outfile = std::fs::File::create(&outpath)?;
                std::io::copy(&mut file, &mut outfile)?;
            }
        }
        Ok(())
    }).await??;

    // 4. Verify installation
    if !steam_exe_path.exists() {
        return Err(anyhow!(
            "Steam installation seemed to succeed, but steam.exe was not found at {}",
            steam_exe_path.display()
        ));
    }

    tracing::info!(appid = game_id, "Ghost Steam successfully installed at {}", steam_exe_path.display());
    Ok(steam_exe_path)
}
