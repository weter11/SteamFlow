use std::path::PathBuf;
use crate::config::{config_dir, absolute_path};
use crate::utils::download_windows_steam_client;
use anyhow::{anyhow, Result, Context};
use tokio::process::Command;

/// Installs the "Ghost Steam" client into a specific Proton prefix for a game.
/// This avoids dependency conflicts by giving each game its own minimal Steam installation.
pub async fn install_ghost_steam_in_prefix(game_id: u32, proton_path: PathBuf) -> Result<PathBuf> {
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

    // 2. Locate the Raw Wine binary inside the Proton directory
    // We must bypass the 'proton' script to avoid its Steam environment checks.
    let wine_candidates = [
        proton_path.parent().and_then(|p| p.parent()).map(|p| p.join("dist/bin/wine")),
        proton_path.parent().and_then(|p| p.parent()).map(|p| p.join("files/bin/wine")),
    ];

    let wine_exe = wine_candidates.into_iter()
        .flatten()
        .find(|p| p.exists())
        .ok_or_else(|| anyhow!("Failed to locate wine binary within Proton path: {:?}", proton_path))?;

    // 3. Manual Sanitization (Remove Proton's built-in Steam stubs)
    let steam_dir = prefix_path.join("drive_c/Program Files (x86)/Steam");
    if steam_dir.exists() {
        let stubs = ["steam.exe", "lsteamclient.dll", "tier0_s.dll", "vstdlib_s.dll"];
        for stub in stubs {
            let path = steam_dir.join(stub);
            if path.exists() {
                tracing::info!(appid = game_id, stub = stub, "Removing built-in stub before install");
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
    } else {
        tokio::fs::create_dir_all(&steam_dir).await
            .context("Failed to create Steam directory in prefix")?;
    }

    // 4. Run the installer via Raw Wine
    tracing::info!(appid = game_id, wine = ?wine_exe, "Executing Steam installer via Raw Wine...");
    let mut cmd = Command::new(&wine_exe);
    cmd.arg(&installer_path)
       .arg("/S") // Silent install flag
       .env("WINEPREFIX", &prefix_path)
       .env("WINEDLLOVERRIDES", "mscoree,mshtml=;steam.exe=n;lsteamclient=n;steam_api=n;steam_api64=n;steamclient=n")
       .env_remove("SteamAppId")
       .env_remove("STEAM_COMPAT_DATA_PATH")
       .env_remove("STEAM_COMPAT_CLIENT_INSTALL_PATH");

    let status = cmd.status().await
        .context(format!("Failed to run Wine installer for app {}", game_id))?;

    if !status.success() {
        return Err(anyhow!("Wine installer exited with non-zero status for app {}", game_id));
    }

    // 5. Verify installation
    if !steam_exe_path.exists() {
        return Err(anyhow!(
            "Steam installation seemed to succeed, but steam.exe was not found at {}",
            steam_exe_path.display()
        ));
    }

    tracing::info!(appid = game_id, "Ghost Steam successfully installed at {}", steam_exe_path.display());
    Ok(steam_exe_path)
}
