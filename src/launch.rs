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

    // 2. Ensure compatdata directory exists
    tokio::fs::create_dir_all(&compat_data_path).await
        .context("Failed to create compatdata directory")?;

    // 3. Run the installer via Proton
    // We need to set STEAM_COMPAT_DATA_PATH so Proton knows where the prefix is.
    // We also set STEAM_COMPAT_CLIENT_INSTALL_PATH to our config dir.
    let mut cmd = Command::new(&proton_path);
    cmd.arg("run")
       .arg(&installer_path)
       // .arg("/S") // Silent install flag - DISABLED FOR DEBUGGING
       .env("WINEPREFIX", compat_data_path.join("pfx"))
       .env("STEAM_COMPAT_DATA_PATH", &compat_data_path)
       .env("STEAM_COMPAT_CLIENT_INSTALL_PATH", &base_dir);

    tracing::info!("DEBUG: Launching Installer for App {}: {:?}", game_id, cmd);
    let status = cmd.status().await
        .context(format!("Failed to run Proton installer for app {}", game_id))?;

    if !status.success() {
        return Err(anyhow!("Proton installer exited with non-zero status for app {}", game_id));
    }

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
