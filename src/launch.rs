use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

/// Task 1: Find the wine binary within a Proton directory dynamically.
pub fn find_wine_binary(proton_path: &Path) -> Result<PathBuf> {
    let candidates = [
        proton_path.join("files/bin/wine"), // Modern Proton / GE-Proton
        proton_path.join("dist/bin/wine"),  // Older Proton
        proton_path.join("bin/wine"),       // Ancient/System
    ];

    for candidate in &candidates {
        if candidate.exists() {
            info!("Found wine binary at: {:?}", candidate);
            return Ok(candidate.clone());
        }
    }

    Err(anyhow!("Wine binary not found in Proton dir: {:?}", proton_path))
}

/// Task 2: Install the official Windows Steam Client into the game's Proton prefix.
pub fn install_ghost_steam_in_prefix(
    proton_path: &Path,
    prefix_path: &Path,
    steam_setup_exe: &Path,
) -> Result<()> {
    if !steam_setup_exe.exists() {
        return Err(anyhow!("SteamSetup.exe not found at {:?}", steam_setup_exe));
    }

    // Step A: Sanitize Target
    let steam_dir = prefix_path.join("drive_c/Program Files (x86)/Steam");
    if steam_dir.exists() {
        info!("Sanitizing target Steam directory: {:?}", steam_dir);
        let stubs = ["steam.exe", "lsteamclient.dll", "tier0_s.dll", "vstdlib_s.dll"];
        for stub in stubs {
            let stub_path = steam_dir.join(stub);
            if stub_path.exists() {
                info!("Removing Proton stub: {:?}", stub_path);
                let _ = std::fs::remove_file(stub_path);
            }
        }
    }

    // Step B: Execute Installer (Raw Wine)
    let wine_bin = find_wine_binary(proton_path)?;
    let absolute_prefix = prefix_path.canonicalize()
        .context("Failed to canonicalize prefix path")?;

    info!("Installing Ghost Steam into prefix: {:?}", absolute_prefix);

    let mut cmd = Command::new(&wine_bin);
    cmd.arg(steam_setup_exe)
       .arg("/S");

    // Env Vars (CRITICAL)
    cmd.env("WINEPREFIX", &absolute_prefix);
    cmd.env("WINEDLLOVERRIDES", "mscoree=d;mshtml=d");

    // REMOVE Steam-specific env vars to ensure clean install
    cmd.env_remove("STEAM_COMPAT_DATA_PATH");
    cmd.env_remove("STEAM_COMPAT_CLIENT_INSTALL_PATH");
    cmd.env_remove("SteamAppId");

    let status = cmd.status().context("Failed to execute Steam installer")?;
    if !status.success() {
        warn!("Steam installer exited with non-zero status: {:?}", status.code());
    }

    Ok(())
}
