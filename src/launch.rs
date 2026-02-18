use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

/// Helper to find the Steam executable with fuzzy case matching in common paths.
pub fn get_installed_steam_path(prefix: &Path) -> Option<PathBuf> {
    let drive_c = prefix.join("drive_c");
    let candidates = vec![
        "Program Files (x86)/Steam/steam.exe",
        "Program Files (x86)/Steam/Steam.exe",
        "Program Files/Steam/steam.exe",
        "Program Files/Steam/Steam.exe",
        "Steam/steam.exe",
        "Steam/Steam.exe",
        "Program Files (x86)/steam/steam.exe",
    ];

    for subpath in candidates {
        let p = drive_c.join(subpath);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Debug helper to list directory contents.
fn list_directory_contents(path: &Path) {
    if let Ok(entries) = std::fs::read_dir(path) {
        info!("Listing directory contents for {:?}:", path);
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                let type_str = if meta.is_dir() { "DIR" } else { "FILE" };
                info!("  [{}] {:?}", type_str, entry.file_name());
            }
        }
    } else {
        warn!("Failed to read directory {:?}", path);
    }
}

/// Install the official Windows Steam Client into the game's Proton prefix.
/// Returns the path to the installed steam.exe on success.
pub fn install_ghost_steam_in_prefix(
    proton_path: &Path,
    prefix_path: &Path,
    steam_setup_exe: &Path,
) -> Result<PathBuf> {
    if !steam_setup_exe.exists() {
        return Err(anyhow!("SteamSetup.exe not found at {:?}", steam_setup_exe));
    }

    // Optimization: Skip installation if Ghost Steam is already present
    if let Some(steam_exe) = get_installed_steam_path(prefix_path) {
        info!("Ghost Steam already installed at {:?}", steam_exe);
        return Ok(steam_exe);
    }

    // Step 1: Sanitize Target (Crucial)
    // We remove Proton's fake stubs to ensure a clean environment for the real installer.
    let steam_dir = prefix_path.join("drive_c/Program Files (x86)/Steam");
    if steam_dir.exists() {
        info!("Sanitizing target Steam directory: {:?}", steam_dir);
        let stubs = ["lsteamclient.dll", "steam.exe"];
        for stub in stubs {
            let stub_path = steam_dir.join(stub);
            if stub_path.exists() {
                info!("Removing Proton stub/file: {:?}", stub_path);
                let _ = std::fs::remove_file(stub_path);
            }
        }
    }

    // Step 2: Execute Installer (Proton Run)
    let absolute_prefix = prefix_path.canonicalize()
        .context("Failed to canonicalize prefix path")?;

    info!("Installing Ghost Steam into prefix using Proton: {:?}", absolute_prefix);

    // proton_path is expected to be the path to the 'proton' executable/script
    let mut cmd = Command::new(proton_path);
    cmd.arg("run")
       .arg(steam_setup_exe)
       .arg("/S");

    // Env Vars (The 'Brain Surgery')
    // 1. Force Native DLLs (This ignores Proton's fake lsteamclient.dll)
    cmd.env("WINEDLLOVERRIDES", "steam.exe=n;lsteamclient=n;steam_api=n;steam_api64=n;steamclient=n;mscoree=d;mshtml=d");

    // 2. Unset Proton's Steam Hooks (Hide the fact we are in Steam)
    cmd.env_remove("STEAM_COMPAT_CLIENT_INSTALL_PATH");
    cmd.env_remove("SteamAppId");
    cmd.env_remove("SteamGameId");

    // 3. Set the Prefix Explicitly
    cmd.env("WINEPREFIX", &absolute_prefix);

    let status = cmd.status().context("Failed to execute Steam installer via Proton")?;
    if !status.success() {
        warn!("Steam installer exited with non-zero status: {:?}", status.code());
    }

    // Step 4: Post-Install Check
    if let Some(steam_exe) = get_installed_steam_path(prefix_path) {
        info!("Ghost Steam successfully installed at {:?}", steam_exe);
        Ok(steam_exe)
    } else {
        warn!("Ghost Steam installation might have failed: steam.exe not found in common paths.");
        let drive_c = prefix_path.join("drive_c");
        list_directory_contents(&drive_c);
        if let Ok(entries) = std::fs::read_dir(&drive_c) {
            for entry in entries.flatten() {
                if entry.metadata().map(|m| m.is_dir()).unwrap_or(false) {
                    list_directory_contents(&entry.path());
                }
            }
        }
        Err(anyhow!("Ghost Steam installation failed: steam.exe not found"))
    }
}
