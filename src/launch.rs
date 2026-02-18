use anyhow::{anyhow, Context, Result};
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

/// Install the official Windows Steam Client into the game's Proton prefix.
/// Now using the Proton Script (proton run) but with overrides to bypass fake Steam stubs.
pub fn install_ghost_steam_in_prefix(
    proton_path: &Path,
    prefix_path: &Path,
    steam_setup_exe: &Path,
) -> Result<()> {
    if !steam_setup_exe.exists() {
        return Err(anyhow!("SteamSetup.exe not found at {:?}", steam_setup_exe));
    }

    let steam_dir = prefix_path.join("drive_c/Program Files (x86)/Steam");
    let installed_steam_exe = steam_dir.join("steam.exe");

    // Optimization: Skip installation if Ghost Steam is already present
    if installed_steam_exe.exists() {
        info!("Ghost Steam already installed at {:?}", installed_steam_exe);
        return Ok(());
    }

    // Step 1: Sanitize Target (Crucial)
    // We remove Proton's fake stubs to ensure a clean environment for the real installer.
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
    if installed_steam_exe.exists() {
        info!("Ghost Steam successfully installed at {:?}", installed_steam_exe);
    } else {
        warn!("Ghost Steam installation might have failed: steam.exe not found at {:?}", installed_steam_exe);
    }

    Ok(())
}
