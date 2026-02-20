use std::path::{Path, PathBuf};
use anyhow::{Result, Context, anyhow};
use crate::config::{config_dir, LauncherConfig};
use crate::utils::build_runner_command;

pub async fn install_master_steam(config: &LauncherConfig) -> Result<()> {
    let base_dir = config_dir()?;
    let master_prefix = base_dir.join("master_steam_prefix");
    let runtimes_dir = base_dir.join("runtimes");
    std::fs::create_dir_all(&runtimes_dir)?;

    let setup_exe = runtimes_dir.join("SteamSetup.exe");
    if !setup_exe.exists() {
        download_steam_setup(&setup_exe).await?;
    }

    let runner_path = &config.steam_runtime_runner;
    if runner_path.as_os_str().is_empty() {
        return Err(anyhow!("No Steam Runtime Runner selected in Global Settings"));
    }

    let mut cmd = build_runner_command(runner_path)?;

    // Check if steam.exe exists in the prefix
    let steam_exe_path = find_steam_exe_in_prefix(&master_prefix);

    if let Some(exe_path) = steam_exe_path {
        // Run existing steam.exe
        cmd.arg(exe_path);
    } else {
        // Run installer
        cmd.arg(setup_exe);
    }

    // Arguments
    cmd.arg("-tcp");
    cmd.arg("-cef-disable-gpu-compositing");

    // Environment Variables
    cmd.env("WINEPREFIX", &master_prefix);
    cmd.env("STEAM_COMPAT_DATA_PATH", &master_prefix);
    cmd.env("STEAM_COMPAT_CLIENT_INSTALL_PATH", &base_dir);
    cmd.env("WINEDLLOVERRIDES", "steam.exe=n;steamclient=n;lsteamclient=n;steam_api=n;steam_api64=n");

    if let Ok(display) = std::env::var("DISPLAY") {
        cmd.env("DISPLAY", display);
    }
    if let Ok(wayland) = std::env::var("WAYLAND_DISPLAY") {
        cmd.env("WAYLAND_DISPLAY", wayland);
    }
    if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
        cmd.env("XDG_RUNTIME_DIR", xdg_runtime);
    }

    tracing::info!("Launching Master Steam: {:?}", cmd);

    let _child = cmd.spawn().context("Failed to spawn master steam process")?;

    // We don't wait here because it's a background process or interactive installer
    // But for the installer, maybe we should? The prompt doesn't specify.
    // "Run SteamSetup.exe (Interactive, NO /S flag)."
    // If it's interactive, we probably should NOT block the main thread.
    // However, this is called from an async task in ui.rs, so it's fine to block that task if needed.
    // But usually we want to let the user continue using the app.

    Ok(())
}

async fn download_steam_setup(path: &Path) -> Result<()> {
    tracing::info!("Downloading SteamSetup.exe...");
    let url = "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe";
    let response = reqwest::get(url).await?.bytes().await?;
    std::fs::write(path, response)?;
    Ok(())
}

fn find_steam_exe_in_prefix(prefix: &Path) -> Option<PathBuf> {
    let common_paths = [
        "drive_c/Program Files (x86)/Steam/steam.exe",
        "drive_c/Program Files/Steam/steam.exe",
    ];

    for rel_path in common_paths {
        let full_path = prefix.join(rel_path);
        if full_path.exists() {
            return Some(full_path);
        }
    }

    None
}
