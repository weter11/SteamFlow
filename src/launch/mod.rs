pub mod pipeline;
pub mod stages;
pub mod validators;
pub mod dll_provider_resolver;
pub mod fixups;

#[cfg(test)]
mod verification_tests;

use std::path::{Path, PathBuf};
use anyhow::{Result, Context, anyhow};
use crate::config::{config_dir, LauncherConfig};
use crate::utils::build_runner_command;

/// Repair result enum for tracking repair progress
#[derive(Debug, Clone)]
pub enum RepairStatus {
    Starting,
    StoppingProcesses,
    CreatingBackup,
    Installing,
    Completed,
    Failed(String),
}

pub async fn install_master_steam(config: &LauncherConfig) -> Result<()> {
    let base_dir = config_dir()?;
    let steam_cfg = crate::utils::get_master_steam_config();
    let runtimes_dir = base_dir.join("runtimes");
    std::fs::create_dir_all(&runtimes_dir)?;

    let setup_exe = runtimes_dir.join("SteamSetup.exe");
    if !setup_exe.exists() {
        download_steam_setup(&setup_exe).await?;
    }

    let runner_name = config.steam_runtime_runner.to_string_lossy();
    if runner_name.is_empty() {
        return Err(anyhow!("No Steam Runtime Runner selected in Global Settings"));
    }

    let library_root = PathBuf::from(&config.steam_library_path);
    let resolved_runner = crate::utils::resolve_runner(&runner_name, &library_root);
    let mut cmd = build_runner_command(&resolved_runner)?;

    tracing::info!("Unified Master Steam resolution:");
    tracing::info!("  - Root Dir: {}", steam_cfg.root_dir.display());
    tracing::info!("  - Wine Prefix: {}", steam_cfg.wine_prefix.display());
    tracing::info!("  - Layout Kind: {}", steam_cfg.layout_kind);
    if let Some(ref exe) = steam_cfg.steam_exe {
        tracing::info!("  - Steam Exe: {}", exe.display());
        cmd.arg(exe);
    } else {
        tracing::info!("  - Steam Exe: NOT FOUND (running installer)");
        cmd.arg(setup_exe);
    }

    // Arguments
    cmd.arg("-tcp");
    cmd.arg("-cef-disable-gpu-compositing");

    // Environment Variables
    cmd.env("WINEPREFIX", &steam_cfg.wine_prefix);
    cmd.env("STEAM_COMPAT_DATA_PATH", &steam_cfg.root_dir);
    cmd.env("WINEPATH", "C:\\Program Files (x86)\\Steam");

    let fake_env = crate::utils::setup_fake_steam_trap(&base_dir)?;
    cmd.env("STEAM_COMPAT_CLIENT_INSTALL_PATH", &fake_env);
    cmd.env("WINEDLLOVERRIDES", "vstdlib_s=n;tier0_s=n;steamclient=n;steamclient64=n;steam_api=n;steam_api64=n;lsteamclient=");

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

pub fn launch_wine_control_panel(config: &LauncherConfig) -> Result<()> {
    let library_root = PathBuf::from(&config.steam_library_path);
    let resolved_runner = crate::utils::resolve_runner(&config.proton_version, &library_root);
    let mut cmd = build_runner_command(&resolved_runner)?;
    let steam_cfg = crate::utils::get_master_steam_config();

    std::fs::create_dir_all(&steam_cfg.wine_prefix)
        .with_context(|| format!("failed creating Wine prefix {}", steam_cfg.wine_prefix.display()))?;

    cmd.arg("control.exe");
    cmd.env("WINEPREFIX", &steam_cfg.wine_prefix);
    cmd.env("STEAM_COMPAT_DATA_PATH", &steam_cfg.root_dir);

    if let Ok(display) = std::env::var("DISPLAY") {
        cmd.env("DISPLAY", display);
    }
    if let Ok(wayland) = std::env::var("WAYLAND_DISPLAY") {
        cmd.env("WAYLAND_DISPLAY", wayland);
    }
    if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
        cmd.env("XDG_RUNTIME_DIR", xdg_runtime);
    }

    tracing::info!(
        runner = %resolved_runner.display(),
        wineprefix = %steam_cfg.wine_prefix.display(),
        "Launching Wine Control Panel"
    );

    cmd.spawn().context("Failed to spawn Wine Control Panel")?;
    Ok(())
}

async fn download_steam_setup(path: &Path) -> Result<()> {
    tracing::info!("Downloading SteamSetup.exe...");
    let url = "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe";
    let response = reqwest::get(url).await?.bytes().await?;
    std::fs::write(path, response)?;
    Ok(())
}

/// Repair the master Steam prefix by backing up the existing one and reinstalling.
/// This function handles the complete repair flow including:
/// - Stopping any running Steam/wine processes in the master prefix
/// - Backing up the existing prefix (keeping at most 1 previous backup)
/// - Re-running the install_master_steam flow against the fresh prefix
///
/// Returns a stream of RepairStatus updates for UI progress reporting.
pub async fn repair_master_steam<F>(config: &LauncherConfig, mut on_status: F) -> Result<()>
where
    F: FnMut(RepairStatus),
{
    let steam_cfg = crate::utils::get_master_steam_config();

    // Check if prefix exists
    if !steam_cfg.root_dir.exists() {
        tracing::info!("No existing master Steam prefix found, performing fresh install");
        on_status(RepairStatus::Installing);
        install_master_steam(config).await?;
        on_status(RepairStatus::Completed);
        return Ok(());
    }

    // Step 1: Stop any running Steam/wine processes in the master prefix
    on_status(RepairStatus::StoppingProcesses);
    tracing::info!("Stopping any running Steam/wine processes in master prefix");
    crate::steam_client::SteamClient::kill_steam_in_prefix(&steam_cfg.wine_prefix);
    crate::utils::kill_all_wine_in_prefix(&steam_cfg.wine_prefix);

    // Give processes a moment to terminate
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Step 2: Create backup of existing prefix
    on_status(RepairStatus::CreatingBackup);
    tracing::info!("Backing up existing master Steam prefix");

    // Find and remove any existing backup
    if let Ok(entries) = std::fs::read_dir(&steam_cfg.root_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("master_steam_prefix.bak.") {
                tracing::info!("Removing old backup: {}", name_str);
                if let Err(e) = std::fs::remove_dir_all(entry.path()) {
                    tracing::warn!("Failed to remove old backup {}: {}", name_str, e);
                }
            }
        }
    }

    // Create new backup with timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup_path = steam_cfg.root_dir.with_file_name(format!("master_steam_prefix.bak.{}", timestamp));

    if let Err(e) = std::fs::rename(&steam_cfg.root_dir, &backup_path) {
        // If rename fails (e.g., different filesystem), try copy
        tracing::warn!("Rename failed, attempting copy: {}", e);
        copy_dir_all(&steam_cfg.root_dir, &backup_path)?;
        if let Err(e) = std::fs::remove_dir_all(&steam_cfg.root_dir) {
            tracing::warn!("Failed to remove original after copy: {}", e);
        }
    }

    tracing::info!("Backup created at: {}", backup_path.display());

    // Step 3: Re-run install_master_steam against the fresh prefix path
    on_status(RepairStatus::Installing);
    tracing::info!("Running fresh install of master Steam");

    install_master_steam(config).await?;

    on_status(RepairStatus::Completed);
    tracing::info!("Master Steam repair completed successfully");
    Ok(())
}

/// Copy a directory recursively
fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}
