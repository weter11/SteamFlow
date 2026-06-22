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

pub async fn install_master_steam(config: &LauncherConfig) -> Result<()> {
    let base_dir = config_dir()?;
    let steam_cfg = crate::utils::get_master_steam_config();
    let runtimes_dir = base_dir.join("runtimes");
    std::fs::create_dir_all(&runtimes_dir)?;
    std::fs::create_dir_all(&steam_cfg.wine_prefix)?;

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

pub async fn backup_master_steam() -> Result<()> {
    let steam_cfg = crate::utils::get_master_steam_config();
    if !steam_cfg.root_dir.exists() {
        return Err(anyhow!("Master Steam prefix does not exist"));
    }

    tracing::info!("Backing up Windows Steam Runtime in {}", steam_cfg.wine_prefix.display());

    // 1. Kill all processes
    crate::steam_client::SteamClient::kill_steam_in_prefix(&steam_cfg.wine_prefix);
    crate::utils::kill_all_wine_in_prefix(&steam_cfg.wine_prefix);

    // 2. Manage backups
    let parent = steam_cfg.root_dir.parent().context("master steam root has no parent")?;

    // Find existing backups
    if let Ok(entries) = std::fs::read_dir(parent) {
        let mut backups: Vec<_> = entries.flatten()
            .filter(|e| {
                e.file_name().to_string_lossy().starts_with("master_steam_prefix.bak.")
            })
            .map(|e| e.path())
            .collect();

        // Keep at most 1 previous backup: delete all but the newest before creating a new one
        backups.sort_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());

        // If we have more than one, delete the oldest
        if backups.len() >= 1 {
            for i in 0..backups.len() {
                tracing::info!("Removing old backup: {}", backups[i].display());
                let _ = std::fs::remove_dir_all(&backups[i]);
            }
        }
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let backup_path = parent.join(format!("master_steam_prefix.bak.{}", timestamp));

    tracing::info!("Moving {} to {}", steam_cfg.root_dir.display(), backup_path.display());
    std::fs::rename(&steam_cfg.root_dir, &backup_path)
        .context("failed to move prefix to backup")?;

    Ok(())
}

pub fn get_latest_backup() -> Option<PathBuf> {
    let steam_cfg = crate::utils::get_master_steam_config();
    let parent = steam_cfg.root_dir.parent()?;

    if let Ok(entries) = std::fs::read_dir(parent) {
        let mut backups: Vec<_> = entries.flatten()
            .filter(|e| {
                e.file_name().to_string_lossy().starts_with("master_steam_prefix.bak.")
            })
            .map(|e| e.path())
            .collect();

        backups.sort_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());
        return backups.pop();
    }
    None
}

pub async fn restore_master_steam() -> Result<()> {
    let latest_backup = get_latest_backup().ok_or_else(|| anyhow!("No backup found to restore"))?;
    let steam_cfg = crate::utils::get_master_steam_config();

    tracing::info!("Restoring Master Steam from {}", latest_backup.display());

    // 1. Kill all processes in current prefix if it exists
    if steam_cfg.wine_prefix.exists() {
        crate::steam_client::SteamClient::kill_steam_in_prefix(&steam_cfg.wine_prefix);
        crate::utils::kill_all_wine_in_prefix(&steam_cfg.wine_prefix);
    }

    // 2. Move current aside if it exists
    if steam_cfg.root_dir.exists() {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let old_path = steam_cfg.root_dir.with_extension(format!("old.{}", timestamp));
        std::fs::rename(&steam_cfg.root_dir, &old_path)?;
    }

    // 3. Restore
    std::fs::rename(latest_backup, &steam_cfg.root_dir)?;
    Ok(())
}

pub async fn repair_master_steam(config: &LauncherConfig) -> Result<()> {
    let steam_cfg = crate::utils::get_master_steam_config();
    tracing::info!("Starting repair for Windows Steam Runtime in {}", steam_cfg.wine_prefix.display());

    // 1. Backup existing (handles killing processes and rotation)
    if steam_cfg.root_dir.exists() {
        backup_master_steam().await?;
    }

    // 2. Re-install (handles directory creation)
    install_master_steam(config).await
}
