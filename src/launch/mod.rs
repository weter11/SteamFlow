pub mod pipeline;
pub mod stages;
pub mod validators;
pub mod dll_provider_resolver;
pub mod fixups;
pub mod diagnostics;

use std::path::{Path, PathBuf};
use anyhow::{Result, Context, anyhow};
use crate::config::{config_dir, LauncherConfig};

pub async fn install_master_steam(config: &LauncherConfig) -> Result<()> {
    let base_dir = config_dir()?;
    let steam_cfg = crate::utils::get_master_steam_config();
    let runtimes_dir = base_dir.join("runtimes");
    std::fs::create_dir_all(&runtimes_dir)?;
    std::fs::create_dir_all(&steam_cfg.wine_prefix)?;

    // Pin the Windows Steam client so Proton-based runners cannot trigger the in-client
    // self-updater. Under Proton wines (proton-tkg, proton-cachyos) Steam's updater
    // downloads a fresh client and the resulting build then fails to connect to the
    // Steam network ("cant connect to steam network"); wine-tkg does not trigger the
    // update and works. Disabling the self-update keeps the known-good client in place.
    if let Some(ref steam_exe) = steam_cfg.steam_exe {
        if let Some(steam_dir) = steam_exe.parent() {
            if config.skip_steam_self_update {
                crate::steam_client::SteamClient::ensure_no_self_update(steam_dir);
            } else {
                crate::steam_client::SteamClient::clear_no_self_update(steam_dir);
            }
        }
    }

    // Clear any Steam/wine processes still locked into the master prefix. A leftover
    // steam.exe / SteamService from a previous (failed) launch makes SteamSetup report
    // "steam already running, close it and continue installation" and blocks the install.
    // Killing first ensures a clean bootstrap.
    crate::utils::kill_all_wine_in_prefix(&steam_cfg.wine_prefix);

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
    let runner_kind = crate::utils::classify_runner(&resolved_runner);
    let is_proton = matches!(runner_kind, crate::utils::RunnerKind::Proton { .. });

    // Launch Windows Steam with the BARE Wine binary of the selected runner — exactly how
    // a plain wine-tkg launch works. We deliberately do NOT use the `proton run` script:
    // `proton run` is designed to execute inside Steam's runtime container (pressure-vessel)
    // and dies with SIGSYS ("Bad system call (core dumped)") when spawned directly. Bare
    // wine (whether wine-tkg's or Proton's bundled wine binary) launches Windows Steam fine.
    //
    // STEAM_COMPAT_CLIENT_INSTALL_PATH:
    //  * Plain Wine (wine-tkg): point at the fake_env trap (dummy steam/steam.sh). This is
    //    the original hack that keeps Wine-Steam from hijacking the Linux Steam client, and
    //    it disables steamclient/steam_api on the Steam process. This combination is known
    //    to work for wine-tkg.
    //  * Proton (bare wine): point at the REAL Windows Steam client dir. Under bare wine the
    //    STEAM_COMPAT_* vars are mostly inert, but pointing at the real client is correct and
    //    we must NOT disable steamclient/steam_api (Steam needs its own client DLLs).
    let mut cmd = crate::utils::build_bare_wine_command(&resolved_runner)?;

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
    // Harden the CEF/webhelper renderer under Wine/Proton. The background
    // self-update + GPU-accelerated CEF is the usual cause of Steam crashing
    // shortly after launch under Proton; disabling GPU compositing/sandbox
    // keeps the client stable. Steam forwards these to the real client
    // (visible in bootstrap_log.txt).
    cmd.arg("-cef-disable-gpu");
    cmd.arg("-no-cef-sandbox");

    // Environment Variables
    cmd.env("WINEPREFIX", &steam_cfg.wine_prefix);
    cmd.env("STEAM_COMPAT_DATA_PATH", &steam_cfg.root_dir);
    cmd.env("WINEPATH", "C:\\Program Files (x86)\\Steam");

    if is_proton {
        // Bare-wine Proton launch: point STEAM_COMPAT_CLIENT_INSTALL_PATH at the REAL
        // Windows Steam client dir (where the user installed/launched Windows Steam).
        // Under bare wine this var is mostly inert, but it is correct, and crucially we
        // must NOT disable steamclient/steam_api on the Steam process (Steam needs its
        // own client DLLs so games see a live Windows Steam for achievements/etc.).
        let client_path = steam_cfg
            .steam_exe
            .as_ref()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("C:\\Program Files (x86)\\Steam"));
        let client_win = crate::utils::to_windows_path(&client_path);
        cmd.env("STEAM_COMPAT_CLIENT_INSTALL_PATH", &client_win);
        tracing::info!(
            "Proton (bare wine) Steam launch: STEAM_COMPAT_CLIENT_INSTALL_PATH={} (real client)",
            client_win
        );
    } else {
        // Plain wine-tkg: the original working hack. The fake_env trap (dummy
        // steam/steam.sh) plus steamclient/steam_api=n keeps Wine-Steam from hijacking
        // the Linux Steam client. Known to work for wine-tkg.
        let fake_env = crate::utils::setup_fake_steam_trap(&base_dir)?;
        cmd.env("STEAM_COMPAT_CLIENT_INSTALL_PATH", &fake_env);
        cmd.env("WINEDLLOVERRIDES", "vstdlib_s=n;tier0_s=n;steamclient=n;steamclient64=n;steam_api=n;steam_api64=n;lsteamclient=");
    }

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

    let _ = diagnostics::apply_install_diagnostics(&mut cmd)?;

    let _child = cmd.spawn().context("Failed to spawn master steam process")?;

    Ok(())
}

pub fn launch_wine_control_panel(config: &LauncherConfig) -> Result<()> {
    let library_root = PathBuf::from(&config.steam_library_path);
    let resolved_runner = crate::utils::resolve_runner(&config.proton_version, &library_root);
    let mut cmd = crate::utils::build_bare_wine_command(&resolved_runner)?;
    let steam_cfg = crate::utils::get_master_steam_config();

    std::fs::create_dir_all(&steam_cfg.wine_prefix)
        .with_context(|| format!("failed creating Wine prefix {}", steam_cfg.wine_prefix.display()))?;

    // Kill any wineserver already locked into this prefix under a DIFFERENT runner.
    // Mixing runners in one WINEPREFIX produces the classic
    // "wine client error: version mismatch ... your wine binary was not upgraded correctly"
    // because the new wine64 and the old wineserver disagree on the pipe protocol.
    crate::utils::kill_all_wine_in_prefix(&steam_cfg.wine_prefix);

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
    tracing::info!("Repairing Windows Steam Runtime in {}", steam_cfg.wine_prefix.display());

    crate::steam_client::SteamClient::kill_steam_in_prefix(&steam_cfg.wine_prefix);
    crate::utils::kill_all_wine_in_prefix(&steam_cfg.wine_prefix);

    // A damaged client (e.g. a half-applied in-place self-update that fails to
    // rename steamwebhelper.exe under Proton) cannot be fixed by relaunching it --
    // launch just re-runs the failing updater. Instead we REINSTALL the client over
    // the prefix: move the broken Steam install directory aside, run SteamSetup, then
    // restore the user data that lives *inside* the client dir.
    //
    // PRESERVED (relocated out and back): steamapps/ (game library, NEVER deleted)
    // and userdata/ (saves, login, config). The Wine prefix (pfx/drive_c) is left
    // intact. The broken client dir is removed only after a successful reinstall +
    // restore, so no user data is lost.

    let client_dir: Option<PathBuf> = steam_cfg
        .steam_exe
        .as_ref()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .or_else(|| {
            let cand = steam_cfg
                .wine_prefix
                .join("drive_c/Program Files (x86)/Steam");
            if cand.exists() { Some(cand) } else { None }
        });

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let backup_stage = steam_cfg
        .wine_prefix
        .parent()
        .unwrap_or(&steam_cfg.wine_prefix)
        .join(format!("steam_client.broken.{}", ts));

    if let Some(ref client_dir) = client_dir {
        if client_dir.exists() {
            tracing::info!("Moving broken Steam client aside to {}", backup_stage.display());
            std::fs::create_dir_all(
                backup_stage.parent().unwrap_or(&backup_stage),
            )
            .context("failed creating repair stage dir")?;
            std::fs::rename(client_dir, &backup_stage)
                .with_context(|| format!("failed moving client dir to {}", backup_stage.display()))?;
        }

        let restore = || -> Result<()> {
            if backup_stage.exists() {
                std::fs::create_dir_all(client_dir).ok();
                for name in ["steamapps", "userdata"] {
                    let src = backup_stage.join(name);
                    let dst = client_dir.join(name);
                    if src.exists() && !dst.exists() {
                        tracing::info!("Restoring preserved {} into new client", name);
                        std::fs::rename(&src, &dst).with_context(|| {
                            format!("failed restoring {} from repair stage", name)
                        })?;
                    }
                }
            }
            Ok(())
        };

        let res = install_master_steam(config).await;
        if let Err(e) = restore() {
            tracing::warn!("repair: failed to restore preserved data: {e}");
        }
        res?;

        if config.skip_steam_self_update {
            crate::steam_client::SteamClient::ensure_no_self_update(client_dir);
        } else {
            crate::steam_client::SteamClient::clear_no_self_update(client_dir);
        }

        if backup_stage.exists() {
            let _ = std::fs::remove_dir_all(&backup_stage);
            tracing::info!("Removed broken client stage {}", backup_stage.display());
        }
    } else {
        install_master_steam(config).await?;
        if let Some(ref exe) = steam_cfg.steam_exe {
            if let Some(dir) = exe.parent() {
                if config.skip_steam_self_update {
                    crate::steam_client::SteamClient::ensure_no_self_update(dir);
                } else {
                    crate::steam_client::SteamClient::clear_no_self_update(dir);
                }
            }
        }
    }

    Ok(())
}
