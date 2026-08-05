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
    //
    // steamwebhelper is FORCED alive during client-management operations regardless of
    // the user's global or per-game "Disable CEF browser" settings: the web helper is
    // required for the client's login flow and UI, so Manage/Repair/Reinstall must
    // leave it running. First lift any chmod-000 lock left by per-game CEF enforcement
    // (in Shared prefix mode that enforcement targets this very prefix), then never
    // kill the web helper during the op. The user's configured state is re-applied
    // after the operation finishes (see the restore block at the end of this function).
    crate::steam_client::SteamClient::restore_steamwebhelper_in_prefix(&steam_cfg.wine_prefix);
    crate::steam_client::SteamClient::kill_steam_in_prefix(
        &steam_cfg.wine_prefix,
        false,
    );

    // Stage 2: register native Linux Steam library folders in the Windows
    // client's libraryfolders.vdf. Must happen while the client is STOPPED
    // (Steam rewrites this file on exit). This makes the client report games
    // installed by native Steam as installed, so strict Steamworks games
    // (RE2 etc.) pass the "is it installed?" API gate after login.
    match crate::steam_client::SteamClient::register_native_libraries_in_windows_client(
        &steam_cfg.wine_prefix,
    ) {
        Ok(n) if n > 0 => {
            tracing::info!(
                "Registered {n} native Steam library folder(s) in Windows client libraryfolders.vdf"
            );
        }
        Ok(_) => {
            tracing::debug!("Native library registration: nothing new to register");
        }
        Err(e) => {
            // Non-fatal: a broken VDF must not block install/repair.
            tracing::warn!("Native library registration skipped: {e}");
        }
    }

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
    let is_proton = matches!(
        crate::utils::classify_runner(&resolved_runner),
        crate::utils::RunnerKind::Proton { .. }
    );

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

    // NOTE: On the bare-wine path we deliberately do NOT replicate Proton's
    // LD_LIBRARY_PATH / WINEDLLPATH / GST_PLUGIN_SYSTEM_PATH_1_0 / PATH exports from
    // the `proton` script. Proton's bundled wine binary self-locates its own libs
    // (libwine, ntdll) via its baked-in RPATH, and the system X11/GL libraries live
    // in /lib/x86_64-linux-gnu. Overriding LD_LIBRARY_PATH with ONLY Proton's lib
    // dirs (which contain no libX11/libGL) makes winex11 fail to load ->
    // 'err:winediag:nodrv_CreateWindow / explorer process failed to start'. This is
    // exactly why the PlainWine (wine-tkg) path works: it sets no such override and
    // inherits the system X/GL libs. Launch Proton's bare wine the same way.

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

    // SteamSetup.exe refuses to install into a non-empty destination ("destination
    // folder should be empty"). A previous failed/partial install can leave a Steam
    // dir with package/ + steamapps/ but no valid steam.exe, which trips that error.
    //
    // When we are launching the INSTALLER (no steam.exe), delete the broken client
    // dir but first move the user's game library (steamapps/) and saves (userdata/)
    // aside so they survive the reinstall. The staged data is restored into the fresh
    // client AFTER the installer finishes (see below), so the destination stays empty
    // for the installer itself.
    if steam_cfg.steam_exe.is_none() {
        prepare_clean_install_target(&steam_cfg.wine_prefix)?;
    }

    // Spawn SteamSetup and BLOCK on it. The user's library/saves were staged into a
    // sibling folder (steam_client.staged.<ts>) by prepare_clean_install_target; they
    // must stay OUT of the install target for the ENTIRE install, otherwise SteamSetup
    // aborts with "destination folder should be empty". We only restore them after the
    // installer process exits. On the launcher path (steam.exe present) there is nothing
    // to stage, so we spawn without blocking.
    let install_path = steam_cfg.wine_prefix.parent().map(|p| p.to_path_buf());
    if steam_cfg.steam_exe.is_none() {
        let mut child = cmd.spawn().context("Failed to spawn master steam process")?;
        if let Some(parent) = install_path {
            let staged = find_staged_install_data(&parent);
            // Wait for SteamSetup; copy (not move) staged data back as it finishes so a
            // crash during restore does not lose the original staged copy.
            let res = child.wait();
            if let Some(stage) = staged {
                restore_staged_install_data(&stage, &steam_cfg.wine_prefix);
                let _ = std::fs::remove_dir_all(&stage);
            }
            res.context("SteamSetup exited abnormally")?;
        }
    } else {
        let _child = cmd.spawn().context("Failed to spawn master steam process")?;
    }

    // Restore steamwebhelper to the state the user's settings actually specify.
    // During the operation above it was force-enabled (the op's client relaunch
    // spawns it, and we never killed it). If the user's GLOBAL config disables
    // CEF, re-apply the enforcement after a short boot window so we do not leave
    // the web helper force-enabled once the operation is done. The per-game
    // setting is re-applied automatically on that game's next launch (its own
    // enforcement task), so only the global default needs handling here.
    let restore_slc = config.steam_launch_config.clone();
    if restore_slc.no_browser
        || restore_slc.no_friends_ui
        || restore_slc.no_overlay
        || restore_slc.no_chat_ui
    {
        let restore_prefix = steam_cfg.wine_prefix.clone();
        tokio::spawn(async move {
            // Match the per-game path's 30s boot window: the CEF subsystem spawns
            // children while it boots, so acting immediately would race Steam's
            // crash-recovery and cause respawn loops.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            crate::steam_client::SteamClient::enforce_disabled_steam_features_in_prefix(
                &restore_prefix,
                restore_slc.no_browser,
                restore_slc.no_friends_ui,
                restore_slc.no_overlay,
                restore_slc.no_chat_ui,
            );
        });
    }

    Ok(())
}

/// Launch Wine Configuration (winecfg.exe) using the configured runner and
/// master Wine prefix. winecfg lets you configure Wine's Wine DLL overrides,
/// Windows version, audio drivers, display settings, and more — useful
/// for tuning the Wine environment for specific Windows applications.
pub fn launch_winecfg(config: &LauncherConfig) -> Result<()> {
    let library_root = PathBuf::from(&config.steam_library_path);
    let resolved_runner = crate::utils::resolve_runner(&config.proton_version, &library_root);
    let mut cmd = crate::utils::build_bare_wine_command(&resolved_runner)?;
    let steam_cfg = crate::utils::get_master_steam_config();

    std::fs::create_dir_all(&steam_cfg.wine_prefix)
        .with_context(|| format!("failed creating Wine prefix {}", steam_cfg.wine_prefix.display()))?;

    crate::utils::kill_all_wine_in_prefix(&steam_cfg.wine_prefix, !config.steam_launch_config.no_browser);

    cmd.arg("winecfg.exe");
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
        "Launching Wine Configuration"
    );

    cmd.spawn().context("Failed to spawn Wine Configuration")?;
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
    crate::utils::kill_all_wine_in_prefix(&steam_cfg.wine_prefix, !config.steam_launch_config.no_browser);

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

/// Launch Wine File Manager (winefile.exe) using the configured runner and
/// master Wine prefix. winefile provides a graphical GUI for browsing the
/// Wine prefix filesystem — useful for manually finding and editing Wine
/// registry files, ini files, and other configuration outside the Wine
/// registry editor.
pub fn launch_wine_file_manager(config: &LauncherConfig) -> Result<()> {
    let library_root = PathBuf::from(&config.steam_library_path);
    let resolved_runner = crate::utils::resolve_runner(&config.proton_version, &library_root);
    let mut cmd = crate::utils::build_bare_wine_command(&resolved_runner)?;
    let steam_cfg = crate::utils::get_master_steam_config();

    std::fs::create_dir_all(&steam_cfg.wine_prefix)
        .with_context(|| format!("failed creating Wine prefix {}", steam_cfg.wine_prefix.display()))?;

    crate::utils::kill_all_wine_in_prefix(&steam_cfg.wine_prefix, !config.steam_launch_config.no_browser);

    cmd.arg("winefile.exe");
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
        "Launching Wine File Manager"
    );

    cmd.spawn().context("Failed to spawn Wine File Manager")?;
    Ok(())
}

/// Launch Wine Registry Editor (regedit.exe) using the configured runner and
/// master Wine prefix. regedit lets you view and edit the Wine registry
/// (HKLM, HKCU, etc.) — useful for manually fixing registry entries that
/// the Wine uninstaller or SteamSetup didn't clean up.
pub fn launch_wine_regedit(config: &LauncherConfig) -> Result<()> {
    let library_root = PathBuf::from(&config.steam_library_path);
    let resolved_runner = crate::utils::resolve_runner(&config.proton_version, &library_root);
    let mut cmd = crate::utils::build_bare_wine_command(&resolved_runner)?;
    let steam_cfg = crate::utils::get_master_steam_config();

    std::fs::create_dir_all(&steam_cfg.wine_prefix)
        .with_context(|| format!("failed creating Wine prefix {}", steam_cfg.wine_prefix.display()))?;

    crate::utils::kill_all_wine_in_prefix(&steam_cfg.wine_prefix, !config.steam_launch_config.no_browser);

    cmd.arg("regedit.exe");
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
        "Launching Wine Registry Editor"
    );

    cmd.spawn().context("Failed to spawn Wine Registry Editor")?;

/// Launch Wine Task Manager (taskmgr.exe) using the configured runner and
/// master Wine prefix. taskmgr lets you view and kill processes running
/// inside the Wine prefix — useful for stopping stuck wine processes
/// before repair/reinstall.
    Ok(())
}

/// Launch Wine Task Manager (taskmgr.exe) using the configured runner and
/// master Wine prefix. taskmgr lets you view and kill processes
/// running inside the Wine prefix — useful for stopping stuck wine
/// processes before repair/reinstall.
pub fn launch_wine_taskmgr(config: &LauncherConfig) -> Result<()> {
    let library_root = PathBuf::from(&config.steam_library_path);
    let resolved_runner = crate::utils::resolve_runner(&config.proton_version, &library_root);
    let mut cmd = crate::utils::build_bare_wine_command(&resolved_runner)?;
    let steam_cfg = crate::utils::get_master_steam_config();

    std::fs::create_dir_all(&steam_cfg.wine_prefix)
        .with_context(|| format!("failed creating Wine prefix {}", steam_cfg.wine_prefix.display()))?;

    crate::utils::kill_all_wine_in_prefix(&steam_cfg.wine_prefix, !config.steam_launch_config.no_browser);

    cmd.arg("taskmgr.exe");
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
        "Launching Wine Task Manager"
    );

    cmd.spawn().context("Failed to spawn Wine Task Manager")?;
    Ok(())
}

/// Prepares an EMPTY Steam install target so SteamSetup.exe does not error with
/// "destination folder should be empty".
///
/// The broken client dir is deleted, but the user's game library (steamapps/) and
/// saves (userdata/) are moved aside first (into a sibling `steam_client.broken.<ts>`
/// stage) so they survive the reinstall. The destination is left empty for the
/// installer; `restore_staged_install_data` moves them back afterwards.
/// On a fresh install (no existing client dir) this is a no-op.
fn prepare_clean_install_target(wine_prefix: &Path) -> Result<()> {
    let client_dir = wine_prefix.join("drive_c/Program Files (x86)/Steam");
    if !client_dir.exists() {
        return Ok(());
    }

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let stage = wine_prefix
        .parent()
        .unwrap_or(wine_prefix)
        .join(format!("steam_client.staged.{}", ts));

    tracing::info!(
        "Clearing Steam install target {} for fresh installer (staging library/saves)",
        client_dir.display()
    );
    std::fs::create_dir_all(stage.parent().unwrap_or(&stage))
        .context("failed creating install stage dir")?;
    std::fs::rename(&client_dir, &stage)
        .with_context(|| format!("failed moving client dir to {}", stage.display()))?;

    Ok(())
}

/// Locates the staged install data directory created by
/// `prepare_clean_install_target` (named `steam_client.staged.<ts>`), if any.
fn find_staged_install_data(parent: &Path) -> Option<PathBuf> {
    let mut found: Option<PathBuf> = None;
    if let Ok(entries) = std::fs::read_dir(parent) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("steam_client.staged.") {
                found = Some(entry.path());
                break;
            }
        }
    }
    found
}

/// Restores the game library (steamapps/) and saves (userdata/) from a specific
/// staged dir into the freshly installed client dir. Called AFTER SteamSetup exits,
/// so the installer always saw an empty target. Any failure is logged but non-fatal
/// (the install itself is what matters).
///
/// We COPY entries (not move/rename the whole folder) and MERGE, because SteamSetup
/// may have already created an empty `steamapps/`. A naive move that skips an
/// existing destination would silently drop the user's installed games, so we descend
/// and copy individual entries, never overwriting what the installer created.
fn restore_staged_install_data(stage: &Path, wine_prefix: &Path) {
    let client_dir = wine_prefix.join("drive_c/Program Files (x86)/Steam");
    tracing::info!("Restoring staged library/saves from {}", stage.display());
    for sub in ["steamapps", "userdata"] {
        let src = stage.join(sub);
        let dst = client_dir.join(sub);
        if !src.exists() {
            continue;
        }
        let _ = std::fs::create_dir_all(&dst);
        if let Ok(children) = std::fs::read_dir(&src) {
            for child in children.flatten() {
                let cname = child.file_name();
                let from = child.path();
                let to = dst.join(&cname);
                if !to.exists() {
                    if let Err(e) = std::fs::rename(&from, &to) {
                        tracing::warn!("failed restoring {}/{}: {}", sub, cname.to_string_lossy(), e);
                    }
                }
            }
        }
    }
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
    crate::steam_client::SteamClient::kill_steam_in_prefix(&steam_cfg.wine_prefix, false);
    crate::utils::kill_all_wine_in_prefix(&steam_cfg.wine_prefix, true);

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
        crate::steam_client::SteamClient::kill_steam_in_prefix(&steam_cfg.wine_prefix, false);
        crate::utils::kill_all_wine_in_prefix(&steam_cfg.wine_prefix, true);
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

    // Force steamwebhelper alive for the duration of the repair regardless of the
    // user's global/per-game CEF settings (see install_master_steam for the full
    // rationale): lift any chmod-000 lock left by per-game enforcement and never
    // kill the web helper during the operation.
    crate::steam_client::SteamClient::restore_steamwebhelper_in_prefix(&steam_cfg.wine_prefix);
    crate::steam_client::SteamClient::kill_steam_in_prefix(&steam_cfg.wine_prefix, false);
    crate::utils::kill_all_wine_in_prefix(&steam_cfg.wine_prefix, true);

    // A damaged client (e.g. a half-applied in-place self-update that fails to
    // rename steamwebhelper.exe under Proton) cannot be fixed by relaunching it --
    // launch just re-runs the failing updater. We use Wine\'s built-in uninstaller
    // to cleanly remove Steam from the prefix (registry + uninstall.exe), then run
    // SteamSetup fresh. The uninstaller removes only Steam components; user data
    // (steamapps/, userdata/) is left intact in the prefix.
    //
    // PRESERVED: steamapps/ (game library, NEVER deleted) and userdata/ (saves,
    // login, config). The Wine prefix (pfx/drive_c) stays intact throughout.

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

    // Try Wine\'s uninstaller first (clean registry + file removal) if Steam is registered
    if let Some(ref client_dir) = client_dir {
        if client_dir.exists() {
            let system_reg = steam_cfg.wine_prefix.join("pfx/system.reg");
            let has_uninstall_entry = system_reg.exists()
                && std::fs::read_to_string(&system_reg)
                    .map(|c| c.contains("Uninstall\\Steam") && c.contains("UninstallString"))
                    .unwrap_or(false);

            if has_uninstall_entry {
                tracing::info!("Steam found in Wine registry — attempting clean uninstall via wine uninstaller");
                let uninstall_output = std::process::Command::new("wine")
                    .arg("uninstaller")
                    .arg("--remove")
                    .arg("Steam")
                    .env("WINEPREFIX", &steam_cfg.wine_prefix)
                    .env("WINEDLLOVERRIDES", "mshtml=")
                    .output();

                match uninstall_output {
                    Ok(output) if output.status.success() => {
                        tracing::info!("Wine uninstaller removed Steam successfully");
                        // Wait for wineserver to settle after registry removal
                        let _ = std::process::Command::new("wineserver")
                            .arg("-w")
                            .env("WINEPREFIX", &steam_cfg.wine_prefix)
                            .status();
                    }
                    Ok(output) => {
                        tracing::warn!(
                            "Wine uninstaller exited with status {:?}: stderr={}",
                            output.status.code(),
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Failed to run wine uninstaller: {}", e);
                    }
                }
            } else {
                tracing::info!("Steam not found in Wine registry — uninstaller skip, proceeding to fresh install");
            }
        }
    }

    let res = install_master_steam(config).await;
    if let Err(e) = res {
        tracing::warn!("repair: install_master_steam failed: {e}");
        return Err(e);
    }

    if config.skip_steam_self_update {
        if let Some(ref dir) = client_dir {
            crate::steam_client::SteamClient::ensure_no_self_update(dir);
        }
    } else {
        if let Some(ref dir) = client_dir {
            crate::steam_client::SteamClient::clear_no_self_update(dir);
        }
    }

    Ok(())
}

