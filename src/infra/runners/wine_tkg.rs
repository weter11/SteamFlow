use std::collections::HashMap;
use anyhow::anyhow;
use std::path::{Path, PathBuf};
use std::process::Command;
use crate::infra::runners::{Runner, LaunchContext, CommandSpec};
use crate::steam_client::SteamClient;
use crate::launch::pipeline::{LaunchError, LaunchErrorKind};

pub struct WineTkgRunner;

/// Resolve the runner (Compatibility Layer) the game should launch under.
///
/// When the Windows Steam Runtime is Active, the background Steam process owns the
/// shared WINEPREFIX and runs under `launcher_config.steam_runtime_runner`. If the game
/// were launched under a DIFFERENT runner, two wineservers (different pipe protocols)
/// would collide in the same prefix and the game would crash with
/// "wine client error: version mismatch ... your wine binary was not upgraded correctly".
/// To avoid that, when the runtime is active we force the game's compatibility layer to
/// the runtime runner so both share a single wineserver — which is exactly why the
/// "both wine-tkg" combination worked but "runtime=wine-tkg, game=proton" crashed.
fn effective_game_proton(ctx: &LaunchContext) -> String {
    // The runtime runner launches background Steam only. The game runner is
    // selected by the user's per-game or global compatibility-layer settings.
    crate::utils::resolve_effective_proton_name(
        ctx.app.app_id,
        &ctx.launcher_config,
        ctx.proton_path.as_deref(),
    ).to_string()
}

/// Compare two runner paths for equality, tolerating symlinked installs and
/// paths that do not exist yet (resolve_runner falls back to the raw name when
/// a runner is not installed).
fn runner_paths_equal(a: &Path, b: &Path) -> bool {
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    canon(a) == canon(b)
}

/// Pure decision core of the runner-mismatch guard (testable without a
/// `LaunchContext`): when the configured prefix mode is `Shared` but the Steam
/// Runtime runner differs from the game runner, return `PerGame`.
///
/// A Shared prefix cannot host two different Wine/Proton runners at the same
/// time: each wine build speaks its own `wineserver` protocol, so mixing them
/// in one WINEPREFIX fails with
/// "wine client error: version mismatch ... your wine binary was not upgraded
/// correctly". Falling back to PerGame gives each runner its own prefix.
pub(crate) fn effective_prefix_mode_impl(
    configured: crate::models::SteamPrefixMode,
    steam_runtime_runner: &Path,
    game_runner_name: &str,
    library_root: &Path,
) -> crate::models::SteamPrefixMode {
    if configured != crate::models::SteamPrefixMode::Shared {
        return configured;
    }
    let steam_runner = steam_runtime_runner.to_string_lossy();
    if steam_runner.is_empty() {
        // No Steam Runtime runner configured — nothing can collide in the prefix.
        return configured;
    }
    let steam_runner_path = crate::utils::resolve_runner(&steam_runner, library_root);
    let game_runner_path = crate::utils::resolve_runner(game_runner_name, library_root);
    if runner_paths_equal(&steam_runner_path, &game_runner_path) {
        return configured;
    }
    tracing::warn!(
        "[SteamFlow] Runner mismatch detected (Steam Runtime: \"{}\", Game: \"{}\"). Automatically switching to PerGame prefix mode to prevent wineserver protocol collision.",
        steam_runner_path.display(),
        game_runner_path.display()
    );
    crate::models::SteamPrefixMode::PerGame
}

/// Resolve the EFFECTIVE Steam prefix mode for a launch: the user-configured
/// mode (per-game user config → global launcher default), auto-fallbacked to
/// `PerGame` when a `Shared` prefix would host two different Wine/Proton
/// runners (see `effective_prefix_mode_impl`).
pub(crate) fn effective_prefix_mode(ctx: &LaunchContext) -> crate::models::SteamPrefixMode {
    let configured = ctx.user_config.as_ref()
        .map(|c| c.steam_prefix_mode.clone())
        .unwrap_or(ctx.launcher_config.steam_prefix_mode.clone());
    let game_runner = effective_game_proton(ctx);
    effective_prefix_mode_impl(
        configured,
        &ctx.launcher_config.steam_runtime_runner,
        &game_runner,
        Path::new(&ctx.launcher_config.steam_library_path),
    )
}

#[async_trait::async_trait]
impl Runner for WineTkgRunner {
    fn name(&self) -> &str { "Wine-TKG" }

    async fn prepare_prefix(&self, ctx: &LaunchContext) -> std::result::Result<(), LaunchError> {
        let library_root = PathBuf::from(&ctx.launcher_config.steam_library_path);

        let proton = effective_game_proton(ctx);
        let active_runner = crate::utils::resolve_runner(&proton, &library_root);

        let (use_steam_runtime, runtime_source) = match ctx.user_config.as_ref().map(|c| &c.steam_runtime_policy) {
            Some(crate::models::SteamRuntimePolicy::Enabled) => (true, "override"),
            Some(crate::models::SteamRuntimePolicy::Disabled) => (false, "override"),
            Some(crate::models::SteamRuntimePolicy::Auto) | None => {
                // Fallback to deprecated boolean if policy is Auto/None for backward compat
                let manual_toggle = ctx.user_config.as_ref().map(|c| c.use_steam_runtime).unwrap_or(false);
                if manual_toggle {
                    (true, "override_legacy")
                } else {
                    (false, "default")
                }
            }
        };
        // Effective prefix mode: the configured mode, auto-fallbacked from
        // Shared to PerGame when the Steam Runtime runner and the game runner
        // differ (two wineservers with different protocols cannot share one
        // WINEPREFIX). See `effective_prefix_mode_impl`.
        let steam_prefix_mode = effective_prefix_mode(ctx);

        let user_config_store: crate::models::UserConfigStore = ctx.user_config.as_ref().map(|c| {
            let mut store = HashMap::new();
            store.insert(ctx.app.app_id, c.clone());
            store
        }).unwrap_or_default().into();

        let effective_game_prefix = crate::utils::steam_wineprefix_for_game(
            &ctx.launcher_config,
            ctx.app.app_id,
            &user_config_store,
            Some(steam_prefix_mode.clone()),
        );
        std::fs::create_dir_all(&effective_game_prefix)
            .map_err(|e| LaunchError::new(LaunchErrorKind::Permission, format!("failed creating {}", effective_game_prefix.display())).with_source(anyhow!(e)))?;

        // === Native prefix seeding (Phase 2 tail, valve-stack directive) ===
        // Port of Proton's `default_pfx.py`/`CompatData.setup_prefix`: when the
        // game's prefix is fresh (no `system.reg` yet) and the runner is a
        // Proton-kind tree shipping `files/share/default_pfx`, seed the prefix
        // directly from it (copy tree + dosdevices symlinks + version marker)
        // WITHOUT invoking external Python init scripts. Non-fatal: a seeding
        // failure logs and the launch proceeds (wine would create an empty
        // prefix anyway); the version marker comes from the runner's `version`
        // file (e.g. `proton-11.0-1b`) or the runner dir name.
        if !effective_game_prefix.join("system.reg").exists() {
            let runner_root = crate::utils::derive_runner_root(&active_runner);
            let default_pfx_candidates = [
                "files/share/default_pfx",
                "share/default_pfx",
                "dist/share/default_pfx",
            ];
            let default_pfx = default_pfx_candidates
                .iter()
                .map(|p| runner_root.join(p))
                .find(|p| p.is_dir());
            if let Some(default_pfx_dir) = default_pfx {
                let proton_version = std::fs::read_to_string(runner_root.join("version"))
                    .ok()
                    .map(|s| crate::utils::parse_short_version(&s))
                    .filter(|v| v != "unknown" && !v.is_empty())
                    .unwrap_or_else(|| {
                        active_runner
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| "unknown".to_string())
                    });
                match crate::runner::proton_abi::seed_prefix(
                    &default_pfx_dir,
                    &effective_game_prefix,
                    &proton_version,
                ) {
                    Ok(created) => tracing::info!(
                        "Native prefix seeding: seeded {} from {} ({} paths, version {})",
                        effective_game_prefix.display(),
                        default_pfx_dir.display(),
                        created.len(),
                        proton_version
                    ),
                    Err(e) => tracing::warn!(
                        "Native prefix seeding failed for {} (continuing with wine's own init): {e}",
                        effective_game_prefix.display()
                    ),
                }
            } else {
                tracing::debug!(
                    "No default_pfx in runner {} — skipping native prefix seeding",
                    runner_root.display()
                );
            }
        }

        tracing::info!("Effective game prefix: {}", effective_game_prefix.display());
        tracing::info!("Shared steam compatibility data enabled: {}", ctx.launcher_config.use_shared_compat_data);
        tracing::info!("Steam Runtime Prefix Mode: {:?}", steam_prefix_mode);

        if use_steam_runtime {
            let steam_cfg = crate::utils::get_master_steam_config();
            tracing::info!("Unified Master Steam resolution (Game Launch):");
            tracing::info!("  - Root Dir: {}", steam_cfg.root_dir.display());
            tracing::info!("  - Wine Prefix: {}", steam_cfg.wine_prefix.display());
            tracing::info!("  - Layout Kind: {}", steam_cfg.layout_kind);

            let master_steam_dir = match &steam_cfg.steam_exe {
                Some(exe) => exe.parent().unwrap().to_path_buf(),
                None => {
                    return Err(LaunchError::new(
                        LaunchErrorKind::Environment,
                        format!(
                            "use_steam_runtime is enabled but steam.exe was not found in {}.\n\
                             Go to Settings → 'Install / Manage Windows Steam Runtime' first.",
                            steam_cfg.wine_prefix.display()
                        )
                    ).with_context("master_prefix", steam_cfg.wine_prefix.to_string_lossy()));
                }
            };

            tracing::info!("  - Steam Exe: {}", steam_cfg.steam_exe.as_ref().unwrap().display());

            let (prefix_steam_dir, steam_wineprefix) = match steam_prefix_mode {
                        crate::models::SteamPrefixMode::Shared => {
                            (master_steam_dir.clone(), steam_cfg.wine_prefix.clone())
                        }
                        crate::models::SteamPrefixMode::PerGame => {
                            let target_steam_dir = effective_game_prefix
                                .join("drive_c/Program Files (x86)/Steam");

                            tracing::info!(
                                "Deploying required Steam runtime files to {}",
                                target_steam_dir.display()
                            );
                            let _ = std::fs::create_dir_all(&target_steam_dir);

                            let required_files = [
                                "steam.exe",
                                "steamclient.dll",
                                "steamclient64.dll",
                                "tier0_s.dll",
                                "tier0_s64.dll",
                                "vstdlib_s.dll",
                                "vstdlib_s64.dll",
                            ];

                            for file in required_files {
                                let src = master_steam_dir.join(file);
                                let dst = target_steam_dir.join(file);
                                if src.exists() && !dst.exists() {
                                    #[cfg(unix)]
                                    {
                                        if let Err(e) = std::os::unix::fs::symlink(&src, &dst) {
                                            tracing::warn!("Symlink failed for {}, falling back to copy: {}", file, e);
                                            let _ = std::fs::copy(&src, &dst);
                                        }
                                    }
                                    #[cfg(not(unix))]
                                    {
                                        let _ = std::fs::copy(&src, &dst);
                                    }
                                }
                            }

                            // Also symlink required subdirectories
                            let required_dirs = ["bin", "public"];
                            for dir in required_dirs {
                                let src = master_steam_dir.join(dir);
                                let dst = target_steam_dir.join(dir);
                                if src.exists() && !dst.exists() {
                                    #[cfg(unix)]
                                    {
                                        if let Err(e) = std::os::unix::fs::symlink(&src, &dst) {
                                            tracing::warn!("Symlink failed for {}, falling back to copy: {}", dir, e);
                                            let _ = crate::utils::copy_dir_all(&src, &dst);
                                        }
                                    }
                                    #[cfg(not(unix))]
                                    {
                                        let _ = crate::utils::copy_dir_all(&src, &dst);
                                    }
                                }
                            }

                    (target_steam_dir, effective_game_prefix.clone())
                }
            };

            tracing::debug!("Runtime Steam dir : {}", prefix_steam_dir.display());
                    tracing::debug!("Runtime WINEPREFIX : {}", steam_wineprefix.display());

                    if !matches!(crate::utils::classify_runner(&active_runner), crate::utils::RunnerKind::Unknown) {
                        if let Some(active_wine) =
                            crate::utils::detect_wineserver_for_runner(&steam_wineprefix, &active_runner)
                        {
                            let active_root = crate::utils::derive_runner_root(&active_wine);
                            let runner_root = crate::utils::derive_runner_root(&active_runner);

                            let active_canonical = active_root.canonicalize().unwrap_or(active_root);
                            let runner_canonical = runner_root.canonicalize().unwrap_or(runner_root);

                            if active_canonical != runner_canonical {
                                tracing::warn!(
                                    "Stale wineserver (different runner {:?}) detected in prefix {}. Terminating it before launch.",
                                    active_canonical, steam_wineprefix.display()
                                );
                                crate::utils::kill_wineserver_in_prefix(&steam_wineprefix);
                                std::thread::sleep(std::time::Duration::from_millis(500));
                            }
                        }
                    }

                    SteamClient::write_headless_steam_cfg(&prefix_steam_dir);

                    let slc = ctx.user_config.as_ref()
                        .map(|c| c.steam_launch_config.clone())
                        .unwrap_or_default();

                    let mut steam_args = vec![
                        "-silent".to_string(),
                        "-tcp".to_string(),
                        "-noverifyfiles".to_string(),
                        "-noreactlogin".to_string(),
                        "-cef-disable-gpu".to_string(),
                        "-cef-disable-sandbox".to_string(),
                    ];

                    if slc.no_friends_ui {
                        steam_args.push("-nofriendsui".to_string());
                    }
                    if slc.no_chat_ui {
                        steam_args.push("-nochatui".to_string());
                    }
                    if slc.no_overlay {
                        steam_args.push("-disable-overlay".to_string());
                    }
                    // Note: -noopenvr and -bigpicture are removed to avoid
                    // interfering with Steam's normal service operation and
                    // user preferences (VR and Big Picture mode are user-facing).

                    let steam_running = SteamClient::is_steam_running_in_prefix(&steam_wineprefix);

                    unsafe {
                        if !ctx.verification_ptr.is_null() {
                            let v = &mut *ctx.verification_ptr;
                            v.steam_running_before_launch = steam_running;
                            v.effective_game_wineprefix = Some(effective_game_prefix.to_string_lossy().to_string());
                            v.effective_steam_wineprefix = Some(steam_wineprefix.to_string_lossy().to_string());
                            v.per_game_prefix_requested = steam_prefix_mode == crate::models::SteamPrefixMode::PerGame;
                            v.per_game_prefix_honored = effective_game_prefix == steam_wineprefix;
                            v.steam_runtime_policy = format!("{:?}", ctx.user_config.as_ref().map(|c| &c.steam_runtime_policy).unwrap_or(&crate::models::SteamRuntimePolicy::Auto));
                            v.steam_runtime_source = runtime_source.to_string();
                            v.windows_steam_discovery_enabled = ctx.launcher_config.windows_steam_discovery_enabled;
                        }
                    }

                    if steam_running {
                        // Steam is already running in the prefix (from a prior game
                        // launch or manual launch). Don't kill and respawn — that
                        // disrupts the user's existing session. The CEF enforcement
                        // pass (after readiness gate) will handle newly spawned
                        // helpers to ensure user-disabled features are enforced.
                    } else {
                        // PerGame mode: the per-game prefix is seeded by the
                        // game's own runner (seed_prefix copies its
                        // default_pfx), so the background Steam client MUST run
                        // under that same wine family. A mismatched runner
                        // cannot initialize inside the seeded prefix — e.g. a
                        // classic-wow64 wine-tkg client in a pure-PE-seeded
                        // prefix fails with
                        //   "init_wow64: could not load wow64.dll" → exit 53
                        // (pure-PE wine has no wow64.dll; its 32-bit half is
                        // PE-only). Shared mode keeps the configured runtime
                        // runner, which owns the master prefix.
                        let steam_runner = if steam_prefix_mode == crate::models::SteamPrefixMode::PerGame {
                            tracing::info!(
                                "PerGame mode: using the game's runner ({}) for background Steam (prefix is seeded by it)",
                                active_runner.display()
                            );
                            active_runner.clone()
                        } else if !ctx.launcher_config.steam_runtime_runner.as_os_str().is_empty() {
                            ctx.launcher_config.steam_runtime_runner.clone()
                        } else {
                            let discovered = crate::utils::resolve_runner("wine-tkg", &library_root);
                            if !discovered.exists() {
                                return Err(LaunchError::new(
                                    LaunchErrorKind::Runner,
                                    "Steam Runtime Runner is not set and no wine-tkg/plain Wine runner was found. Set “Steam Runtime Runner” in Settings."
                                ));
                            }
                            discovered
                        };

                        tracing::info!("Using runner for background Steam: {}", steam_runner.display());

                        let mut steam_cmd = crate::utils::build_bare_wine_command(&steam_runner)
                                .map_err(|e| LaunchError::new(LaunchErrorKind::Runner, format!("Invalid Steam Runtime runner path: {}", steam_runner.display())).with_source(e))?;
                        steam_cmd.current_dir(&prefix_steam_dir);
                        steam_cmd
                            .arg("C:\\Program Files (x86)\\Steam\\steam.exe")
                            .args(&steam_args);
                        steam_cmd
                            .env("WINEPREFIX", &steam_wineprefix)
                            .env(
                                "WINEDLLOVERRIDES",
                                "vstdlib_s=n,b;tier0_s=n,b;steamclient=n,b;steamclient64=n,b;\
                                 steam_api=n,b;steam_api64=n,b;lsteamclient=;\
                                 GameOverlayRenderer=n;GameOverlayRenderer64=n",
                            )
                            .env("WINEPATH", "C:\\Program Files (x86)\\Steam")
                            .env("STEAMCMD", "1") // tells Steam it's running as a cmd tool
                            .stdout(std::process::Stdio::null()) // silence CEF log spam
                            .stderr(std::process::Stdio::null());

                        println!("Program: {:?}", steam_cmd.get_program());
                        println!("Args: {:?}", steam_cmd.get_args().collect::<Vec<_>>());
                        println!("--------------------------");

                        // Record Steam runtime diagnostics
                        unsafe {
                            if !ctx.verification_ptr.is_null() {
                                let v = &mut *ctx.verification_ptr;
                                v.steam_runtime_exe = Some(steam_cmd.get_program().to_string_lossy().to_string());
                                v.steam_runtime_args = steam_cmd.get_args().map(|a| a.to_string_lossy().to_string()).collect();
                                v.steam_runtime_milestone = "steam_process_spawn_requested".to_string();
                                v.steam_auto_start_attempted = true;
                            }
                        }

                        let start_time = std::time::Instant::now();
                        let mut steam_process =
                            steam_cmd.spawn().map_err(|e| LaunchError::new(LaunchErrorKind::Process, "Failed to spawn background Steam").with_source(anyhow!(e)))?;

                        unsafe {
                            if !ctx.verification_ptr.is_null() {
                                (*ctx.verification_ptr).steam_runtime_milestone = "steam_process_spawned".to_string();
                            }
                        }

                        // Adaptive readiness polling — checks actual Steam readiness signals
                        // instead of a fixed timeout. Max 30s by default, bails early on signal.
                        let readiness_timeout = 30;
                        println!("Waiting for Windows Steam to initialise (max {}s, signal-based)...", readiness_timeout);

                        let steam_pid_path = prefix_steam_dir.join("steam.pid");
                        let steam_pipe     = steam_wineprefix.join("drive_c/windows/temp/.steampath");
                        let steam_config_vdf = prefix_steam_dir.join("config/config.vdf");
                        let steam_logs_dir   = prefix_steam_dir.join("logs");

                        // Steam readiness is NOT "a file appeared once". config.vdf is written
                        // extremely early in boot (often within the first second on a cold
                        // start), so treating its presence as "ready" produced false positives
                        // ("Steam ready after 1s") while Steam was still initialising.
                        //
                        // Correct signal: the main Steam client process must be UP and stay up
                        // for a sustained window (SUSTAINED_SECS). We watch for any of the
                        // real "client reached main loop" markers (steam.pid / .steampath /
                        // config.vdf) and only declare ready once that marker has been present
                        // continuously for SUSTAINED_SECS while the process is still alive.
                        // A process that crashes/restarts resets the timer, so crash loops are
                        // never misread as "ready".
                        const SUSTAINED_SECS: u64 = 6;
                        let mut signal_first_seen: Option<std::time::Instant> = None;

                        let ready = 'wait: {
                            let mut signal_msg = None;
                            for i in 0..readiness_timeout {
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                                // Crash detection — bail immediately
                                if let Ok(Some(status)) = steam_process.try_wait() {
                                    println!("❌ FATAL: Background Steam exited after {}s with: {}", i + 1, status);
                                    unsafe {
                                        if !ctx.verification_ptr.is_null() {
                                            let v = &mut *ctx.verification_ptr;
                                            v.steam_runtime_exit_code = status.code();
                                            v.steam_runtime_lifetime_ms = Some(start_time.elapsed().as_millis() as u64);
                                            v.steam_runtime_milestone = "steam_process_exited_early".to_string();
                                        }
                                    }
                                    break 'wait false;
                                }

                                // Primary readiness markers: the main client process has
                                // started (pid file, Proton .steampath pipe, or config.vdf).
                                let signal_present =
                                    steam_pid_path.exists() || steam_pipe.exists() || steam_config_vdf.exists();

                                if signal_present {
                                    match signal_first_seen {
                                        None => {
                                            signal_first_seen = Some(std::time::Instant::now());
                                        }
                                        Some(t0) => {
                                            let elapsed = t0.elapsed().as_secs();
                                            if elapsed >= SUSTAINED_SECS {
                                                signal_msg = Some(format!(
                                                    "Steam process stable for {}s (marker present since {}s)",
                                                    SUSTAINED_SECS, i + 1
                                                ));
                                                break;
                                            }
                                        }
                                    }
                                } else {
                                    // Lost the marker (crashed / restarted) — restart the timer.
                                    signal_first_seen = None;
                                }

                                // Secondary hint (NOT a trigger): subsystems logging.
                                let log_count = std::fs::read_dir(&steam_logs_dir)
                                    .map(|d| d.count())
                                    .unwrap_or(0);
                                if log_count >= 2 {
                                    unsafe {
                                        if !ctx.verification_ptr.is_null() {
                                            (*ctx.verification_ptr).steam_runtime_milestone =
                                                "steam_ready_signal_observed".to_string();
                                        }
                                    }
                                }

                                println!(
                                    "  Waiting... {}s (client marker: {})",
                                    i + 1,
                                    if signal_present { "present" } else { "absent" }
                                );
                            }

                            if let Some(msg) = signal_msg {
                                println!("✅ Steam ready signal: {}", msg);

                                // Grace period check: ensure it didn't crash immediately after signaling ready
                                tokio::time::sleep(std::time::Duration::from_secs(8)).await;
                                if let Ok(Some(status)) = steam_process.try_wait() {
                                    println!("❌ FATAL: Background Steam exited during grace period with: {}", status);
                                    unsafe {
                                        if !ctx.verification_ptr.is_null() {
                                            let v = &mut *ctx.verification_ptr;
                                            v.steam_runtime_exit_code = status.code();
                                            v.steam_runtime_lifetime_ms = Some(start_time.elapsed().as_millis() as u64);
                                            v.steam_runtime_milestone = "steam_process_exited_early".to_string();
                                        }
                                    }
                                    break 'wait false;
                                }
                                true
                            } else {
                                println!("⚠️ Steam did not signal ready after {}s, launching game anyway", readiness_timeout);
                                unsafe {
                                    if !ctx.verification_ptr.is_null() {
                                        (*ctx.verification_ptr).steam_runtime_milestone = "steam_ready_timeout".to_string();
                                    }
                                }
                                true
                            }
                        };

                        if !ready {
                            unsafe {
                                if !ctx.verification_ptr.is_null() {
                                    (*ctx.verification_ptr).steam_auto_start_failed = true;
                                }
                            }
                            return Err(LaunchError::new(
                                LaunchErrorKind::Process,
                                "Background Steam crashed before the game could start — this often indicates a corrupted Windows Steam install — try Settings → Repair / Reinstall Windows Steam Runtime"
                            ));
                        }
                    }
        }

        if use_steam_runtime {
            // Enforce the user's disabled Steam features (webhelper/CEF, friends
            // UI, chat UI, overlay) as a background task, fully decoupled from
            // the game launch critical path — this does NOT block the game.
            //
            // Deliberately NOT done at t+2s: steamwebhelper's CEF subsystem
            // spawns multiple child processes while it boots, and killing it
            // mid-spawn just triggers Steam's own crash-recovery, which
            // respawns it — repeatedly, on every single launch, competing with
            // the game for CPU/RAM/disk I/O the whole time. That's what caused
            // the ~20s regression after PR63 replaced PR62's persistent
            // chmod-000 lockout with a one-shot SIGTERM that doesn't stop the
            // process from coming back.
            //
            // Waiting 30s lets the helper subsystem finish whatever it's going
            // to spawn before we act at all, and
            // enforce_disabled_steam_features_in_prefix now also locks the
            // underlying file (resolved safely from the process's own argv,
            // never via /proc/<pid>/exe).
            let enforcement_prefix = crate::utils::steam_wineprefix_for_game(
                &ctx.launcher_config,
                ctx.app.app_id,
                &user_config_store,
                Some(steam_prefix_mode.clone()),
            );
            let slc = ctx.user_config.as_ref()
                .map(|c| c.steam_launch_config.clone())
                .unwrap_or_default();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                SteamClient::enforce_disabled_steam_features_in_prefix(
                    &enforcement_prefix,
                    slc.no_browser,
                    slc.no_friends_ui,
                    slc.no_overlay,
                    slc.no_chat_ui,
                );
            });
        }

        // Write steam_appid.txt to the game working directory
        let install_dir = PathBuf::from(
            ctx.app.install_path
                .clone()
                .ok_or_else(|| LaunchError::new(LaunchErrorKind::GameData, format!("game {} is not installed", ctx.app.app_id)))?,
        );

        let exe_rel = ctx.launch_info.executable.replace('\\', "/");
        let executable = if Path::new(&exe_rel).is_absolute() {
            PathBuf::from(&exe_rel)
        } else {
            install_dir.join(&exe_rel)
        };
        let game_working_dir: PathBuf = ctx.launch_info.workingdir
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|wd| install_dir.join(wd.replace('\\', "/")))
            .or_else(|| executable.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| install_dir.clone());

        // Only write steam_appid.txt when the Windows Steam Runtime is actually in use.
        // When the runtime is Disabled, writing it (and exposing STEAM_COMPAT_CLIENT_INSTALL_PATH
        // in build_env) makes DRM-free games such as Amnesia: The Dark Descent (AppID 57300) try to
        // init Steam and fail with "could not init steam", even though they don't need it.
        let runtime_active_for_appid = match ctx.user_config.as_ref().map(|c| &c.steam_runtime_policy) {
            Some(crate::models::SteamRuntimePolicy::Enabled) => true,
            Some(crate::models::SteamRuntimePolicy::Disabled) => false,
            Some(crate::models::SteamRuntimePolicy::Auto) | None => {
                ctx.user_config.as_ref().map(|c| c.use_steam_runtime).unwrap_or(false)
            }
        };
        if runtime_active_for_appid {
            let app_id_str = ctx.app.app_id.to_string();
            let app_id_path = game_working_dir.join("steam_appid.txt");
            let _ = std::fs::write(&app_id_path, &app_id_str);
        } else {
            // Runtime disabled: also remove any steam_appid.txt left behind by a previous
            // launch. Steam's steam_api reads this file from the working directory and will
            // attempt to init Steam even when the env vars are absent, so a stale artifact
            // makes DRM-free games (e.g. Amnesia, AppID 57300) fail with "could not init steam".
            let stale = game_working_dir.join("steam_appid.txt");
            if stale.exists() {
                let _ = std::fs::remove_file(&stale);
                tracing::info!(
                    "Removed stale steam_appid.txt from {} (Windows Steam Runtime disabled)",
                    stale.display()
                );
            }
        }

        Ok(())
    }

    async fn build_env(&self, ctx: &LaunchContext) -> std::result::Result<HashMap<String, String>, LaunchError> {
        let mut env = HashMap::new();
        let app_id_str = ctx.app.app_id.to_string();

        let library_root = PathBuf::from(&ctx.launcher_config.steam_library_path);
        let compat_data_path = library_root
            .join("steamapps")
            .join("compatdata")
            .join(&app_id_str);

        // Effective prefix mode (runner-mismatch guard), used for the game's
        // WINEPREFIX below AND the background-Steam spawn decision.
        let steam_prefix_mode = effective_prefix_mode(ctx);

        let user_config_store: crate::models::UserConfigStore = ctx.user_config.as_ref().map(|c| {
            let mut store = HashMap::new();
            store.insert(ctx.app.app_id, c.clone());
            store
        }).unwrap_or_default().into();

        let effective_game_prefix = crate::utils::steam_wineprefix_for_game(
            &ctx.launcher_config,
            ctx.app.app_id,
            &user_config_store,
            Some(steam_prefix_mode.clone()),
        );

        // === Pre-launch Steam API readiness check ===
        // If Windows Steam Runtime is required for this launch, verify Steam is available
        // (either already running or needs to be started). This gate runs BEFORE the game
        // spawns so the user gets a clear warning rather than a silent crash with
        // "SteamAPI Initialization Failed" in the logs.
        let game_requires_steam_api = ctx.user_config.as_ref()
            .map(|c| c.requires_steam_api)
            .unwrap_or(false);

        let steam_runtime_policy = ctx.user_config.as_ref()
            .map(|c| c.steam_runtime_policy.clone())
            .unwrap_or(crate::models::SteamRuntimePolicy::Auto);

        let effective_steam_runtime_for_gate = match steam_runtime_policy {
            crate::models::SteamRuntimePolicy::Enabled => true,
            crate::models::SteamRuntimePolicy::Disabled => false,
            crate::models::SteamRuntimePolicy::Auto => {
                ctx.user_config.as_ref()
                    .map(|c| c.use_steam_runtime)
                    .unwrap_or(game_requires_steam_api)
            }
        };

        if effective_steam_runtime_for_gate {
            let master_steam_cfg = crate::utils::get_master_steam_config();
            let steam_wineprefix = master_steam_cfg.wine_prefix.clone();
            let steam_is_running = SteamClient::is_steam_running_in_prefix(&steam_wineprefix);

            if !steam_is_running {
                tracing::warn!(
                    "Windows Steam Runtime is {:?} but Steam is not running in prefix {}. Game {} may fail if it requires Steam API (Steamworks).",
                    steam_runtime_policy,
                    steam_wineprefix.display(),
                    ctx.app.app_id
                );
            }
        }

        // DX12 overlay auto-suppression: when VKD3D is active (DX12 → Vulkan),
        // Steam overlay causes black screens in most modern DX12 games.
        // Auto-suppress unless the user has explicitly disabled no_overlay globally.
        let glc = ctx.user_config.as_ref()
            .map(|c| c.graphics_layers.clone())
            .unwrap_or_default();
        let dx12_requires_overlay_suppress = matches!(
            glc.d3d12_policy,
            crate::models::D3D12ProviderPolicy::Vkd3dProton |
            crate::models::D3D12ProviderPolicy::Vkd3dWine
        );

        // Only expose Steam identity vars when the Windows Steam Runtime is actually in use.
        // When the runtime is Disabled, leaving these set (in addition to steam_appid.txt /
        // STEAM_COMPAT_CLIENT_INSTALL_PATH) makes DRM-free games such as Amnesia: The Dark Descent
        // (AppID 57300) attempt to initialize Steam and fail with "could not init steam".
        let runtime_active_for_env = match ctx.user_config.as_ref().map(|c| &c.steam_runtime_policy) {
            Some(crate::models::SteamRuntimePolicy::Enabled) => true,
            Some(crate::models::SteamRuntimePolicy::Disabled) => false,
            Some(crate::models::SteamRuntimePolicy::Auto) | None => {
                ctx.user_config.as_ref().map(|c| c.use_steam_runtime).unwrap_or(false)
            }
        };
        if runtime_active_for_env {
            env.insert("SteamAppId".to_string(), app_id_str.clone());
            env.insert("SteamGameId".to_string(), app_id_str.clone());
            env.insert("STEAM_COMPAT_APP_ID".to_string(), app_id_str.clone());
        }
        env.insert("WINEPREFIX".to_string(), effective_game_prefix.to_string_lossy().to_string());
        env.insert("STEAM_COMPAT_DATA_PATH".to_string(), compat_data_path.to_string_lossy().to_string());

        // Add user identity context if available
        if let Ok(session) = crate::config::load_session().await {
            if let Some(steam_id) = session.steam_id {
                env.insert("SteamUser".to_string(), steam_id.to_string());
            }
            if let Some(account_name) = session.account_name {
                env.insert("SteamAppUser".to_string(), account_name);
            }
        }

        let glc = ctx.user_config.as_ref()
            .map(|c| c.graphics_layers.clone())
            .unwrap_or_default();

        // Overlay suppression: the manual per-game "Suppress overlay for DX12
        // games" flag was removed — DX12 overlay suppression is auto-applied
        // whenever VKD3D is active (see dx12_requires_overlay_suppress above),
        // and the in-game overlay itself is controlled by the CEF browser
        // (steamwebhelper) toggle.
        let no_overlay = ctx.user_config.as_ref()
            .map(|c| c.steam_launch_config.no_overlay)
            .unwrap_or(true)
            || dx12_requires_overlay_suppress;


        // Steamworks readiness gate (runs only when Windows Steam Runtime is required).
        // This diagnoses the "lsteamclient.dll cannot be loaded" class of failures that hit
        // Steamworks games such as An Arcade Full of Cats (AppID 2368470). It does NOT block
        // the launch \u2014 it surfaces a clear, actionable warning so the user knows Windows
        // Steam must be installed/running, rather than getting a silent "SteamAPI Initialization Failed".
        if effective_steam_runtime_for_gate {
            let master_steam_cfg = crate::utils::get_master_steam_config();
            let steam_wineprefix = master_steam_cfg.wine_prefix.clone();

            // A real Windows Steam install always ships lsteamclient.dll in its install dir.
            let steam_exe_dir = master_steam_cfg.steam_exe
                .as_ref()
                .and_then(|e| e.parent().map(|p| p.to_path_buf()));
            let has_lsteamclient = steam_exe_dir
                .as_ref()
                .map(|d| d.join("lsteamclient.dll").exists() || d.join("lsteamclient64.dll").exists())
                .unwrap_or(false);
            let steam_running = SteamClient::is_steam_running_in_prefix(&steam_wineprefix);

            if !has_lsteamclient || !steam_running {
                tracing::warn!(
                    "Steamworks game {} may fail: Windows Steam not fully ready in prefix {} (lsteamclient present={}, running={}).",
                    ctx.app.app_id,
                    steam_wineprefix.display(),
                    has_lsteamclient,
                    steam_running,
                );
                if game_requires_steam_api {
                    tracing::error!(
                        "Game {} has 'Requires Steam API' enabled but Windows Steam is not available.                          Install/run Windows Steam (Settings -> 'Install / Manage Windows Steam Runtime')                          or set 'Use Windows Steam Runtime' to Enabled before launching.",
                        ctx.app.app_id
                    );
                }
            }
        }

        let game_working_dir: PathBuf = {
            let install_dir = PathBuf::from(
                ctx.app.install_path
                    .clone()
                    .ok_or_else(|| LaunchError::new(LaunchErrorKind::GameData, format!("game {} is not installed", ctx.app.app_id)))?,
            );

            let exe_rel = ctx.launch_info.executable.replace('\\', "/");
            let executable = if Path::new(&exe_rel).is_absolute() {
                PathBuf::from(&exe_rel)
            } else {
                install_dir.join(&exe_rel)
            };
            ctx.launch_info.workingdir
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|wd| install_dir.join(wd.replace('\\', "/")))
                .or_else(|| executable.parent().map(|p| p.to_path_buf()))
                .unwrap_or_else(|| install_dir.clone())
        };

        // Resolve proton version for component detection and DLL path building
        let proton = effective_game_proton(ctx);

        let active_runner_path = crate::utils::resolve_runner(&proton, &library_root);
        if !active_runner_path.exists() {
            return Err(LaunchError::new(
                LaunchErrorKind::Runner,
                format!(
                    "Compatibility Layer '{}' not found. Please check your Compatibility Layer setting in Global Settings.",
                    proton
                )
            ));
        }
        let game_runner_kind = crate::utils::classify_runner(&active_runner_path);
        if matches!(game_runner_kind, crate::utils::RunnerKind::Unknown) {
            return Err(LaunchError::new(LaunchErrorKind::Runner, format!("Unknown Compatibility Layer path: {}", active_runner_path.display())));
        }
        // === Steam SDK shim repair (SAFE) ===
        // Some games ship a broken/corrupt libsteam_api.so (observed: all-zero file,
        // e.g. "An Arcade Full of Cats", AppID 2368470). That makes the dynamic loader
        // reject it with "invalid ELF header" and abort the launch.
        //
        // CRITICAL: libsteam_api.so is the Steamworks SDK redist and is ABI/version
        // specific to the game's build. Blindly copying ANY other libsteam_api.so
        // (e.g. one bundled with a Proton layer) causes symbol mismatches such as
        // "undefined symbol: SteamInternal_SteamAPI_Init" and still breaks the game.
        //
        // Therefore we ONLY repair when a candidate is BOTH a valid ELF AND exports the
        // exact symbol the game imports. If no compatible shim exists, we remove the
        // corrupt file and emit a clear error telling the user to Verify/Reinstall the
        // game's files (the only correct source of the right SDK).
        {
            let game_lib = game_working_dir.join("libsteam_api.so");
            let is_corrupt = if game_lib.exists() {
                std::fs::read(&game_lib).map(|b| b.len() < 4 || &b[0..4] != b"\x7fELF").unwrap_or(true)
            } else {
                false
            };

            if is_corrupt {
                // The symbol a native Linux Steamworks game imports from its shim.
                let needed_symbol = "SteamInternal_SteamAPI_Init";

                let mut sdk_candidates: Vec<PathBuf> = Vec::new();
                if let Some(steam_dir) = crate::config::get_steam_root_hint() {
                    let mut scan = |dir: &Path| {
                        if let Ok(entries) = std::fs::read_dir(dir) {
                            for entry in entries.flatten() {
                                for cand in [
                                    entry.path().join("files/lib64/libsteam_api.so"),
                                    entry.path().join("files/lib/libsteam_api.so"),
                                    entry.path().join("dist/lib64/libsteam_api.so"),
                                    entry.path().join("dist/lib/libsteam_api.so"),
                                ] {
                                    if cand.exists() {
                                        sdk_candidates.push(cand);
                                    }
                                }
                            }
                        }
                    };
                    scan(&steam_dir.join("compatibilitytools.d"));
                    scan(&steam_dir.join("steamapps/common"));
                }

                // A candidate is acceptable only if it is a valid ELF AND exports the
                // exact symbol the game needs. Without symbol verification we would
                // reintroduce the ABI-mismatch crash.
                let exports_symbol = |cand: &Path, symbol: &str| -> bool {
                    std::process::Command::new("readelf")
                        .args(["-sW", cand.to_str().unwrap_or("")])
                        .output()
                        .ok()
                        .and_then(|o| String::from_utf8(o.stdout).ok())
                        .map(|out| out.contains(symbol))
                        .unwrap_or(false)
                };
                let valid_src = sdk_candidates.iter().find(|p| {
                    std::fs::read(p)
                        .map(|b| b.len() >= 4 && &b[0..4] == b"\x7fELF")
                        .unwrap_or(false)
                        && exports_symbol(p, needed_symbol)
                });

                match valid_src {
                    Some(src) => {
                        if let Err(e) = std::fs::copy(src, &game_lib) {
                            tracing::error!(
                                "Failed to repair libsteam_api.so for game {} from {}: {}",
                                ctx.app.app_id, src.display(), e
                            );
                        } else {
                            tracing::warn!(
                                "Repaired corrupt libsteam_api.so for game {} from {}",
                                ctx.app.app_id, src.display()
                            );
                        }
                    }
                    None => {
                        // No ABI-compatible shim: remove the corrupt file and tell the
                        // user the only correct fix is to Verify/Reinstall game files.
                        let _ = std::fs::remove_file(&game_lib);
                        tracing::error!(
                            "Game {} ships a corrupt libsteam_api.so and no ABI-compatible Steamworks SDK shim was found on this system.                              The launch will fail. Fix: in Steam, right-click the game -> Properties -> Installed Files -> 'Verify integrity of game files' (or reinstall).                              This restores the exact libsteam_api.so the game was built against.",
                            ctx.app.app_id
                        );
                    }
                }
            }
        }
        unsafe {
            if !ctx.verification_ptr.is_null() {
                (*ctx.verification_ptr).protonfixes_routed = matches!(game_runner_kind, crate::utils::RunnerKind::Proton { has_protonfixes: true, .. });
                if let Some(result) = &ctx.fixup_result {
                    if !result.extra_env.is_empty() || !result.extra_dll_overrides.is_empty() || !result.actions_log.is_empty() {
                        (*ctx.verification_ptr).rhai_fixup_applied.get_or_insert_with(|| ctx.app.app_id.to_string());
                    }
                }
            }
        }
        let _components = crate::utils::detect_runner_components(
            &active_runner_path,
            Some(&effective_game_prefix),
        );

        // 1. Resolve DX8-11 policy (GraphicsBackendPolicy) - CONSERVATIVE.
        // Auto does NOT automatically enable DXVK. Empirical testing shows DXVK breaks
        // several titles on this setup (e.g. Metro 2033 Redux crashes during boot under
        // DXVK, and native-Linux games such as Portal 2 must not be forced through Wine's
        // D3D path at all). Wine's built-in D3D (or per-game "Force WineD3D") is the safe
        // default; the user opts into DXVK explicitly via the DXVK policy or per-game
        // override when a specific game needs it.
        let (policy_dxvk, force_builtin, strict_dxvk) = match glc.graphics_backend_policy {
            crate::models::GraphicsBackendPolicy::Auto => (false, false, false),
            crate::models::GraphicsBackendPolicy::WineD3D => (false, true, false),
            crate::models::GraphicsBackendPolicy::DXVK => (true, false, true),
        };

        // Manual override takes precedence if enabled
        let effective_dxvk = glc.dxvk_enabled || policy_dxvk;

        // If user explicitly selected WineD3D and didn't force DXVK, we use builtins.
        let force_builtin_d3d = force_builtin && !effective_dxvk;

        // 2. Resolve DX12 policy (D3D12ProviderPolicy).
        // Auto: prefer VKD3D-Proton when the runner bundles it, falling back to
        // Wine VKD3D only when VKD3D-Proton is absent. Explicit selections are
        // honored strictly (no fallback) per the fallback-only-in-Auto rule.
        let (policy_vkd3dp, policy_vkd3dw) = match glc.d3d12_policy {
            crate::models::D3D12ProviderPolicy::Auto => (_components.vkd3d_proton.is_some(), !_components.vkd3d_proton.is_some() && _components.vkd3d.is_some()),
            crate::models::D3D12ProviderPolicy::Vkd3dProton => (true, false),
            crate::models::D3D12ProviderPolicy::Vkd3dWine => (false, true),
        };
        // Manual overrides take precedence
        let effective_vkd3d_proton = glc.vkd3d_proton_enabled || policy_vkd3dp;
        let effective_vkd3d = glc.vkd3d_enabled || policy_vkd3dw;

        // Strict D3D12 provider selection: when VKD3D-Proton is explicitly requested,
        // do NOT fall back to upstream Wine VKD3D — the two are incompatible providers.
        let effective_vkd3d_proton = if effective_vkd3d_proton && _components.vkd3d_proton.is_none() {
            tracing::warn!(
                "VKD3D-Proton selected but not found in runner '{}'; keeping selection active (DLL not resolved).",
                active_runner_path.display()
            );
            false
        } else {
            effective_vkd3d_proton
        };

        // Strict D3D12 provider selection: when VKD3D (Wine) is explicitly requested,
        // do NOT fall back to VKD3D-Proton.
        let effective_vkd3d = if effective_vkd3d && _components.vkd3d.is_none() {
            tracing::warn!(
                "VKD3D (Wine) selected but not found in runner '{}'; keeping selection active (DLL not resolved).",
                active_runner_path.display()
            );
            false
        } else {
            effective_vkd3d
        };

        // 3. Resolve DX3-7 policy (D3D7BackendPolicy).
        // Auto: use D7VK if detected in runner, otherwise fall back to WineD3D.
        // WineD3D: force Wine's built-in D3D (no D7VK).
        // D7VK: force D7VK if present in runner.
        let effective_ddraw_d7vk = match glc.d3d7_policy {
            crate::models::D3D7BackendPolicy::Auto => _components.d7vk.is_some(),
            crate::models::D3D7BackendPolicy::WineD3D => false,
            crate::models::D3D7BackendPolicy::D7VK => _components.d7vk.is_some(),
        };

        // NVAPI / DXVK-NVAPI Support
        let nvapi_enabled_cfg = ctx.user_config.as_ref().map(|c| c.graphics_layers.nvapi_enabled).unwrap_or(true);
        let has_nvapi = _components.nvapi.is_some() || _components.dxvk_nvapi.is_some();
        let nvapi_active = has_nvapi && nvapi_enabled_cfg;
        if nvapi_active {
            tracing::info!("NVAPI component detected and enabled, will be exposed to game");
        } else if has_nvapi {
            tracing::info!("NVAPI component detected but disabled by per-game settings");
        } else {
            tracing::info!("NVAPI component not detected in runner");
        }

        let use_symlinks = glc.use_symlinks_in_prefix;
        let runner_root = crate::utils::derive_runner_root(&active_runner_path);
        let mut dll_overrides = crate::utils::build_dll_overrides(
            effective_dxvk,
            effective_vkd3d_proton,
            effective_vkd3d,
            no_overlay,
            force_builtin_d3d,
            Some(&game_working_dir),
            strict_dxvk,
            Some(&runner_root),
        );
        if let Some(fixup) = &ctx.fixup_result {
            for fragment in &fixup.extra_dll_overrides {
                if !fragment.trim().is_empty() {
                    if !dll_overrides.is_empty() {
                        dll_overrides.push(';');
                    }
                    dll_overrides.push_str(fragment.trim());
                }
            }
            for action in &fixup.actions_log {
                tracing::info!("rhai fixup action: {}", action);
            }
        }

        // For Proton games, lsteamclient.dll MUST be loaded so it can communicate
        // with the Windows Steam process via Steam's own IPC protocol.
        // build_dll_overrides defaults lsteamclient=n (builtin only), which
        // prevents Proton's lsteamclient from being found. We remove that override
        // so the game's Proton lsteamclient loads normally.
        // Under PlainWine (wine-tkg for background Steam) the override stays:
        // wine-tkg handles Steam IPC itself and the game must not use its own lsteamclient.
        // (The Properties-tab "Compatibility Layer Override" free-text input was
        // removed — the per-game runner override is Options -> "Force specific
        // Proton/Wine version", which resolve_effective_proton_name honors here.)
        let game_runner_for_dll = effective_game_proton(ctx);
        let is_proton_game = matches!(
            crate::utils::classify_runner(
                &crate::utils::resolve_runner(&game_runner_for_dll, &library_root)
            ),
            crate::utils::RunnerKind::Proton { .. }
        );
        if is_proton_game {
            dll_overrides = dll_overrides
                .split(';')
                .filter(|seg| !seg.trim().starts_with("lsteamclient="))
                .collect::<Vec<_>>()
                .join(";");
        }

        // Enhance overrides with resolved DLL providers
        for res in &ctx.dll_resolutions {
            if res.chosen_provider == crate::launch::dll_provider_resolver::DllProvider::GameLocal {
                // GAME-LOCAL PRIORITY: the game ships its own copy of this DLL
                // (e.g. Portal 2 RTX Remix ships bin/d3d9.dll + dxvk_d3d9.dll,
                // .trex/d3d9.dll). Do NOT add a native override: Wine's native
                // search consults WINEDLLPATH (runner dirs) before the game's
                // dir, so "=n" would hand the game the runner's DXVK instead of
                // its own Remix build and break the launch. Leave the override
                // absent so the game's own DLL loads.
                tracing::info!(
                    "DLL {} provided by the game itself; no override added (game-local priority)",
                    res.name
                );
                continue;
            }
            if (res.chosen_provider == crate::launch::dll_provider_resolver::DllProvider::Custom && !use_symlinks) ||
               (res.chosen_provider == crate::launch::dll_provider_resolver::DllProvider::Runner && res.name.contains("nvapi")) {

                // Do not emit overrides for DLLs that are handled via internal capabilities
                if res.chosen_provider == crate::launch::dll_provider_resolver::DllProvider::Internal {
                     tracing::info!("Resolved DLL {} is handled internally (alias), skipping explicit override", res.name);
                     continue;
                }

                // Ensure native wins for non-symlinked custom DLLs
                if !dll_overrides.contains(&format!("{}=n", res.name)) {
                     tracing::info!("Adding native override for resolved DLL: {} (provider: {:?})", res.name, res.chosen_provider);
                     dll_overrides.push_str(&format!(";{}=n", res.name));
                }
                // D7VK ships ddraw.dll and requires ddraw=n,b in WINEDLLOVERRIDES
                if effective_ddraw_d7vk && res.name == "ddraw" && !dll_overrides.contains("ddraw=n,b") {
                     tracing::info!("Adding D7VK WINEDLLOVERRIDES: ddraw=n,b");
                     dll_overrides.push_str(";ddraw=n,b");
                }
            } else if res.chosen_provider == crate::launch::dll_provider_resolver::DllProvider::Internal {
                 tracing::info!("Resolved DLL {} is handled internally (alias), skipping explicit override", res.name);
            }
        }

        tracing::info!("Final WINEDLLOVERRIDES: {}", dll_overrides);
        env.insert("WINEDLLOVERRIDES".to_string(), dll_overrides.clone());

        // === Native Rust Proton ABI (Phase 2 item 2, valve-stack directive) ===
        // Port of Valve's `proton` script launch semantics, applied WITHOUT
        // invoking Python. Computes the per-app compat-option set
        // (default_compat_config + forcelgadd default + per-game
        // proton_compat_options), then merges Proton's env rules and base
        // DLL overrides into the env SteamFlow already assembled.
        //
        // This resolves the two real env gaps the test-diff harness found on
        // RE2 (883710): PROTON_FORCE_LARGE_ADDRESS_AWARE (forcelgadd default)
        // and the wined3d option were set by native Steam but never emitted
        // by SteamFlow. See docs/architecture/valve-stack-replication.md.
        {
            let mut compat = crate::runner::proton_abi::default_compat_config(ctx.app.app_id);
            if let Some(user_config) = &ctx.user_config {
                for opt in &user_config.proton_compat_options {
                    compat.insert(opt.clone());
                }
            }
            crate::runner::proton_abi::apply_forcelgadd_default(&mut compat);

            // Merge Proton's env rules (WINE_LARGE_ADDRESS_AWARE, WINE_HEAP_*,
            // DXVK_ENABLE_NVAPI, WINE_MONO_HIDETYPES, __GLVND_DISALLOW_PATCHING,
            // PROTON_USE_XALIA, …). SteamFlow's existing env values win.
            //
            // Order-preserving merge: WINEDLLOVERRIDES is order-sensitive for
            // per-DLL settings (dll=setting pairs), so keep SteamFlow's
            // original sequence and append Proton-only entries at the end.
            let mut proton_dll_overrides: Vec<(String, String)> = Vec::new();
            for seg in dll_overrides.split(';').filter(|s| !s.trim().is_empty()) {
                if let Some((dll, setting)) = seg.split_once('=') {
                    let dll = dll.trim().to_string();
                    let setting = setting.trim().to_string();
                    // Last occurrence wins (SteamFlow sometimes emits a DLL
                    // twice); drop earlier duplicates.
                    if let Some(prev) = proton_dll_overrides.iter_mut().find(|(d, _)| *d == dll) {
                        prev.1 = setting;
                    } else {
                        proton_dll_overrides.push((dll, setting));
                    }
                }
            }
            crate::runner::proton_abi::apply_proton_env_rules(
                ctx.app.app_id,
                &compat,
                &mut env,
                &mut proton_dll_overrides,
            );
            let merged = crate::runner::proton_abi::serialize_dll_overrides(&proton_dll_overrides);
            env.insert("WINEDLLOVERRIDES".to_string(), merged.clone());
            tracing::info!(
                "Proton ABI: compat={:?} → WINEDLLOVERRIDES={}",
                compat,
                merged
            );
        }
        if let Some(fixup) = &ctx.fixup_result {
            for (key, value) in &fixup.extra_env {
                env.insert(key.clone(), value.clone());
            }
        }

        // NOTE: `steam_prefix_mode` is the EFFECTIVE mode, resolved at the top
        // of this fn via `effective_prefix_mode(ctx)` (runner-mismatch guard).
        if steam_prefix_mode == crate::models::SteamPrefixMode::Shared && SteamClient::is_steam_running_in_prefix(&effective_game_prefix) {
            let msg = "Shared prefix mode: Steam is already running in this prefix. Launching a second game with a different runner will crash. Consider switching to per-game prefix mode in Settings.";
            tracing::warn!("{}", msg);
            unsafe {
                if !ctx.verification_ptr.is_null() {
                    let v = &mut *ctx.verification_ptr;
                    v.detailed_status = Some(msg.to_string());
                }
            }
        }

        // Track effective state for diagnostics (HACK: should ideally be done in a separate stage)
        // This is safe because WineTkgRunner is currently the only one implementing this logic.
        // We'll see if we can move it to PipelineContext later.

        // Translate Runner-resolved DLL paths into WINEDLLPATH so Wine can
        // actually find the bundled DLLs (VKD3D-Proton, DXVK, etc.) in the runner.
        // WITHOUT THIS, d3d12=n,b finds whatever is in the prefix's system32 instead.
        // CONSERVATIVE: only include paths for DLLs that are actually requested to be native.
        let mut wine_dll_dirs: Vec<String> = Vec::new();
        let use_symlinks = glc.use_symlinks_in_prefix;

        for res in &ctx.dll_resolutions {
            if (res.chosen_provider == crate::launch::dll_provider_resolver::DllProvider::Runner ||
                res.chosen_provider == crate::launch::dll_provider_resolver::DllProvider::Custom) && !use_symlinks
            {
                // Check if this DLL is actually selected for use by the current policy/overrides
                let name = res.name.to_lowercase();
                let is_dxvk_dll = matches!(name.as_str(), "d3d8" | "d3d9" | "d3d10" | "d3d10_1" | "d3d10core" | "d3d11" | "dxgi");
                let is_d3d12_dll = matches!(name.as_str(), "d3d12" | "d3d12core" | "libvkd3d-1" | "libvkd3d-shader-1");

                let is_nvapi_dll = matches!(name.as_str(), "nvapi" | "nvapi64" | "nvofapi64");
                let is_ddraw_dll = matches!(name.as_str(), "ddraw");
                let selected = (is_dxvk_dll && effective_dxvk) || (is_d3d12_dll && (effective_vkd3d_proton || effective_vkd3d)) || is_nvapi_dll || (is_ddraw_dll && effective_ddraw_d7vk);

                if !selected {
                    continue;
                }

                if let Some(path) = &res.chosen_path {
                    if let Some(parent) = path.parent() {
                        let dir = parent.to_string_lossy().to_string();
                        if !wine_dll_dirs.contains(&dir) {
                            wine_dll_dirs.push(dir);
                        }

                        // For Wine-TKG and similar layouts, we must ensure both 64-bit and 32-bit
                        // architecture folders are in WINEDLLPATH if they exist, so that both
                        // architectures of a game find their respective native DLLs.
                        let folder_name = parent.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if folder_name == "x86_64-windows" {
                            let sibling = parent.parent().unwrap().join("i386-windows");
                            if sibling.exists() {
                                let s = sibling.to_string_lossy().to_string();
                                if !wine_dll_dirs.contains(&s) {
                                    wine_dll_dirs.push(s);
                                }
                            }
                        } else if folder_name == "i386-windows" {
                            let sibling = parent.parent().unwrap().join("x86_64-windows");
                            if sibling.exists() {
                                let s = sibling.to_string_lossy().to_string();
                                if !wine_dll_dirs.contains(&s) {
                                    wine_dll_dirs.push(s);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Also add the runner's main lib/wine directories so Wine can find
        // the .dll.so PE loader stubs it needs to bridge into native DLLs.
        let active_runner = crate::utils::resolve_runner(&proton, &library_root);
        let runner_root = crate::utils::derive_runner_root(&active_runner);
        for lib_sub in crate::proton::COMPONENT_LIB_SUBDIRS {
            let p = runner_root.join(lib_sub);
            if p.exists() {
                let s = p.to_string_lossy().to_string();
                if !wine_dll_dirs.contains(&s) {
                    wine_dll_dirs.push(s);
                }

                // Ensure architecture-specific subdirectories are also in WINEDLLPATH.
                // This is critical for PE-based runners where Wine expects DLLs in
                // x86_64-windows or i386-windows folders even for the main runner libs.
                for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
                    let arch_p = p.join(arch_dir);
                    if arch_p.exists() {
                        let arch_s = arch_p.to_string_lossy().to_string();
                        if !wine_dll_dirs.contains(&arch_s) {
                            wine_dll_dirs.push(arch_s);
                        }
                    }
                }
            }
        }

        if !wine_dll_dirs.is_empty() {
            // Preserve any WINEDLLPATH the user may have set in env_variables
            let existing = env.get("WINEDLLPATH").cloned().unwrap_or_default();
            let combined = if existing.is_empty() {
                wine_dll_dirs.join(":")
            } else {
                format!("{}:{}", wine_dll_dirs.join(":"), existing)
            };
            env.insert("WINEDLLPATH".to_string(), combined);
        }

        let mut wine_path = vec!["C:\\Program Files (x86)\\Steam".to_string()];
        // Append runner DLL directories to WINEPATH to aid native PE loading
        for dir in &wine_dll_dirs {
            wine_path.push(dir.clone());
        }
        env.insert("WINEPATH".to_string(), wine_path.join(";"));

        let (use_steam_runtime, _runtime_source) = match ctx.user_config.as_ref().map(|c| &c.steam_runtime_policy) {
            Some(crate::models::SteamRuntimePolicy::Enabled) => (true, "override"),
            Some(crate::models::SteamRuntimePolicy::Disabled) => (false, "override"),
            Some(crate::models::SteamRuntimePolicy::Auto) | None => {
                let manual_toggle = ctx.user_config.as_ref().map(|c| c.use_steam_runtime).unwrap_or(false);
                if manual_toggle {
                    (true, "override_legacy")
                } else {
                    (false, "default")
                }
            }
        };

        if use_steam_runtime {
            let steam_cfg = crate::utils::get_master_steam_config();
            let steam_prefix_mode = ctx.user_config.as_ref()
                .map(|c| c.steam_prefix_mode.clone())
                .unwrap_or(ctx.launcher_config.steam_prefix_mode.clone());

            let steam_client_path = match steam_prefix_mode {
                crate::models::SteamPrefixMode::Shared => {
                    steam_cfg.steam_exe.as_ref().and_then(|e| e.parent().map(|p| p.to_path_buf()))
                }
                crate::models::SteamPrefixMode::PerGame => {
                    Some(effective_game_prefix.join("drive_c/Program Files (x86)/Steam"))
                }
            };

            if let Some(path) = steam_client_path {
                env.insert("STEAM_COMPAT_CLIENT_INSTALL_PATH".to_string(), path.to_string_lossy().to_string());
                unsafe {
                    if !ctx.verification_ptr.is_null() {
                        let v = &mut *ctx.verification_ptr;
                        v.steam_client_install_path_exposed_to_game = Some(path.to_string_lossy().to_string());
                        v.steam_client_install_path_source = Some("real".to_string());
                    }
                }
            } else {
                // steam_exe present but per-game path is missing: fall back to a fake trap so the
                // game still sees a Steam client path without crashing the launch wiring.
                let config_dir = crate::config::config_dir().map_err(|e| LaunchError::new(LaunchErrorKind::Environment, "failed to get config dir").with_source(e))?;
                let fake_env = crate::utils::setup_fake_steam_trap(&config_dir)
                    .map_err(|e| LaunchError::new(LaunchErrorKind::Permission, "failed to setup fake steam trap").with_source(e))?;
                env.insert("STEAM_COMPAT_CLIENT_INSTALL_PATH".to_string(), fake_env.to_string_lossy().to_string());
                unsafe {
                    if !ctx.verification_ptr.is_null() {
                        let v = &mut *ctx.verification_ptr;
                        v.steam_client_install_path_exposed_to_game = Some(fake_env.to_string_lossy().to_string());
                        v.steam_client_install_path_source = Some("fake_trap".to_string());
                    }
                }
            }
        } else {
            // Windows Steam Runtime is Disabled: do NOT expose any Steam client path.
            // A fake trap still makes DRM-free games (e.g. Amnesia: The Dark Descent, AppID 57300)
            // attempt Steam init and fail with "could not init steam". Leaving the var unset lets
            // them run standalone as the developer intended.
            tracing::info!(
                "Windows Steam Runtime disabled for game {} — not exposing STEAM_COMPAT_CLIENT_INSTALL_PATH",
                ctx.app.app_id
            );
            unsafe {
                if !ctx.verification_ptr.is_null() {
                    let v = &mut *ctx.verification_ptr;
                    v.steam_client_install_path_exposed_to_game = None;
                    v.steam_client_install_path_source = Some("none_disabled".to_string());
                }
            }
        }

        if let Ok(display) = std::env::var("DISPLAY") {
            env.insert("DISPLAY".to_string(), display);
        }
        if let Ok(wayland) = std::env::var("WAYLAND_DISPLAY") {
            env.insert("WAYLAND_DISPLAY".to_string(), wayland);
        }
        if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
            env.insert("XDG_RUNTIME_DIR".to_string(), xdg_runtime);
        }

        // Apply GPU preference if specified. CONSERVATIVE: No forced offload if unset.
        if let Some(gpu_pref) = ctx.user_config.as_ref().and_then(|c| c.gpu_preference.as_ref()) {
            let available_gpus = crate::utils::list_available_gpus();
            if let Some(gpu) = available_gpus.iter().find(|g| &g.name == gpu_pref) {
                if gpu.name.contains("NVIDIA") {
                    env.insert("__NV_PRIME_RENDER_OFFLOAD".to_string(), "1".to_string());
                    env.insert("__NV_PRIME_RENDER_OFFLOAD_PROVIDER".to_string(), "NVIDIA-G0".to_string());
                    env.insert("__VK_LAYER_NV_optimus".to_string(), "NVIDIA_only".to_string());
                    env.insert("__GLX_VENDOR_LIBRARY_NAME".to_string(), "nvidia".to_string());
                } else if gpu.name.contains("AMD") || gpu.name.contains("Intel") || gpu.name.contains("Unknown") {
                    // Standard DRI_PRIME for non-NVIDIA discrete/specific GPUs
                    // Try to find "cardN" and extract N
                    let re = regex::Regex::new(r"card(\d+)").unwrap();
                    if let Some(caps) = re.captures(&gpu.name) {
                        if let Some(idx_match) = caps.get(1) {
                            if let Ok(card_idx) = idx_match.as_str().parse::<u32>() {
                                 // DRI_PRIME=1 is the most common way to select the second GPU
                                 // For now we use the standard PRIME offload if it's not card0.
                                 if card_idx > 0 {
                                     env.insert("DRI_PRIME".to_string(), "1".to_string());
                                 } else {
                                     env.insert("DRI_PRIME".to_string(), "0".to_string());
                                 }
                            }
                        }
                    }
                }
            }
        }

        if let Some(config) = &ctx.user_config {
            for (key, val) in &config.env_variables {
                env.insert(key.clone(), val.clone());
            }

            // Add debug toggles
            if effective_dxvk {
                if !env.contains_key("DXVK_HUD") {
                    env.insert("DXVK_HUD".to_string(), "compiler".to_string());
                }
            }
            if effective_vkd3d_proton || effective_vkd3d {
                 if !env.contains_key("VKD3D_DEBUG") {
                    env.insert("VKD3D_DEBUG".to_string(), "warn".to_string());
                }
            }
        }

        let wants_mangohud = ctx.user_config.as_ref()
            .map(|c| {
                c.env_variables.contains_key("MANGOHUD")
                    || c.launch_options
                        .split_whitespace()
                        .any(|a| a == "-mangohud" || a == "--mangohud")
            })
            .unwrap_or(false);

        if wants_mangohud {
            let lib_path = SteamClient::find_mangohud_lib();
            match lib_path {
                Some(lib) => {
                    let existing = std::env::var("LD_PRELOAD").unwrap_or_default();
                    let new_preload = if existing.is_empty() {
                        lib.to_string_lossy().to_string()
                    } else {
                        format!("{}:{}", lib.to_string_lossy(), existing)
                    };
                    env.insert("LD_PRELOAD".to_string(), new_preload);
                    env.insert("MANGOHUD".to_string(), "1".to_string());
                    env.insert("MANGOHUD_DLSYM".to_string(), "1".to_string());
                }
                None => {
                    println!("⚠️  MangoHud requested but libMangoHud.so not found — skipping");
                }
            }
        }

        env.insert("WINEDEBUG".to_string(), "err+all,warn+module,warn+loaddll".to_string());

        // Dev-only overlay: ~/.config/SteamFlow/debug.json is applied last so its
        // keys win over per-game env variables and built-in debug defaults.
        // (Not exposed in the UI; see crate::config::load_debug_config.)
        for (key, val) in crate::config::load_debug_config().env {
            env.insert(key, val);
        }

        let log_dir = crate::config::config_dir()
            .unwrap_or_else(|_| PathBuf::from("/tmp"))
            .join("logs");
        let log_path = log_dir.join(format!("wine_{}.log", ctx.app.app_id));
        env.insert("WINE_LOG_OUTPUT".to_string(), log_path.to_string_lossy().to_string());

        Ok(env)
    }

    async fn build_command(&self, ctx: &LaunchContext) -> std::result::Result<CommandSpec, LaunchError> {
        let library_root = PathBuf::from(&ctx.launcher_config.steam_library_path);

        // The per-game runner override (Options -> "Force specific Proton/Wine
        // version") takes precedence over the global runner.
        let effective_proton = effective_game_proton(ctx);
        let active_runner = crate::utils::resolve_runner(&effective_proton, &library_root);
        let game_runner_kind = crate::utils::classify_runner(&active_runner);
        if matches!(game_runner_kind, crate::utils::RunnerKind::Unknown) {
            return Err(LaunchError::new(LaunchErrorKind::Runner, format!("Unknown Compatibility Layer path: {}", active_runner.display())));
        }

        let mut spec = CommandSpec::default();

        // Build the base command (handles 'proton run' wrapper and directory resolution)
        let base_cmd = match &game_runner_kind {
            crate::utils::RunnerKind::Proton { has_protonfixes: false, bundled_wine64: Some(wine64), .. } => Command::new(wine64),
            crate::utils::RunnerKind::Proton { has_protonfixes: false, bundled_wine64: None, .. } => {
                return Err(LaunchError::new(LaunchErrorKind::Runner, format!("Compatibility Layer {} has a proton script but no protonfixes and no bundled wine64 for fallback", active_runner.display())));
            }
            // Real Proton must go through the proton script so bundled protonfixes and
            // pressure-vessel/bootstrap behavior run naturally. Environment construction is
            // shared with Wine so DLL override/WINEDLLPATH handling remains intact.
            _ => crate::utils::build_runner_command(&active_runner)
                .map_err(|e| LaunchError::new(LaunchErrorKind::Runner, format!("Invalid Compatibility Layer path: {}", active_runner.display())).with_source(e))?,
        };
        spec.program = base_cmd.get_program().into();
        spec.args = base_cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();

        let install_dir = PathBuf::from(
            ctx.app.install_path
                .clone()
                .ok_or_else(|| LaunchError::new(LaunchErrorKind::GameData, format!("game {} is not installed", ctx.app.app_id)))?,
        );

        let exe_rel = ctx.launch_info.executable.replace('\\', "/");
        let executable = if Path::new(&exe_rel).is_absolute() {
            PathBuf::from(&exe_rel)
        } else {
            install_dir.join(&exe_rel)
        };
        let game_working_dir: PathBuf = ctx.launch_info.workingdir
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|wd| install_dir.join(wd.replace('\\', "/")))
            .or_else(|| executable.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| install_dir.clone());

        spec.cwd = Some(game_working_dir);

        let launch_mode = ctx.user_config
            .as_ref()
            .map(|c| c.launch_mode)
            .unwrap_or(ctx.launcher_config.launch_mode);

        // Collect the arguments that must be forwarded to the game. These come from
        // three sources, applied in precedence order: the manifest launch_info, any
        // Rhai fixup `append_argument` results (before user options so the user's
        // explicit Launch Options take final precedence), and the user's Launch
        // Options (minus the mangohud shims, which are handled as a wrapper).
        let mut forwarded_args: Vec<String> = Vec::new();
        forwarded_args.extend(
            ctx.launch_info.arguments
                .split_whitespace()
                .map(ToString::to_string),
        );
        if let Some(fixup) = &ctx.fixup_result {
            for arg in &fixup.extra_launch_args {
                if !arg.trim().is_empty() {
                    forwarded_args.push(arg.trim().to_string());
                }
            }
        }
        forwarded_args.extend(
            ctx.user_config.as_ref()
                .map(|c| c.launch_options.split_whitespace().map(ToString::to_string).collect::<Vec<_>>())
                .unwrap_or_default()
                .into_iter()
                .filter(|a| a != "-mangohud" && a != "--mangohud"),
        );

        let steam_mediated = !matches!(launch_mode, crate::models::LaunchMode::DirectWine);
        let mut steam_mode_args: Option<Vec<String>> = None;
        if steam_mediated {
            let steam_exe = crate::utils::get_master_steam_config().steam_exe
                .ok_or_else(|| LaunchError::new(
                    LaunchErrorKind::Environment,
                    "Steam-mediated launch requires an installed Windows Steam client",
                ))?;
            let mut args = vec![steam_exe.to_string_lossy().to_string()];
            match launch_mode {
                crate::models::LaunchMode::SteamAppLaunch => {
                    // `-applaunch <id>` forwards every trailing argument to the game,
                    // so the forwarded args may be appended after the app id.
                    args.push("-applaunch".to_string());
                    args.push(ctx.app.app_id.to_string());
                    args.extend(forwarded_args.iter().cloned());
                }
                crate::models::LaunchMode::SteamProtocol => {
                    // `steam://rungameid/<id>` ignores trailing argv. To forward launch
                    // options the args must be embedded in the URI as `//<args>` with
                    // spaces percent-encoded (%20) — Steam parses them as launch options.
                    let mut uri = format!("steam://rungameid/{}", ctx.app.app_id);
                    if !forwarded_args.is_empty() {
                        uri.push_str("//");
                        uri.push_str(&forwarded_args.join("%20"));
                    }
                    args.push(uri);
                }
                crate::models::LaunchMode::DirectWine => unreachable!(),
            }
            steam_mode_args = Some(args);
        }

        if let Some(args) = steam_mode_args {
            spec.args = args;
        } else {
            spec.args.push(executable.to_string_lossy().to_string());
            spec.args.extend(forwarded_args.iter().cloned());
        }

        spec.env = self.build_env(ctx).await?;

        // Steam-mediated launches invoke steam.exe, which lives in the master prefix.
        // build_env() sets WINEPREFIX to the game's effective prefix — for per-game
        // compatdata that is the game's own prefix, where steam.exe does not exist.
        // Force the master prefix so steam.exe runs under the right environment.
        if steam_mediated {
            let master_prefix = crate::utils::get_master_steam_config().wine_prefix;
            spec.env.insert("WINEPREFIX".to_string(), master_prefix.to_string_lossy().to_string());
        }

        Ok(spec)
    }

    fn launch(&self, spec: &CommandSpec) -> std::result::Result<std::process::Child, LaunchError> {
        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args);
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }
        for (key, val) in &spec.env {
            cmd.env(key, val);
        }

        let log_path = spec.env.get("WINE_LOG_OUTPUT").map(PathBuf::from);
        if let Some(path) = log_path {
            std::fs::create_dir_all(path.parent().unwrap()).ok();
            if let Ok(log_file) = std::fs::File::create(&path) {
                cmd.stderr(log_file);
            } else {
                cmd.stderr(std::process::Stdio::inherit());
            }
        } else {
            cmd.stderr(std::process::Stdio::inherit());
        }

        cmd.stdout(std::process::Stdio::inherit());

        println!("--- RUNNER LAUNCH ---");
        println!("Program: {:?}", cmd.get_program());
        println!("Args: {:?}", cmd.get_args().collect::<Vec<_>>());
        println!("Working Dir: {:?}", cmd.get_current_dir());
        println!("-------------------------");

        cmd.spawn().map_err(|e| LaunchError::new(LaunchErrorKind::Process, "failed to spawn runner process").with_source(anyhow!(e)))
    }
}
