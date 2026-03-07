use std::collections::HashMap;
use anyhow::anyhow;
use std::path::{Path, PathBuf};
use std::process::Command;
use crate::infra::runners::{Runner, LaunchContext, CommandSpec};
use crate::steam_client::SteamClient;
use crate::launch::pipeline::{LaunchError, LaunchErrorKind};

pub struct WineTkgRunner;

#[async_trait::async_trait]
impl Runner for WineTkgRunner {
    fn name(&self) -> &str { "Wine-TKG" }
    async fn prepare_prefix(&self, ctx: &LaunchContext) -> std::result::Result<(), LaunchError> {
        let library_root = PathBuf::from(&ctx.launcher_config.steam_library_path);
        let use_steam_runtime = ctx.user_config.as_ref().map(|c| c.use_steam_runtime).unwrap_or(false);
        let steam_prefix_mode = ctx.user_config.as_ref()
            .map(|c| c.steam_prefix_mode.clone())
            .unwrap_or(ctx.launcher_config.steam_prefix_mode.clone());

        let compat_data_path = library_root
            .join("steamapps")
            .join("compatdata")
            .join(ctx.app.app_id.to_string());
        let target_prefix_path = compat_data_path.join("pfx");
        std::fs::create_dir_all(&target_prefix_path)
            .map_err(|e| LaunchError::new(LaunchErrorKind::Permission, format!("failed creating {}", target_prefix_path.display())).with_source(anyhow!(e)))?;

        let mut steam_wineprefix = target_prefix_path.clone();

        if use_steam_runtime {
            let base_config = crate::config::config_dir().map_err(|e| LaunchError::new(LaunchErrorKind::Environment, "failed to get config dir").with_source(e))?;
            let master_prefix = base_config.join("master_steam_prefix");

            tracing::info!("Looking for Master Steam in: {}", master_prefix.display());

            match find_master_steam_dir(&master_prefix) {
                None => {
                    return Err(LaunchError::new(
                        LaunchErrorKind::Environment,
                        format!(
                            "use_steam_runtime is enabled but steam.exe was not found in {}.\n\
                             Go to Settings → 'Install / Manage Windows Steam Runtime' first.",
                            master_prefix.display()
                        )
                    ).with_context("master_prefix", master_prefix.to_string_lossy()));
                }
                Some(master_steam_dir) => {
                    let master_wineprefix_original = crate::utils::resolve_master_wineprefix();

                    let prefix_steam_dir = match steam_prefix_mode {
                        crate::models::SteamPrefixMode::Shared => {
                            steam_wineprefix = master_wineprefix_original.clone();
                            master_steam_dir.clone()
                        }
                        crate::models::SteamPrefixMode::PerGame => {
                            let target_steam_dir = target_prefix_path
                                .join("drive_c/Program Files (x86)/Steam");

                            tracing::info!(
                                "Linking/Cloning {} → {}",
                                master_steam_dir.display(),
                                target_steam_dir.display()
                            );
                            let _ = std::fs::create_dir_all(target_steam_dir.parent().unwrap());
                            #[cfg(unix)]
                            {
                                if !target_steam_dir.exists() {
                                    if let Err(e) =
                                        std::os::unix::fs::symlink(&master_steam_dir, &target_steam_dir)
                                    {
                                        tracing::warn!("Symlink failed, falling back to copy: {}", e);
                                        let _ = crate::utils::copy_dir_all(
                                            &master_steam_dir,
                                            &target_steam_dir,
                                        );
                                    }
                                }
                            }
                            #[cfg(not(unix))]
                            {
                                let _ = crate::utils::copy_dir_all(
                                    &master_steam_dir,
                                    &target_steam_dir,
                                );
                            }
                            target_steam_dir
                        }
                    };

                    println!("--- STEAM LAUNCH DEBUG ---");
                    println!("Prefix Steam dir : {}", prefix_steam_dir.display());
                    println!("Steam WINEPREFIX : {}", steam_wineprefix.display());

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
                    if slc.no_browser {
                        steam_args.push("-no-browser".to_string());
                    }
                    if slc.no_overlay {
                        steam_args.push("-disable-overlay".to_string());
                    }
                    if slc.no_vr {
                        steam_args.push("-noopenvr".to_string());
                    }
                    if slc.big_picture {
                        steam_args.push("-bigpicture".to_string());
                    }

                    if SteamClient::is_steam_running_in_prefix(&steam_wineprefix) {
                        println!("✅ Steam already running in prefix — skipping spawn");
                    } else {
                        let proton = if let Some(forced) = ctx.launcher_config
                            .game_configs
                            .get(&ctx.app.app_id)
                            .and_then(|c| c.forced_proton_version.as_ref())
                        {
                            forced.as_str()
                        } else {
                            ctx.proton_path.as_deref()
                                .filter(|p| !p.is_empty())
                                .ok_or_else(|| LaunchError::new(LaunchErrorKind::Environment, "proton path is required for Windows launch"))?
                        };
                        let active_runner = crate::utils::resolve_runner(proton, &library_root);

                        let mut steam_cmd = crate::utils::build_runner_command(&active_runner)
                            .map_err(|e| LaunchError::new(LaunchErrorKind::Runner, format!("Invalid Compatibility Layer path: {}", active_runner.display())).with_source(e))?;
                        steam_cmd.current_dir(&prefix_steam_dir);
                        steam_cmd
                            .arg("C:\\Program Files (x86)\\Steam\\steam.exe")
                            .args(&steam_args);
                        steam_cmd
                            .env("WINEPREFIX", &steam_wineprefix)
                            .env(
                                "WINEDLLOVERRIDES",
                                "vstdlib_s=n;tier0_s=n;steamclient=n;steamclient64=n;\
                                 steam_api=n;steam_api64=n;lsteamclient=;\
                                 GameOverlayRenderer=n;GameOverlayRenderer64=n",
                            )
                            .env("WINEPATH", "C:\\Program Files (x86)\\Steam")
                            .env("STEAM_DISABLE_BROWSER", "1")
                            .env("STEAM_NO_BROWSER", "1")
                            .env("STEAMCMD", "1") // tells Steam it's running as a cmd tool
                            .stdout(std::process::Stdio::null()) // silence CEF log spam
                            .stderr(std::process::Stdio::null());

                        println!("Program: {:?}", steam_cmd.get_program());
                        println!("Args: {:?}", steam_cmd.get_args().collect::<Vec<_>>());
                        println!("--------------------------");

                        let mut steam_process =
                            steam_cmd.spawn().map_err(|e| LaunchError::new(LaunchErrorKind::Process, "Failed to spawn background Steam").with_source(anyhow!(e)))?;

                        println!("Waiting for Steam to initialise (max 30s)...");

                        let steam_pid_path = prefix_steam_dir.join("steam.pid");
                        let steam_pipe     = steam_wineprefix.join("drive_c/windows/temp/.steampath");
                        let steam_config_vdf = prefix_steam_dir.join("config/config.vdf");
                        let steam_logs_dir   = prefix_steam_dir.join("logs");

                        let ready = 'wait: {
                            for i in 0..30 {
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                                // Crash detection — bail immediately
                                if let Ok(Some(status)) = steam_process.try_wait() {
                                    println!("❌ FATAL: Background Steam exited after {}s with: {}", i + 1, status);
                                    break 'wait false;
                                }

                                // Signal 1: pid file (some Wine/Steam combos do write this)
                                if steam_pid_path.exists() {
                                    println!("✅ Steam ready after {}s (steam.pid found)", i + 1);
                                    break 'wait true;
                                }

                                // Signal 2: .steampath in temp (Proton-style)
                                if steam_pipe.exists() {
                                    println!("✅ Steam ready after {}s (.steampath found)", i + 1);
                                    break 'wait true;
                                }

                                // Signal 3: config.vdf written — Steam has finished early init
                                if steam_config_vdf.exists() {
                                    println!("✅ Steam ready after {}s (config.vdf found)", i + 1);
                                    break 'wait true;
                                }

                                // Signal 4: logs dir has multiple entries — Steam's subsystems are running
                                let log_count = std::fs::read_dir(&steam_logs_dir)
                                    .map(|d| d.count())
                                    .unwrap_or(0);
                                if log_count >= 2 {
                                    println!("✅ Steam ready after {}s ({} log files found)", i + 1, log_count);
                                    break 'wait true;
                                }

                                println!("  Waiting... {}s", i + 1);
                            }
                            println!("⚠️ Steam did not signal ready after 30s, launching game anyway");
                            true
                        };

                        if !ready {
                                    return Err(LaunchError::new(LaunchErrorKind::Process, "Background Steam crashed before the game could start"));
                        }
                    }
                }
            }
        }

        // Write steam_appid.txt to the game working directory
        let install_dir = PathBuf::from(
            ctx.app.install_path
                .clone()
                .ok_or_else(|| LaunchError::new(LaunchErrorKind::GameData, format!("game {} is not installed", ctx.app.app_id)))?,
        );
        let executable = install_dir.join(&ctx.launch_info.executable.replace('\\', "/"));
        let game_working_dir: PathBuf = ctx.launch_info.workingdir
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|wd| install_dir.join(wd.replace('\\', "/")))
            .or_else(|| executable.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| install_dir.clone());

        let app_id_str = ctx.app.app_id.to_string();
        let app_id_path = game_working_dir.join("steam_appid.txt");
        let _ = std::fs::write(&app_id_path, &app_id_str);

        Ok(())
    }

    async fn build_env(&self, ctx: &LaunchContext) -> std::result::Result<HashMap<String, String>, LaunchError> {
        let mut env = HashMap::new();
        let app_id_str = ctx.app.app_id.to_string();

        let library_root = PathBuf::from(&ctx.launcher_config.steam_library_path);
        let steam_prefix_mode = ctx.user_config.as_ref()
            .map(|c| c.steam_prefix_mode.clone())
            .unwrap_or(ctx.launcher_config.steam_prefix_mode.clone());
        let use_steam_runtime = ctx.user_config.as_ref().map(|c| c.use_steam_runtime).unwrap_or(false);

        let compat_data_path = library_root
            .join("steamapps")
            .join("compatdata")
            .join(&app_id_str);
        let target_prefix_path = compat_data_path.join("pfx");

        let mut game_wineprefix = target_prefix_path.clone();
        if use_steam_runtime && matches!(steam_prefix_mode, crate::models::SteamPrefixMode::Shared) {
            game_wineprefix = crate::utils::resolve_master_wineprefix();
        }

        env.insert("SteamAppId".to_string(), app_id_str.clone());
        env.insert("SteamGameId".to_string(), app_id_str);
        env.insert("WINEPREFIX".to_string(), game_wineprefix.to_string_lossy().to_string());
        env.insert("STEAM_COMPAT_DATA_PATH".to_string(), compat_data_path.to_string_lossy().to_string());

        let mut glc = ctx.user_config.as_ref()
            .map(|c| c.graphics_layers.clone())
            .unwrap_or_default();
        let no_overlay = ctx.user_config.as_ref()
            .map(|c| c.steam_launch_config.no_overlay)
            .unwrap_or(true);

        let install_dir = PathBuf::from(
            ctx.app.install_path
                .clone()
                .ok_or_else(|| LaunchError::new(LaunchErrorKind::GameData, format!("game {} is not installed", ctx.app.app_id)))?,
        );
        let executable = install_dir.join(&ctx.launch_info.executable.replace('\\', "/"));
        let game_working_dir: PathBuf = ctx.launch_info.workingdir
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|wd| install_dir.join(wd.replace('\\', "/")))
            .or_else(|| executable.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| install_dir.clone());

        // Resolve graphics backend policy
        match glc.graphics_backend_policy {
            crate::models::GraphicsBackendPolicy::Auto => {
                let components = crate::utils::detect_runner_components(
                    &crate::utils::resolve_runner(
                        ctx.proton_path.as_deref().unwrap_or("wine"),
                        &library_root
                    ),
                    Some(&game_wineprefix)
                );

                if components.dxvk.is_some() {
                    glc.dxvk_enabled = true;
                }
                if components.vkd3d_proton.is_some() {
                    glc.vkd3d_proton_enabled = true;
                }
            }
            crate::models::GraphicsBackendPolicy::WineD3D => {
                glc.dxvk_enabled = false;
                glc.vkd3d_proton_enabled = false;
                glc.vkd3d_enabled = false;
            }
            crate::models::GraphicsBackendPolicy::DXVK => {
                glc.dxvk_enabled = true;
            }
            crate::models::GraphicsBackendPolicy::VKD3D => {
                glc.vkd3d_proton_enabled = true;
            }
        }

        let mut dll_overrides = crate::utils::build_dll_overrides(
            glc.dxvk_enabled,
            glc.vkd3d_proton_enabled,
            glc.vkd3d_enabled,
            no_overlay,
            Some(&game_working_dir),
        );

        // Enhance overrides with resolved DLL providers
        for res in &ctx.dll_resolutions {
            if let crate::launch::dll_provider_resolver::DllProvider::GameLocal = res.chosen_provider {
                // Ensure native wins for game-local DLLs
                if !dll_overrides.contains(&format!("{}=n", res.name)) {
                     dll_overrides.push_str(&format!(";{}=n", res.name));
                }
            }
        }

        env.insert("WINEDLLOVERRIDES".to_string(), dll_overrides);

        env.insert("WINEPATH".to_string(), "C:\\Program Files (x86)\\Steam".to_string());

        let config_dir = crate::config::config_dir().map_err(|e| LaunchError::new(LaunchErrorKind::Environment, "failed to get config dir").with_source(e))?;
        let fake_env = crate::utils::setup_fake_steam_trap(&config_dir)
            .map_err(|e| LaunchError::new(LaunchErrorKind::Permission, "failed to setup fake steam trap").with_source(e))?;
        env.insert("STEAM_COMPAT_CLIENT_INSTALL_PATH".to_string(), fake_env.to_string_lossy().to_string());

        if let Ok(display) = std::env::var("DISPLAY") {
            env.insert("DISPLAY".to_string(), display);
        }
        if let Ok(wayland) = std::env::var("WAYLAND_DISPLAY") {
            env.insert("WAYLAND_DISPLAY".to_string(), wayland);
        }
        if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
            env.insert("XDG_RUNTIME_DIR".to_string(), xdg_runtime);
        }

        if let Some(config) = &ctx.user_config {
            for (key, val) in &config.env_variables {
                env.insert(key.clone(), val.clone());
            }

            // Add debug toggles
            if config.graphics_layers.dxvk_enabled {
                if !env.contains_key("DXVK_HUD") {
                    env.insert("DXVK_HUD".to_string(), "compiler".to_string());
                }
            }
            if config.graphics_layers.vkd3d_proton_enabled || config.graphics_layers.vkd3d_enabled {
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

        let log_dir = crate::config::config_dir()
            .unwrap_or_else(|_| PathBuf::from("/tmp"))
            .join("logs");
        let log_path = log_dir.join(format!("wine_{}.log", ctx.app.app_id));
        env.insert("WINE_LOG_OUTPUT".to_string(), log_path.to_string_lossy().to_string());

        Ok(env)
    }

    async fn build_command(&self, ctx: &LaunchContext) -> std::result::Result<CommandSpec, LaunchError> {
        let library_root = PathBuf::from(&ctx.launcher_config.steam_library_path);

        let proton = if let Some(forced) = ctx.launcher_config
            .game_configs
            .get(&ctx.app.app_id)
            .and_then(|c| c.forced_proton_version.as_ref())
        {
            forced.as_str()
        } else {
            ctx.proton_path.as_deref()
                .filter(|p| !p.is_empty())
                .ok_or_else(|| LaunchError::new(LaunchErrorKind::Environment, "proton path is required for Windows launch"))?
        };
        let active_runner = crate::utils::resolve_runner(proton, &library_root);

        let mut spec = CommandSpec::default();

        // Build the base command (handles 'proton run' wrapper and directory resolution)
        let base_cmd = crate::utils::build_runner_command(&active_runner)
            .map_err(|e| LaunchError::new(LaunchErrorKind::Runner, format!("Invalid Compatibility Layer path: {}", active_runner.display())).with_source(e))?;
        spec.program = base_cmd.get_program().into();
        spec.args = base_cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();

        let install_dir = PathBuf::from(
            ctx.app.install_path
                .clone()
                .ok_or_else(|| LaunchError::new(LaunchErrorKind::GameData, format!("game {} is not installed", ctx.app.app_id)))?,
        );
        let executable = install_dir.join(&ctx.launch_info.executable.replace('\\', "/"));
        let game_working_dir: PathBuf = ctx.launch_info.workingdir
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|wd| install_dir.join(wd.replace('\\', "/")))
            .or_else(|| executable.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| install_dir.clone());

        spec.cwd = Some(game_working_dir);
        spec.args.push(executable.to_string_lossy().to_string());

        // Split args from launch_info
        let args = ctx.launch_info.arguments.split_whitespace().map(ToString::to_string);
        spec.args.extend(args);

        // Split user launch args
        let user_launch_args = ctx.user_config.as_ref()
            .map(|c| c.launch_options.split_whitespace().map(ToString::to_string).collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .filter(|a| a != "-mangohud" && a != "--mangohud");
        spec.args.extend(user_launch_args);

        spec.env = self.build_env(ctx).await?;

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

fn find_master_steam_exe(prefix: &Path) -> Option<PathBuf> {
    let candidates = [
        "pfx/drive_c/Program Files (x86)/Steam/steam.exe",
        "pfx/drive_c/Program Files/Steam/steam.exe",
        "drive_c/Program Files (x86)/Steam/steam.exe",
        "drive_c/Program Files/Steam/steam.exe",
    ];

    for rel_path in candidates {
        let full_path = prefix.join(rel_path);
        if full_path.exists() {
            return Some(full_path);
        }
    }

    None
}

fn find_master_steam_dir(prefix: &Path) -> Option<PathBuf> {
    find_master_steam_exe(prefix).and_then(|exe| exe.parent().map(|p| p.to_path_buf()))
}
