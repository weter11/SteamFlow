use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use crate::utils::ensure_steam_installer;

pub fn build_runner_command(runner_path: &Path) -> Result<Command> {
    // 1. Check if it's Proton (has a 'proton' script in the root)
    let proton_script = runner_path.join("proton");
    if proton_script.exists() {
        let mut cmd = Command::new(proton_script);
        cmd.arg("run");
        return Ok(cmd);
    }

    // 2. Check if it's standard Wine / wine-tkg (has 'bin/wine')
    let wine_bin = runner_path.join("bin/wine");
    if wine_bin.exists() {
        return Ok(Command::new(wine_bin));
    }

    // 3. Fallback for system wine if runner_path is just "/usr/bin/wine"
    if runner_path.is_file() && runner_path.file_name() == Some(std::ffi::OsStr::new("wine")) {
        return Ok(Command::new(runner_path));
    }

    Err(anyhow::anyhow!("failed to find wine binary in runner directory: {:?}", runner_path))
}

pub async fn install_ghost_steam(app_id: u32, proton_path: &Path) -> Result<()> {
    println!("Starting Steam Runtime Installation for AppID: {}...", app_id);
    let launcher_config = crate::config::load_launcher_config().await?;
    let library_root = crate::config::absolute_path(&launcher_config.steam_library_path)?;
    let prefix = library_root.join("steamapps/compatdata").join(app_id.to_string());

    let installer_path = ensure_steam_installer().await?;
    println!("Installer Path: {}", installer_path.display());
    println!("Prefix Path: {}", prefix.display());

    // Step A: Sanitize Target
    let target_dir = prefix.join("pfx/drive_c/Program Files (x86)/Steam");
    if target_dir.exists() {
        println!("Sanitizing prefix...");
        let mut deleted_count = 0;
        let entries = ["steam.exe", "lsteamclient.dll"];
        for entry in entries {
            let file_path = target_dir.join(entry);
            if file_path.exists() {
                std::fs::remove_file(&file_path)?;
                deleted_count += 1;
            }
        }
        println!("Sanitizing prefix... deleted {} files.", deleted_count);
    }

    // Step B: Construct Command
    let mut cmd = build_runner_command(proton_path)?;
    cmd.arg(&installer_path).arg("/S");

    let abs_prefix = crate::config::absolute_path(prefix.join("pfx"))?;
    cmd.env("WINEPREFIX", &abs_prefix);
    cmd.env("WINEDLLOVERRIDES", "steam.exe=n;lsteamclient=n;steam_api=n;steam_api64=n;steamclient=n");

    // REMOVE: SteamAppId, SteamGameId, STEAM_COMPAT_CLIENT_INSTALL_PATH
    cmd.env_remove("SteamAppId");
    cmd.env_remove("SteamGameId");
    cmd.env_remove("STEAM_COMPAT_CLIENT_INSTALL_PATH");

    // Fix TLS/Network Error
    cmd.env("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt");
    cmd.env("SSL_CERT_DIR", "/etc/ssl/certs");

    // Pass through display variables for installer UI (even if silent, sometimes needed)
    for var in ["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR"] {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }

    // Step C: Execute & Wait
    let status = cmd.status().await.context("failed to run Steam installer")?;
    println!("Installer finished with exit code: {}", status);

    Ok(())
}

pub async fn launch_ghost_steam(
    app_id: u32,
    proton_path: &Path,
    steam_exe: &Path,
    prefix: &Path,
    silent: bool,
) -> Result<()> {
    if silent {
        println!("Launching Steam Runtime in background...");
    } else {
        println!("Launching Steam Runtime interactively...");
    }

    let mut cmd = build_runner_command(proton_path)?;
    if silent {
        cmd.arg(steam_exe).arg("-silent").arg("-no-browser").arg("-noverifyfiles").arg("-tcp").arg("-cef-disable-gpu-compositing");
    } else {
        cmd.arg(steam_exe).arg("-tcp").arg("-cef-disable-gpu-compositing");
    }

    let abs_prefix = crate::config::absolute_path(prefix.join("pfx"))?;
    cmd.env("WINEPREFIX", &abs_prefix);
    cmd.env("STEAM_COMPAT_DATA_PATH", crate::config::absolute_path(prefix)?);

    if app_id != 0 {
        cmd.env("SteamAppId", app_id.to_string());
    }

    // Ensure it uses native binaries
    cmd.env("WINEDLLOVERRIDES", "steam.exe=n;lsteamclient=n;steam_api=n;steam_api64=n;steamclient=n");

    // Fix TLS/Network Error
    cmd.env("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt");
    cmd.env("SSL_CERT_DIR", "/etc/ssl/certs");

    // Pass through display variables
    for var in ["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR"] {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }

    if silent {
        let _child = cmd.spawn().context("failed to launch Ghost Steam")?;
        println!("Waiting for Steam Runtime initialization...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    } else {
        let status = cmd.status().await.context("failed to run interactive Steam")?;
        println!("Interactive Steam exited with status: {}", status);
    }

    Ok(())
}

pub fn get_installed_steam_path(prefix: &Path) -> Option<PathBuf> {
    let pfx_path = prefix.join("pfx");
    if !pfx_path.exists() {
        return None;
    }

    let drive_c = pfx_path.join("drive_c");
    let search_paths = [
        drive_c.join("Program Files (x86)/Steam"),
        drive_c.join("Program Files/Steam"),
        drive_c.join("Steam"),
    ];

    for path in search_paths {
        if path.exists() {
            if let Ok(entries) = std::fs::read_dir(&path) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                    if name == "steam.exe" {
                        println!("Steam Executable Found: Yes ({})", entry.path().display());
                        return Some(entry.path());
                    }
                }
            }
        }
    }

    println!("Steam Executable Found: No");
    None
}
