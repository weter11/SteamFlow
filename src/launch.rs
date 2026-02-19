use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use crate::utils::ensure_steam_installer;

pub async fn install_ghost_steam_in_prefix(app_id: u32, proton_path: &Path, library_root: &Path) -> Result<()> {
    let prefix = library_root.join("steamapps/compatdata").join(app_id.to_string());
    let steam_dir = prefix.join("pfx/drive_c/Program Files (x86)/Steam");

    println!("Prefix Path: {}", prefix.display());
    println!("Sanitizing prefix...");

    let mut deleted_count = 0;
    if steam_dir.exists() {
        let files_to_delete = ["steam.exe", "lsteamclient.dll", "tier0_s.dll", "vstdlib_s.dll"];
        for entry in std::fs::read_dir(&steam_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if files_to_delete.contains(&name.as_str()) {
                std::fs::remove_file(entry.path())?;
                deleted_count += 1;
            }
        }
    }
    println!("Sanitizing prefix... deleted {} files.", deleted_count);

    let installer_path = ensure_steam_installer().await?;
    println!("Installer Path: {}", installer_path.display());

    println!("First time setup: Please complete the Steam installation, log in to your account, and then close Steam.");
    println!("Starting Steam Runtime Installation...");

    let trap_path = crate::utils::setup_fake_steam_env()?;
    println!("Fake Steam Trap: {}", trap_path.display());

    let mut cmd = Command::new(proton_path);
    cmd.arg("run").arg(&installer_path);

    let abs_prefix_path = crate::config::absolute_path(prefix.join("pfx"))?;
    cmd.env("WINEPREFIX", &abs_prefix_path);
    cmd.env("WINEDLLOVERRIDES", "steam.exe=n;lsteamclient=n;steam_api=n;steam_api64=n;steamclient=n;mscoree=d;mshtml=d");

    // Proton requires these to function correctly
    cmd.env("STEAM_COMPAT_DATA_PATH", crate::config::absolute_path(&prefix)?);
    cmd.env("STEAM_COMPAT_CLIENT_INSTALL_PATH", &trap_path);

    // Modify PATH to prioritize the fake steam trap
    let existing_path = std::env::var("PATH").unwrap_or_default();
    cmd.env("PATH", format!("{}:{}", trap_path.display(), existing_path));

    // Fix TLS/Network Error by providing host SSL certificates
    cmd.env("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt");
    cmd.env("SSL_CERT_DIR", "/etc/ssl/certs");

    // Hide the fact we are launching from a Steam-like app
    cmd.env_remove("SteamAppId");
    cmd.env_remove("SteamGameId");

    let status = cmd.status().context("failed to run Steam installer")?;
    println!("Installer finished with exit code: {}", status);

    Ok(())
}

pub async fn launch_ghost_steam(
    app_id: u32,
    resolved_proton: &Path,
    steam_exe: &Path,
    prefix: &Path,
    _library_root: &Path,
) -> Result<()> {
    let trap_path = crate::utils::setup_fake_steam_env()?;
    println!("Fake Steam Trap: {}", trap_path.display());

    println!("Launching Steam Runtime in background...");
    let mut steam_cmd = Command::new(resolved_proton);
    steam_cmd.arg("run").arg(steam_exe).arg("-silent").arg("-no-browser").arg("-noverifyfiles");

    let abs_prefix = crate::config::absolute_path(prefix.join("pfx"))?;
    steam_cmd.env("WINEPREFIX", &abs_prefix);
    steam_cmd.env("STEAM_COMPAT_DATA_PATH", crate::config::absolute_path(prefix)?);
    steam_cmd.env("STEAM_COMPAT_CLIENT_INSTALL_PATH", &trap_path);
    steam_cmd.env("SteamAppId", app_id.to_string());

    // Modify PATH to prioritize the fake steam trap
    let existing_path = std::env::var("PATH").unwrap_or_default();
    steam_cmd.env("PATH", format!("{}:{}", trap_path.display(), existing_path));

    // Ensure Steam uses its own binaries
    steam_cmd.env("WINEDLLOVERRIDES", "steam.exe=n;lsteamclient=n;steam_api=n;steam_api64=n;steamclient=n");

    // Spawn detached
    let _steam_child = steam_cmd.spawn().context("failed to launch Ghost Steam")?;

    println!("Waiting for Steam Runtime initialization...");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

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
