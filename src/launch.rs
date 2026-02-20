use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use crate::utils::ensure_steam_installer;

pub async fn launch_master_steam(proton_path: &Path) -> Result<()> {
    let master_prefix = crate::config::master_steam_prefix()?;
    let steam_exe = get_installed_steam_path(&master_prefix);

    if let Some(exe_path) = steam_exe {
        println!("Master Steam found. Launching interactively...");
        let mut cmd = Command::new(proton_path);
        cmd.arg("run").arg(exe_path).arg("-tcp").arg("-cef-disable-gpu-compositing");

        let abs_master_pfx = crate::config::absolute_path(master_prefix.join("pfx"))?;
        cmd.env("WINEPREFIX", &abs_master_pfx);
        cmd.env("STEAM_COMPAT_DATA_PATH", crate::config::absolute_path(&master_prefix)?);

        // Pass through display variables
        for var in ["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR"] {
            if let Ok(val) = std::env::var(var) {
                cmd.env(var, val);
            }
        }

        cmd.env("WINEDLLOVERRIDES", "steam.exe=n;steamclient=n;steamclient64=n;lsteamclient=n;steam_api=n;steam_api64=n");

        let status = cmd.status().context("failed to run master Steam")?;
        println!("Master Steam exited with status: {}", status);
    } else {
        println!("Master Steam NOT found. Starting Installation...");
        let installer_path = ensure_steam_installer().await?;

        let proton_dir = proton_path.parent().context("failed to get proton directory")?;
        let wine_bin = find_wine_binary(proton_dir).context("failed to find wine binary in proton directory")?;
        let lib64_dir = proton_dir.join("files/lib64");
        let lib32_dir = proton_dir.join("files/lib");

        let mut cmd = Command::new(wine_bin);
        cmd.arg(&installer_path);

        let abs_master_pfx = crate::config::absolute_path(master_prefix.join("pfx"))?;
        cmd.env("WINEPREFIX", &abs_master_pfx);

        // Pass through display variables
        for var in ["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR"] {
            if let Ok(val) = std::env::var(var) {
                cmd.env(var, val);
            }
        }

        // Manual LD_LIBRARY_PATH to fix network/GnuTLS
        let existing_ld = std::env::var("LD_LIBRARY_PATH").unwrap_or_default();
        let new_ld = if existing_ld.is_empty() {
            format!("{}:{}", lib64_dir.display(), lib32_dir.display())
        } else {
            format!("{}:{}:{}", lib64_dir.display(), lib32_dir.display(), existing_ld)
        };
        cmd.env("LD_LIBRARY_PATH", new_ld);

        // Fix TLS/Network Error
        cmd.env("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt");
        cmd.env("SSL_CERT_DIR", "/etc/ssl/certs");

        let status = cmd.status().context("failed to run Steam installer")?;
        println!("Installer finished with exit code: {}", status);

        if get_installed_steam_path(&master_prefix).is_some() {
            println!("Master Steam installation verified.");
        } else {
            anyhow::bail!("Steam installer failed to create steam.exe in master prefix.");
        }
    }

    Ok(())
}

fn find_wine_binary(proton_dir: &Path) -> Option<PathBuf> {
    let candidates = [
        proton_dir.join("files/bin/wine"),
        proton_dir.join("dist/bin/wine"),
        proton_dir.join("bin/wine"),
    ];

    for path in candidates {
        if path.exists() {
            return Some(path);
        }
    }
    None
}

pub async fn launch_silent_steam(
    app_id: u32,
    resolved_proton: &Path,
    steam_exe: &Path,
    prefix: &Path,
) -> Result<()> {
    let trap_path = crate::utils::setup_fake_steam_env()?;
    println!("Fake Steam Trap: {}", trap_path.display());

    println!("Launching Steam Runtime in background...");
    let mut steam_cmd = Command::new(resolved_proton);
    steam_cmd.arg("run").arg(steam_exe).arg("-silent").arg("-no-browser").arg("-noverifyfiles").arg("-tcp").arg("-cef-disable-gpu-compositing");

    let abs_prefix = crate::config::absolute_path(prefix.join("pfx"))?;
    steam_cmd.env("WINEPREFIX", &abs_prefix);
    steam_cmd.env("STEAM_COMPAT_DATA_PATH", crate::config::absolute_path(prefix)?);
    steam_cmd.env("STEAM_COMPAT_CLIENT_INSTALL_PATH", &trap_path);
    steam_cmd.env("SteamAppId", app_id.to_string());

    // Modify PATH to prioritize the fake steam trap
    let existing_path = std::env::var("PATH").unwrap_or_default();
    steam_cmd.env("PATH", format!("{}:{}", trap_path.display(), existing_path));

    // Ensure Steam uses its own binaries
    steam_cmd.env("WINEDLLOVERRIDES", "steam.exe=n;steamclient=n;steamclient64=n;lsteamclient=n;steam_api=n;steam_api64=n");

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
