use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::fs;

pub async fn ensure_steam_installer() -> Result<PathBuf> {
    let config_dir = crate::config::config_dir()?;
    let runtimes_dir = config_dir.join("runtimes");
    fs::create_dir_all(&runtimes_dir).await?;

    let installer_path = runtimes_dir.join("SteamSetup.exe");
    if installer_path.exists() {
        return Ok(installer_path.canonicalize()?);
    }

    println!("Downloading Steam Runtime installer...");
    let url = "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe";
    let response = reqwest::get(url).await.context("failed to download Steam installer")?;
    let bytes = response.bytes().await.context("failed to read Steam installer bytes")?;

    fs::write(&installer_path, bytes).await.context("failed to write Steam installer to disk")?;
    println!("Download Complete");

    Ok(installer_path.canonicalize()?)
}

pub async fn deploy_master_steam(game_prefix: &std::path::Path) -> Result<()> {
    let master_prefix = crate::config::master_steam_prefix()?;
    let src_steam_dir = master_prefix.join("pfx/drive_c/Program Files (x86)/Steam");
    let dest_steam_dir = game_prefix.join("pfx/drive_c/Program Files (x86)/Steam");

    if !src_steam_dir.exists() {
        anyhow::bail!("Master Steam installation not found. Please launch 'Steam Runtime (Windows)' from the library first.");
    }

    println!("Deploying Master Steam to game prefix...");
    println!("Source: {}", src_steam_dir.display());
    println!("Destination: {}", dest_steam_dir.display());

    if dest_steam_dir.exists() {
        let _ = std::fs::remove_dir_all(&dest_steam_dir);
    }
    std::fs::create_dir_all(&dest_steam_dir)?;

    for entry in walkdir::WalkDir::new(&src_steam_dir) {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let rel = path.strip_prefix(&src_steam_dir)?;
            std::fs::create_dir_all(dest_steam_dir.join(rel))?;
        } else {
            let rel = path.strip_prefix(&src_steam_dir)?;
            std::fs::copy(path, dest_steam_dir.join(rel))?;
        }
    }

    println!("Master Steam deployment complete.");
    Ok(())
}

pub fn setup_fake_steam_env() -> Result<std::path::PathBuf> {
    let config_dir = crate::config::config_dir()?;
    let fake_env_dir = config_dir.join("fake_env");
    std::fs::create_dir_all(&fake_env_dir)?;

    let scripts = ["steam", "steam.sh"];
    let content = "#!/bin/sh\nexit 0\n";

    for script in scripts {
        let script_path = fake_env_dir.join(script);
        std::fs::write(&script_path, content)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))?;
        }
    }

    Ok(fake_env_dir.canonicalize()?)
}
