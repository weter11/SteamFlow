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

pub async fn harvest_credentials(prefix_path: &std::path::Path) -> Result<()> {
    let secrets_dir = crate::config::config_dir()?.join("secrets");
    fs::create_dir_all(&secrets_dir).await?;

    let steam_dir = prefix_path.join("pfx/drive_c/Program Files (x86)/Steam");
    if !steam_dir.exists() {
        return Ok(());
    }

    let config_dir = steam_dir.join("config");
    let files_to_harvest = ["config.vdf", "loginusers.vdf"];

    for file_name in files_to_harvest {
        let src = config_dir.join(file_name);
        if src.exists() {
            let dest = secrets_dir.join(file_name);
            fs::copy(src, dest).await?;
        }
    }

    // Harvest ssfn* files
    let mut entries = fs::read_dir(&steam_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("ssfn") {
            let dest = secrets_dir.join(name);
            fs::copy(entry.path(), dest).await?;
        }
    }

    Ok(())
}

pub async fn inject_credentials(prefix_path: &std::path::Path) -> Result<()> {
    let secrets_dir = crate::config::config_dir()?.join("secrets");
    if !secrets_dir.exists() {
        return Ok(());
    }

    let steam_dir = prefix_path.join("pfx/drive_c/Program Files (x86)/Steam");
    if !steam_dir.exists() {
        return Ok(());
    }

    let config_dir = steam_dir.join("config");
    fs::create_dir_all(&config_dir).await?;

    let files_to_inject = ["config.vdf", "loginusers.vdf"];
    for file_name in files_to_inject {
        let src = secrets_dir.join(file_name);
        if src.exists() {
            let dest = config_dir.join(file_name);
            fs::copy(src, dest).await?;
        }
    }

    // Inject ssfn* files
    let mut entries = fs::read_dir(&secrets_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("ssfn") {
            let dest = steam_dir.join(name);
            fs::copy(entry.path(), dest).await?;
        }
    }

    Ok(())
}
