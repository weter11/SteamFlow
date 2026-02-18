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
