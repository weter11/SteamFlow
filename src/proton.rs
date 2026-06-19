use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use anyhow::{Result, anyhow, Context};
use std::fs;

pub const VALVE_PROTONS: &[(&str, &str)] = &[
    ("Proton - Experimental", "experimental"),
    ("Proton 11.0", "11.0"),
    ("Proton 10.0", "10.0"),
    ("Proton 9.0 (Beta)", "9.0"),
    ("Proton 8.0", "8.0"),
    ("Proton 7.0", "7.0"),
    ("Proton 6.3", "6.3"),
    ("Proton 5.13", "5.13"),
    ("Proton 5.0", "5.0"),
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtonSource {
    Valve,
    Github,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubSource {
    pub repo: &'static str,
    pub label: &'static str,
    pub ext: &'static str,
}

pub const GE_SOURCES: &[GithubSource] = &[
    GithubSource { repo: "GloriousEggroll/proton-ge-custom", label: "Proton-GE", ext: ".tar.gz" },
    GithubSource { repo: "GloriousEggroll/wine-ge-custom", label: "Wine-GE", ext: ".tar.xz" },
    GithubSource { repo: "CachyOS/proton-cachyos", label: "Proton-CachyOS", ext: ".tar.xz" },
    // TODO: Wine-TKG is not implemented here because it has no stable tagged releases,
    // ships nightlies only (r0.g<hash> tags), and requires local compilation rather
    // than downloading a finished build.
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtonPackage {
    pub name: String,
    pub source: ProtonSource,
    pub label: String, // e.g. "Proton-GE", "Valve"
    pub download_url: Option<String>,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledProton {
    pub name: String,
    pub path: PathBuf,
}

pub fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_lowercase()
}

pub async fn list_available() -> Result<Vec<ProtonPackage>> {
    let mut available = Vec::new();

    // Valve Protons
    for (name, _id) in VALVE_PROTONS {
        available.push(ProtonPackage {
            name: name.to_string(),
            source: ProtonSource::Valve,
            label: "Valve".to_string(),
            download_url: None,
            size: 0, // Unknown/Not applicable for Valve protons here
        });
    }

    // Github Sources
    for src in GE_SOURCES {
        match fetch_github_releases(src).await {
            Ok(mut packages) => available.append(&mut packages),
            Err(e) => tracing::error!("Failed to fetch releases for {}: {}", src.repo, e),
        }
    }

    Ok(available)
}

async fn fetch_github_releases(src: &GithubSource) -> Result<Vec<ProtonPackage>> {
    let url = format!("https://api.github.com/repos/{}/releases", src.repo);
    let client = reqwest::Client::builder()
        .user_agent("SteamFlow")
        .build()?;

    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(anyhow!("Failed to fetch GitHub releases for {}: {}", src.repo, response.status()));
    }
    let releases: Vec<GithubRelease> = response.json().await?;
    let mut packages = Vec::new();

    for release in releases {
        if let Some(package) = release_to_package(release, src) {
            packages.push(package);
        }
    }

    Ok(packages)
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

fn release_to_package(release: GithubRelease, src: &GithubSource) -> Option<ProtonPackage> {
    for asset in release.assets {
        if asset.name.ends_with(src.ext) {
            // Basic filtering for checksums/sigs is already handled by ends_with(src.ext)
            // But we should ensure we don't pick up .sha512sum or similar if src.ext is .tar.gz
            return Some(ProtonPackage {
                name: asset.name.replace(src.ext, ""),
                source: ProtonSource::Github,
                label: src.label.to_string(),
                download_url: Some(asset.browser_download_url),
                size: asset.size,
            });
        }
    }
    None
}

pub fn list_installed(library_root: &Path) -> Vec<InstalledProton> {
    let mut installed = Vec::new();

    // Official Valve Protons in steamapps/common
    let common_dir = library_root.join("steamapps/common");
    if let Ok(entries) = fs::read_dir(common_dir) {
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_dir() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if VALVE_PROTONS.iter().any(|(v_name, _)| *v_name == name) {
                        installed.push(InstalledProton {
                            name,
                            path: entry.path(),
                        });
                    }
                }
            }
        }
    }

    // Custom Protons in compatibilitytools.d
    let home = std::env::var("HOME").unwrap_or_default();
    let custom_paths = vec![
        PathBuf::from(&home).join(".local/share/Steam/compatibilitytools.d"),
        PathBuf::from(&home).join(".steam/steam/compatibilitytools.d"),
        crate::config::config_dir().unwrap_or_default().join("runtimes"),
    ];

    let mut unique_paths = Vec::new();
    for p in custom_paths {
        if let Ok(can) = fs::canonicalize(&p) {
            unique_paths.push(can);
        }
    }
    unique_paths.sort();
    unique_paths.dedup();

    for path in unique_paths {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        // Avoid duplicates if already found in Valve
                        if !installed.iter().any(|i| i.name == name) {
                             installed.push(InstalledProton {
                                name,
                                path: entry.path(),
                            });
                        }
                    }
                }
            }
        }
    }

    installed
}

pub async fn install_github_package<F>(package: ProtonPackage, mut progress: F) -> Result<()>
where F: FnMut(u64, u64) + Send + 'static
{
    let url = package.download_url.ok_or_else(|| anyhow!("Package has no download URL"))?;
    let response = reqwest::get(&url).await?;
    let total_size = response.content_length().unwrap_or(package.size);

    let mut downloaded: u64 = 0;
    let mut stream = response.bytes_stream();

    let temp_dir = tempfile::tempdir()?;
    let tarball_path = temp_dir.path().join("proton.tar");

    {
        use futures::StreamExt;
        let mut file = tokio::fs::File::create(&tarball_path).await?;
        while let Some(item) = stream.next().await {
            let chunk = item?;
            tokio::io::copy(&mut chunk.as_ref(), &mut file).await?;
            downloaded += chunk.len() as u64;
            progress(downloaded, total_size);
        }
    }

    // Extract to compatibilitytools.d
    let target_dir = crate::config::config_dir()?.join("runtimes");
    fs::create_dir_all(&target_dir)?;

    tracing::info!("Extracting {} to {}", tarball_path.display(), target_dir.display());

    // We use the 'tar' command if available, otherwise we'd need a crate.
    // Given the environment, 'tar' is likely available.
    let status = std::process::Command::new("tar")
        .arg("-xf")
        .arg(&tarball_path)
        .arg("-C")
        .arg(&target_dir)
        .status()
        .context("Failed to execute tar command")?;

    if !status.success() {
        return Err(anyhow!("tar extraction failed with status {}", status));
    }

    Ok(())
}

pub fn remove(name: &str) -> Result<()> {
    // Determine path
    let home = std::env::var("HOME").unwrap_or_default();
    let search_paths = vec![
        PathBuf::from(&home).join(".local/share/Steam/compatibilitytools.d"),
        PathBuf::from(&home).join(".steam/steam/compatibilitytools.d"),
        crate::config::config_dir().unwrap_or_default().join("runtimes"),
    ];

    for path in search_paths {
        let p = path.join(name);
        if p.exists() && p.is_dir() {
            fs::remove_dir_all(p)?;
            return Ok(());
        }
    }

    Err(anyhow!("Proton installation not found or cannot be removed: {}", name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_picks_matching_asset() {
        let release = GithubRelease {
            tag_name: "GE-Proton9-7".to_string(),
            assets: vec![
                GithubAsset {
                    name: "GE-Proton9-7.sha512sum".to_string(),
                    browser_download_url: "url1".to_string(),
                    size: 100,
                },
                GithubAsset {
                    name: "GE-Proton9-7.tar.gz".to_string(),
                    browser_download_url: "url2".to_string(),
                    size: 500_000_000,
                },
            ],
        };
        let src = &GE_SOURCES[0]; // Proton-GE, .tar.gz
        let package = release_to_package(release, src).unwrap();
        assert_eq!(package.name, "GE-Proton9-7");
        assert_eq!(package.download_url.unwrap(), "url2");
    }

    #[test]
    fn test_cachyos_asset_matching() {
        let release = GithubRelease {
            tag_name: "cachyos-11.0-20260602-slr".to_string(),
            assets: vec![
                GithubAsset {
                    name: "proton-cachyos-11.0-20260602-slr-x86_64.sha512sum".to_string(),
                    browser_download_url: "url1".to_string(),
                    size: 100,
                },
                GithubAsset {
                    name: "proton-cachyos-11.0-20260602-slr-x86_64.tar.xz".to_string(),
                    browser_download_url: "url2".to_string(),
                    size: 500_000_000,
                },
            ],
        };
        let src = &GE_SOURCES[2]; // Proton-CachyOS, .tar.xz
        let package = release_to_package(release, src).unwrap();
        assert_eq!(package.name, "proton-cachyos-11.0-20260602-slr-x86_64");
        assert_eq!(package.download_url.unwrap(), "url2");
    }
}
