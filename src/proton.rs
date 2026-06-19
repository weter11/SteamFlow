use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use anyhow::{Result, anyhow, Context};
use std::fs;

// TODO: Valve Proton tools could be discovered dynamically via PICS
// by querying the Steam client's supported compatibility tools list.
pub const VALVE_PROTONS: &[(&str, u32)] = &[
    ("Proton - Experimental", 1493710),
    ("Proton 11.0", 4628710),
    ("Proton 10.0", 3658110),
    ("Proton 9.0", 2805730),
    ("Proton 8.0", 2348590),
    ("Proton 7.0", 1887720),
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtonSource {
    Valve { app_id: u32 },
    Github { url: String, ext: String },
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
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledProton {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostArchTag {
    Arm64,
    X86_64V3, // AVX2 baseline
    X86_64,   // generic fallback
}

pub fn detect_host_arch_tag() -> HostArchTag {
    #[cfg(target_arch = "aarch64")]
    {
        return HostArchTag::Arm64;
    }

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2")
            && is_x86_feature_detected!("fma")
            && is_x86_feature_detected!("bmi2")
        {
            return HostArchTag::X86_64V3;
        }
        return HostArchTag::X86_64;
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        HostArchTag::X86_64
    }
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
    for (name, app_id) in VALVE_PROTONS {
        available.push(ProtonPackage {
            name: name.to_string(),
            source: ProtonSource::Valve { app_id: *app_id },
            label: "Valve".to_string(),
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

#[derive(Deserialize, Clone)]
pub struct GithubAsset {
    pub name: String,
    browser_download_url: String,
    size: u64,
}

pub fn select_asset(assets: &[GithubAsset], arch: HostArchTag, ext: &str) -> Option<GithubAsset> {
    let candidates: Vec<GithubAsset> = assets
        .iter()
        .filter(|a| {
            a.name.ends_with(ext)
                && !a.name.contains("sha512sum")
                && !a.name.contains("sha256sum")
                && !a.browser_download_url.contains("/archive/refs/tags/")
        })
        .cloned()
        .collect();

    if candidates.is_empty() {
        return None;
    }

    if candidates.len() == 1 {
        return candidates.into_iter().next();
    }

    // Multiple variants (e.g. CachyOS arm64/x86_64/x86_64_v3) — pick by host arch
    let preferred = match arch {
        HostArchTag::Arm64 => "arm64",
        HostArchTag::X86_64V3 => "x86_64_v3",
        HostArchTag::X86_64 => "x86_64",
    };

    candidates
        .iter()
        .find(|a| a.name.ends_with(&format!("{}{}", preferred, ext)))
        .cloned()
        // Fallback: if exact v3 tag isn't found, accept plain x86_64
        // so non-AVX2 CPUs (or future releases without v3) still work
        .or_else(|| {
            if arch == HostArchTag::X86_64V3 {
                candidates
                    .iter()
                    .find(|a| {
                        a.name.ends_with(&format!("x86_64{}", ext)) && !a.name.contains("arm64")
                    })
                    .cloned()
            } else {
                None
            }
        })
        .or_else(|| candidates.first().cloned())
}

fn release_to_package(release: GithubRelease, src: &GithubSource) -> Option<ProtonPackage> {
    let tag = detect_host_arch_tag();
    let asset = select_asset(&release.assets, tag, src.ext)?;

    Some(ProtonPackage {
        name: release.tag_name,
        source: ProtonSource::Github {
            url: asset.browser_download_url,
            ext: src.ext.to_string(),
        },
        label: src.label.to_string(),
        size: asset.size,
    })
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
    let url = match package.source {
        ProtonSource::Github { url, .. } => url,
        _ => return Err(anyhow!("Package is not a GitHub source")),
    };
    let response = reqwest::get(&url).await?;
    let total_size = response.content_length().unwrap_or(package.size);

    let mut downloaded: u64 = 0;
    let mut stream = response.bytes_stream();

    let temp_dir = tempfile::tempdir()?;
    let tarball_path = temp_dir.path().join("proton.tar");

    {
        use futures::StreamExt;
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::File::create(&tarball_path).await?;
        while let Some(item) = stream.next().await {
            let chunk = item?;
            file.write_all(&chunk).await?;
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
                    browser_download_url: "https://github.com/GloriousEggroll/proton-ge-custom/releases/download/GE-Proton9-7/GE-Proton9-7.sha512sum".to_string(),
                    size: 100,
                },
                GithubAsset {
                    name: "GE-Proton9-7.tar.gz".to_string(),
                    browser_download_url: "https://github.com/GloriousEggroll/proton-ge-custom/releases/download/GE-Proton9-7/GE-Proton9-7.tar.gz".to_string(),
                    size: 500_000_000,
                },
            ],
        };
        let src = &GE_SOURCES[0]; // Proton-GE, .tar.gz
        let package = release_to_package(release, src).unwrap();
        assert_eq!(package.name, "GE-Proton9-7");
        if let ProtonSource::Github { url, .. } = package.source {
            assert_eq!(url, "https://github.com/GloriousEggroll/proton-ge-custom/releases/download/GE-Proton9-7/GE-Proton9-7.tar.gz");
        } else {
            panic!("Expected Github source");
        }
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
        assert_eq!(package.name, "cachyos-11.0-20260602-slr");
        if let ProtonSource::Github { url, .. } = package.source {
            assert_eq!(url, "url2");
        } else {
            panic!("Expected Github source");
        }
    }

    #[test]
    fn cachyos_prefers_x86_64_v3_on_avx2_host() {
        let assets = vec![
            GithubAsset {
                name: "proton-cachyos-11.0-20260602-slr-arm64.tar.xz".to_string(),
                browser_download_url: "url_arm".to_string(),
                size: 100,
            },
            GithubAsset {
                name: "proton-cachyos-11.0-20260602-slr-x86_64.tar.xz".to_string(),
                browser_download_url: "url_x64".to_string(),
                size: 100,
            },
            GithubAsset {
                name: "proton-cachyos-11.0-20260602-slr-x86_64_v3.tar.xz".to_string(),
                browser_download_url: "url_v3".to_string(),
                size: 100,
            },
        ];

        let selected = select_asset(&assets, HostArchTag::X86_64V3, ".tar.xz").unwrap();
        assert_eq!(selected.browser_download_url, "url_v3");

        let selected = select_asset(&assets, HostArchTag::X86_64, ".tar.xz").unwrap();
        assert_eq!(selected.browser_download_url, "url_x64");

        let selected = select_asset(&assets, HostArchTag::Arm64, ".tar.xz").unwrap();
        assert_eq!(selected.browser_download_url, "url_arm");
    }

    #[test]
    fn source_tarball_is_never_selected() {
        let assets = vec![GithubAsset {
            name: "proton-11.0-1-beta5.tar.gz".to_string(),
            browser_download_url: "https://github.com/ValveSoftware/Proton/archive/refs/tags/proton-11.0-1-beta5.tar.gz".to_string(),
            size: 100,
        }];

        let selected = select_asset(&assets, HostArchTag::X86_64, ".tar.gz");
        assert!(selected.is_none());
    }
}
