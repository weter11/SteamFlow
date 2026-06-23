use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const VALVE_PROTONS: &[(&str, u32)] = &[
    ("Proton - Experimental", 1493710),
    ("Proton 11.0", 4628710),
    ("Proton 10.0", 3658110),
    ("Proton 9.0 (Beta)", 2805730),
    ("Proton 8.0", 2348590),
    ("Proton 7.0", 1887720),
    ("Proton 6.3", 1580130),
    ("Proton 5.13", 1420170),
    ("Proton 5.0", 1245040),
];

pub fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_lowercase()
}

pub const UNIFIED_LIB_SUBDIRS: &[&str] = &[
    "files/lib/wine",
    "files/lib64/wine",
    "lib/wine",
    "lib64/wine",
    "dist/lib/wine",
    "dist/lib64/wine",
];

pub const UNIFIED_BASE_LIB_SUBDIRS: &[&str] = &[
    "files/lib",
    "files/lib64",
    "lib",
    "lib64",
    "dist/lib",
    "dist/lib64",
];

pub const ARCH_SUBDIRS: &[(&str, &str)] = &[
    ("x86_64", "x86_64-windows"),
    ("i386", "i386-windows"),
    ("x86_64", "x86_64-unix"),
    ("i386", "i386-unix"),
];

pub const COMPONENT_FAMILIES: &[&str] = &[
    "dxvk",
    "d7vk",
    "vkd3d-proton",
    "vkd3d",
    "nvapi",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtonSource {
    Steam,
    Github,
}

#[derive(Debug, Clone)]
pub struct GithubSource {
    pub repo: &'static str,
    pub label: &'static str,
    pub ext: &'static str,
}

pub const PROTON_SOURCES: &[GithubSource] = &[
    GithubSource { repo: "GloriousEggroll/proton-ge-custom", label: "Proton-GE", ext: ".tar.gz" },
    GithubSource { repo: "GloriousEggroll/wine-ge-custom", label: "Wine-GE", ext: ".tar.xz" },
    GithubSource { repo: "CachyOS/proton-cachyos", label: "Proton-CachyOS", ext: ".tar.xz" },
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtonPackage {
    pub name: String,
    pub version: String,
    pub source: ProtonSource,
    pub download_url: Option<String>,
    pub size: u64,
    pub installed: bool,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledProton {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

pub fn detect_host_arch_tag() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            "x86_64_v3"
        } else {
            "x86_64"
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "unknown"
    }
}

pub async fn list_available() -> Result<Vec<ProtonPackage>> {
    let mut packages = Vec::new();

    // 1. Valve Protons (Steam)
    for (label, _) in VALVE_PROTONS {
        packages.push(ProtonPackage {
            name: label.to_string(),
            version: label.to_string(),
            source: ProtonSource::Steam,
            download_url: None,
            size: 0,
            installed: false,
            label: "Valve".to_string(),
        });
    }

    // 2. GitHub Sources
    let client = reqwest::Client::builder()
        .user_agent("SteamFlow")
        .build()?;

    let arch_tag = detect_host_arch_tag();

    for src in PROTON_SOURCES {
        let url = format!("https://api.github.com/repos/{}/releases", src.repo);
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            continue;
        }
        let releases: Vec<GithubRelease> = response.json().await?;

        for release in releases {
            if let Some(pkg) = release_to_package(&release, src, arch_tag) {
                packages.push(pkg);
            }
        }
    }

    Ok(packages)
}

fn release_to_package(release: &GithubRelease, src: &GithubSource, arch_tag: &str) -> Option<ProtonPackage> {
    let is_cachy = src.repo == "CachyOS/proton-cachyos";

    let asset = release.assets.iter().find(|a| {
        if a.browser_download_url.contains("/archive/refs/tags/") {
            return false;
        }

        if is_cachy {
            a.name.ends_with(&format!("{arch_tag}{}", src.ext))
        } else {
            a.name.ends_with(src.ext)
        }
    })?;

    let label = if is_cachy {
        format!("{} ({} — {} optimized)", src.label, arch_tag, if arch_tag == "x86_64_v3" { "AVX2" } else { "baseline" })
    } else {
        src.label.to_string()
    };

    Some(ProtonPackage {
        name: asset.name.trim_end_matches(src.ext).to_string(),
        version: release.tag_name.clone(),
        source: ProtonSource::Github,
        download_url: Some(asset.browser_download_url.clone()),
        size: asset.size,
        installed: false,
        label,
    })
}

pub fn list_installed(library_root: &Path) -> Result<Vec<InstalledProton>> {
    let mut installed = Vec::new();

    // 1. compatibilitytools.d
    let home = std::env::var("HOME").unwrap_or_default();
    let compat_paths = vec![
        PathBuf::from(&home).join(".local/share/Steam/compatibilitytools.d"),
        PathBuf::from(&home).join(".steam/steam/compatibilitytools.d"),
        crate::config::config_dir().unwrap_or_default().join("runtimes"),
    ];

    let mut seen_paths = std::collections::HashSet::new();

    for path in compat_paths {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let p = entry.path();
                    if let Ok(can) = std::fs::canonicalize(&p) {
                        if seen_paths.insert(can) {
                            installed.push(InstalledProton {
                                name: entry.file_name().to_string_lossy().to_string(),
                                path: p,
                            });
                        }
                    }
                }
            }
        }
    }

    // 2. steamapps/common (Valve Protons)
    let common_dir = library_root.join("steamapps/common");
    if let Ok(entries) = std::fs::read_dir(common_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if VALVE_PROTONS.iter().any(|(label, _)| *label == name) {
                let p = entry.path();
                if let Ok(can) = std::fs::canonicalize(&p) {
                    if seen_paths.insert(can) {
                        installed.push(InstalledProton {
                            name,
                            path: p,
                        });
                    }
                }
            }
        }
    }

    Ok(installed)
}

pub async fn install_github_package<F>(
    package: ProtonPackage,
    mut progress_cb: F,
) -> Result<()>
where F: FnMut(u64, u64) + Send + 'static
{
    let url = package.download_url.clone().ok_or_else(|| anyhow!("No download URL"))?;
    let client = reqwest::Client::new();
    let mut response = client.get(url).send().await?;
    let total_size = response.content_length().unwrap_or(package.size);

    let home = std::env::var("HOME").unwrap_or_default();
    let target_dir = PathBuf::from(&home).join(".local/share/Steam/compatibilitytools.d");
    tokio::fs::create_dir_all(&target_dir).await?;

    let archive_name = package.download_url.as_ref()
        .and_then(|u| u.split('/').last())
        .unwrap_or("proton_archive.tar.gz");
    let archive_path = target_dir.join(archive_name);

    let mut file = tokio::fs::File::create(&archive_path).await?;
    let mut downloaded = 0u64;

    while let Some(chunk) = response.chunk().await? {
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await?;
        downloaded += chunk.len() as u64;
        progress_cb(downloaded, total_size);
    }

    // Extract
    let output = std::process::Command::new("tar")
        .arg("-xf")
        .arg(&archive_path)
        .arg("-C")
        .arg(&target_dir)
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("Extraction failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Remove archive
    let _ = std::fs::remove_file(archive_path);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_tag() {
        let tag = detect_host_arch_tag();
        assert!(tag == "x86_64" || tag == "x86_64_v3" || tag == "arm64" || tag == "unknown");
    }

    #[test]
    fn test_release_to_package_cachy() {
        let release = GithubRelease {
            tag_name: "11.0-20260602".to_string(),
            assets: vec![
                GithubAsset {
                    name: "proton-cachyos-11.0-20260602-x86_64.tar.xz".to_string(),
                    browser_download_url: "https://example.com/x86_64.tar.xz".to_string(),
                    size: 100,
                },
                GithubAsset {
                    name: "proton-cachyos-11.0-20260602-x86_64_v3.tar.xz".to_string(),
                    browser_download_url: "https://example.com/x86_64_v3.tar.xz".to_string(),
                    size: 200,
                },
            ],
        };
        let src = &PROTON_SOURCES[2]; // Proton-CachyOS

        let pkg_v3 = release_to_package(&release, src, "x86_64_v3").unwrap();
        assert_eq!(pkg_v3.name, "proton-cachyos-11.0-20260602-x86_64_v3");
        assert_eq!(pkg_v3.download_url.unwrap(), "https://example.com/x86_64_v3.tar.xz");

        let pkg_v1 = release_to_package(&release, src, "x86_64").unwrap();
        assert_eq!(pkg_v1.name, "proton-cachyos-11.0-20260602-x86_64");
        assert_eq!(pkg_v1.download_url.unwrap(), "https://example.com/x86_64.tar.xz");
    }
}

pub fn remove(package_name: &str, library_root: &Path) -> Result<()> {
    let installed = list_installed(library_root)?;
    let p = installed.iter().find(|i| i.name == package_name)
        .ok_or_else(|| anyhow!("Package not found: {}", package_name))?;

    if p.path.is_dir() {
        std::fs::remove_dir_all(&p.path)?;
    } else {
        std::fs::remove_file(&p.path)?;
    }

    Ok(())
}
