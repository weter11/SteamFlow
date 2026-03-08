use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn build_runner_command(runner_path: &Path) -> Result<Command> {
    let mut final_path = runner_path.to_path_buf();

    // 1. Directory Resolution: If it's a directory, find the binary
    if final_path.is_dir() {
        if final_path.join("proton").exists() {
            final_path.push("proton");
        } else if final_path.join("bin/wine").exists() {
            final_path.push("bin/wine");
        } else if final_path.join("bin/wine64").exists() {
            final_path.push("bin/wine64");
        }
    }

    // 2. Identification and Command Building
    if let Some(file_name) = final_path.file_name().and_then(|f| f.to_str()) {
        if file_name == "proton" {
            let mut cmd = Command::new(&final_path);
            cmd.arg("run");
            return Ok(cmd);
        }
        if file_name == "wine" || file_name == "wine64" {
            return Ok(Command::new(&final_path));
        }
    }

    // 3. Last Resort: Just return the command if it exists
    if final_path.exists() && final_path.is_file() {
        return Ok(Command::new(&final_path));
    }

    bail!("Failed to resolve a valid runner binary from {}", runner_path.display())
}

pub fn resolve_runner(name: &str, library_root: &Path) -> PathBuf {
    let name_path = Path::new(name);
    if name_path.is_absolute() || name_path.exists() {
        return name_path.to_path_buf();
    }

    // 1. Steam Library (steamapps/common)
    let steam_path = library_root.join("steamapps/common").join(name);
    if steam_path.exists() {
        return steam_path;
    }

    // 2. compatibilitytools.d (Steam Custom)
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let compat_path = PathBuf::from(&home).join(".local/share/Steam/compatibilitytools.d").join(name);
    if compat_path.exists() {
        return compat_path;
    }

    // 3. Lutris Runners
    let lutris_path = PathBuf::from(&home).join(".local/share/lutris/runners/wine").join(name);
    if lutris_path.exists() {
        return lutris_path;
    }

    // 4. Fallback to name as provided
    name_path.to_path_buf()
}

pub fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Result<()> {
    std::fs::create_dir_all(&dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

pub fn setup_fake_steam_trap(config_dir: &Path) -> Result<PathBuf> {
    let trap_dir = config_dir.join("fake_env");
    std::fs::create_dir_all(&trap_dir)?;

    let dummy_script = "#!/bin/sh\nexit 0\n";

    let steam_path = trap_dir.join("steam");
    let steam_sh_path = trap_dir.join("steam.sh");

    if !steam_path.exists() {
        std::fs::write(&steam_path, dummy_script)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&steam_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&steam_path, perms)?;
        }
    }

    if !steam_sh_path.exists() {
        std::fs::write(&steam_sh_path, dummy_script)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&steam_sh_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&steam_sh_path, perms)?;
        }
    }

    Ok(trap_dir)
}

#[derive(Debug, Clone, Default)]
pub struct RunnerComponents {
    pub dxvk: Option<ComponentInfo>,
    pub vkd3d_proton: Option<ComponentInfo>,
    pub vkd3d: Option<ComponentInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DetectionState {
    Found,
    Partial,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Architecture {
    X86_64,
    I386,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComponentInfo {
    pub version: String,
    pub source: ComponentSource,
    pub path: Option<PathBuf>,
    pub state: DetectionState,
    pub arches: Vec<Architecture>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ComponentSource {
    BundledWithRunner,
    InstalledInPrefix,
    SystemWide,
}

impl std::fmt::Display for ComponentSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BundledWithRunner => write!(f, "bundled"),
            Self::InstalledInPrefix => write!(f, "in prefix"),
            Self::SystemWide => write!(f, "system"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_short_version() {
        assert_eq!(parse_short_version("dxvk (v2.7.1-404-g0bf876eb)"), "2.7.1-404");
        assert_eq!(parse_short_version("v2.10.1"), "2.10.1");
        assert_eq!(parse_short_version("2.3-dirty"), "2.3-dirty");
        assert_eq!(parse_short_version("vkd3d-proton (v2.11-1-g1234567)"), "2.11-1");
        assert_eq!(parse_short_version(""), "unknown");
        assert_eq!(parse_short_version("   "), "unknown");
    }
}

pub fn derive_runner_root(binary_path: &Path) -> PathBuf {
    let parent = if binary_path.is_file() {
        binary_path.parent().unwrap_or(binary_path)
    } else {
        binary_path
    };
    // If it's in a 'bin' directory (like wine-tkg), the root is one level up
    if parent.file_name().map(|n| n == "bin").unwrap_or(false) {
        return parent.parent().unwrap_or(parent).to_path_buf();
    }

    // Otherwise (like proton script), the root is the parent directory
    parent.to_path_buf()
}

pub fn get_runner_layout_roots(runner_root: &Path) -> Vec<PathBuf> {
    let subdirs = [
        "lib/wine/dxvk",
        "lib/wine/vkd3d",
        "lib/wine/vkd3d-proton",
        "lib64/wine/dxvk",
        "lib64/wine/vkd3d",
        "lib64/wine/vkd3d-proton",
        "files/lib/wine/dxvk",
        "files/lib/wine/vkd3d",
        "files/lib/wine/vkd3d-proton",
        "files/lib64/wine/dxvk",
        "files/lib64/wine/vkd3d",
        "files/lib64/wine/vkd3d-proton",
        "files/lib/vkd3d",
        "files/lib/vkd3d-proton",
        "dist/lib/wine/dxvk",
        "dist/lib/wine/vkd3d",
        "dist/lib/wine/vkd3d-proton",
        "dist/lib64/wine/dxvk",
        "dist/lib64/wine/vkd3d",
        "dist/lib64/wine/vkd3d-proton",
    ];
    let mut roots: Vec<PathBuf> = subdirs.iter().map(|s| runner_root.join(s)).collect();

    // Proton often has multiple architectures in specialized subdirs under files/lib/vkd3d
    // These are handled by check_arch_aware_bundled searching for x86_64-windows etc.
    // but the root files/lib/vkd3d itself is already in the list above.

    roots.sort();
    roots.dedup();
    roots
}

pub fn detect_runner_components(
    runner_path: &Path,
    _prefix_ignored: Option<&Path>,
) -> RunnerComponents {
    let root = derive_runner_root(runner_path);

    let dxvk = detect_dxvk(&root);
    let vkd3d_proton = detect_vkd3d_proton(&root);
    let vkd3d = detect_vkd3d(&root);

    RunnerComponents {
        dxvk,
        vkd3d_proton,
        vkd3d,
    }
}

// ── DXVK ────────────────────────────────────────────────────────────────────

fn detect_dxvk(root: &Path) -> Option<ComponentInfo> {
    let required_dlls = ["d3d11.dll", "dxgi.dll", "d3d9.dll"];
    // Optional but expected: "d3d8.dll", "d3d10core.dll", etc.
    let all_expected = ["d3d11.dll", "dxgi.dll", "d3d9.dll", "d3d8.dll", "d3d10core.dll", "d3d10.dll", "d3d10_1.dll"];

    let version_files = [
        "files/share/dxvk/version",
        "dist/share/dxvk/version",
        "share/dxvk/version",
    ];

    // 1. Bundled
    if let Some(info) = check_arch_aware_bundled(root, "dxvk", &required_dlls, &all_expected, &version_files) {
        return Some(info);
    }

    // 2. System-wide
    let system_paths = [
        "/usr/share/dxvk/x64/d3d11.dll",
        "/usr/lib/dxvk/d3d11.dll",
        "/usr/lib/x86_64-linux-gnu/dxvk/d3d11.dll",
        "/usr/local/share/dxvk/x64/d3d11.dll",
    ];
    check_system(&system_paths)
}

fn detect_vkd3d_proton(root: &Path) -> Option<ComponentInfo> {
    let required_dlls = ["d3d12.dll", "d3d12core.dll"];
    let version_files = [
        "files/share/vkd3d-proton/version",
        "dist/share/vkd3d-proton/version",
        "share/vkd3d-proton/version",
    ];

    if let Some(info) = check_arch_aware_bundled(root, "vkd3d-proton", &required_dlls, &required_dlls, &version_files) {
        return Some(info);
    }

    let system_paths = [
        "/usr/share/vkd3d-proton/x64/d3d12.dll",
        "/usr/lib/vkd3d-proton/d3d12.dll",
        "/usr/local/share/vkd3d-proton/x64/d3d12.dll",
    ];
    check_system(&system_paths)
}

fn detect_vkd3d(root: &Path) -> Option<ComponentInfo> {
    let required_dlls = ["libvkd3d-1.dll", "libvkd3d-shader-1.dll"];
    let version_files = [
        "files/share/vkd3d/version",
        "dist/share/vkd3d/version",
        "share/vkd3d/version",
    ];

    if let Some(info) = check_arch_aware_bundled(root, "vkd3d", &required_dlls, &required_dlls, &version_files) {
        return Some(info);
    }

    let system_paths = [
        "/usr/lib/x86_64-linux-gnu/libvkd3d.so.1",
        "/usr/lib64/libvkd3d.so.1",
        "/usr/local/lib/libvkd3d.so.1",
    ];
    check_system(&system_paths)
}

fn check_arch_aware_bundled(
    root: &Path,
    component_name: &str,
    required_dlls: &[&str],
    _all_expected: &[&str],
    version_files: &[&str],
) -> Option<ComponentInfo> {
    let layout_roots = get_runner_layout_roots(root);
    let mut arches_found = Vec::new();
    let mut primary_path = None;

    let search_arches = [
        (Architecture::X86_64, "x86_64-windows"),
        (Architecture::I386, "i386-windows"),
    ];

    for lr in &layout_roots {
        let lr_s = lr.to_string_lossy();

        // Skip layout roots that don't belong to this component
        if component_name == "dxvk" {
             if lr_s.contains("vkd3d") {
                 continue;
             }
        } else if component_name == "vkd3d" {
             if lr_s.contains("vkd3d-proton") {
                 continue;
             }
             if !lr_s.contains("vkd3d") {
                 continue;
             }
        } else if !lr_s.contains(component_name) {
             continue;
        }

        let mut current_lr_arches = Vec::new();
        for (arch, subdir) in &search_arches {
            let arch_dir = lr.join(subdir);
            if arch_dir.exists() {
                let mut any_file_present = false;
                for dll in required_dlls {
                    if arch_dir.join(dll).exists() {
                        any_file_present = true;
                        break;
                    }
                }
                if any_file_present {
                    current_lr_arches.push(*arch);
                    if primary_path.is_none() {
                        // Find first existing dll to use as primary_path for version extraction
                        for dll in required_dlls {
                             let p = arch_dir.join(dll);
                             if p.exists() {
                                 primary_path = Some(p);
                                 break;
                             }
                        }
                    }
                }
            }
        }

        // If no arch subdirs, check the root itself for a flat layout
        if current_lr_arches.is_empty() {
             let mut any_file_present = false;
             for dll in required_dlls {
                 if lr.join(dll).exists() {
                     any_file_present = true;
                     break;
                 }
             }
             if any_file_present {
                 // Heuristic: assume x86_64 for flat layout
                 current_lr_arches.push(Architecture::X86_64);
                 if primary_path.is_none() {
                     for dll in required_dlls {
                         let p = lr.join(dll);
                         if p.exists() {
                             primary_path = Some(p);
                             break;
                         }
                     }
                 }
             }
        }

        for a in current_lr_arches {
            if !arches_found.contains(&a) {
                arches_found.push(a);
            }
        }
    }

    if arches_found.is_empty() {
        return None;
    }

    let state = if arches_found.len() == search_arches.len() {
        DetectionState::Found
    } else {
        DetectionState::Partial
    };

    let version = version_files
        .iter()
        .filter_map(|rel| {
            let p = root.join(rel);
            if p.exists() {
                std::fs::read_to_string(p).ok()
            } else {
                None
            }
        })
        .map(|s| parse_short_version(&s))
        .find(|s| s != "unknown")
        .or_else(|| {
             primary_path.as_ref().and_then(|p| extract_version_from_dll(p))
        })
        .unwrap_or_else(|| "unknown".to_string());

    let reason = match state {
        DetectionState::Found => None,
        DetectionState::Partial => {
            if arches_found.len() < search_arches.len() {
                Some(format!("Missing architectures. Found: {:?}", arches_found))
            } else {
                // Found both arches but maybe missing some optional DLLs?
                // Actually DetectionState::Found currently only checks arches.
                None
            }
        },
        DetectionState::NotFound => Some("No required DLLs found in any searched layout".into()),
    };

    Some(ComponentInfo {
        version,
        source: ComponentSource::BundledWithRunner,
        path: primary_path,
        state,
        arches: arches_found,
        reason,
    })
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn check_system(paths: &[&str]) -> Option<ComponentInfo> {
    for path in paths {
        let p = Path::new(path);
        if p.exists() {
            let version = extract_version_from_dll(p)
                .or_else(|| read_adjacent_version_file(p))
                .unwrap_or_else(|| "unknown".to_string());
            return Some(ComponentInfo {
                version,
                source: ComponentSource::SystemWide,
                path: Some(p.to_path_buf()),
                state: DetectionState::Found,
                arches: vec![Architecture::X86_64],
                reason: None,
            });
        }
    }
    None
}

fn read_adjacent_version_file(dll: &Path) -> Option<String> {
    let parent = dll.parent()?;
    let version_file = parent.join("version");
    std::fs::read_to_string(version_file)
        .ok()
        .map(|s| parse_short_version(&s))
        .filter(|s| !s.is_empty())
}

pub fn parse_short_version(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return "unknown".to_string();
    }

    // Try to find content inside parentheses first: dxvk (v2.7.1-404-g0bf876eb) -> v2.7.1-404-g0bf876eb
    let v = if let (Some(start), Some(end)) = (s.find('('), s.rfind(')')) {
        if start < end {
            &s[start + 1..end]
        } else {
            s
        }
    } else {
        s
    };

    let mut v = v.trim();

    // Strip leading 'v' if followed by a digit
    if v.starts_with('v') && v.len() > 1 && v.as_bytes()[1].is_ascii_digit() {
        v = &v[1..];
    }

    // Strip trailing git hash suffix: -g[0-9a-f]{7,10}
    // We look for the LAST "-g" followed by exactly 7-10 hex digits
    if let Some(hyphen_idx) = v.rfind("-g") {
        let suffix = &v[hyphen_idx + 2..];
        if !suffix.is_empty()
            && suffix.len() >= 7
            && suffix.len() <= 10
            && suffix.chars().all(|c| c.is_ascii_hexdigit())
        {
            return v[..hyphen_idx].to_string();
        }
    }

    v.to_string()
}


fn extract_version_from_dll(dll_path: &Path) -> Option<String> {
    let data = std::fs::read(dll_path).ok()?;

    // Collect all printable ASCII runs of length >= 4
    let mut runs: Vec<String> = Vec::new();
    let mut current = Vec::new();
    for &byte in &data {
        if byte >= 0x20 && byte < 0x7f {
            current.push(byte as char);
        } else {
            if current.len() >= 4 {
                runs.push(current.iter().collect());
            }
            current.clear();
        }
    }
    if current.len() >= 4 {
        runs.push(current.iter().collect());
    }

    // Match semver-like patterns: optional 'v', digits, dots, optional suffix
    // e.g. "2.3.1", "v1.10.3", "2.4-dirty", "v2.0.0-alpha.1+git"
    let semver_re = regex::Regex::new(r"^v?(\d{1,3})\.(\d{1,3})(\.\d{1,3})?([-.][a-zA-Z0-9._-]+)?$").ok()?;

    // Prefer strings that look like "vX.Y.Z" over bare "X.Y"
    let mut candidates: Vec<String> = runs
        .into_iter()
        .filter(|s| semver_re.is_match(s))
        .filter(|s| {
            // Exclude obviously non-version strings (all zeros, single digit etc.)
            let parts: Vec<&str> = s.trim_start_matches('v').splitn(2, '.').collect();
            parts.len() >= 2 && parts[0].parse::<u32>().unwrap_or(100) <= 99
        })
        .collect();

    // Sort: longer (more specific) versions first
    candidates.sort_by(|a, b| b.len().cmp(&a.len()));
    candidates.into_iter().next()
}

#[derive(Debug, Clone, PartialEq)]
pub enum GraphicsLayer {
    Dxvk,
    Vkd3dProton,
    Vkd3d,
}

/// Finds all source DLLs for a given layer from system paths.
/// Returns (x64_dir, x32_dir) if found.
pub fn find_layer_source(layer: &GraphicsLayer) -> Option<(PathBuf, Option<PathBuf>)> {
    let x64_candidates = match layer {
        GraphicsLayer::Dxvk => vec![
            "/usr/share/dxvk/x64",
            "/usr/lib/dxvk/x64",
            "/usr/lib/x86_64-linux-gnu/dxvk",
            "/usr/local/share/dxvk/x64",
        ],
        GraphicsLayer::Vkd3dProton => vec![
            "/usr/share/vkd3d-proton/x64",
            "/usr/lib/vkd3d-proton/x64",
            "/usr/local/share/vkd3d-proton/x64",
        ],
        GraphicsLayer::Vkd3d => vec![
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib64",
            "/usr/local/lib",
        ],
    };

    let x32_candidates = match layer {
        GraphicsLayer::Dxvk => vec![
            "/usr/share/dxvk/x32",
            "/usr/lib32/dxvk",                      // Arch multilib
            "/usr/lib/dxvk/x32",
            "/usr/lib/i386-linux-gnu/dxvk",          // Debian/Ubuntu
            "/usr/local/share/dxvk/x32",
            "/usr/lib/dxvk",                         // some Fedora layouts put both here
        ],
        GraphicsLayer::Vkd3dProton => vec![
            "/usr/share/vkd3d-proton/x86",
            "/usr/lib32/vkd3d-proton",               // Arch multilib
            "/usr/lib/vkd3d-proton/x86",
            "/usr/lib/i386-linux-gnu/vkd3d-proton",
            "/usr/local/share/vkd3d-proton/x86",
        ],
        GraphicsLayer::Vkd3d => vec![
            "/usr/lib/i386-linux-gnu",
            "/usr/lib32",
            "/usr/local/lib32",
        ],
    };

    let x64 = x64_candidates
        .iter()
        .map(|p| Path::new(p))
        .find(|p| p.exists() && layer_dir_has_dlls(p, layer))?
        .to_path_buf();

    let x32 = x32_candidates
        .iter()
        .map(|p| Path::new(p))
        .find(|p| p.exists() && layer_dir_has_dlls(p, layer))
        .map(|p| p.to_path_buf());

    Some((x64, x32))
}

fn layer_dir_has_dlls(dir: &Path, layer: &GraphicsLayer) -> bool {
    let sentinel = match layer {
        GraphicsLayer::Dxvk => "d3d11.dll",
        GraphicsLayer::Vkd3dProton => "d3d12.dll",
        GraphicsLayer::Vkd3d => "d3d12.dll",
    };
    dir.join(sentinel).exists()
}

/// Installs a graphics layer into the given WINEPREFIX by copying DLLs
/// into system32 (x64) and syswow64 (x32).
pub fn install_layer_into_prefix(layer: &GraphicsLayer, wineprefix: &Path) -> Result<Vec<String>> {
    let (x64_src, x32_src) =
        find_layer_source(layer).context("could not find source DLLs for graphics layer")?;

    let sys32 = wineprefix.join("drive_c/windows/system32");
    let sys64 = wineprefix.join("drive_c/windows/syswow64");
    std::fs::create_dir_all(&sys32)?;
    std::fs::create_dir_all(&sys64)?;

    let dlls_for = |layer: &GraphicsLayer| -> &[&str] {
        match layer {
            GraphicsLayer::Dxvk => &[
                "d3d8.dll",
                "d3d9.dll",
                "d3d10.dll",
                "d3d10_1.dll",
                "d3d10core.dll",
                "d3d11.dll",
                "dxgi.dll",
            ],
            GraphicsLayer::Vkd3dProton => &["d3d12.dll", "d3d12core.dll"],
            GraphicsLayer::Vkd3d => &["d3d12.dll", "libvkd3d-1.dll", "libvkd3d-shader-1.dll"],
        }
    };

    let mut installed = Vec::new();

    // x64 DLLs go into system32 (Wine's convention for 64-bit)
    for dll_name in dlls_for(layer) {
        let src = x64_src.join(dll_name);
        if src.exists() {
            let dst = sys32.join(dll_name);
            std::fs::copy(&src, &dst).with_context(|| format!("failed copying {} to system32", dll_name))?;
            installed.push(dll_name.to_string());
        }
    }

    // x32 DLLs go into syswow64 (Wine's convention for 32-bit)
    if let Some(x32) = x32_src {
        for dll_name in dlls_for(layer) {
            let src = x32.join(dll_name);
            if src.exists() {
                let dst = sys64.join(dll_name);
                std::fs::copy(&src, &dst).with_context(|| format!("failed copying {} to syswow64", dll_name))?;
            }
        }
    } else {
        tracing::warn!(
            "No 32-bit DLLs found for {:?} — 32-bit games (Batman, etc.) will not use this layer",
            layer
        );
        installed.push("(WARNING: no x32 DLLs found — 32-bit games unaffected)".to_string());
    }

    if installed.is_empty() {
        anyhow::bail!("no DLLs were copied — source directory may be empty");
    }

    Ok(installed)
}

/// Removes a graphics layer from the prefix, restoring Wine's builtins.
pub fn remove_layer_from_prefix(layer: &GraphicsLayer, wineprefix: &Path) -> Result<()> {
    let sys32 = wineprefix.join("drive_c/windows/system32");
    let sys64 = wineprefix.join("drive_c/windows/syswow64");

    let dlls: &[&str] = match layer {
        GraphicsLayer::Dxvk => &[
            "d3d9.dll",
            "d3d10.dll",
            "d3d10_1.dll",
            "d3d10core.dll",
            "d3d11.dll",
            "dxgi.dll",
        ],
        GraphicsLayer::Vkd3dProton => &["d3d12.dll", "d3d12core.dll"],
        GraphicsLayer::Vkd3d => &["d3d12.dll"],
    };

    for dll in dlls {
        for dir in [&sys32, &sys64] {
            let path = dir.join(dll);
            if path.exists() {
                std::fs::remove_file(&path).with_context(|| format!("failed removing {}", path.display()))?;
            }
        }
        // Special case for Wine-style DLLs which might have been copied without .dll suffix
        if dll.ends_with(".dll") {
            let stem = &dll[..dll.len() - 4];
            for dir in [&sys32, &sys64] {
                let path = dir.join(stem);
                if path.exists() && !path.is_dir() {
                     let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    Ok(())
}

/// Returns the WINEDLLOVERRIDES string needed to activate installed layers.
pub fn build_dll_overrides(
    dxvk_active: bool,
    vkd3d_proton_active: bool,
    vkd3d_active: bool,
    no_overlay: bool,
    game_dir: Option<&std::path::Path>, // check for game-local DLLs
) -> String {
    let mut overrides: Vec<String> = vec![
        "vstdlib_s=n".into(),
        "tier0_s=n".into(),
        "steamclient=n".into(),
        "steamclient64=n".into(),
        "steam_api=n".into(),
        "steam_api64=n".into(),
        "lsteamclient=".into(),
    ];

    if no_overlay {
        overrides.push("GameOverlayRenderer=n".into());
        overrides.push("GameOverlayRenderer64=n".into());
    }

    if dxvk_active {
        // If the game ships its own d3d DLLs, don't fight them — just
        // ensure native wins without specifying which native.
        // Wine searches exe-dir before system32, so "n,b" is fine UNLESS
        // a foreign dll landed in system32. We skip the override entirely
        // for DLLs the game already provides locally.
        let game_has = |dll: &str| -> bool { game_dir.map(|d| d.join(dll).exists()).unwrap_or(false) };

        for dll in &[
            "d3d8.dll",
            "d3d9.dll",
            "d3d10.dll",
            "d3d10_1.dll",
            "d3d10core.dll",
            "d3d11.dll",
            "dxgi.dll",
        ] {
            let stem = dll.trim_end_matches(".dll");
            if !game_has(dll) {
                overrides.push(format!("{stem}=n,b"));
            }
            // If the game ships it locally, leave Wine's default search order
            // alone — exe-dir native wins automatically.
        }
    }

    if vkd3d_proton_active || vkd3d_active {
        overrides.push("d3d12=n,b".into());
        overrides.push("d3d12core=n,b".into());
        if vkd3d_active {
             overrides.push("libvkd3d-1=n,b".into());
             overrides.push("libvkd3d-shader-1=n,b".into());
        }
    }

    overrides.join(";")
}

/// Detects the actual WINEPREFIX layout for the master Steam install.
/// Handles both master_steam_prefix/pfx/drive_c and master_steam_prefix/drive_c layouts.
pub fn resolve_master_wineprefix() -> PathBuf {
    let base = crate::config::config_dir()
        .unwrap_or_default()
        .join("master_steam_prefix");

    // Check direct layout first (drive_c directly under base) — this wins
    // if Steam was installed with WINEPREFIX=master_steam_prefix (no /pfx).
    // Only fall back to /pfx if drive_c genuinely lives there.
    if base.join("drive_c").exists() {
        return base;
    }
    if base.join("pfx/drive_c").exists() {
        return base.join("pfx");
    }

    // Fresh install default — Proton-style nesting
    base.join("pfx")
}

pub fn has_exe_binary(dir: &Path) -> bool {
    if !dir.exists() {
        return false;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if name.ends_with(".exe") {
                return true;
            }
            // Check one level deep for common 'bin' or 'launcher' folders
            if entry.path().is_dir() {
                if let Ok(sub) = std::fs::read_dir(entry.path()) {
                    for sub_entry in sub.flatten() {
                        if sub_entry.file_name().to_string_lossy().to_lowercase().ends_with(".exe") {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

pub fn steam_wineprefix_for_game(
    config: &crate::config::LauncherConfig,
    app_id: u32,
    user_configs: &crate::models::UserConfigStore,
) -> std::path::PathBuf {
    let mode = user_configs
        .get(&app_id)
        .map(|c| c.steam_prefix_mode.clone())
        .unwrap_or_default();

    match mode {
        crate::models::SteamPrefixMode::Shared => resolve_master_wineprefix(),
        crate::models::SteamPrefixMode::PerGame => {
            std::path::PathBuf::from(&config.steam_library_path)
                .join("steamapps/compatdata")
                .join(app_id.to_string())
                .join("pfx")
        }
    }
}
