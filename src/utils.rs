use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Clone)]
pub struct ComponentInfo {
    pub version: String,
    pub source: ComponentSource,
}

#[derive(Debug, Clone, PartialEq)]
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

pub fn detect_runner_components(
    runner_path: &Path,
    wineprefix: Option<&Path>,
) -> RunnerComponents {
    let root = derive_runner_root(runner_path);

    let (dxvk, vkd3d_proton, vkd3d) = (
        detect_dxvk(&root, wineprefix),
        detect_vkd3d_proton(&root, wineprefix),
        detect_vkd3d(&root, wineprefix),
    );


    RunnerComponents {
        dxvk,
        vkd3d_proton,
        vkd3d,
    }
}

/// Detects NVIDIA Optimus / hybrid graphics and returns the env vars needed
/// to force the discrete NVIDIA GPU. Returns empty map on non-hybrid systems.
pub fn detect_prime_env() -> std::collections::HashMap<String, String> {
    let mut vars = std::collections::HashMap::new();

    let has_nvidia_dev = std::path::Path::new("/dev/nvidia0").exists()
        || std::path::Path::new("/proc/driver/nvidia").exists();
    // Check for a second DRM device (the integrated one)
    let has_igpu = std::path::Path::new("/dev/dri/card1").exists();

    if has_nvidia_dev && has_igpu {
        // Optimus: force discrete NVIDIA for both Vulkan and OpenGL
        vars.insert("__NV_PRIME_RENDER_OFFLOAD".to_string(), "1".to_string());
        vars.insert(
            "__NV_PRIME_RENDER_OFFLOAD_PROVIDER".to_string(),
            "NVIDIA-G0".to_string(),
        );
        vars.insert(
            "__VK_LAYER_NV_optimus".to_string(),
            "NVIDIA_only".to_string(),
        );
        vars.insert("__GLX_VENDOR_LIBRARY_NAME".to_string(), "nvidia".to_string());

        // Also hint VKD3D-Proton via its own knob
        if let Ok(val) = std::env::var("VKD3D_FEATURE_FLAGS") {
            vars.insert("VKD3D_FEATURE_FLAGS".to_string(), val);
        }
    }

    vars
}

// ── DXVK ────────────────────────────────────────────────────────────────────

fn detect_dxvk(root: &Path, prefix: Option<&Path>) -> Option<ComponentInfo> {
    // 1. Bundled inside runner (Proton & Wine-TKG styles)
    let bundled_dlls = [
        "files/lib/wine/dxvk/d3d11.dll",
        "files/lib64/wine/dxvk/d3d11.dll",
        "files/lib/wine/x86_64-windows/d3d11.dll",
        "files/lib/wine/i386-windows/d3d11.dll",
        "dist/lib/wine/dxvk/d3d11.dll",
        "dist/lib64/wine/dxvk/d3d11.dll",
        "lib/wine/dxvk/d3d11.dll",
        "lib64/wine/dxvk/d3d11.dll",
        "lib/wine/x86_64-windows/d3d11.dll",
        "lib/wine/i386-windows/d3d11.dll",
    ];
    if let Some(info) = check_bundled(
        root,
        &bundled_dlls,
        &[
            "files/share/dxvk/version",
            "dist/share/dxvk/version",
            "share/dxvk/version",
        ],
    ) {
        return Some(info);
    }

    // 2. Installed into WINEPREFIX (winetricks / manual)
    if let Some(pfx) = prefix {
        let prefix_dlls = [
            "drive_c/windows/system32/d3d11.dll",
            "drive_c/windows/syswow64/d3d11.dll",
        ];
        if let Some(info) = check_prefix(pfx, &prefix_dlls, "DXVK") {
            return Some(info);
        }
    }

    // 3. System-wide (package manager install)
    let system_paths = [
        "/usr/share/dxvk/x64/d3d11.dll",
        "/usr/lib/dxvk/d3d11.dll",
        "/usr/lib/x86_64-linux-gnu/dxvk/d3d11.dll",
        "/usr/local/share/dxvk/x64/d3d11.dll",
    ];
    check_system(&system_paths)
}

// ── VKD3D-Proton ─────────────────────────────────────────────────────────────

fn detect_vkd3d_proton(root: &Path, prefix: Option<&Path>) -> Option<ComponentInfo> {
    let bundled_dlls = [
        "files/lib/wine/vkd3d-proton/d3d12.dll",
        "files/lib64/wine/vkd3d-proton/d3d12.dll",
        "files/lib/wine/x86_64-windows/d3d12.dll",
        "dist/lib/wine/vkd3d-proton/d3d12.dll",
        "dist/lib64/wine/vkd3d-proton/d3d12.dll",
        "lib/wine/vkd3d-proton/d3d12.dll",
        "lib64/wine/vkd3d-proton/d3d12.dll",
        "lib/wine/x86_64-windows/d3d12.dll",
    ];
    // VKD3D-Proton requires both d3d12.dll and d3d12core.dll for modern titles
    let core_bundled_dlls = [
        "files/lib/wine/vkd3d-proton/d3d12core.dll",
        "files/lib64/wine/vkd3d-proton/d3d12core.dll",
        "files/lib/wine/x86_64-windows/d3d12core.dll",
        "dist/lib/wine/vkd3d-proton/d3d12core.dll",
        "dist/lib64/wine/vkd3d-proton/d3d12core.dll",
        "lib/wine/vkd3d-proton/d3d12core.dll",
        "lib64/wine/vkd3d-proton/d3d12core.dll",
        "lib/wine/x86_64-windows/d3d12core.dll",
    ];

    if !core_bundled_dlls.iter().any(|rel| root.join(rel).exists()) {
        tracing::debug!("VKD3D-Proton partial: d3d12core.dll missing in bundled paths");
    }

    if let Some(info) = check_bundled(
        root,
        &bundled_dlls,
        &[
            "files/share/vkd3d-proton/version",
            "dist/share/vkd3d-proton/version",
            "share/vkd3d-proton/version",
        ],
    ) {
        return Some(info);
    }

    // VKD3D-Proton replaces d3d12.dll — check prefix for it
    // Distinguish from plain vkd3d by scanning for "vkd3d-proton" string in DLL
    if let Some(pfx) = prefix {
        let prefix_dlls = [
            "drive_c/windows/system32/d3d12.dll",
            "drive_c/windows/syswow64/d3d12.dll",
        ];
        for rel in prefix_dlls {
            let p = pfx.join(rel);
            if p.exists() {
                // Check binary for "vkd3d-proton" marker to distinguish from plain vkd3d
                if dll_contains_string(&p, "vkd3d-proton") {
                    let version = extract_version_from_dll(&p).unwrap_or_else(|| "unknown".to_string());
                    return Some(ComponentInfo {
                        version,
                        source: ComponentSource::InstalledInPrefix,
                    });
                }
            }
        }
    }

    let system_paths = [
        "/usr/share/vkd3d-proton/x64/d3d12.dll",
        "/usr/lib/vkd3d-proton/d3d12.dll",
        "/usr/local/share/vkd3d-proton/x64/d3d12.dll",
    ];
    check_system(&system_paths)
}

// ── VKD3D (upstream) ─────────────────────────────────────────────────────────

fn detect_vkd3d(root: &Path, prefix: Option<&Path>) -> Option<ComponentInfo> {
    // Upstream Wine VKD3D uses libvkd3d.dll/libvkd3d-1.dll and libvkd3d-shader.dll
    let bundled_dlls = [
        "files/lib/wine/vkd3d/libvkd3d-1.dll",
        "files/lib64/wine/vkd3d/libvkd3d-1.dll",
        "files/lib/wine/x86_64-windows/libvkd3d-1.dll",
        "files/lib/vkd3d/libvkd3d-1.dll",
        "dist/lib/wine/vkd3d/libvkd3d-1.dll",
        "lib/wine/vkd3d/libvkd3d-1.dll",
        "lib64/wine/vkd3d/libvkd3d-1.dll",
        "lib/wine/x86_64-windows/libvkd3d-1.dll",
        "files/lib/wine/vkd3d/d3d12.dll",
        "files/lib64/wine/vkd3d/d3d12.dll",
        "files/lib/vkd3d/d3d12.dll",
        "dist/lib/wine/vkd3d/d3d12.dll",
        "lib/wine/vkd3d/d3d12.dll",
    ];
    if let Some(info) = check_bundled(
        root,
        &bundled_dlls,
        &[
            "files/share/vkd3d/version",
            "dist/share/vkd3d/version",
            "share/vkd3d/version",
        ],
    ) {
        return Some(info);
    }

    if let Some(pfx) = prefix {
        let prefix_dlls = [
            "drive_c/windows/system32/d3d12.dll",
            "drive_c/windows/syswow64/d3d12.dll",
        ];
        for rel in prefix_dlls {
            let p = pfx.join(rel);
            if p.exists() && !dll_contains_string(&p, "vkd3d-proton") {
                let version = extract_version_from_dll(&p).unwrap_or_else(|| "unknown".to_string());
                return Some(ComponentInfo {
                    version,
                    source: ComponentSource::InstalledInPrefix,
                });
            }
        }
    }

    let system_paths = [
        "/usr/lib/x86_64-linux-gnu/libvkd3d.so.1",
        "/usr/lib64/libvkd3d.so.1",
        "/usr/local/lib/libvkd3d.so.1",
    ];
    check_system(&system_paths)
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn check_bundled(root: &Path, dll_candidates: &[&str], version_files: &[&str]) -> Option<ComponentInfo> {
    let found_dll = dll_candidates.iter().find(|rel| root.join(rel).exists());
    if let Some(rel) = found_dll {
        tracing::debug!("Found bundled component DLL at: {}", root.join(rel).display());
    } else {
        return None;
    }

    let version = version_files
        .iter()
        .filter_map(|rel| {
            let p = root.join(rel);
            if p.exists() {
                tracing::debug!("Found version file: {}", p.display());
                std::fs::read_to_string(p).ok()
            } else {
                None
            }
        })
        .map(|s| parse_short_version(&s))
        .find(|s| s != "unknown")
        .or_else(|| {
            dll_candidates
                .iter()
                .map(|rel| root.join(rel))
                .find(|p| p.exists())
                .and_then(|p| extract_version_from_dll(&p))
        })
        .unwrap_or_else(|| "unknown".to_string());

    Some(ComponentInfo {
        version,
        source: ComponentSource::BundledWithRunner,
    })
}

fn check_prefix(prefix: &Path, dll_candidates: &[&str], _name: &str) -> Option<ComponentInfo> {
    for rel in dll_candidates {
        let p = prefix.join(rel);
        if p.exists() {
            // Exclude Wine's own built-in wined3d stubs (very small, < 50KB)
            let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            if size < 51_200 {
                continue;
            }

            let version = extract_version_from_dll(&p).unwrap_or_else(|| "unknown".to_string());
            return Some(ComponentInfo {
                version,
                source: ComponentSource::InstalledInPrefix,
            });
        }
    }
    None
}

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

    // Try to find content inside parentheses first
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

    // Strip leading 'v'
    if v.starts_with('v') && v.len() > 1 && v.as_bytes()[1].is_ascii_digit() {
        v = &v[1..];
    }

    // Strip trailing git hash suffix: -g[0-9a-f]{7,10}
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

fn dll_contains_string(path: &Path, needle: &str) -> bool {
    let needle_lower = needle.to_ascii_lowercase();
    std::fs::read(path)
        .map(|bytes| {
            bytes.windows(needle.len()).any(|w| {
                w.iter()
                    .zip(needle_lower.bytes())
                    .all(|(b, n)| b.to_ascii_lowercase() == n)
            })
        })
        .unwrap_or(false)
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

/// Returns the WINEDLLOVERRIDES string needed to activate installed layers.
pub fn build_dll_overrides(
    dxvk_active: bool,
    vkd3d_proton_active: bool,
    vkd3d_active: bool,
    no_overlay: bool,
    force_builtin_d3d: bool, // NEW — for WineD3D policy
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

    if force_builtin_d3d {
        // Explicitly force Wine's own builtins for all D3D DLLs.
        // This overrides any native DLL sitting in the prefix's system32
        // from a previous DXVK/VKD3D install.
        for dll in &[
            "d3d8",
            "d3d9",
            "d3d10",
            "d3d10_1",
            "d3d10core",
            "d3d11",
            "dxgi",
            "d3d12",
            "d3d12core",
        ] {
            overrides.push(format!("{dll}=b"));
        }
        return overrides.join(";");
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedGpu {
    pub name: String,
    pub pci_id: Option<String>,
    pub is_discrete: bool,
}

pub fn list_available_gpus() -> Vec<DetectedGpu> {
    let mut gpus = Vec::new();

    // Try scanning /sys/class/drm/card* to find GPUs
    // This is more reliable than just checking /dev/dri/
    let drm_path = Path::new("/sys/class/drm");
    if let Ok(entries) = std::fs::read_dir(drm_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("card") && !name.contains('-') {
                let card_path = entry.path();

                // Read vendor and device IDs if available
                let device_path = card_path.join("device");
                let vendor = std::fs::read_to_string(device_path.join("vendor"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                let device = std::fs::read_to_string(device_path.join("device"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();

                let pci_id = if !vendor.is_empty() && !device.is_empty() {
                    Some(format!("{}:{}", vendor.replace("0x", ""), device.replace("0x", "")))
                } else {
                    None
                };

                // Heuristic for discrete vs integrated
                // This is a bit simplified, but often works on Linux
                let is_discrete = pci_id.as_ref().map(|id| {
                    // NVIDIA, AMD (discrete), etc.
                    id.starts_with("10de") || id.starts_with("1002")
                }).unwrap_or(false);

                let gpu_name = match pci_id.as_deref() {
                    Some(id) if id.starts_with("10de") => format!("NVIDIA GPU ({})", name),
                    Some(id) if id.starts_with("1002") => format!("AMD GPU ({})", name),
                    Some(id) if id.starts_with("8086") => format!("Intel GPU ({})", name),
                    _ => format!("Unknown GPU ({})", name),
                };

                gpus.push(DetectedGpu {
                    name: gpu_name,
                    pci_id,
                    is_discrete,
                });
            }
        }
    }

    // Fallback if /sys scan failed but we have NVIDIA tools or similar
    if gpus.is_empty() {
        if Path::new("/dev/nvidia0").exists() {
             gpus.push(DetectedGpu {
                 name: "NVIDIA Discrete GPU".to_string(),
                 pci_id: Some("10de:unknown".to_string()),
                 is_discrete: true,
             });
        }
    }

    gpus.sort_by(|a, b| b.is_discrete.cmp(&a.is_discrete));
    gpus
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
