use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunnerKind {
    /// A real Proton tree: has a `proton` script AND a bundled `protonfixes/` python package.
    Proton {
        proton_script: PathBuf,
        bundled_wine64: Option<PathBuf>,
        has_protonfixes: bool,
    },
    /// Plain Wine / wine-tkg: a `wine`/`wine64` binary with no Proton script and no
    /// bundled protonfixes package.
    PlainWine {
        wine64: PathBuf,
        wine32: Option<PathBuf>,
    },
    Unknown,
}

pub fn classify_runner(runner_path: &Path) -> RunnerKind {
    let root = if runner_path.is_file() {
        if runner_path.file_name().and_then(|n| n.to_str()) == Some("proton") {
            runner_path.parent().unwrap_or(runner_path).to_path_buf()
        } else {
            derive_runner_root(runner_path)
        }
    } else {
        runner_path.to_path_buf()
    };

    let proton_script = root.join("proton");
    let has_protonfixes = ["protonfixes", "files/protonfixes", "dist/protonfixes"]
        .iter()
        .any(|p| root.join(p).is_dir());
    if proton_script.is_file() {
        let bundled_wine64 = ["files/bin/wine64", "dist/bin/wine64", "bin/wine64", "files/bin/wine", "dist/bin/wine", "bin/wine"]
            .iter()
            .map(|p| root.join(p))
            .find(|p| p.is_file());
        return RunnerKind::Proton { proton_script, bundled_wine64, has_protonfixes };
    }

    if runner_path.is_file() {
        if let Some(name) = runner_path.file_name().and_then(|n| n.to_str()) {
            if name == "wine64" || name == "wine" {
                let parent = runner_path.parent().unwrap_or(runner_path);
                let wine32 = if name == "wine64" {
                    let p = parent.join("wine");
                    p.is_file().then_some(p)
                } else {
                    None
                };
                return RunnerKind::PlainWine { wine64: runner_path.to_path_buf(), wine32 };
            }
        }
    }

    if runner_path.is_dir() && !runner_path.join("proton").is_file() {
        for candidate in ["bin/wine64", "bin/wine"] {
            let wine = runner_path.join(candidate);
            if wine.is_file() {
                let wine32 = runner_path.join("bin/wine");
                return RunnerKind::PlainWine {
                    wine64: wine,
                    wine32: wine32.is_file().then_some(wine32),
                };
            }
        }
    }

    RunnerKind::Unknown
}

pub fn validate_steam_runtime_runner_path(runner_path: &Path) -> Option<String> {
    if runner_path.as_os_str().is_empty() {
        return None;
    }
    matches!(classify_runner(runner_path), RunnerKind::Unknown).then(|| {
        format!(
            "Steam Runtime Runner '{}' is not a recognized Proton or Wine runner.",
            runner_path.display()
        )
    })
}

#[cfg(unix)]
pub fn detect_active_wineserver_runtime(wineprefix: &Path) -> Option<PathBuf> {
    detect_active_wineserver_runtime_filtered(wineprefix, false)
}

/// Scans `/proc` for a wine/wineserver process whose environment references
/// `wineprefix`, and returns the path to its `exe`.
///
/// When `exclude_steam` is true, processes whose cmdline contains `steam.exe`
/// are ignored. In the split-runtime architecture the background Windows
/// Steam client runs under `steam_runtime_runner` while the game uses a
/// different runner — both in the same `WINEPREFIX` in Shared mode.
/// The Steam client is expected and not a conflict.
#[cfg(unix)]
pub fn detect_active_wineserver_runtime_filtered(
    wineprefix: &Path,
    exclude_steam: bool,
) -> Option<PathBuf> {
    let prefix_str = wineprefix.to_string_lossy().to_string();
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let pid_path = entry.path();
        if !pid_path.file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(false)
        {
            continue;
        }
        let Ok(environ) = std::fs::read(pid_path.join("environ")) else { continue; };
        let environ_str = String::from_utf8_lossy(&environ);
        if !environ_str.contains(&prefix_str) { continue; }
        let Ok(cmdline) = std::fs::read(pid_path.join("cmdline")) else { continue; };
        let cmdline_str = String::from_utf8_lossy(&cmdline).to_lowercase();
        if !cmdline_str.contains("wine") { continue; }
        if exclude_steam && cmdline_str.contains("steam.exe") { continue; }
        if let Ok(exe) = std::fs::read_link(pid_path.join("exe")) {
            return Some(exe);
        }
    }
    None
}

#[cfg(not(unix))]
pub fn detect_active_wineserver_runtime(_wineprefix: &Path) -> Option<PathBuf> {
    None
}

#[cfg(not(unix))]
pub fn detect_active_wineserver_runtime_filtered(_wineprefix: &Path, _exclude_steam: bool) -> Option<PathBuf> {
    None
}

/// Detect a wineserver belonging to a specific runner that is running in the given prefix.
/// Returns the path to the wineserver binary (from that runner's tree) if found.
/// Unlike detect_active_wineserver_runtime, this accepts a runner_path to scope the match:
/// only a wineserver whose runner root matches the given runner is returned.
/// This lets the caller distinguish "the active wineserver belongs to the game's own runner"
/// (no conflict) from "a different runner's wineserver is active" (conflict).
#[cfg(unix)]
pub fn detect_wineserver_for_runner(
    wineprefix: &Path,
    runner_path: &Path,
) -> Option<PathBuf> {
    let prefix_str = wineprefix.to_string_lossy().to_string();
    let runner_root = derive_runner_root(runner_path);
    let runner_root_lossy = runner_root.to_string_lossy().to_string();
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let pid_path = entry.path();
        if !pid_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(false)
        {
            continue;
        }
        let environ = std::fs::read(pid_path.join("environ")).ok()?;
        let environ_str = String::from_utf8_lossy(&environ);
        if !environ_str.contains(&prefix_str) {
            continue;
        }
        let cmdline = std::fs::read(pid_path.join("cmdline")).ok()?;
        let cmdline_str = String::from_utf8_lossy(&cmdline);
        if !cmdline_str.to_lowercase().contains("wineserver") {
            continue;
        }
        if let Ok(exe) = std::fs::read_link(pid_path.join("exe")) {
            let exe_str = exe.to_string_lossy().to_string();
            if exe_str.contains(&runner_root_lossy) {
                return Some(exe);
            }
        }
    }
    None
}

pub fn kill_all_wine_in_prefix(wineprefix: &Path, preserve_webhelper: bool) {
    // Same /proc scan pattern as is_steam_running_in_prefix and kill_steam_in_prefix
    // but match on any process whose cmdline contains "wine" (case-insensitive)
    // and whose environ contains the prefix path
    // Send SIGTERM first; this covers: wine, wine64, wineserver, winedevice,
    // plugplay, steam.exe, steamwebhelper.exe, the game exe itself
    #[cfg(unix)]
    {
        let prefix_str = wineprefix.to_string_lossy().to_string();

        // Phase 1: collect PIDs, then SIGTERM all prefix wine processes.
        let mut killed_pids: Vec<i32> = Vec::new();
        if let Ok(proc_dir) = std::fs::read_dir("/proc") {
            for entry in proc_dir.flatten() {
                let pid_path = entry.path();
                let Some(pid_str) = pid_path.file_name()
                    .and_then(|n| n.to_str())
                    .filter(|n| n.chars().all(|c| c.is_ascii_digit()))
                else { continue };
                let environ = match std::fs::read(pid_path.join("environ")) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                if !String::from_utf8_lossy(&environ).contains(&prefix_str) { continue }
                let cmdline = std::fs::read(pid_path.join("cmdline"))
                    .map(|b| String::from_utf8_lossy(&b).to_string())
                    .unwrap_or_default();
                let lower = cmdline.to_lowercase();
                if !lower.contains("wine") { continue }
                // Preserve steamwebhelper when the caller asked for it (Manage /
                // Repair with "Disable CEF browser" unchecked): the web helper is
                // needed for the client's login flow and UI.
                if preserve_webhelper && lower.contains("steamwebhelper.exe") {
                    continue;
                }
                if let Ok(pid) = pid_str.parse::<i32>() {
                    unsafe { libc::kill(pid, libc::SIGTERM); }
                    killed_pids.push(pid);
                }
            }
        }

        // Phase 2: wait for all SIGTERM'd processes to die (up to 3 seconds).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let alive: Vec<i32> = killed_pids.iter().copied().filter(|pid| {
                unsafe { libc::kill(*pid, 0) == 0 }
            }).collect();
            if alive.is_empty() { break; }
            if std::time::Instant::now() > deadline { break; }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // Phase 3: SIGKILL any stragglers (winedevice.exe commonly survives SIGTERM
        // because it defers shutdown until pending device I/O completes).
        if let Ok(proc_dir) = std::fs::read_dir("/proc") {
            for entry in proc_dir.flatten() {
                let pid_path = entry.path();
                let Some(pid_str) = pid_path.file_name()
                    .and_then(|n| n.to_str())
                    .filter(|n| n.chars().all(|c| c.is_ascii_digit()))
                else { continue };
                let environ = match std::fs::read(pid_path.join("environ")) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                if !String::from_utf8_lossy(&environ).contains(&prefix_str) { continue }
                let cmdline = std::fs::read(pid_path.join("cmdline"))
                    .map(|b| String::from_utf8_lossy(&b).to_string())
                    .unwrap_or_default();
                if !cmdline.to_lowercase().contains("wine") { continue }
                if let Ok(pid) = pid_str.parse::<i32>() {
                    unsafe { libc::kill(pid, libc::SIGKILL); }
                }
            }
        }
    }
}


/// Kill only wineserver processes in a prefix that belong to a specific runner.
/// Unlike kill_all_wine_in_prefix, this preserves wine processes for other runners
/// (e.g., a background Steam client running under wine-tkg should survive when
/// proton-cachyos kills its own stale wineserver).
#[cfg(unix)]
pub fn kill_wineserver_in_prefix(wineprefix: &Path) {
    let prefix_str = wineprefix.to_string_lossy().to_string();
    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let pid_path = entry.path();
            let Some(pid_str) = pid_path.file_name()
                .and_then(|n| n.to_str())
                .filter(|n| n.chars().all(|c| c.is_ascii_digit()))
            else { continue };
            let environ = match std::fs::read(pid_path.join("environ")) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if !String::from_utf8_lossy(&environ).contains(&prefix_str) { continue }
            let cmdline = match std::fs::read(pid_path.join("cmdline")) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let cmdline_str = String::from_utf8_lossy(&cmdline);
            // Only kill wineserver, not steam.exe or other wine processes
            if !cmdline_str.to_lowercase().contains("wineserver") { continue }
            if let Ok(pid) = pid_str.parse::<i32>() {
                unsafe { libc::kill(pid, libc::SIGTERM); }
            }
        }
    }
}

#[cfg(not(unix))]
pub fn kill_wineserver_in_prefix(_wineprefix: &Path) {}

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

/// Builds a command that points directly to a bare Wine binary, bypassing any
/// Proton scripts or bootstrap logic. This is critical for background Steam
/// management where we want minimal interference.
pub fn build_bare_wine_command(runner_path: &Path) -> Result<Command> {
    match classify_runner(runner_path) {
        RunnerKind::PlainWine { wine64, .. } => Ok(Command::new(wine64)),
        RunnerKind::Proton { bundled_wine64: Some(wine64), .. } => Ok(Command::new(wine64)),
        RunnerKind::Proton { bundled_wine64: None, .. } => {
            bail!("Proton tree {} has no bundled wine64", runner_path.display())
        }
        RunnerKind::Unknown => {
            // Fallback for ad-hoc paths
            if runner_path.is_file() {
                Ok(Command::new(runner_path))
            } else {
                bail!("Could not resolve bare Wine binary from {}", runner_path.display())
            }
        }
    }
}

/// Resolves the effective Proton/Wine runner *name* (not yet an absolute path)
/// that will be used to launch `app_id`, using the same precedence as
/// `WineTkgRunner::effective_game_proton`:
///   1. the per-game override (`LauncherConfig.game_configs[app_id].forced_proton_version`)
///   2. an explicit `proton_path` passed into this launch (`PipelineContext::proton_path`)
///   3. the global default (`LauncherConfig.proton_version`)
///
/// IMPORTANT: this must stay in sync with the resolution logic inside
/// `WineTkgRunner::effective_game_proton`. Any pipeline stage that needs
/// to know "which runner is this game actually using" (e.g. DLL/component
/// detection in ResolveDllProvidersStage) should call this instead of
/// re-deriving it, or it can silently disagree with the runner that
/// actually launches the process.
pub fn resolve_effective_proton_name<'a>(
    app_id: u32,
    launcher_config: &'a crate::config::LauncherConfig,
    ctx_proton_path: Option<&'a str>,
) -> &'a str {
    if let Some(forced) = launcher_config
        .game_configs
        .get(&app_id)
        .and_then(|c| c.forced_proton_version.as_ref())
    {
        forced.as_str()
    } else {
        ctx_proton_path
            .filter(|p| !p.is_empty())
            .unwrap_or(launcher_config.proton_version.as_str())
    }
}

pub fn resolve_runner(name: &str, library_root: &Path) -> PathBuf {
    let name_path = Path::new(name);
    if name_path.is_absolute() || name_path.exists() {
        return name_path.to_path_buf();
    }

    // 1. Steam Library (steamapps/common)
    let common_dir = library_root.join("steamapps/common");
    let steam_path = common_dir.join(name);
    if steam_path.exists() {
        return steam_path;
    }

    // Fallback: Normalized match in steamapps/common
    if let Ok(entries) = std::fs::read_dir(&common_dir) {
        let normalized_input = crate::proton::normalize_name(name);
        for entry in entries.flatten() {
            if let Ok(file_name) = entry.file_name().into_string() {
                if crate::proton::normalize_name(&file_name) == normalized_input {
                    let path = entry.path();
                    if path.is_dir() {
                        tracing::debug!("Found normalized runner match: {} -> {}", name, file_name);
                        return path;
                    }
                }
            }
        }
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
    tracing::warn!(
        "Runner '{}' not found in searched locations: {:?}, {:?}, {:?}",
        name,
        library_root.join("steamapps/common"),
        PathBuf::from(&home).join(".local/share/Steam/compatibilitytools.d"),
        PathBuf::from(&home).join(".local/share/lutris/runners/wine")
    );
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunnerComponents {
    pub dxvk: Option<ComponentInfo>,
    pub d7vk: Option<ComponentInfo>,
    pub vkd3d_proton: Option<ComponentInfo>,
    pub vkd3d: Option<ComponentInfo>,
    pub nvapi: Option<ComponentInfo>,
    pub dxvk_nvapi: Option<ComponentInfo>,
    /// True when lib64/wine/i386-windows/ contains valid 32-bit PE DLLs
    /// (dxgi.dll, d3d11.dll, d3d12.dll, ddraw.dll) — confirms 32-bit game compatibility.
    pub has_wow64_32bit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentInfo {
    pub version: String,
    pub source: ComponentSource,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// Convert a (possibly Unix) path into a Windows-style path string (backslashes,
/// drive-letter form when it sits under a Wine prefix's drive_c). Used for env vars
/// such as STEAM_COMPAT_CLIENT_INSTALL_PATH that Proton expects in `C:\\...` form.
pub fn to_windows_path(path: &Path) -> String {
    let s = path.to_string_lossy().replace('/', "\\");
    // If this looks like a Wine prefix dosdevice path, normalise to a C:\ drive letter.
    if let Some(idx) = s.to_lowercase().find("drive_c") {
        let rest = &s[idx + "drive_c".len()..];
        return format!("C:{}", rest);
    }
    s
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

    let (mut dxvk, mut d7vk, mut vkd3d_proton, mut vkd3d, mut nvapi) = (
        detect_dxvk(&root, wineprefix),
        detect_d7vk(&root, wineprefix),
        detect_vkd3d_proton(&root, wineprefix),
        detect_vkd3d(&root, wineprefix),
        detect_nvapi(&root, wineprefix),
    );
    let mut dxvk_nvapi = detect_dxvk_nvapi(&root, wineprefix);

    let versions = read_versions_txt(&root);
    apply_versions_override(&mut dxvk, &versions, "dxvk");
    apply_versions_override(&mut d7vk, &versions, "d7vk");
    apply_versions_override(&mut vkd3d_proton, &versions, "vkd3d_proton");
    apply_versions_override(&mut vkd3d, &versions, "vkd3d");
    apply_versions_override(&mut nvapi, &versions, "nvapi");
    apply_versions_override(&mut dxvk_nvapi, &versions, "dxvk_nvapi");

    let has_wow64_32bit = ["lib64/wine/i386-windows", "files/lib64/wine/i386-windows", "dist/lib64/wine/i386-windows"]
        .iter()
        .any(|d| {
            let dir = root.join(d);
            ["dxgi.dll", "d3d11.dll", "d3d12.dll", "ddraw.dll"]
                .iter()
                .any(|dll| dir.join(dll).exists())
        });

    RunnerComponents {
        dxvk,
        d7vk,
        vkd3d_proton,
        vkd3d,
        nvapi,
        dxvk_nvapi,
        has_wow64_32bit,
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

fn detect_d7vk(root: &Path, _prefix: Option<&Path>) -> Option<ComponentInfo> {
    // 1. Bundled inside runner (Modern Wine-TKG layout)
    let comp_subdirs = ["lib/wine/d7vk", "files/lib/wine/d7vk", "dist/lib/wine/d7vk"];
    let required = ["ddraw.dll"];

    for subdir in comp_subdirs {
        let comp_path = root.join(subdir);
        if comp_path.is_dir() {
            // Check arch subfolders
            for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
                let arch_path = comp_path.join(arch_dir);
                if required.iter().all(|dll| arch_path.join(dll).exists()) {
                    let version = ["version", "../version"] // check in arch or component folder
                        .iter()
                        .filter_map(|v| {
                            let p = arch_path.join(v);
                            std::fs::read_to_string(p).ok()
                        })
                        .map(|s| parse_short_version(&s))
                        .find(|s| s != "unknown")
                        .unwrap_or_else(|| "found".to_string());

                    return Some(ComponentInfo {
                        version,
                        source: ComponentSource::BundledWithRunner,
                        path: Some(arch_path),
                    });
                }
            }
        }
    }

    // Unified layout (Proton 11+ / CachyOS)
    for subdir in crate::proton::COMPONENT_LIB_SUBDIRS {
        for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
            let arch_path = root.join(subdir).join(arch_dir);
            if required.iter().all(|dll| arch_path.join(dll).exists()) {
                let version = ["version", "../version", "../../version"]
                    .iter()
                    .filter_map(|v| {
                        let p = arch_path.join(v);
                        std::fs::read_to_string(p).ok()
                    })
                    .map(|s| parse_short_version(&s))
                    .find(|s| s != "unknown")
                    .unwrap_or_else(|| "found".to_string());

                return Some(ComponentInfo {
                    version,
                    source: ComponentSource::BundledWithRunner,
                    path: Some(arch_path),
                });
            }
        }
    }

    None
}

fn detect_dxvk_nvapi(root: &Path, prefix: Option<&Path>) -> Option<ComponentInfo> {
    // 1. Bundled inside runner (Modern Wine-TKG layout)
    let comp_subdirs = [
        "lib/wine/dxvk-nvapi",
        "files/lib/wine/dxvk-nvapi",
        "dist/lib/wine/dxvk-nvapi",
    ];
    let required = vec!["nvapi64.dll", "nvofapi64.dll"];
    let alt_required = vec!["nvapi.dll"];

    for subdir in comp_subdirs {
        let comp_path = root.join(subdir);
        if comp_path.is_dir() {
            for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
                let arch_path = comp_path.join(arch_dir);
                let req = if *arch_dir == "i386-windows" {
                    &alt_required
                } else {
                    &required
                };
                if req.iter().all(|dll| arch_path.join(dll).exists()) {
                    let version = ["version", "../version"]
                        .iter()
                        .filter_map(|v| {
                            let p = arch_path.join(v);
                            std::fs::read_to_string(p).ok()
                        })
                        .map(|s| parse_short_version(&s))
                        .find(|s| s != "unknown")
                        .unwrap_or_else(|| "found".to_string());

                    return Some(ComponentInfo {
                        version,
                        source: ComponentSource::BundledWithRunner,
                        path: Some(arch_path),
                    });
                }
            }
        }
    }

    // 2. Installed into WINEPREFIX (dxvk-nvapi often deployed to system32)
    if let Some(pfx) = prefix {
        let prefix_dlls = vec!["drive_c/windows/system32/nvapi64.dll"];
        if let Some(info) = check_prefix(pfx, &prefix_dlls, "DXVK-NVAPI") {
            return Some(info);
        }
    }

    None
}

fn detect_dxvk(root: &Path, prefix: Option<&Path>) -> Option<ComponentInfo> {
    // 1. Bundled inside runner (Modern Wine-TKG layout)
    let comp_subdirs = ["lib/wine/dxvk", "files/lib/wine/dxvk", "dist/lib/wine/dxvk"];
    let required = ["d3d11.dll", "dxgi.dll", "d3d9.dll", "d3d8.dll", "d3d10core.dll"];

    for subdir in comp_subdirs {
        let comp_path = root.join(subdir);
        if comp_path.is_dir() {
            // Check arch subfolders
            for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
                let arch_path = comp_path.join(arch_dir);
                if required.iter().all(|dll| arch_path.join(dll).exists()) {
                    let version = ["version", "../version"] // check in arch or component folder
                        .iter()
                        .filter_map(|v| {
                            let p = arch_path.join(v);
                            std::fs::read_to_string(p).ok()
                        })
                        .map(|s| parse_short_version(&s))
                        .find(|s| s != "unknown")
                        .unwrap_or_else(|| "found".to_string());

                    return Some(ComponentInfo {
                        version,
                        source: ComponentSource::BundledWithRunner,
                        path: Some(arch_path),
                    });
                }
            }
        }
    }

    // Unified layout (Proton 11+ / CachyOS)
    for subdir in crate::proton::COMPONENT_LIB_SUBDIRS {
        for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
            let arch_path = root.join(subdir).join(arch_dir);
            if required.iter().all(|dll| arch_path.join(dll).exists()) {
                let version = ["version", "../version", "../../version"]
                    .iter()
                    .filter_map(|v| {
                        let p = arch_path.join(v);
                        std::fs::read_to_string(p).ok()
                    })
                    .map(|s| parse_short_version(&s))
                    .find(|s| s != "unknown")
                    .unwrap_or_else(|| "found".to_string());

                return Some(ComponentInfo {
                    version,
                    source: ComponentSource::BundledWithRunner,
                    path: Some(arch_path),
                });
            }
        }
    }

    // Legacy/Proton fallback
    let bundled_dlls = [
        "files/lib64/wine/dxvk/d3d11.dll",
        "files/lib/wine/dxvk/d3d11.dll",
        "dist/lib64/wine/dxvk/d3d11.dll",
        "dist/lib/wine/dxvk/d3d11.dll",
        "lib64/wine/dxvk/d3d11.dll",
        "lib/wine/dxvk/d3d11.dll",
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
    // 0. Content-based rule for flat WoW64 layouts (steamflow-runner):
    //    both d3d12.dll AND d3d12core.dll in the same dir => VKD3D-Proton.
    //    (Wine's built-in VKD3D ships only d3d12.dll.)
    for subdir in ["lib64/wine", "files/lib64/wine", "dist/lib64/wine", "lib/wine", "files/lib/wine", "dist/lib/wine"] {
        for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
            let arch_path = root.join(subdir).join(arch_dir);
            if arch_path.join("d3d12.dll").exists() && arch_path.join("d3d12core.dll").exists() {
                let version = ["version", "../version", "../../version"]
                    .iter()
                    .filter_map(|v| {
                        let p = arch_path.join(v);
                        std::fs::read_to_string(p).ok()
                    })
                    .map(|s| parse_short_version(&s))
                    .find(|s| s != "unknown")
                    .unwrap_or_else(|| "found".to_string());
                return Some(ComponentInfo {
                    version,
                    source: ComponentSource::BundledWithRunner,
                    path: Some(arch_path),
                });
            }
        }
    }

    // 1. Modern Wine-TKG layout
    let comp_subdirs = ["lib/wine/vkd3d-proton", "files/lib/wine/vkd3d-proton", "dist/lib/wine/vkd3d-proton"];
    let required = ["d3d12.dll", "d3d12core.dll"];

    for subdir in comp_subdirs {
        let comp_path = root.join(subdir);
        if comp_path.is_dir() {
            for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
                let arch_path = comp_path.join(arch_dir);
                if required.iter().all(|dll| arch_path.join(dll).exists()) {
                    let version = ["version", "../version"]
                        .iter()
                        .filter_map(|v| {
                            let p = arch_path.join(v);
                            std::fs::read_to_string(p).ok()
                        })
                        .map(|s| parse_short_version(&s))
                        .find(|s| s != "unknown")
                        .unwrap_or_else(|| "found".to_string());

                    return Some(ComponentInfo {
                        version,
                        source: ComponentSource::BundledWithRunner,
                        path: Some(arch_path),
                    });
                }
            }
        }
    }

    // Unified layout (Modern Proton 11+ has vkd3d under files/lib/)
    for subdir in crate::proton::UNIFIED_BASE_LIB_SUBDIRS {
        for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
            for arch_path in [
                root.join(subdir).join("vkd3d").join(arch_dir),
                root.join(subdir).join(arch_dir),
            ] {
                if required.iter().all(|dll| arch_path.join(dll).exists()) {
                let version = ["version", "../version", "../../version"]
                    .iter()
                    .filter_map(|v| {
                        let p = arch_path.join(v);
                        std::fs::read_to_string(p).ok()
                    })
                    .map(|s| parse_short_version(&s))
                    .find(|s| s != "unknown")
                    .unwrap_or_else(|| "found".to_string());

                    return Some(ComponentInfo {
                        version,
                        source: ComponentSource::BundledWithRunner,
                        path: Some(arch_path),
                    });
                }
            }
        }
    }

    // Legacy Unified layout
    for subdir in crate::proton::COMPONENT_LIB_SUBDIRS {
        for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
            let arch_path = root.join(subdir).join(arch_dir);
            if required.iter().all(|dll| arch_path.join(dll).exists()) {
                let version = ["version", "../version", "../../version"]
                    .iter()
                    .filter_map(|v| {
                        let p = arch_path.join(v);
                        std::fs::read_to_string(p).ok()
                    })
                    .map(|s| parse_short_version(&s))
                    .find(|s| s != "unknown")
                    .unwrap_or_else(|| "found".to_string());

                return Some(ComponentInfo {
                    version,
                    source: ComponentSource::BundledWithRunner,
                    path: Some(arch_path),
                });
            }
        }
    }

    // Legacy/Proton fallback
    let bundled_dlls = [
        "files/lib64/wine/vkd3d-proton/d3d12.dll",
        "files/lib/wine/vkd3d-proton/d3d12.dll",
        "dist/lib64/wine/vkd3d-proton/d3d12.dll",
        "dist/lib/wine/vkd3d-proton/d3d12.dll",
        "lib64/wine/vkd3d-proton/d3d12.dll",
        "lib/wine/vkd3d-proton/d3d12.dll",
    ];
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
    if let Some(pfx) = prefix {
        let prefix_dlls = [
            "drive_c/windows/system32/d3d12.dll",
            "drive_c/windows/syswow64/d3d12.dll",
        ];
        for rel in prefix_dlls {
            let p = pfx.join(rel);
            if p.exists() {
                if dll_contains_string(&p, "vkd3d-proton") {
                    let version = extract_version_from_dll(&p).unwrap_or_else(|| "unknown".to_string());
                    return Some(ComponentInfo {
                        version,
                        source: ComponentSource::InstalledInPrefix,
                        path: Some(p),
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

fn detect_nvapi(root: &Path, prefix: Option<&Path>) -> Option<ComponentInfo> {
    // 1. Bundled inside runner (Modern Wine-TKG layout)
    let comp_subdirs = ["lib/wine/nvapi", "files/lib/wine/nvapi", "dist/lib/wine/nvapi"];

    for subdir in comp_subdirs {
        let comp_path = root.join(subdir);
        if comp_path.is_dir() {
            // Check arch subfolders
            for (arch_name, arch_dir) in crate::proton::ARCH_SUBDIRS {
                let arch_path = comp_path.join(arch_dir);
                let dlls = if *arch_name == "x86_64" {
                    vec!["nvapi64.dll"]
                } else {
                    vec!["nvapi.dll"]
                };

                if dlls.iter().all(|dll| arch_path.join(dll).exists()) {
                    let version = ["version", "../version"]
                        .iter()
                        .filter_map(|v| {
                            let p = arch_path.join(v);
                            std::fs::read_to_string(p).ok()
                        })
                        .map(|s| parse_short_version(&s))
                        .find(|s| s != "unknown")
                        .unwrap_or_else(|| "found".to_string());

                    return Some(ComponentInfo {
                        version,
                        source: ComponentSource::BundledWithRunner,
                        path: Some(arch_path),
                    });
                }
            }
        }
    }

    // Unified layout
    for subdir in crate::proton::COMPONENT_LIB_SUBDIRS {
        for (arch_name, arch_dir) in crate::proton::ARCH_SUBDIRS {
            let arch_path = root.join(subdir).join(arch_dir);
            let dlls = if *arch_name == "x86_64" {
                vec!["nvapi64.dll"]
            } else {
                vec!["nvapi.dll"]
            };

            if dlls.iter().all(|dll| arch_path.join(dll).exists()) {
                let version = ["version", "../version", "../../version"]
                    .iter()
                    .filter_map(|v| {
                        let p = arch_path.join(v);
                        std::fs::read_to_string(p).ok()
                    })
                    .map(|s| parse_short_version(&s))
                    .find(|s| s != "unknown")
                    .unwrap_or_else(|| "found".to_string());

                return Some(ComponentInfo {
                    version,
                    source: ComponentSource::BundledWithRunner,
                    path: Some(arch_path),
                });
            }
        }
    }

    // 2. Installed into WINEPREFIX
    if let Some(pfx) = prefix {
        let prefix_dlls = [
            "drive_c/windows/system32/nvapi64.dll",
            "drive_c/windows/syswow64/nvapi.dll",
        ];
        if let Some(info) = check_prefix(pfx, &prefix_dlls, "NVAPI") {
            return Some(info);
        }
    }

    None
}

fn detect_vkd3d(root: &Path, prefix: Option<&Path>) -> Option<ComponentInfo> {
    // 0. Content-based rule for flat WoW64 layouts (steamflow-runner):
    //    d3d12.dll WITHOUT d3d12core.dll in the same dir => Wine's built-in VKD3D.
    for subdir in ["lib64/wine", "files/lib64/wine", "dist/lib64/wine", "lib/wine", "files/lib/wine", "dist/lib/wine"] {
        for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
            let arch_path = root.join(subdir).join(arch_dir);
            if arch_path.join("d3d12.dll").exists() && !arch_path.join("d3d12core.dll").exists() {
                let version = ["version", "../version", "../../version"]
                    .iter()
                    .filter_map(|v| {
                        let p = arch_path.join(v);
                        std::fs::read_to_string(p).ok()
                    })
                    .map(|s| parse_short_version(&s))
                    .find(|s| s != "unknown")
                    .unwrap_or_else(|| "found".to_string());
                return Some(ComponentInfo {
                    version,
                    source: ComponentSource::BundledWithRunner,
                    path: Some(arch_path),
                });
            }
        }
    }

    // 1. Modern Wine-TKG layout
    let comp_subdirs = ["lib/wine/vkd3d", "files/lib/wine/vkd3d", "dist/lib/wine/vkd3d"];
    let required = ["libvkd3d-1.dll", "libvkd3d-shader-1.dll"];

    for subdir in comp_subdirs {
        let comp_path = root.join(subdir);
        if comp_path.is_dir() {
            for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
                let arch_path = comp_path.join(arch_dir);
                if required.iter().all(|dll| arch_path.join(dll).exists()) {
                    let version = ["version", "../version"]
                        .iter()
                        .filter_map(|v| {
                            let p = arch_path.join(v);
                            std::fs::read_to_string(p).ok()
                        })
                        .map(|s| parse_short_version(&s))
                        .find(|s| s != "unknown")
                        .unwrap_or_else(|| "found".to_string());

                    return Some(ComponentInfo {
                        version,
                        source: ComponentSource::BundledWithRunner,
                        path: Some(arch_path),
                    });
                }
            }
        }
    }

    // Unified layout (Modern Proton 11+ has vkd3d under files/lib/)
    for subdir in crate::proton::UNIFIED_BASE_LIB_SUBDIRS {
        for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
            let arch_path = root.join(subdir).join("vkd3d").join(arch_dir);
            if required.iter().all(|dll| arch_path.join(dll).exists()) {
                let version = ["version", "../version", "../../version"]
                    .iter()
                    .filter_map(|v| {
                        let p = arch_path.join(v);
                        std::fs::read_to_string(p).ok()
                    })
                    .map(|s| parse_short_version(&s))
                    .find(|s| s != "unknown")
                    .unwrap_or_else(|| "found".to_string());

                return Some(ComponentInfo {
                    version,
                    source: ComponentSource::BundledWithRunner,
                    path: Some(arch_path),
                });
            }
        }
    }

    // Legacy Unified layout
    for subdir in crate::proton::COMPONENT_LIB_SUBDIRS {
        for (_, arch_dir) in crate::proton::ARCH_SUBDIRS {
            let arch_path = root.join(subdir).join(arch_dir);
            if required.iter().all(|dll| arch_path.join(dll).exists()) {
                let version = ["version", "../version", "../../version"]
                    .iter()
                    .filter_map(|v| {
                        let p = arch_path.join(v);
                        std::fs::read_to_string(p).ok()
                    })
                    .map(|s| parse_short_version(&s))
                    .find(|s| s != "unknown")
                    .unwrap_or_else(|| "found".to_string());

                return Some(ComponentInfo {
                    version,
                    source: ComponentSource::BundledWithRunner,
                    path: Some(arch_path),
                });
            }
        }
    }

    // Legacy/Proton fallback
    // Upstream Wine VKD3D uses libvkd3d.dll/libvkd3d-1.dll and libvkd3d-shader.dll
    let bundled_dlls = [
        "files/lib64/wine/vkd3d/libvkd3d-1.dll",
        "files/lib/wine/vkd3d/libvkd3d-1.dll",
        "dist/lib64/wine/vkd3d/libvkd3d-1.dll",
        "dist/lib/wine/vkd3d/libvkd3d-1.dll",
        "lib64/wine/vkd3d/libvkd3d-1.dll",
        "lib/wine/vkd3d/libvkd3d-1.dll",
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
                    path: Some(p),
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
        path: root.join(found_dll.unwrap()).parent().map(|p| p.to_path_buf()),
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
                path: Some(p),
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
                path: Some(p.to_path_buf()),
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

    // Try to find content inside parentheses first (Wine-TKG style)
    let v = if let (Some(start), Some(end)) = (s.find('('), s.rfind(')')) {
        if start < end {
            &s[start + 1..end]
        } else {
            s
        }
    } else {
        // If no parentheses, it might be a simple version string
        // or a Wine-TKG style without () but with multiple space-separated parts.
        if s.contains(' ') {
            s.split_whitespace().last().unwrap_or(s)
        } else {
            s
        }
    };

    let mut v = v.trim();

    // Strip component name prefixes (like 'dxvk-', 'vkd3d-proton-', 'vkd3d-')
    for prefix in &["vkd3d-proton-", "vkd3d-", "dxvk-"] {
        if v.starts_with(prefix) {
            v = &v[prefix.len()..];
            break;
        }
    }

    // Strip leading 'v' if followed by a digit
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

#[derive(Debug, Clone, Default)]
pub struct RunnerVersions {
    pub wine_commit: Option<String>,
    pub dxvk: Option<String>,
    pub d7vk: Option<String>,
    pub vkd3d_proton: Option<String>,
    pub vkd3d: Option<String>,
    pub nvapi: Option<String>,
    pub dxvk_nvapi: Option<String>,
    pub wine_mono: Option<String>,
    pub wine_gecko: Option<String>,
    pub build_date: Option<String>,
    /// The runner's own version (the tarball/release version SteamFlow
    /// extracted). Written by `write_runner_versions_txt` during extraction.
    pub runner_version: Option<String>,
}

/// Parse VERSIONS.txt from the runner root. Each line is KEY=VALUE.
pub fn read_versions_txt(root: &Path) -> RunnerVersions {
    let path = root.join("VERSIONS.txt");
    let mut versions = RunnerVersions::default();
    if let Ok(content) = std::fs::read_to_string(&path) {
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || !line.contains('=') {
                continue;
            }
            let mut parts = line.splitn(2, '=');
            let key = parts.next().map(|s| s.trim()).unwrap_or("");
            let val = parts.next().map(|s| s.trim()).unwrap_or("");
            if val.is_empty() {
                continue;
            }
            match key {
                "WINE_COMMIT" => versions.wine_commit = Some(val.to_string()),
                "DXVK_VERSION" => versions.dxvk = Some(val.to_string()),
                "D7VK_VERSION" => versions.d7vk = Some(val.to_string()),
                "VKD3D_PROTON_VERSION" => versions.vkd3d_proton = Some(val.to_string()),
                "DXVK_NVAPI_VERSION" => versions.dxvk_nvapi = Some(val.to_string()),
                "WINE_MONO_VERSION" => versions.wine_mono = Some(val.to_string()),
                "WINE_GECKO_VERSION" => versions.wine_gecko = Some(val.to_string()),
                "BUILD_DATE" => versions.build_date = Some(val.to_string()),
                "RUNNER_VERSION" => versions.runner_version = Some(val.to_string()),
                _ => {}
            }
        }
    }
    versions
}

/// Write a canonical `VERSIONS.txt` at the runner root after extracting a
/// runner tarball (Phase 2 item 3 of the valve-stack directive — kill the
/// `found(bundled)` display bug).
///
/// Detection (`detect_*`) returns the placeholder `"found"` when no `version`
/// file sits next to a component DLL (flat WoW64 layout). `apply_versions_override`
/// treats `"found"` as needing the `VERSIONS.txt` override — but the override
/// only exists if SteamFlow writes the file. This function:
///
/// 1. Harvests the component versions the tarball ships (the classic
///    `files/lib/wine/<component>/version` files, root `version` file), and
/// 2. Stamps the runner's own tarball/release version as `RUNNER_VERSION`.
///
/// It never overwrites an existing `VERSIONS.txt` (e.g. the custom
/// `steamflow-runner` ships an authoritative one). Non-fatal: failures log and
/// return `Ok(false)` so extraction is never blocked by version bookkeeping.
pub fn write_runner_versions_txt(runner_root: &Path, tarball_version: &str) -> bool {
    let path = runner_root.join("VERSIONS.txt");
    if path.exists() {
        tracing::debug!(
            "VERSIONS.txt already exists at {} — leaving it untouched",
            path.display()
        );
        return false;
    }

    let mut lines: Vec<String> = Vec::new();

    // (VERSIONS.txt key, candidate version-file paths under the runner root)
    let harvest: &[(&str, &[&str])] = &[
        (
            "DXVK_VERSION",
            &[
                "files/lib/wine/dxvk/version",
                "lib/wine/dxvk/version",
                "dist/lib/wine/dxvk/version",
            ],
        ),
        (
            "D7VK_VERSION",
            &[
                "files/lib/wine/d7vk/version",
                "lib/wine/d7vk/version",
                "dist/lib/wine/d7vk/version",
            ],
        ),
        (
            "VKD3D_PROTON_VERSION",
            &[
                "files/lib/wine/vkd3d-proton/version",
                "lib/wine/vkd3d-proton/version",
                "dist/lib/wine/vkd3d-proton/version",
            ],
        ),
        (
            "VKD3D_VERSION",
            &[
                "files/lib/vkd3d/version",
                "lib/vkd3d/version",
                "dist/lib/vkd3d/version",
            ],
        ),
        (
            "DXVK_NVAPI_VERSION",
            &[
                "files/lib/wine/nvapi/version",
                "lib/wine/nvapi/version",
                "dist/lib/wine/nvapi/version",
                "files/lib/wine/dxvk-nvapi/version",
            ],
        ),
    ];

    for (key, candidates) in harvest {
        let found = candidates.iter().find_map(|rel| {
            let p = runner_root.join(rel);
            std::fs::read_to_string(&p)
                .ok()
                .map(|s| parse_short_version(&s))
                .filter(|v| v != "unknown" && !v.is_empty())
        });
        if let Some(v) = found {
            lines.push(format!("{key}={v}"));
        }
    }

    // Runner's own version: root `version` file (Proton layout, e.g.
    // "1785138253 proton-11.0-1b") takes precedence; else the tarball version.
    let runner_version = std::fs::read_to_string(runner_root.join("version"))
        .ok()
        .map(|s| parse_short_version(&s))
        .filter(|v| v != "unknown" && !v.is_empty())
        .unwrap_or_else(|| tarball_version.trim().to_string());
    if !runner_version.is_empty() {
        lines.push(format!("RUNNER_VERSION={runner_version}"));
    }

    if lines.is_empty() {
        tracing::debug!(
            "No version info harvestable from {} — not writing VERSIONS.txt",
            runner_root.display()
        );
        return false;
    }

    let content = format!("{}\n", lines.join("\n"));
    match std::fs::write(&path, content) {
        Ok(()) => {
            tracing::info!(
                "Wrote VERSIONS.txt at {} ({} entries, runner {runner_version})",
                path.display(),
                lines.len()
            );
            true
        }
        Err(e) => {
            tracing::warn!("Failed to write {}: {e}", path.display());
            false
        }
    }
}

fn apply_versions_override(
    component: &mut Option<ComponentInfo>,
    versions: &RunnerVersions,
    key: &str,
) {
    if component
        .as_ref()
        .map(|c| {
            !c.version.is_empty()
                && c.version != "unknown"
                // "found" is a placeholder emitted by detection when no version
                // file sits next to the DLL (flat WoW64 layout). It is not a
                // real version — allow the VERSIONS.txt override to fill it in.
                && c.version != "found"
        })
        .unwrap_or(false)
    {
        return;
    }
    let ver = match key {
        "dxvk" => versions.dxvk.as_deref(),
        "d7vk" => versions.d7vk.as_deref(),
        "vkd3d_proton" => versions.vkd3d_proton.as_deref(),
        "vkd3d" => versions.vkd3d.as_deref(),
        "nvapi" => versions.nvapi.as_deref(),
        "dxvk_nvapi" => versions.dxvk_nvapi.as_deref(),
        _ => None,
    };
    if let Some(v) = ver {
        let path = component
            .as_ref()
            .and_then(|c| c.path.clone());
        *component = Some(ComponentInfo {
            version: v.to_string(),
            source: ComponentSource::BundledWithRunner,
            path,
        });
    }
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

/// Returns the WINEDLLOVERRIDES string needed to activate installed layers.
pub fn build_dll_overrides(
    dxvk_active: bool,
    vkd3d_proton_active: bool,
    vkd3d_active: bool,
    no_overlay: bool,
    force_builtin_d3d: bool, // NEW — for WineD3D policy
    game_dir: Option<&std::path::Path>, // check for game-local DLLs
    strict_dxvk: bool,
    runner_root: Option<&std::path::Path>, // runner root, to test which builtins ship
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

    // NOTE: no blanket amd_ags_x64/amd_ags_x86 overrides. Games that need AMD
    // AGS ship their own amd_ags_x64.dll / amd_ags_x86.dll in their install
    // dir (e.g. RE2), and per the game-local-priority rule that DLL must win.
    // Forcing "=b" made the game's own copy unresolvable (exit 53,
    // missing_required_module) when the runner doesn't bundle the builtin.
    // If a game genuinely needs AGS and doesn't ship it, the user can add a
    // per-game WINEDLLOVERRIDES via Launch Options.

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

    // Game-local priority: check the game dir AND common subdirs the game
    // loads from (bin/, .trex/ etc). If the game ships its own copy, do NOT
    // override it — the game's DLL must win (e.g. Portal 2 RTX Remix ships
    // bin/d3d9.dll + dxvk_d3d9.dll + .trex/d3d9.dll).
    let game_has = |dll: &str| -> bool {
        game_dir.map(|d| {
            d.join(dll).exists()
                || d.join("bin").join(dll).exists()
                || d.join("bin").join(".trex").join(dll).exists()
                || d.join(".trex").join(dll).exists()
        }).unwrap_or(false)
    };

    if dxvk_active {
        // If the game ships its own d3d DLLs, don't fight them — just
        // ensure native wins without specifying which native.
        // Wine searches exe-dir before system32, so "n,b" is fine UNLESS
        // a foreign dll landed in system32. We skip the override entirely
        // for DLLs the game already provides locally.
        for dll in &[
            "d3d8.dll",
            "d3d9.dll",
            "d3d10core.dll",
            "d3d11.dll",
            "dxgi.dll",
        ] {
            let stem = dll.trim_end_matches(".dll");
            let mode = if strict_dxvk { "n" } else { "n,b" };

            // Game-local priority is absolute: if the game ships its own copy,
            // never override it, even in strict DXVK mode (the game's build may
            // be a modified fork — e.g. Portal 2 RTX Remix's dxvk_d3d9.dll).
            if !game_has(dll) {
                overrides.push(format!("{stem}={mode}"));
            }
            // If the game ships it locally and we are not in strict mode,
            // leave Wine's default search order alone — exe-dir native wins automatically.
        }
    }

    if vkd3d_proton_active || vkd3d_active {
        overrides.push("d3d12=n,b".into());
        overrides.push("d3d12core=n,b".into());
        if vkd3d_proton_active {
            // VKD3D-Proton creates a Vulkan device and requires DXVK's native
            // dxgi.dll to present swapchains. Without dxgi=n,b, Wine loads its
            // builtin wined3d-based dxgi, producing a Vulkan-device + wined3d/
            // llvmpipe swapchain mismatch that crashes in wined3d.dll on
            // D3D12 games (e.g. Little Nightmares EE / Atlas engine).
            overrides.push("dxgi=n,b".into());
            // Pair every D3D10/11 DLL with native dxgi: Wine's builtin d3d11 /
            // d3d10core import Wine-internal symbols (DXGID3D10CreateDevice,
            // DXGID3D10RegisterLayers) from dxgi.dll that DXVK's native dxgi
            // does not export. Loading builtin d3d11 against native dxgi yields
            // null imports -> broken D3D11 device -> crash (Portal 2, RE2).
            // Only push when the DXVK branch (above) hasn't already done so.
            //
            // CRITICAL (dxvk_enabled=false contract): the d3d8/d3d9/d3d10core/
            // d3d11 "=n,b" entries hand the game the runner's DXVK DLLs (the
            // proton script installs them into the prefix by default). When
            // DXVK is disabled they must NOT be emitted — Wine then loads its
            // builtin WineD3D DLLs, which is what dxvk_enabled=false promises.
            if dxvk_active {
                for stem in &["d3d8", "d3d9", "d3d10core", "d3d11"] {
                    if game_has(&format!("{stem}.dll")) {
                        // Game ships its own copy — keep game-local priority.
                        continue;
                    }
                    let entry = format!("{stem}=n,b");
                    if !overrides.iter().any(|o| o.starts_with(&format!("{stem}="))) {
                        overrides.push(entry);
                    }
                }
            }
        }
        if vkd3d_active {
            overrides.push("libvkd3d-1=n,b".into());
            overrides.push("libvkd3d-shader-1=n,b".into());
        }
    }

    overrides.join(";")
}

#[derive(Debug, Clone)]
pub struct MasterSteamConfig {
    pub root_dir: PathBuf,      // e.g. ~/.config/SteamFlow/master_steam_prefix
    pub wine_prefix: PathBuf,   // e.g. root_dir or root_dir/pfx
    pub layout_kind: String,    // "root" or "pfx"
    pub steam_exe: Option<PathBuf>,
}

pub fn get_master_steam_config() -> MasterSteamConfig {
    let root_dir = crate::config::config_dir()
        .unwrap_or_default()
        .join("master_steam_prefix");

    // Layout detection: prefer /pfx if it exists, otherwise check root for drive_c
    let (wine_prefix, layout_kind) = if root_dir.join("pfx/drive_c").exists() {
        (root_dir.join("pfx"), "pfx".to_string())
    } else if root_dir.join("drive_c").exists() {
        (root_dir.clone(), "root".to_string())
    } else {
        // Default for new installs
        (root_dir.join("pfx"), "pfx".to_string())
    };

    let steam_exe = find_steam_exe_in_prefix(&wine_prefix);

    MasterSteamConfig {
        root_dir,
        wine_prefix,
        layout_kind,
        steam_exe,
    }
}

pub fn find_steam_exe_in_prefix(prefix: &Path) -> Option<PathBuf> {
    let candidates = [
        "drive_c/Program Files (x86)/Steam/steam.exe",
        "drive_c/Program Files/Steam/steam.exe",
    ];

    for rel_path in candidates {
        let full_path = prefix.join(rel_path);
        if full_path.exists() {
            return Some(full_path);
        }
    }

    None
}

/// Detects the actual WINEPREFIX layout for the master Steam install.
/// Handles both master_steam_prefix/pfx/drive_c and master_steam_prefix/drive_c layouts.
pub fn resolve_master_wineprefix() -> PathBuf {
    get_master_steam_config().wine_prefix
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

pub fn detect_exe_architecture(exe_path: &Path) -> crate::models::ExecutableArchitecture {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = match std::fs::File::open(exe_path) {
        Ok(f) => f,
        Err(_) => return crate::models::ExecutableArchitecture::Unknown,
    };

    let mut mz_header = [0u8; 2];
    if file.read_exact(&mut mz_header).is_err() || &mz_header != b"MZ" {
        return crate::models::ExecutableArchitecture::Unknown;
    }

    // Offset 0x3C contains the offset to the PE header
    if file.seek(SeekFrom::Start(0x3C)).is_err() {
        return crate::models::ExecutableArchitecture::Unknown;
    }

    let mut pe_offset_buf = [0u8; 4];
    if file.read_exact(&mut pe_offset_buf).is_err() {
        return crate::models::ExecutableArchitecture::Unknown;
    }
    let pe_offset = u32::from_le_bytes(pe_offset_buf);

    if file.seek(SeekFrom::Start(pe_offset as u64)).is_err() {
        return crate::models::ExecutableArchitecture::Unknown;
    }

    let mut pe_signature = [0u8; 4];
    if file.read_exact(&mut pe_signature).is_err() || &pe_signature != b"PE\0\0" {
        return crate::models::ExecutableArchitecture::Unknown;
    }

    // COFF Header starts right after PE signature
    // Machine is the first 2 bytes
    let mut machine_buf = [0u8; 2];
    if file.read_exact(&mut machine_buf).is_err() {
        return crate::models::ExecutableArchitecture::Unknown;
    }
    let machine = u16::from_le_bytes(machine_buf);

    match machine {
        0x014c => crate::models::ExecutableArchitecture::X86,
        0x8664 => crate::models::ExecutableArchitecture::X86_64,
        _ => crate::models::ExecutableArchitecture::Unknown,
    }
}

pub fn detect_custom_components(path: &Path) -> crate::utils::RunnerComponents {
    let (dxvk, d7vk, vkd3d_proton, vkd3d, nvapi) = (
        detect_dxvk(path, None),
        detect_d7vk(path, None),
        detect_vkd3d_proton(path, None),
        detect_vkd3d(path, None),
        detect_nvapi(path, None),
    );

    let dxvk_nvapi = detect_dxvk_nvapi(path, None);
    let has_wow64_32bit = ["lib64/wine/i386-windows", "files/lib64/wine/i386-windows", "dist/lib64/wine/i386-windows"]
        .iter()
        .any(|d| {
            let dir = path.join(d);
            ["dxgi.dll", "d3d11.dll", "d3d12.dll", "ddraw.dll"]
                .iter()
                .any(|dll| dir.join(dll).exists())
        });
    crate::utils::RunnerComponents {
        dxvk,
        d7vk,
        vkd3d_proton,
        vkd3d,
        nvapi,
        dxvk_nvapi,
        has_wow64_32bit,
    }
}

pub fn repair_dangling_prefix_symlinks(prefix: &Path, runner_root: &Path) -> Result<(usize, usize)> {
    // A prefix seeded by an older runner keeps absolute symlinks into that
    // runner's lib/wine tree (system32/*.dll, syswow64/*.dll → …/files/lib/wine/
    // {x86_64,i386}-windows/…). If that runner dir is renamed/removed, every
    // builtin DLL link dangles and wine dies with `could not load kernel32.dll,
    // status c0000135` (exit 53) — regardless of which runner is then used.
    // This walks the prefix's windows DLL dirs, re-points dangling links at the
    // ACTIVE runner's equivalent file (same relative lib/wine subpath), and
    // drops links whose target the active runner does not ship (a fresh prefix
    // wouldn't have them at all). Returns (repointed, removed).
    let mut repointed = 0usize;
    let mut removed = 0usize;

    let dirs = [
        prefix.join("drive_c/windows/system32"),
        prefix.join("drive_c/windows/syswow64"),
    ];

    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("repair_dangling_prefix_symlinks: cannot read {}: {e}", dir.display());
                continue;
            }
        };
        for entry in entries.flatten() {
            let link = entry.path();
            let meta = match std::fs::symlink_metadata(&link) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !meta.file_type().is_symlink() {
                continue;
            }
            let target = match std::fs::read_link(&link) {
                Ok(t) => t,
                Err(_) => continue,
            };
            if target.exists() {
                continue; // healthy link
            }
            // Dangling. If the target points into a lib/wine tree (the seeding
            // layout), map it onto the active runner; otherwise drop it.
            if let Some(rel) = lib_wine_relative(&target) {
                let candidate = runner_root.join(&rel);
                if candidate.exists() {
                    tracing::info!(
                        "Re-pointing dangling prefix symlink {} -> {}",
                        link.display(),
                        candidate.display()
                    );
                    let _ = std::fs::remove_file(&link);
                    #[cfg(unix)]
                    {
                        if let Err(e) = std::os::unix::fs::symlink(&candidate, &link) {
                            tracing::warn!("repoint failed for {}: {e}", link.display());
                            continue;
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        if let Err(e) = std::fs::copy(&candidate, &link) {
                            tracing::warn!("repoint failed for {}: {e}", link.display());
                            continue;
                        }
                    }
                    repointed += 1;
                } else {
                    tracing::warn!(
                        "Removing dangling prefix symlink {} (active runner ships no {}: {})",
                        link.display(),
                        rel.display(),
                        target.display()
                    );
                    let _ = std::fs::remove_file(&link);
                    removed += 1;
                }
            } else {
                tracing::warn!(
                    "Removing dangling prefix symlink {} (not a runner lib/wine link: {})",
                    link.display(),
                    target.display()
                );
                let _ = std::fs::remove_file(&link);
                removed += 1;
            }
        }
    }

    Ok((repointed, removed))
}

/// If `target` points into a runner's `files/lib/wine/…` (or `lib/wine/…`)
/// tree, return the path relative to the runner root (e.g.
/// `files/lib/wine/x86_64-windows/kernel32.dll`).
fn lib_wine_relative(target: &Path) -> Option<PathBuf> {
    let s = target.to_string_lossy();
    for marker in ["/files/lib/wine/", "/lib/wine/"] {
        if let Some(idx) = s.find(marker) {
            let rel = &s[idx + 1..]; // strip leading '/'
            return Some(PathBuf::from(rel));
        }
    }
    None
}

pub fn deploy_dll_symlinks(
    prefix: &Path,
    resolutions: &[crate::launch::dll_provider_resolver::DllResolution],
    target_arch: &crate::models::ExecutableArchitecture,
) -> Result<Vec<PathBuf>> {
    let mut deployed = Vec::new();
    let is_64bit_prefix = prefix.join("drive_c/windows/syswow64").exists();

    for res in resolutions {
        if res.chosen_provider != crate::launch::dll_provider_resolver::DllProvider::Runner &&
           res.chosen_provider != crate::launch::dll_provider_resolver::DllProvider::Custom {
            continue;
        }

        if let Some(src_path) = &res.chosen_path {
            let dll_name = format!("{}.dll", res.name);

            // Determine destination directory in prefix
            let dest_dir = match target_arch {
                crate::models::ExecutableArchitecture::X86_64 => {
                    prefix.join("drive_c/windows/system32")
                }
                crate::models::ExecutableArchitecture::X86 => {
                    if is_64bit_prefix {
                        prefix.join("drive_c/windows/syswow64")
                    } else {
                        prefix.join("drive_c/windows/system32")
                    }
                }
                _ => continue,
            };

            if !dest_dir.exists() {
                continue;
            }

            let dest_path = dest_dir.join(&dll_name);

            // Safety check: if it exists (including as a dangling symlink,
            // which `Path::exists()` follows and reports as missing — e.g. a
            // link to a runner dir that was renamed/removed) and is not a
            // symlink, back it up or skip? Usually we want to replace it if
            // it's a Wine builtin.
            if dest_path.symlink_metadata().is_ok() {
                let meta = std::fs::symlink_metadata(&dest_path)?;
                if !meta.file_type().is_symlink() {
                    let backup = dest_path.with_extension("dll.bak");
                    if !backup.exists() {
                        tracing::info!("Backing up original DLL: {} -> {}", dest_path.display(), backup.display());
                        std::fs::rename(&dest_path, &backup)?;
                    } else {
                        // Backup already exists, just remove the original to make room for symlink
                        std::fs::remove_file(&dest_path)?;
                    }
                } else {
                    // It's already a symlink, remove it to update
                    std::fs::remove_file(&dest_path)?;
                }
            }

            tracing::info!("Symlinking {} -> {}", src_path.display(), dest_path.display());
            #[cfg(unix)]
            std::os::unix::fs::symlink(src_path, &dest_path)?;
            #[cfg(not(unix))]
            std::fs::copy(src_path, &dest_path)?;

            deployed.push(dest_path);

            // Also try to deploy the "other" architecture if it's a 64-bit prefix and we have it
            if is_64bit_prefix {
                let (other_arch, other_dir) = match target_arch {
                    crate::models::ExecutableArchitecture::X86_64 => (
                        crate::models::ExecutableArchitecture::X86,
                        prefix.join("drive_c/windows/syswow64")
                    ),
                    crate::models::ExecutableArchitecture::X86 => (
                        crate::models::ExecutableArchitecture::X86_64,
                        prefix.join("drive_c/windows/system32")
                    ),
                    _ => continue,
                };

                // We need to find the sibling DLL.
                // This is a bit tricky because we don't have the full resolution for the other arch here.
                // But we can guess based on common layouts.
                if let Some(other_src) = find_sibling_dll(src_path, target_arch, &other_arch) {
                    let other_dest = other_dir.join(&dll_name);
                    if other_dest.exists() {
                        let meta = std::fs::symlink_metadata(&other_dest)?;
                        if !meta.file_type().is_symlink() {
                            let backup = other_dest.with_extension("dll.bak");
                            if !backup.exists() {
                                std::fs::rename(&other_dest, &backup)?;
                            } else {
                                std::fs::remove_file(&other_dest)?;
                            }
                        } else {
                            std::fs::remove_file(&other_dest)?;
                        }
                    }
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(&other_src, &other_dest)?;
                    #[cfg(not(unix))]
                    std::fs::copy(&other_src, &other_dest)?;
                    deployed.push(other_dest);
                }
            }
        }
    }

    Ok(deployed)
}

fn find_sibling_dll(
    path: &Path,
    current_arch: &crate::models::ExecutableArchitecture,
    target_arch: &crate::models::ExecutableArchitecture,
) -> Option<PathBuf> {
    let (current_tag, target_tag) = match (current_arch, target_arch) {
        (crate::models::ExecutableArchitecture::X86_64, crate::models::ExecutableArchitecture::X86) => ("x86_64", "i386"),
        (crate::models::ExecutableArchitecture::X86, crate::models::ExecutableArchitecture::X86_64) => ("i386", "x86_64"),
        _ => return None,
    };

    let path_str = path.to_string_lossy();
    if path_str.contains(current_tag) {
        let other_str = path_str.replace(current_tag, target_tag);
        let other_path = PathBuf::from(other_str);
        if other_path.exists() {
            return Some(other_path);
        }
    }

    // Also check for x64/x32 variant
    let (current_tag2, target_tag2) = match (current_arch, target_arch) {
        (crate::models::ExecutableArchitecture::X86_64, crate::models::ExecutableArchitecture::X86) => ("x64", "x32"),
        (crate::models::ExecutableArchitecture::X86, crate::models::ExecutableArchitecture::X86_64) => ("x32", "x64"),
        _ => return None,
    };
    if path_str.contains(current_tag2) {
        let other_str = path_str.replace(current_tag2, target_tag2);
        let other_path = PathBuf::from(other_str);
        if other_path.exists() {
            return Some(other_path);
        }
    }

    None
}

pub fn cleanup_dll_symlinks(prefix: &Path) -> Result<()> {
    let target_dlls = [
        "d3d8.dll", "d3d9.dll", "dxgi.dll", "d3d10core.dll",
        "d3d11.dll", "d3d12.dll", "d3d12core.dll", "libvkd3d-1.dll", "libvkd3d-shader-1.dll"
    ];

    let dirs = [
        prefix.join("drive_c/windows/system32"),
        prefix.join("drive_c/windows/syswow64"),
    ];

    for dir in dirs {
        if !dir.exists() { continue; }
        for dll in &target_dlls {
            let p = dir.join(dll);
            if p.exists() {
                let meta = std::fs::symlink_metadata(&p)?;
                if meta.file_type().is_symlink() {
                    tracing::info!("Cleaning up symlink: {}", p.display());
                    std::fs::remove_file(&p)?;

                    // Restore backup if it exists
                    let backup = p.with_extension("dll.bak");
                    if backup.exists() {
                        tracing::info!("Restoring backup: {} -> {}", backup.display(), p.display());
                        std::fs::rename(&backup, &p)?;
                    }
                }
            }
        }
    }

    Ok(())
}

pub fn steam_wineprefix_for_game(
    config: &crate::config::LauncherConfig,
    app_id: u32,
    user_configs: &crate::models::UserConfigStore,
    effective_prefix_mode: Option<crate::models::SteamPrefixMode>,
) -> std::path::PathBuf {
    let use_steam_runtime = match user_configs.get(&app_id).map(|c| &c.steam_runtime_policy) {
        Some(crate::models::SteamRuntimePolicy::Enabled) => true,
        Some(crate::models::SteamRuntimePolicy::Disabled) => false,
        Some(crate::models::SteamRuntimePolicy::Auto) | None => {
            user_configs.get(&app_id).map(|c| c.use_steam_runtime).unwrap_or(false)
        }
    };

    let use_per_game_compat_data = match effective_prefix_mode {
        // Launch pipeline: honor the EFFECTIVE mode. The runner-mismatch guard
        // (wine_tkg::effective_prefix_mode) may have auto-fallbacked a Shared
        // configuration to PerGame so the two different runners never share one
        // WINEPREFIX (wineserver protocol collision).
        Some(mode) => use_steam_runtime && mode == crate::models::SteamPrefixMode::PerGame,
        None => user_configs.get(&app_id)
            .map(|c| use_steam_runtime && c.steam_prefix_mode == crate::models::SteamPrefixMode::PerGame)
            .unwrap_or(config.use_shared_compat_data),
    };

    if use_per_game_compat_data {
        std::path::PathBuf::from(&config.steam_library_path)
            .join("steamapps")
            .join("compatdata")
            .join(app_id.to_string())
            .join("pfx")
    } else {
        resolve_master_wineprefix()
    }
}

/// Open a native file-selection dialog (zenity → kdialog → qarma, in that
/// order) starting at `initial_dir`, returning the chosen absolute path.
/// Returns None when the user cancels or no dialog tool is available.
pub fn open_file_dialog(initial_dir: &Path) -> Option<String> {
    // zenity: --filename with a trailing slash opens the directory.
    let zenity_dir = initial_dir.to_string_lossy();
    let zenity_args = [
        "--file-selection",
        "--title=Select a custom executable or script",
        &format!("--filename={}/", zenity_dir.trim_end_matches('/')),
    ];
    if let Ok(out) = std::process::Command::new("zenity").args(zenity_args).output() {
        if out.status.success() {
            let picked = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !picked.is_empty() {
                return Some(picked);
            }
        }
    }

    if let Ok(out) = std::process::Command::new("kdialog")
        .args(["--getopenfilename", initial_dir.to_str().unwrap_or(".")])
        .output()
    {
        if out.status.success() {
            let picked = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !picked.is_empty() {
                return Some(picked);
            }
        }
    }

    if let Ok(out) = std::process::Command::new("qarma")
        .args(["--file-selection", initial_dir.to_str().unwrap_or(".")])
        .output()
    {
        if out.status.success() {
            let picked = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !picked.is_empty() {
                return Some(picked);
            }
        }
    }

    None
}

#[cfg(test)]
mod runner_kind_tests {
    use super::*;

    #[test]
    fn classifies_proton_tree_with_bundled_wine() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("proton"), "#!/usr/bin/env python3").unwrap();
        std::fs::create_dir_all(dir.path().join("files/protonfixes")).unwrap();
        std::fs::create_dir_all(dir.path().join("files/bin")).unwrap();
        std::fs::write(dir.path().join("files/bin/wine64"), "").unwrap();
        match classify_runner(dir.path()) {
            RunnerKind::Proton { proton_script, bundled_wine64: Some(wine), has_protonfixes } => {
                assert_eq!(proton_script, dir.path().join("proton"));
                assert_eq!(wine, dir.path().join("files/bin/wine64"));
                assert!(has_protonfixes);
            }
            other => panic!("unexpected classification: {other:?}"),
        }
    }

    #[test]
    fn classifies_plain_wine_directory_and_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("bin")).unwrap();
        std::fs::write(dir.path().join("bin/wine64"), "").unwrap();
        assert!(matches!(classify_runner(dir.path()), RunnerKind::PlainWine { .. }));
        assert!(matches!(classify_runner(&dir.path().join("bin/wine64")), RunnerKind::PlainWine { .. }));
    }

    #[test]
    fn classifies_unknown() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(classify_runner(dir.path()), RunnerKind::Unknown);
    }

    #[test]
    fn support_matrix_routing_decisions() {
        let proton = tempfile::tempdir().unwrap();
        std::fs::write(proton.path().join("proton"), "").unwrap();
        std::fs::create_dir_all(proton.path().join("protonfixes")).unwrap();
        std::fs::create_dir_all(proton.path().join("files/bin")).unwrap();
        std::fs::write(proton.path().join("files/bin/wine64"), "").unwrap();
        let wine = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(wine.path().join("bin")).unwrap();
        std::fs::write(wine.path().join("bin/wine64"), "").unwrap();

        let is_bg_bare = |p: &Path| match classify_runner(p) {
            RunnerKind::Proton { bundled_wine64: Some(_), .. } | RunnerKind::PlainWine { .. } => true,
            _ => false,
        };
        let game_uses_protonfixes = |p: &Path| matches!(classify_runner(p), RunnerKind::Proton { has_protonfixes: true, .. });
        assert!(is_bg_bare(proton.path()) && game_uses_protonfixes(proton.path())); // row 1
        assert!(is_bg_bare(wine.path()) && !game_uses_protonfixes(wine.path())); // row 2
        assert!(is_bg_bare(proton.path()) && game_uses_protonfixes(proton.path())); // row 3
        assert!(is_bg_bare(wine.path()) && !game_uses_protonfixes(wine.path())); // row 4
        assert!(is_bg_bare(wine.path()) && game_uses_protonfixes(proton.path())); // row 5
        assert!(is_bg_bare(proton.path()) && !game_uses_protonfixes(wine.path())); // row 6
    }
}

#[cfg(test)]
mod versions_txt_tests {
    use super::*;

    #[test]
    fn write_runner_versions_txt_harvests_and_stamps() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Classic Proton component layout: version files in component dirs.
        std::fs::create_dir_all(root.join("files/lib/wine/dxvk")).unwrap();
        std::fs::create_dir_all(root.join("files/lib/wine/vkd3d-proton")).unwrap();
        std::fs::write(
            root.join("files/lib/wine/dxvk/version"),
            "1a5919b7e dxvk (v3.0.2-5-g1a5919b7e)\n",
        )
        .unwrap();
        std::fs::write(
            root.join("files/lib/wine/vkd3d-proton/version"),
            "3dfc6f07 vkd3d-proton (vkd3d-1.1-5438-g3dfc6f07d)\n",
        )
        .unwrap();
        // Runner root `version` file (Proton style) wins for RUNNER_VERSION.
        std::fs::write(root.join("version"), "1785138253 proton-11.0-1b\n").unwrap();

        assert!(write_runner_versions_txt(root, "fallback-tag"));

        let versions = read_versions_txt(root);
        // parse_short_version strips -g<hex> git suffixes.
        assert_eq!(versions.dxvk.as_deref(), Some("3.0.2-5"));
        assert_eq!(versions.vkd3d_proton.as_deref(), Some("1.1-5438"));
        assert_eq!(versions.runner_version.as_deref(), Some("proton-11.0-1b"));
    }

    #[test]
    fn write_runner_versions_txt_uses_tarball_version_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // No root `version` file → the tarball version is stamped instead.
        std::fs::create_dir_all(root.join("files/lib/wine/dxvk")).unwrap();
        std::fs::write(
            root.join("files/lib/wine/dxvk/version"),
            "dxvk (v3.0.2)\n",
        )
        .unwrap();

        assert!(write_runner_versions_txt(root, "GE-Proton11-3"));
        let versions = read_versions_txt(root);
        assert_eq!(versions.dxvk.as_deref(), Some("3.0.2"));
        assert_eq!(versions.runner_version.as_deref(), Some("GE-Proton11-3"));
    }

    #[test]
    fn write_runner_versions_txt_never_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("VERSIONS.txt"), "DXVK_VERSION=9.9.9\n").unwrap();
        std::fs::create_dir_all(root.join("files/lib/wine/dxvk")).unwrap();
        std::fs::write(root.join("files/lib/wine/dxvk/version"), "dxvk (v3.0.2)\n").unwrap();

        assert!(!write_runner_versions_txt(root, "tarball-tag"));
        let versions = read_versions_txt(root);
        assert_eq!(versions.dxvk.as_deref(), Some("9.9.9")); // untouched
    }

    #[test]
    fn write_runner_versions_txt_skips_empty_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Nothing harvestable → no VERSIONS.txt written.
        assert!(!write_runner_versions_txt(root, ""));
        assert!(!root.join("VERSIONS.txt").exists());
    }

    #[test]
    fn test_build_dll_overrides_dxvk_disabled_no_d3d9_native_override() {
        use crate::utils::build_dll_overrides;

        // dxvk_enabled=false + runner ships VKD3D-Proton (the purepe case that
        // used to leak d3d9=n,b and activate DXVK against the user's explicit
        // dxvk_enabled=false): d3d9/d3d11 must NOT get native overrides.
        let off = build_dll_overrides(false, true, false, false, false, None, false, None);
        assert!(!off.contains("d3d9=n"), "dxvk disabled must not emit d3d9=n,b: {off}");
        assert!(!off.contains("d3d11=n"), "dxvk disabled must not emit d3d11=n,b: {off}");
        assert!(!off.contains("d3d8=n"), "dxvk disabled must not emit d3d8=n,b: {off}");
        assert!(!off.contains("d3d10core=n"), "dxvk disabled must not emit d3d10core=n,b: {off}");
        // VKD3D-Proton pairing (d3d12 + dxgi) stays — needed for D3D12 games.
        assert!(off.contains("d3d12=n,b"), "d3d12 pairing must stay: {off}");
        assert!(off.contains("dxgi=n,b"), "dxgi pairing must stay: {off}");

        // dxvk_enabled=true + VKD3D-Proton: full DXVK pairing (regression guard).
        let on = build_dll_overrides(true, true, false, false, false, None, false, None);
        assert!(on.contains("d3d9=n,b"), "dxvk enabled must emit d3d9=n,b: {on}");
        assert!(on.contains("d3d11=n,b"), "dxvk enabled must emit d3d11=n,b: {on}");
        assert!(on.contains("dxgi=n,b"), "dxvk enabled must emit dxgi=n,b: {on}");

        // Game-local d3d9 (e.g. Portal 2 RTX Remix bin/d3d9.dll) must still win.
        let game = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(game.path().join("bin")).unwrap();
        std::fs::write(game.path().join("bin/d3d9.dll"), "remix runtime").unwrap();
        let local = build_dll_overrides(true, true, false, false, false, Some(game.path()), false, None);
        assert!(!local.contains("d3d9=n,b"), "game-local d3d9 must not be overridden: {local}");
    }
}
