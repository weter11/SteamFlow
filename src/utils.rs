use std::path::{Path, PathBuf};
use std::process::Command;
use anyhow::{Result, bail};

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
    pub dxvk: Option<String>,
    pub vkd3d: Option<String>,
    pub vkd3d_proton: Option<String>,
}

pub fn detect_runner_components(runner_path: &Path) -> RunnerComponents {
    // Walk up to the runner root (parent of bin/ or the dir itself)
    let root = if runner_path.is_file() {
        runner_path
            .parent() // bin/
            .and_then(|p| p.parent()) // runner root
            .unwrap_or(runner_path)
            .to_path_buf()
    } else {
        runner_path.to_path_buf()
    };

    // Candidate sub-paths for each component's DLL, ordered by likelihood
    let dxvk_dll_paths = [
        "files/lib/wine/dxvk/d3d11.dll", // official Proton
        "dist/lib/wine/dxvk/d3d11.dll",  // older Proton
        "lib/wine/dxvk/d3d11.dll",       // wine-tkg bundled
        "lib64/wine/dxvk/d3d11.dll",
    ];
    let vkd3d_proton_dll_paths = [
        "files/lib/wine/vkd3d-proton/d3d12.dll", // official Proton
        "dist/lib/wine/vkd3d-proton/d3d12.dll",
        "lib/wine/vkd3d-proton/d3d12.dll",
        "lib64/wine/vkd3d-proton/d3d12.dll",
    ];
    let vkd3d_dll_paths = [
        "files/lib/wine/vkd3d/d3d12.dll",
        "dist/lib/wine/vkd3d/d3d12.dll",
        "lib/wine/vkd3d/d3d12.dll",
        "lib64/wine/vkd3d/d3d12.dll",
    ];

    let read_version_file = |rel: &str| -> Option<String> {
        let p = root.join(rel);
        std::fs::read_to_string(&p)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };

    // Try version file first (fast), then fall back to DLL string scan
    let detect = |dll_candidates: &[&str], file_a: &str, file_b: &str| -> Option<String> {
        // 1. Version text file
        if let Some(v) = read_version_file(file_a).or_else(|| read_version_file(file_b)) {
            return Some(v);
        }

        // 2. Find the first existing DLL
        let dll = dll_candidates
            .iter()
            .map(|rel| root.join(rel))
            .find(|p| p.exists())?;

        // 3. Extract version string embedded in the DLL binary
        extract_version_from_dll(&dll)
    };

    RunnerComponents {
        dxvk: detect(
            &dxvk_dll_paths,
            "files/share/dxvk/version",
            "dist/share/dxvk/version",
        ),
        vkd3d_proton: detect(
            &vkd3d_proton_dll_paths,
            "files/share/vkd3d-proton/version",
            "dist/share/vkd3d-proton/version",
        ),
        vkd3d: detect(
            &vkd3d_dll_paths,
            "files/share/vkd3d/version",
            "dist/share/vkd3d/version",
        ),
    }
}

/// Scans a PE DLL binary for an embedded semantic version string.
/// DXVK/VKD3D embed strings like "2.3.1" or "v1.9.4-dirty" in the binary.
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
            parts.len() >= 2 && parts[0].parse::<u32>().unwrap_or(0) <= 99
        })
        .collect();

    // Sort: longer (more specific) versions first
    candidates.sort_by(|a, b| b.len().cmp(&a.len()));
    candidates.into_iter().next()
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
        crate::models::SteamPrefixMode::Shared => crate::config::config_dir()
            .unwrap_or_default()
            .join("master_steam_prefix/pfx"),
        crate::models::SteamPrefixMode::PerGame => std::path::PathBuf::from(&config.steam_library_path)
            .join("steamapps/compatdata")
            .join(app_id.to_string())
            .join("pfx"),
    }
}
