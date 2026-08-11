//! Environment-parity harness (Phase 2 of the valve-stack directive).
//!
//! Compares the launch environment native Steam hands to a game (captured from
//! a `PROTON_LOG=1` proton log) against SteamFlow's generated
//! `effective_env.json`, and prints a categorized diff:
//!
//!   - MISSING     — set by native Steam, absent from SteamFlow
//!   - EXTRA       — set by SteamFlow, absent from native Steam
//!   - MISMATCHED  — both set, different values
//!   - MATCHED     — both set, identical values
//!
//! Reference: `docs/architecture/valve-stack-replication.md` §Tier 1.
//! Headless entry: `steamflow test-diff <appid> [--native-log <path>]
//! [--session <dir>]`.

use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::infra::logging::debug_utils::load_effective_env;
use crate::infra::logging::EffectiveEnv;

/// `Options:` entry (compat_config) → the `PROTON_*` env var it implies,
/// reverse of Proton's `check_environment` table (verified against
/// official Proton 11.0's `proton` script, ~line 1685).
const OPTION_TO_PROTON_ENV: &[(&str, &str)] = &[
    ("wined3d", "PROTON_USE_WINED3D"),
    ("wined3d11", "PROTON_USE_WINED3D11"),
    ("dxvkd3d8", "PROTON_DXVK_D3D8"),
    ("nod3d11", "PROTON_NO_D3D11"),
    ("nod3d10", "PROTON_NO_D3D10"),
    ("nofsync", "PROTON_NO_FSYNC"),
    ("forcelgadd", "PROTON_FORCE_LARGE_ADDRESS_AWARE"),
    ("oldglstr", "PROTON_OLD_GL_STRING"),
    ("hidenvgpu", "PROTON_HIDE_NVIDIA_GPU"),
    ("hidevggpu", "PROTON_HIDE_VANGOGH_GPU"),
    ("hideintelgpu", "PROTON_HIDE_INTEL_GPU"),
    ("gamedrive", "PROTON_SET_GAME_DRIVE"),
    ("steamdrive", "PROTON_SET_STEAM_DRIVE"),
    ("noxim", "PROTON_NO_XIM"),
    ("heapdelayfree", "PROTON_HEAP_DELAY_FREE"),
    ("heapzeromemory", "PROTON_HEAP_ZERO_MEMORY"),
    ("disablenvapi", "PROTON_DISABLE_NVAPI"),
    ("forcenvapi", "PROTON_FORCE_NVAPI"),
    ("hideapu", "PROTON_HIDE_APU"),
];

/// Shell/process noise — never meaningful for launch parity.
const NOISE_KEYS: &[&str] = &[
    "_", "PWD", "OLDPWD", "SHLVL", "LS_COLORS", "LS_COLORS__", "SHELL", "TERM", "TERM_PROGRAM",
    "TMUX", "TMUX_PANE", "SSH_AGENT_PID", "SSH_AUTH_SOCK", "DBUS_SESSION_BUS_ADDRESS",
];

/// Env vars that matter most for parity reporting (displayed first, flagged).
fn priority_of(key: &str) -> u8 {
    if key == "WINEDLLOVERRIDES" || key == "WINEDEBUG" || key == "WINEDLLPATH" {
        return 0;
    }
    if key.starts_with("STEAM_COMPAT_") || key.starts_with("PROTON_") {
        return 1;
    }
    if key.starts_with("DXVK_")
        || key.starts_with("VKD3D_")
        || key.starts_with("WINE")
        || key.starts_with("__VK_")
        || key.starts_with("__GLX_")
        || key.starts_with("__NV")
        || key == "LD_LIBRARY_PATH"
        || key == "VK_ICD_FILENAMES"
        || key == "VK_LAYER_PATH"
    {
        return 2;
    }
    3
}

/// Parsed facts from a native proton log header (`PROTON_LOG=1`).
#[derive(Debug, Default, Clone)]
pub struct NativeLaunch {
    pub proton_version: Option<String>,
    pub steam_game_id: Option<String>,
    pub command: Option<String>,
    /// `Options: {'forcelgadd', 'wined3d'}` set.
    pub options: Vec<String>,
    pub kernel: Option<String>,
    /// Env vars the log explicitly reports (Effective/System/User settings).
    pub env: BTreeMap<String, String>,
}

impl NativeLaunch {
    /// Env map for diffing: explicitly-reported vars + every `PROTON_*` var
    /// implied by the `Options:` set (native Steam would have set them).
    pub fn effective_env(&self) -> BTreeMap<String, String> {
        let mut map = self.env.clone();
        for opt in &self.options {
            if let Some((_, env_var)) =
                OPTION_TO_PROTON_ENV.iter().find(|(o, _)| o == opt)
            {
                map.entry(env_var.to_string()).or_insert_with(|| "1".into());
            }
        }
        map
    }
}

/// Parse a proton log (both legacy bash-era and modern python-era headers).
pub fn parse_native_proton_log(path: &Path) -> Result<NativeLaunch> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read native log {}", path.display()))?;
    let mut native = NativeLaunch::default();

    // Header block: every line is `Key: value` (or `Key:` with empty value),
    // until the first line that does not match (wine trace output etc.).
    for line in content.lines() {
        let line = line.trim_end_matches('\r');
        // Separator banners (===== / -----) are not header entries.
        let trimmed = line.trim();
        if trimmed.chars().all(|c| c == '=' || c == '-') && !trimmed.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            break; // header block ended (wine debug output follows)
        };
        let key = key.trim();
        let value = value.trim().to_string();
        match key {
            "Proton" => native.proton_version = Some(value),
            "SteamGameId" => native.steam_game_id = Some(value),
            "Command" => native.command = Some(value),
            "Options" => {
                // Python-set repr: {'forcelgadd', 'wined3d'} or empty set()
                let body = value
                    .trim()
                    .trim_start_matches('{')
                    .trim_end_matches('}')
                    .trim();
                if body == "set()" || body.is_empty() {
                    // empty set
                } else {
                    for opt in body.split(',') {
                        let opt = opt.trim().trim_matches('\'').trim_matches('"');
                        if !opt.is_empty() {
                            native.options.push(opt.to_string());
                        }
                    }
                }
            }
            "Kernel" => native.kernel = Some(value),
            "Effective WINEDLLOVERRIDES"
            | "System WINEDLLOVERRIDES"
            | "User settings WINEDLLOVERRIDES" => {
                if !value.is_empty() {
                    native
                        .env
                        .insert("WINEDLLOVERRIDES".into(), value.clone());
                }
            }
            "Effective WINEDEBUG" | "System WINEDEBUG" | "User settings WINEDEBUG" => {
                if !value.is_empty() {
                    native.env.insert("WINEDEBUG".into(), value.clone());
                }
            }
            "PATH" => {
                if !value.is_empty() {
                    native.env.insert("PATH".into(), value.clone());
                }
            }
            // depot/pressure-vessel/scripts/soldier/sniper/Language are
            // informative but not env vars — ignored for the diff.
            _ => {}
        }
        // Stop at the first non-header line only when we've seen the header
        // marker; the block ends at the first line without ':'.
        if !line.contains(':') {
            break;
        }
    }
    Ok(native)
}

/// Find the native proton log for an appid.
/// Search order: explicit path > `~/steam-<appid>.log` > `~/Фото, видео/steam-<appid>.log`
/// > any `steam-<appid>.log` up to 3 levels under HOME.
pub fn find_native_log(appid: u32, explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return p.exists().then(|| p.to_path_buf());
    }
    let home = std::env::var("HOME").ok()?;
    let candidates = [
        PathBuf::from(&home).join(format!("steam-{appid}.log")),
        PathBuf::from(&home).join("Фото, видео").join(format!("steam-{appid}.log")),
        PathBuf::from(&home).join("Emulators").join(format!("steam-{appid}.log")),
    ];
    for c in candidates {
        if c.exists() {
            return Some(c);
        }
    }
    // Shallow recursive scan of HOME (maxdepth 3) as a last resort.
    let root = PathBuf::from(&home);
    let mut stack = vec![root];
    let mut depth = 0;
    while !stack.is_empty() && depth < 3 {
        let mut next = Vec::new();
        for dir in stack {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        next.push(path);
                    } else if path.file_name().map(|n| n.to_string_lossy().to_string())
                        == Some(format!("steam-{appid}.log"))
                    {
                        return Some(path);
                    }
                }
            }
        }
        stack = next;
        depth += 1;
    }
    None
}

/// Find the newest SteamFlow session dir whose effective env targets `appid`.
pub fn find_steamflow_session(appid: u32, explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return p.exists().then(|| p.to_path_buf());
    }
    let home = std::env::var("HOME").ok()?;
    let logs_root = PathBuf::from(&home).join(".config/SteamFlow/logs");
    let entries = std::fs::read_dir(&logs_root).ok()?;
    let mut best: Option<(u64, PathBuf)> = None;
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let env_path = dir.join("effective_env.json");
        if !env_path.exists() {
            continue;
        }
        let Ok(env) = load_effective_env(&dir) else { continue };
        let targets = env
            .env_vars
            .get("SteamAppId")
            .or_else(|| env.env_vars.get("STEAM_COMPAT_APP_ID"))
            .and_then(|v| v.parse::<u32>().ok());
        if targets != Some(appid) {
            continue;
        }
        let mtime = env_path
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if best.as_ref().map(|(t, _)| mtime > *t).unwrap_or(true) {
            best = Some((mtime, dir));
        }
    }
    best.map(|(_, dir)| dir)
}

#[derive(Debug, Default)]
pub struct EnvDiff {
    pub missing: Vec<(String, String)>,    // native-only (var, native value)
    pub extra: Vec<(String, String)>,      // steamflow-only (var, flow value)
    pub mismatched: Vec<(String, String, String)>, // (var, native, flow)
    pub matched: Vec<String>,              // both, same value
}

/// Diff native env against SteamFlow env. Noisy shell keys are skipped.
pub fn diff_envs(
    native: &BTreeMap<String, String>,
    flow: &HashMap<String, String>,
) -> EnvDiff {
    let mut diff = EnvDiff::default();
    let mut keys: Vec<&String> = native.keys().chain(flow.keys()).collect();
    keys.sort();
    keys.dedup();

    for key in keys {
        if NOISE_KEYS.contains(&key.as_str()) {
            continue;
        }
        match (native.get(key), flow.get(key)) {
            (Some(n), Some(f)) if n == f => diff.matched.push(key.clone()),
            (Some(n), Some(f)) => diff.mismatched.push((key.clone(), n.clone(), f.clone())),
            (Some(n), None) => diff.missing.push((key.clone(), n.clone())),
            (None, Some(f)) => diff.extra.push((key.clone(), f.clone())),
            (None, None) => unreachable!(),
        }
    }
    diff
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}… ({} chars)", &s[..max], s.len())
    }
}

/// Render the diff to stdout.
pub fn print_diff(
    appid: u32,
    native: &NativeLaunch,
    native_path: &Path,
    flow_env: &EffectiveEnv,
    flow_dir: &Path,
    diff: &EnvDiff,
) {
    println!("=== Environment parity diff — app {appid} ===");
    println!();
    println!("Native Steam  : {}", native_path.display());
    println!(
        "  Proton       : {}",
        native.proton_version.as_deref().unwrap_or("(unknown)")
    );
    println!(
        "  SteamGameId  : {}",
        native.steam_game_id.as_deref().unwrap_or("(unknown)")
    );
    println!(
        "  Command      : {}",
        native.command.as_deref().unwrap_or("(unknown)")
    );
    println!(
        "  Options      : {}",
        if native.options.is_empty() {
            "(none)".to_string()
        } else {
            format!("{:?}", native.options)
        }
    );
    println!(
        "  Kernel       : {}",
        native.kernel.as_deref().unwrap_or("(unknown)")
    );
    println!();
    println!("SteamFlow     : {}", flow_dir.display());
    println!("  Runner       : {}", flow_env.runner_name);
    println!(
        "  env vars     : {}",
        flow_env.env_vars.len()
    );
    println!();

    let print_kv = |prefix: &str, key: &str, value: &str| {
        let flag = match priority_of(key) {
            0 => "**",
            1 => "* ",
            2 => "  ",
            _ => "  ",
        };
        println!("{prefix} {flag} {key}={}", truncate(value, 160));
    };

    if !diff.mismatched.is_empty() {
        println!("--- MISMATCHED ({}): both set, different values ---", diff.mismatched.len());
        for (key, n, f) in &diff.mismatched {
            println!("  {key}");
            println!("    native   : {}", truncate(n, 200));
            println!("    steamflow: {}", truncate(f, 200));
        }
        println!();
    }

    if !diff.missing.is_empty() {
        println!("--- MISSING ({}): set by native Steam, absent in SteamFlow ---", diff.missing.len());
        for (key, value) in &diff.missing {
            print_kv("-", key, value);
        }
        println!();
    }

    if !diff.extra.is_empty() {
        println!("--- EXTRA ({}): set by SteamFlow, absent in native Steam ---", diff.extra.len());
        for (key, value) in &diff.extra {
            print_kv("+", key, value);
        }
        println!();
    }

    if !diff.matched.is_empty() {
        println!("--- MATCHED ({}): identical on both sides ---", diff.matched.len());
        for key in &diff.matched {
            println!("  = {key}");
        }
        println!();
    }

    let total = diff.missing.len() + diff.extra.len() + diff.mismatched.len();
    println!("=== Summary: {} divergence(s) ({} missing, {} extra, {} mismatched), {} matched ===",
        total, diff.missing.len(), diff.extra.len(), diff.mismatched.len(), diff.matched.len());
    if total == 0 {
        println!("  ✅ Environment parity: SteamFlow matches native Steam.");
    } else {
        println!("  ⚠️  Divergences found — see above. `**` = highest-impact var.");
    }
}

/// `steamflow test-diff <appid> [--native-log <path>] [--session <dir>]`
pub async fn test_diff(args: &[String]) -> Result<()> {
    let appid = args
        .get(1)
        .and_then(|a| a.parse::<u32>().ok())
        .ok_or_else(|| anyhow::anyhow!("usage: test-diff <appid> [--native-log <path>] [--session <dir>]"))?;

    let native_log_arg = args
        .iter()
        .position(|a| a == "--native-log")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);
    let session_arg = args
        .iter()
        .position(|a| a == "--session")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);

    let native_path = find_native_log(appid, native_log_arg.as_deref()).ok_or_else(|| {
        anyhow::anyhow!(
            "no native proton log found for app {appid} (looked for ~/steam-{appid}.log, \
             ~/Фото, видео/steam-{appid}.log, ~/Emulators/steam-{appid}.log, and a shallow \
             HOME scan). Capture one by launching the game from native Steam with \
             PROTON_LOG=1 in its launch options, or pass --native-log <path>."
        )
    })?;
    let native = parse_native_proton_log(&native_path)?;
    if native.steam_game_id.as_deref() != Some(&appid.to_string()) {
        println!(
            "  ⚠️  native log SteamGameId={:?} does not match requested appid {} — \
             continuing anyway",
            native.steam_game_id, appid
        );
    }

    let flow_dir = find_steamflow_session(appid, session_arg.as_deref()).ok_or_else(|| {
        anyhow::anyhow!(
            "no SteamFlow session with effective_env.json for app {appid} \
             (looked in ~/.config/SteamFlow/logs/*/). Run `steamflow test-launch {appid}` \
             first, or pass --session <dir>."
        )
    })?;
    let flow_env = load_effective_env(&flow_dir)?;

    let native_env = native.effective_env();
    let diff = diff_envs(&native_env, &flow_env.env_vars);

    print_diff(appid, &native, &native_path, &flow_env, &flow_dir, &diff);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_header() {
        let log = "======================\n\
                   Proton: 1667865000 GE-Proton7-41\n\
                   SteamGameId: 883710\n\
                   Command: ['/x/re2.exe']\n\
                   Options: {'forcelgadd', 'wined3d'}\n\
                   depot: 0.20220930.72\n\
                   Kernel: Linux 5.18 x86_64\n\
                   ======================\n\
                   fsync: up and running.\n";
        let dir = std::env::temp_dir().join("parity_test_legacy.log");
        std::fs::write(&dir, log).unwrap();
        let native = parse_native_proton_log(&dir).unwrap();
        std::fs::remove_file(&dir).ok();

        assert_eq!(native.proton_version.as_deref(), Some("1667865000 GE-Proton7-41"));
        assert_eq!(native.steam_game_id.as_deref(), Some("883710"));
        assert_eq!(native.options, vec!["forcelgadd", "wined3d"]);
        let env = native.effective_env();
        assert_eq!(env.get("PROTON_FORCE_LARGE_ADDRESS_AWARE").map(String::as_str), Some("1"));
        assert_eq!(env.get("PROTON_USE_WINED3D").map(String::as_str), Some("1"));
        assert!(!env.contains_key("PROTON_NO_FSYNC"));
    }

    #[test]
    fn parses_modern_effective_overrides() {
        let log = "======================\n\
                   Proton: 1785138253 proton-11.0-1b\n\
                   SteamGameId: 883710\n\
                   Command: ['/x/re2.exe']\n\
                   Options: set()\n\
                   Kernel: Linux 6.8 x86_64\n\
                   Effective WINEDLLOVERRIDES: dxvk.dll=n,b\n\
                   Effective WINEDEBUG: +loaddll\n\
                   ======================\n";
        let dir = std::env::temp_dir().join("parity_test_modern.log");
        std::fs::write(&dir, log).unwrap();
        let native = parse_native_proton_log(&dir).unwrap();
        std::fs::remove_file(&dir).ok();

        assert_eq!(native.env.get("WINEDLLOVERRIDES").map(String::as_str), Some("dxvk.dll=n,b"));
        assert_eq!(native.env.get("WINEDEBUG").map(String::as_str), Some("+loaddll"));
        assert!(native.options.is_empty());
    }

    #[test]
    fn diff_categorizes() {
        let mut native = BTreeMap::new();
        native.insert("WINEDLLOVERRIDES".into(), "dxvk=n,b".into());
        native.insert("PROTON_USE_WINED3D".into(), "1".into());
        native.insert("PATH".into(), "/usr/bin".into());

        let mut flow = HashMap::new();
        flow.insert("WINEDLLOVERRIDES".into(), "dxvk=n;wined3d=n".into());
        flow.insert("STEAM_COMPAT_APP_ID".into(), "883710".into());

        let diff = diff_envs(&native, &flow);
        assert_eq!(diff.mismatched.len(), 1);
        assert_eq!(diff.mismatched[0].0, "WINEDLLOVERRIDES");
        // Native-only: PROTON_USE_WINED3D + PATH (PATH is not noise).
        assert_eq!(diff.missing.len(), 2);
        assert!(diff.missing.iter().any(|(k, _)| k == "PROTON_USE_WINED3D"));
        assert!(diff.missing.iter().any(|(k, _)| k == "PATH"));
        assert_eq!(diff.extra.len(), 1);
        assert_eq!(diff.extra[0].0, "STEAM_COMPAT_APP_ID");
        assert!(diff.matched.is_empty());
    }
}
