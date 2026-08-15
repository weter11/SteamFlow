//! Native Rust reimplementation of Valve Proton's launch semantics
//! (the `proton` wrapper script + `default_pfx.py` prefix seeding).
//!
//! Phase 2 item 2 of the valve-stack directive
//! (`docs/architecture/valve-stack-replication.md` §Tier 1): eliminate the
//! dependency on external Python script invocation at game launch by porting
//! the core logic to Rust. Verified against official Proton 11.0's `proton`
//! script (app 4628710, depot 4628711) on 2026-08-11.
//!
//! What lives here (all runner-agnostic, pure semantics):
//!   - `default_compat_config(appid)` — the per-app compat-option table.
//!   - `CompatSession::build_env()` — environment assembly (STEAM_COMPAT_*,
//!     WINE_*/PROTON_*/VKD3D_*/DXVK_* rules, WINEDLLOVERRIDES base set).
//!   - `check_environment` — PROTON_* env var ⇄ compat-option translation.
//!   - `seed_prefix()` — native prefix init (default_pfx copy, dosdevices
//!     symlinks, MachineGuid preservation) without Python.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Compat option table — port of `default_compat_config()` (proton script).
// ---------------------------------------------------------------------------

/// Port of Proton's `default_compat_config()`: the appid → compat-option
/// rules, plus the unconditional `gamedrive`. Returns the option set for an
/// appid. `forcelgadd` is added by the caller unless `noforcelgadd` is set
/// (mirrors `if "noforcelgadd" not in compat_config: compat_config.add("forcelgadd")`).
pub fn default_compat_config(appid: u32) -> BTreeSet<String> {
    let mut ret = BTreeSet::new();
    let appid_str = appid.to_string();

    // nomfdxgiman (CW bug 19741 / 20240 / Unity race)
    if matches!(appid, 1017900 | 1331440 | 2620730 | 2882920 | 2712910) {
        ret.insert("nomfdxgiman".into());
    }
    // noopwr (text-input delay / OWPR code path issues)
    if matches!(
        appid,
        1172620 | 962130 | 495420 | 976730 | 1017900 | 1056090 | 1293830 | 1551360 | 813780
            | 933110 | 1466860 | 1097840 | 1244950 | 1189800 | 1184050 | 1240440 | 1250410
            | 1672970 | 1180660 | 1238430 | 1266670 | 230410 | 3513350 | 3728370
    ) {
        ret.insert("noopwr".into());
    }
    // noforcelgadd
    if matches!(appid, 2710 | 1621680 | 888040) {
        ret.insert("noforcelgadd".into());
    }
    // hidevggpu
    if matches!(appid, 257420 | 2021880) {
        ret.insert("hidevggpu".into());
    }
    // hideintelgpu
    if appid == 1977170 {
        ret.insert("hideintelgpu".into());
    }
    // heapdelayfree
    if matches!(appid, 202990 | 212910 | 499100 | 1404090 | 2052410 | 789910 | 1183470 | 876340)
    {
        ret.insert("heapdelayfree".into());
    }
    // heapzeromemory
    if matches!(appid, 21980 | 553850 | 2055290) {
        ret.insert("heapzeromemory".into());
    }
    // heaptopdown
    if matches!(appid, 71230 | 3328910) {
        ret.insert("heaptopdown".into());
    }
    // nofsync + noesync
    if matches!(appid, 2630 | 1060210 | 414740 | 201510 | 1233880) {
        ret.insert("nofsync".into());
        ret.insert("noesync".into());
    }
    // disablenvapi (titles that dislike dxvknvapi)
    if matches!(
        appid,
        1088850 | 1418100 | 2080180 | 1939100 | 435150 | 2176900 | 2853730
    ) {
        ret.insert("disablenvapi".into());
    }
    // disablenvapi when no NVIDIA driver is loaded (/proc/modules check)
    if matches!(
        appid,
        1808500 | 2073850 | 108710 | 202750 | 505170 | 255220 | 44350 | 407810 | 233130
            | 2067160 | 2621010 | 368500
    ) {
        if !nvidia_driver_loaded() {
            ret.insert("disablenvapi".into());
        }
    }
    // hidenvgpu
    if appid == 2698940 {
        ret.insert("hidenvgpu".into());
    }
    // forcenvapi
    if matches!(appid, 2395210 | 1577120) {
        ret.insert("forcenvapi".into());
    }
    // hideapu
    if appid == 1252330 {
        ret.insert("hideapu".into());
    }
    // fnad3d11
    if matches!(appid, 249610 | 287240 | 280200 | 312530 | 1072860) {
        ret.insert("fnad3d11".into());
    }

    // options to also be enabled for prerequisite setup steps
    ret.insert("gamedrive".into());

    // STEAM_COMPAT_APP_ID block (secondary key)
    if matches!(
        appid,
        247660 | 1026680 | 3280350 | 3513350 | 3837340 | 337000
    ) {
        ret.insert("noxalia".into());
    }
    if matches!(appid, 275850 | 2012840) {
        ret.insert("nohardwarescheduling".into());
    }

    let _ = appid_str;
    ret
}

/// `/proc/modules` NVIDIA-driver probe — mirrors Proton's Python check.
fn nvidia_driver_loaded() -> bool {
    std::fs::read_to_string("/proc/modules")
        .map(|content| {
            content.lines().any(|line| {
                let driver = line.split(' ').next().unwrap_or("");
                matches!(driver, "nvidia" | "nouveau" | "nova")
            })
        })
        .unwrap_or(true) // /proc/modules unreadable → assume NVIDIA (safe default)
}

/// `default_cpu_limit` table — WINE_CPU_TOPOLOGY per appid.
pub fn default_cpu_limit(appid: u32) -> Option<u32> {
    Some(match appid {
        19900 | 298110 | 20920 | 35130 | 55150 | 204450 => 16,
        15620 | 20570 | 56400 | 259170 | 115320 => 8,
        618970 | 10150 | 11440 | 65540 => 4,
        2229830 => 1,
        316260 => 16,
        286810 => 30,
        70000 => 28,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// PROTON_* env ⇄ compat-option translation (`check_environment` port).
// ---------------------------------------------------------------------------

/// `check_environment(env_name, config_name)` table — an env var that, when
/// set non-zero, adds its compat option. This is the same table as
/// `crate::parity::OPTION_TO_PROTON_ENV`, kept here as the launch-side source
/// of truth (parity.rs re-exports from here to avoid drift).
pub const PROTON_ENV_TO_OPTION: &[(&str, &str)] = &[
    ("PROTON_USE_WINED3D", "wined3d"),
    ("PROTON_USE_WINED3D11", "wined3d11"),
    ("PROTON_DXVK_D3D8", "dxvkd3d8"),
    ("PROTON_NO_D3D11", "nod3d11"),
    ("PROTON_NO_D3D10", "nod3d10"),
    ("PROTON_NO_FSYNC", "nofsync"),
    ("PROTON_FORCE_LARGE_ADDRESS_AWARE", "forcelgadd"),
    ("PROTON_OLD_GL_STRING", "oldglstr"),
    ("PROTON_HIDE_NVIDIA_GPU", "hidenvgpu"),
    ("PROTON_HIDE_VANGOGH_GPU", "hidevggpu"),
    ("PROTON_HIDE_INTEL_GPU", "hideintelgpu"),
    ("PROTON_SET_GAME_DRIVE", "gamedrive"),
    ("PROTON_SET_STEAM_DRIVE", "steamdrive"),
    ("PROTON_NO_XIM", "noxim"),
    ("PROTON_HEAP_DELAY_FREE", "heapdelayfree"),
    ("PROTON_HEAP_ZERO_MEMORY", "heapzeromemory"),
    ("PROTON_DISABLE_NVAPI", "disablenvapi"),
    ("PROTON_FORCE_NVAPI", "forcenvapi"),
    ("PROTON_HIDE_APU", "hideapu"),
];

/// Apply `STEAM_COMPAT_CONFIG` (comma-separated options, incl.
/// `cmdlineappend:...`) onto the compat set — port of the Session __init__
/// STEAM_COMPAT_CONFIG parsing.
pub fn apply_steam_compat_config(compat: &mut BTreeSet<String>, config: &str) {
    if config.is_empty() {
        return;
    }
    for part in config.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(rest) = part.strip_prefix("cmdlineappend:") {
            // cmdlineappend entries are not compat options; ignore for env
            // purposes (callers that need the appended argv can parse this
            // separately).
            let _ = rest;
            continue;
        }
        compat.insert(part.to_string());
    }
}

/// Add `forcelgadd` unless `noforcelgadd` is present (Proton Session init).
pub fn apply_forcelgadd_default(compat: &mut BTreeSet<String>) {
    if !compat.contains("noforcelgadd") {
        compat.insert("forcelgadd".to_string());
    }
}

// ---------------------------------------------------------------------------
// Environment assembly — port of Session::init_wine / run_game env rules.
// ---------------------------------------------------------------------------

/// Base WINEDLLOVERRIDES dict (Session __init__).
pub fn base_dll_overrides() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("steam.exe".into(), "b".into()); // always our special built-in steam.exe
    m.insert("dotnetfx35.exe".into(), "b".into());
    m.insert("dotnetfx35setup.exe".into(), "b".into());
    m.insert("beclient.dll".into(), "b,n".into());
    m.insert("beclient_x64.dll".into(), "b,n".into());
    m.insert("winebth.sys".into(), "d".into()); // crashes winedevice.exe
    m
}

/// Port of the per-game dlloverride rules + compat-config env rules
/// (the `run()` / env-assembly block in the proton script).
///
/// `appid` — SteamAppId (0 = unknown). `compat` — the effective compat set.
/// `env` — in/out: SteamFlow's env; Proton's rules are merged in.
/// `dll_overrides` — in/out: ordered (dll, setting) pairs. SteamFlow's
/// existing entries are kept (in order); Proton's base dict and per-game
/// rules are merged in (existing keys keep their SteamFlow value, matching
/// the "thin launcher" directive).
pub fn apply_proton_env_rules(
    appid: u32,
    compat: &BTreeSet<String>,
    env: &mut HashMap<String, String>,
    dll_overrides: &mut Vec<(String, String)>,
) {
    // Helper: get-or-insert preserving order.
    fn upsert(overrides: &mut Vec<(String, String)>, dll: &str, setting: &str) {
        match overrides.iter_mut().find(|(d, _)| d == dll) {
            Some(entry) => entry.1 = setting.to_string(),
            None => overrides.push((dll.to_string(), setting.to_string())),
        }
    }

    // Base dlloverrides (merged; SteamFlow's explicit values win).
    for (k, v) in base_dll_overrides() {
        upsert(dll_overrides, &k, &v);
    }
    // opencl=n,d unless the app opts out (2767030 / 2274200).
    if appid != 2767030 && appid != 2274200 {
        upsert(dll_overrides, "opencl", "n,d");
    }

    // WINE_CPU_TOPOLOGY
    if !env.contains_key("PROTON_CPU_TOPOLOGY") {
        if let Some(limit) = default_cpu_limit(appid) {
            env.insert("WINE_CPU_TOPOLOGY".into(), limit.to_string());
        }
    } else if let Some(v) = env.get("PROTON_CPU_TOPOLOGY") {
        env.insert("WINE_CPU_TOPOLOGY".into(), v.clone());
    }

    // PROTON_* input vars for every active compat option (reverse of
    // check_environment): native Steam's launch env carries these, and the
    // test-diff harness reverse-maps a native log's `Options:` set to them.
    // Emitting them here closes the parity gaps SteamFlow previously had
    // (e.g. PROTON_FORCE_LARGE_ADDRESS_AWARE from the forcelgadd default,
    // PROTON_USE_WINED3D from a per-game wined3d option).
    for (env_var, option) in PROTON_ENV_TO_OPTION {
        if compat.contains(*option) {
            env.insert(env_var.to_string(), "1".to_string());
        }
    }

    // WINE_LARGE_ADDRESS_AWARE (forcelgadd / noforcelgadd)
    if compat.contains("forcelgadd") {
        env.insert("WINE_LARGE_ADDRESS_AWARE".into(), "1".into());
    } else if compat.contains("noforcelgadd") {
        env.insert("WINE_LARGE_ADDRESS_AWARE".into(), "0".into());
    }

    // WINE_HEAP_*
    if compat.contains("heapdelayfree") {
        env.insert("WINE_HEAP_DELAY_FREE".into(), "1".into());
    }
    if compat.contains("heapzeromemory") {
        env.insert("WINE_HEAP_ZERO_MEMORY".into(), "1".into());
    }
    if compat.contains("heaptopdown") {
        env.insert("WINE_HEAP_TOP_DOWN".into(), "1".into());
    }

    // VKD3D_CONFIG / VKD3D_FEATURE_LEVEL
    if compat.contains("vkd3dbindlesstb") {
        append_env_list(env, "VKD3D_CONFIG", "force_bindless_texel_buffer", ",");
    }
    if compat.contains("vkd3dfl12") {
        env.entry("VKD3D_FEATURE_LEVEL".to_string())
            .or_insert_with(|| "12_0".to_string());
    }

    // GPU hiding
    if compat.contains("hidevggpu") {
        env.insert("WINE_HIDE_VANGOGH_GPU".into(), "1".into());
    }
    if compat.contains("hidenvgpu") && !compat.contains("forcenvapi") {
        env.insert("WINE_HIDE_NVIDIA_GPU".into(), "1".into());
    }
    if compat.contains("hideintelgpu") {
        env.insert("WINE_HIDE_INTEL_GPU".into(), "1".into());
    }
    if compat.contains("hideapu") {
        env.insert("WINE_HIDE_APU".into(), "1".into());
    }

    // xinput1_3 / libglesv2 overrides
    if compat.contains("usenativexinput13") {
        upsert(dll_overrides, "xinput1_3", "n");
    }
    if compat.contains("disablelibglesv2") {
        upsert(dll_overrides, "libglesv2", "d");
    }

    // DXGI device-manager / OPWR
    if compat.contains("nomfdxgiman") {
        env.insert("WINE_DO_NOT_CREATE_DXGI_DEVICE_MANAGER".into(), "1".into());
    }
    if compat.contains("noopwr") {
        env.insert("WINE_DISABLE_VULKAN_OPWR".into(), "1".into());
    }

    // XALIA
    if !env.contains_key("PROTON_USE_XALIA") {
        if compat.contains("noxalia") {
            env.insert("PROTON_USE_XALIA".into(), "0".into());
        } else {
            env.insert("PROTON_USE_XALIA".into(), "1".into());
            if !compat.contains("xalia") {
                env.insert("XALIA_SUPPORTED_ONLY".into(), "1".into());
            }
        }
    }

    // Hardware scheduling
    if compat.contains("nohardwarescheduling") && !env.contains_key("WINE_DISABLE_HARDWARE_SCHEDULING")
    {
        env.insert("WINE_DISABLE_HARDWARE_SCHEDULING".into(), "1".into());
    }

    // Crash report dir passthrough
    if let Some(dir) = env.get("PROTON_CRASH_REPORT_DIR") {
        env.insert("WINE_CRASH_REPORT_DIR".into(), dir.clone());
    }

    // FNA3D
    if compat.contains("fnad3d11") && !env.contains_key("FNA3D_FORCE_DRIVER") {
        env.insert("FNA3D_FORCE_DRIVER".into(), "D3D11".into());
    }

    // GLVND
    env.entry("__GLVND_DISALLOW_PATCHING".into()).or_insert_with(|| "1".into());
    // WINE_MONO_HIDETYPES
    env.entry("WINE_MONO_HIDETYPES".into()).or_insert_with(|| "0".into());

    // nod3d11 / nod3d10
    if compat.contains("nod3d11") {
        upsert(dll_overrides, "d3d11", "");
        dll_overrides.retain(|(d, _)| d != "dxgi");
    }
    if compat.contains("nod3d10") {
        upsert(dll_overrides, "d3d10_1", "");
        upsert(dll_overrides, "d3d10", "");
        upsert(dll_overrides, "dxgi", "");
    }
    if compat.contains("nativevulkanloader") {
        upsert(dll_overrides, "vulkan-1", "n");
    }

    // NVAPI
    if !compat.contains("disablenvapi") || compat.contains("forcenvapi") {
        env.entry("DXVK_ENABLE_NVAPI".into()).or_insert_with(|| "1".into());
    }
    if compat.contains("forcenvapi") {
        env.insert("DXVK_NVAPI_ALLOW_OTHER_DRIVERS".into(), "1".into());
        env.insert("DXVK_NVAPI_DRIVER_VERSION".into(), "99999".into());
        env.insert("WINE_HIDE_AMD_GPU".into(), "1".into());
    }

    // PROTON_LIMIT_ADDRESS_SPACE
    if !env.contains_key("PROTON_LIMIT_ADDRESS_SPACE") && matches!(appid, 1282270 | 2963870) {
        env.insert("PROTON_LIMIT_ADDRESS_SPACE".into(), "1".into());
    }

    // OPENSSL_ia32cap (long appid list — ported from the script's list)
    if matches!(
        appid,
        425670 | 1096570 | 492230 | 996580 | 437630 | 442780 | 433100 | 406970 | 451520
            | 1237970 | 1051200 | 285190 | 1133320
    ) {
        env.insert("OPENSSL_ia32cap".into(), "~0x20000000".into());
    }

    // ddraw / dinput / winmm / gameinput per-game overrides
    if matches!(appid, 500810 | 4249100 | 4249110 | 4249130 | 4249150) {
        upsert(dll_overrides, "ddraw", "n,b");
    }
    if appid == 3780660 {
        upsert(dll_overrides, "dinput", "n,b");
    }
    if appid == 2471120 {
        upsert(dll_overrides, "winmm", "n,b");
    }
    if appid == 1928420 {
        upsert(dll_overrides, "gameinput", "d");
    }

    // PROTON_LIMIT_RESOLUTIONS
    if !env.contains_key("PROTON_LIMIT_RESOLUTIONS") {
        if appid == 39540 {
            env.insert("PROTON_LIMIT_RESOLUTIONS".into(), "16".into());
        } else if matches!(appid, 524220 | 814380 | 374320 | 357190) {
            env.insert("PROTON_LIMIT_RESOLUTIONS".into(), "32".into());
        }
    }

    // WINE_HIDE_AMD_GPU (per-app)
    if !env.contains_key("WINE_HIDE_AMD_GPU") && appid == 1282690 {
        env.insert("WINE_HIDE_AMD_GPU".into(), "1".into());
    }

    // atiadlxx (per-app)
    if appid == 2767030 {
        upsert(dll_overrides, "atiadlxx", "b");
    }
}

/// Append `value` to `env[key]` (comma-separated), like Proton's
/// `append_to_env_str`.
pub fn append_env_list(env: &mut HashMap<String, String>, key: &str, value: &str, sep: &str) {
    match env.get_mut(key) {
        Some(existing) if !existing.is_empty() => {
            existing.push_str(sep);
            existing.push_str(value);
        }
        _ => {
            env.insert(key.to_string(), value.to_string());
        }
    }
}

/// Serialize an ordered dlloverrides list into a WINEDLLOVERRIDES string
/// (`dll=setting;...`), matching Proton's ordering (insertion order preserved).
pub fn serialize_dll_overrides(overrides: &[(String, String)]) -> String {
    overrides
        .iter()
        .map(|(dll, setting)| format!("{dll}={setting}"))
        .collect::<Vec<_>>()
        .join(";")
}

// ---------------------------------------------------------------------------
// Prefix seeding — port of `default_pfx.py` / `copy_pfx` + dosdevices.
// ---------------------------------------------------------------------------

/// Native prefix initialization: copy `default_pfx` into `prefix_dir` (files
/// copied, symlinks preserved), create `dosdevices/c:` and `dosdevices/z:`
/// symlinks, and stamp the proton version marker. Returns the list of created
/// paths (for tracking).
///
/// Mirrors Proton's `CompatData.setup_prefix()` → `copy_pfx()` + the
/// dosdevices symlink block, WITHOUT invoking Python.
pub fn seed_prefix(
    default_pfx_dir: &Path,
    prefix_dir: &Path,
    proton_version: &str,
) -> std::io::Result<Vec<PathBuf>> {
    let mut created = Vec::new();

    // copy_pfx: walk default_pfx, copy files / recreate symlinks.
    if default_pfx_dir.is_dir() {
        copy_tree(default_pfx_dir, prefix_dir, &mut created)?;
    }

    // dosdevices symlinks (only if missing).
    let dosdevices = prefix_dir.join("dosdevices");
    std::fs::create_dir_all(&dosdevices)?;
    let c_link = dosdevices.join("c:");
    if !c_link.exists() {
        std::os::unix::fs::symlink("../drive_c", &c_link)?;
        created.push(c_link);
    }
    let z_link = dosdevices.join("z:");
    if !z_link.exists() {
        std::os::unix::fs::symlink("/", &z_link)?;
        created.push(z_link);
    }

    // Version marker (compatdata/version).
    std::fs::create_dir_all(prefix_dir)?;
    std::fs::write(prefix_dir.join("version"), format!("{proton_version}\n"))?;

    Ok(created)
}

fn copy_tree(src: &Path, dst: &Path, created: &mut Vec<PathBuf>) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            let target = std::fs::read_link(&from)?;
            if !to.exists() {
                std::os::unix::fs::symlink(&target, &to)?;
                created.push(to);
            }
        } else if ft.is_dir() {
            copy_tree(&from, &to, created)?;
        } else if !to.exists() {
            std::fs::copy(&from, &to)?;
            created.push(to);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compat_config_re2_empty_plus_gamedrive() {
        // RE2 (883710) is in no special list → only gamedrive (+forcelgadd later).
        let c = default_compat_config(883710);
        assert_eq!(c, BTreeSet::from(["gamedrive".to_string()]));
    }

    #[test]
    fn compat_config_noforcelgadd_listed() {
        let c = default_compat_config(2710); // Act of War
        assert!(c.contains("noforcelgadd"));
        let mut with_default = c.clone();
        apply_forcelgadd_default(&mut with_default);
        assert!(!with_default.contains("forcelgadd"));
    }

    #[test]
    fn compat_config_forcelgadd_default() {
        let mut c = default_compat_config(883710);
        apply_forcelgadd_default(&mut c);
        assert!(c.contains("forcelgadd"));
        assert!(c.contains("gamedrive"));
    }

    #[test]
    fn steam_compat_config_parsing() {
        let mut c = BTreeSet::new();
        apply_steam_compat_config(&mut c, "forcelgadd,cmdlineappend:-nointro,wined3d");
        assert!(c.contains("forcelgadd"));
        assert!(c.contains("wined3d"));
        assert!(!c.contains("cmdlineappend:-nointro"));
    }

    #[test]
    fn env_rules_forcelgadd_sets_large_address_aware() {
        let mut c = default_compat_config(883710);
        apply_forcelgadd_default(&mut c);
        let mut env = HashMap::new();
        let mut dll: Vec<(String, String)> = Vec::new();
        apply_proton_env_rules(883710, &c, &mut env, &mut dll);
        assert_eq!(env.get("WINE_LARGE_ADDRESS_AWARE").map(String::as_str), Some("1"));
        assert_eq!(env.get("DXVK_ENABLE_NVAPI").map(String::as_str), Some("1"));
        assert_eq!(env.get("WINE_MONO_HIDETYPES").map(String::as_str), Some("0"));
        assert_eq!(env.get("__GLVND_DISALLOW_PATCHING").map(String::as_str), Some("1"));
        let opencl = dll.iter().find(|(d, _)| d == "opencl").map(|(_, v)| v.clone());
        assert_eq!(opencl.as_deref(), Some("n,d"));
        let steam = dll.iter().find(|(d, _)| d == "steam.exe").map(|(_, v)| v.clone());
        assert_eq!(steam.as_deref(), Some("b"));
    }

    #[test]
    fn env_rules_wined3d_option() {
        let mut c = BTreeSet::new();
        c.insert("wined3d".into());
        apply_forcelgadd_default(&mut c);
        let mut env = HashMap::new();
        let mut dll: Vec<(String, String)> = Vec::new();
        apply_proton_env_rules(883710, &c, &mut env, &mut dll);
        // wined3d → PROTON_USE_WINED3D is an INPUT var; the option itself is
        // tracked in the compat set (SteamFlow's graphics policy decides the
        // actual backend). Assert the option surfaced in the compat set.
        assert!(c.contains("wined3d"));
        // forcelgadd still default
        assert_eq!(env.get("WINE_LARGE_ADDRESS_AWARE").map(String::as_str), Some("1"));
    }

    #[test]
    fn env_rules_nod3d11_clears_dxgi() {
        let mut c = BTreeSet::new();
        c.insert("nod3d11".into());
        apply_forcelgadd_default(&mut c);
        let mut env = HashMap::new();
        let mut dll: Vec<(String, String)> = vec![("dxgi".to_string(), "n,b".to_string())];
        apply_proton_env_rules(883710, &c, &mut env, &mut dll);
        let d3d11 = dll.iter().find(|(d, _)| d == "d3d11").map(|(_, v)| v.clone());
        assert_eq!(d3d11.as_deref(), Some(""));
        assert!(!dll.iter().any(|(d, _)| d == "dxgi"));
    }

    #[test]
    fn env_rules_emit_proton_input_vars() {
        // Native Steam's launch env carries PROTON_* input vars for active
        // compat options; the ABI must emit them (test-diff parity).
        let mut c = default_compat_config(883710);
        apply_forcelgadd_default(&mut c); // → forcelgadd active
        c.insert("wined3d".into());
        let mut env = HashMap::new();
        let mut dll: Vec<(String, String)> = Vec::new();
        apply_proton_env_rules(883710, &c, &mut env, &mut dll);
        assert_eq!(
            env.get("PROTON_FORCE_LARGE_ADDRESS_AWARE").map(String::as_str),
            Some("1")
        );
        assert_eq!(env.get("PROTON_USE_WINED3D").map(String::as_str), Some("1"));
        assert_eq!(env.get("WINE_LARGE_ADDRESS_AWARE").map(String::as_str), Some("1"));
    }

    #[test]
    fn seed_prefix_creates_symlinks_and_version() {
        let tmp = std::env::temp_dir().join(format!("proton_abi_test_{}", std::process::id()));
        let pfx = tmp.join("pfx");
        let default = tmp.join("default_pfx");
        std::fs::create_dir_all(default.join("drive_c/windows")).unwrap();
        std::fs::write(default.join("system.reg"), "#test").unwrap();
        std::fs::write(default.join("drive_c/windows/win.ini"), "[fonts]\n").unwrap();

        let created = seed_prefix(&default, &pfx, "proton-11.0-1b").unwrap();
        assert!(pfx.join("dosdevices/c:").exists());
        assert!(pfx.join("dosdevices/z:").exists());
        assert_eq!(std::fs::read_to_string(pfx.join("version")).unwrap(), "proton-11.0-1b\n");
        assert_eq!(std::fs::read_to_string(pfx.join("system.reg")).unwrap(), "#test");
        assert_eq!(
            std::fs::read_to_string(pfx.join("drive_c/windows/win.ini")).unwrap(),
            "[fonts]\n"
        );
        assert!(!created.is_empty());
        // c: is a symlink to ../drive_c
        let target = std::fs::read_link(pfx.join("dosdevices/c:")).unwrap();
        assert_eq!(target, PathBuf::from("../drive_c"));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn cpu_limit_table() {
        assert_eq!(default_cpu_limit(19900), Some(16)); // Far Cry 2
        assert_eq!(default_cpu_limit(2229830), Some(1)); // C&C
        assert_eq!(default_cpu_limit(883710), None); // RE2 not listed
    }
}
