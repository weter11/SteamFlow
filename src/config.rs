use crate::models::{
    LaunchMode, OwnedGame, RunnerSource, SessionState, SteamPrefixMode, UserConfigStore,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use steam_vent::auth::ClientInfo;
use tokio::fs;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct GameConfig {
    pub forced_proton_version: Option<String>,
    pub platform_preference: Option<String>,
}

/// Dev-only configuration loaded from `~/.config/SteamFlow/debug.json`.
///
/// Not exposed in the UI — this is a debugging facility for developers.
/// The `env` map is applied as the final (highest-priority) overlay onto
/// every game launch environment, so keys here win over per-game env
/// variables and built-in debug defaults.
///
/// Example file:
/// ```json
/// {
///   "env": {
///     "VKD3D_DEBUG": "info",
///     "DXVK_LOG_LEVEL": "info",
///     "WINEDEBUG": "+mfplat,+wg_transform,+gstreamer",
///     "GST_DEBUG": "2",
///     "GST_DEBUG_NO_COLOR": "1"
///   }
/// }
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DebugConfig {
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// Loads `debug.json` from the SteamFlow config dir.
///
/// - Missing file -> empty [`DebugConfig`] (no-op).
/// - Malformed JSON -> logs a warning to stderr and returns empty config;
///   a broken debug file must never break a game launch.
pub fn load_debug_config() -> DebugConfig {
    let Ok(dir) = config_dir() else {
        return DebugConfig::default();
    };
    let path = dir.join("debug.json");
    if !path.exists() {
        return DebugConfig::default();
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<DebugConfig>(&content) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!(
                    "[debug.json] failed to parse {}: {e}; ignoring debug config",
                    path.display()
                );
                DebugConfig::default()
            }
        },
        Err(e) => {
            eprintln!(
                "[debug.json] failed to read {}: {e}; ignoring debug config",
                path.display()
            );
            DebugConfig::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LauncherConfig {
    pub steam_library_path: String,
    pub proton_version: String,
    #[serde(default)]
    pub steam_runtime_runner: PathBuf,
    #[serde(default)]
    pub steam_runtime_runner_source: RunnerSource,
    #[serde(default)]
    pub steam_prefix_mode: SteamPrefixMode,
    #[serde(default)]
    pub launch_mode: LaunchMode,
    pub enable_cloud_sync: bool,
    #[serde(default)]
    pub use_shared_compat_data: bool,
    #[serde(default = "crate::models::default_true")]
    pub windows_steam_discovery_enabled: bool,
    /// When enabled (default), the Windows Steam client is pinned to skip its in-client
    /// self-updater. Under Proton-based runners Steam's updater downloads a fresh client
    /// that then fails the in-place rename (rename ...steamwebhelper.exe -> .old returns
    /// ERROR_ACCESS_DENIED) and the launch aborts before connecting. Disabling the
    /// self-update keeps the known-good client in place. wine-tkg does not trigger the
    /// update and works either way, but leaving this on is safe for it too.
    #[serde(default = "crate::models::default_true")]
    pub skip_steam_self_update: bool,
    /// Global Steam-launch feature toggles used by client-management operations
    /// (Manage / Repair / Reinstall / Backup / Restore). Defaults to
    /// `all_alive()` — steamwebhelper must survive these operations so the
    /// client can log in and render its UI. The per-game `SteamLaunchConfig`
    /// still controls game launches.
    #[serde(default = "crate::models::default_steam_launch_config_alive")]
    pub steam_launch_config: crate::models::SteamLaunchConfig,
    #[serde(default)]
    pub preferred_launch_options: HashMap<u32, String>,
    #[serde(default)]
    pub game_configs: HashMap<u32, GameConfig>,
    /// Pre-launch VRAM guard: warn when GPU memory usage exceeds this
    /// percentage of total VRAM. Set to 0 to disable the warning entirely.
    #[serde(default)]
    pub vram_warn_threshold_pct: u32,
}

impl LauncherConfig {
    pub async fn load() -> Result<Self> {
        load_launcher_config().await
    }

    pub async fn save(&self) -> Result<()> {
        save_launcher_config(self).await
    }
}

impl Default for LauncherConfig {
    fn default() -> Self {
        let steam_library_path = detect_steam_path()
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
                format!("{home}/Games/SteamFlow")
            });

        Self {
            steam_library_path,
            proton_version: "Proton - Experimental".to_string(),
            steam_runtime_runner: PathBuf::new(),
            steam_runtime_runner_source: RunnerSource::default(),
            steam_prefix_mode: SteamPrefixMode::default(),
            launch_mode: LaunchMode::default(),
            enable_cloud_sync: true,
            use_shared_compat_data: false,
            windows_steam_discovery_enabled: true,
            skip_steam_self_update: true,
            steam_launch_config: crate::models::SteamLaunchConfig::all_alive(),
            preferred_launch_options: HashMap::new(),
            game_configs: HashMap::new(),
            vram_warn_threshold_pct: 75,
        }
    }
}

pub fn detect_steam_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let candidates = [PathBuf::from(r"C:\Program Files (x86)\Steam")];
        return candidates.into_iter().find(|path| path.exists());
    }

    #[cfg(not(target_os = "windows"))]
    {
        let home = std::env::var("HOME").ok()?;
        let candidates = [
            PathBuf::from(&home).join(".steam/steam"),
            PathBuf::from(&home).join(".local/share/Steam"),
            PathBuf::from(&home).join(".steam/root"),
        ];
        candidates.into_iter().find(|path| path.exists())
    }
}

/// Returns the Steam install root that contains `compatibilitytools.d` and
/// `steamapps/common` (where Steam SDK shims such as libsteam_api.so live).
/// On Linux this is typically ~/.local/share/Steam (with ~/.steam/steam often a
/// symlink to it). Best-effort fallback source when a game's own Steam SDK shim
/// is missing or corrupt and must be repaired from another location.
pub fn get_steam_root_hint() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let candidates = [
        PathBuf::from(&home).join(".local/share/Steam"),
        PathBuf::from(&home).join(".steam/steam"),
        PathBuf::from(&home).join(".steam/root"),
    ];
    for c in &candidates {
        if c.join("compatibilitytools.d").is_dir() || c.join("steamapps/common").is_dir() {
            return Some(c.clone());
        }
    }
    candidates.into_iter().find(|p| p.exists())
}

pub fn config_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config/SteamFlow"))
}

pub async fn ensure_config_dirs() -> Result<()> {
    let config = config_dir()?;
    fs::create_dir_all(&config).await?;
    let images = opensteam_image_cache_dir()?;
    fs::create_dir_all(&images).await?;
    Ok(())
}

pub fn opensteam_image_cache_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("images"))
}

pub fn data_dir() -> Result<PathBuf> {
    config_dir() // or use XDG_DATA_HOME if you want proper separation
}

/// Mode for files that carry credentials: owner read/write only.
const SECRET_MODE: u32 = 0o600;

/// Write `body` to `path` as an owner-only file, atomically.
///
/// Two properties that a plain `fs::write` does not give:
///
/// - **Mode.** The file is created with `0o600` explicitly rather than
///   inheriting the umask (typically `0644`), so the refresh token in
///   `session.json` and the machine identity in `machine_id.json` are not
///   readable by other local users. The mode is also re-applied on an
///   existing file, which `fs::write` would leave at whatever mode it had.
/// - **Atomicity.** The content goes to a temp file in the same directory and
///   is then `rename`d over the target, so a crash or a full disk leaves the
///   previous file intact instead of a truncated one. `rename` within a
///   directory is atomic on POSIX; the temp file must share the directory so
///   it cannot land on a different filesystem.
///
/// Both secret writers go through this function rather than each doing their
/// own `fs::write`, so the two cannot drift apart on mode or atomicity again.
pub(crate) async fn write_secret_file(path: &Path, body: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("secret path has no file name")?;
    let (temp_path, mut file) = create_unique_temp_file(path, file_name).await?;

    // Removes the temp file on ANY early return below, including the `?`s. A
    // guard rather than a cleanup call at the end, so a new failure path cannot
    // leak a token-bearing temp file by forgetting it.
    let mut cleanup = TempFileGuard::armed(temp_path.clone());

    // `create_new` means this process created the file, so the mode above
    // already applied; re-asserting it keeps the guarantee independent of that
    // detail (and of any platform that applies `mode` differently).
    file.set_permissions(Permissions::from_mode(SECRET_MODE))
        .await
        .with_context(|| format!("failed securing {}", temp_path.display()))?;

    file.write_all(body)
        .await
        .with_context(|| format!("failed writing {}", temp_path.display()))?;
    file.sync_all()
        .await
        .with_context(|| format!("failed flushing {}", temp_path.display()))?;
    drop(file);

    // Rename first, disarm second: afterwards the temp path no longer exists, so
    // deleting it would only be a pointless failed syscall.
    fs::rename(&temp_path, path)
        .await
        .with_context(|| format!("failed replacing {}", path.display()))?;
    cleanup.disarm();
    Ok(())
}

/// Creates and exclusively opens a temp file next to `path`.
///
/// The name is unique per WRITE, not per process, and the file is opened
/// `create_new`. Deriving it from the target name and the PID alone was not
/// enough: overlapping login workers in one process — a superseded attempt still
/// writing while its replacement starts — opened the same `.<name>.<pid>.tmp`,
/// truncated each other's partial content and raced the rename, which can leave
/// a corrupt credential file. A per-process counter plus `create_new` is
/// collision-free even then, and the counter also makes a crashed run's leftover
/// harmless: the next write simply takes the next number.
async fn create_unique_temp_file(path: &Path, file_name: &str) -> Result<(PathBuf, fs::File)> {
    static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let pid = std::process::id();
    loop {
        let seq = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let candidate = path.with_file_name(format!(".{file_name}.{pid}.{seq}.tmp"));
        let mut options = fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true) // fails if the name is taken: never clobber
            .mode(SECRET_MODE);
        match options.open(&candidate).await {
            Ok(file) => return Ok((candidate, file)),
            // Name already taken (a concurrent write, or a leftover from a
            // crashed run): take the next counter value.
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(anyhow::Error::new(err)
                    .context(format!("failed creating {}", candidate.display())));
            }
        }
    }
}

/// Deletes its temp file on drop unless disarmed. Synchronous on purpose:
/// `Drop` cannot await, and unlinking a few-KB file in a config directory is not
/// worth an async cleanup path.
struct TempFileGuard {
    path: PathBuf,
    armed: bool,
}

impl TempFileGuard {
    fn armed(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    /// Called once the temp file has been renamed onto its target, so Drop does
    /// not try to delete a path that no longer exists.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Test-only re-export of [`write_secret_file`].
///
/// The concurrency property (no two writers sharing a temp file) belongs to the
/// WRITER, not to any one credential file, so the test drives this directly at
/// an arbitrary path rather than going through `save_session`.
#[doc(hidden)]
pub async fn write_secret_file_for_test(path: &Path, body: &[u8]) -> Result<()> {
    write_secret_file(path, body).await
}

pub async fn load_session() -> Result<SessionState> {
    let session_path = config_dir()?.join("session.json");
    if !session_path.exists() {
        return Ok(SessionState::default());
    }

    let raw = fs::read_to_string(&session_path)
        .await
        .with_context(|| format!("failed reading {}", session_path.display()))?;
    let state = serde_json::from_str(&raw)
        .with_context(|| format!("failed parsing {}", session_path.display()))?;
    Ok(state)
}

pub async fn save_session(session: &SessionState) -> Result<()> {
    let config = config_dir()?;
    fs::create_dir_all(&config)
        .await
        .with_context(|| format!("failed creating {}", config.display()))?;

    let body = serde_json::to_string_pretty(session)?;
    write_secret_file(&config.join("session.json"), body.as_bytes()).await
}

pub async fn delete_session() -> Result<()> {
    let session_path = config_dir()?.join("session.json");
    if session_path.exists() {
        fs::remove_file(&session_path).await?;
    }
    Ok(())
}

/// Path of the persisted machine identity.
///
/// Deliberately NOT `session.json`. `delete_session` removes that file wholesale
/// on logout, and the machine identity must outlive a logout: it describes the
/// machine, not the account session. Keeping it here means a logout clears the
/// refresh token without also making the next login look like a new machine.
fn machine_id_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("machine_id.json"))
}

/// Load the persisted machine identity, if any.
///
/// Returns `Ok(None)` when none has been written yet, and on a corrupt file —
/// a machine identity we cannot parse is not worth failing a login over, and
/// the next login will simply mint a fresh one.
pub async fn load_client_info() -> Result<Option<ClientInfo>> {
    let path = machine_id_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = match fs::read_to_string(&path).await {
        Ok(raw) => raw,
        Err(err) => {
            tracing::warn!(
                error = %err,
                path = %path.display(),
                "failed reading machine identity; will generate a new one"
            );
            return Ok(None);
        }
    };
    match serde_json::from_str::<ClientInfo>(&raw) {
        Ok(info) => Ok(Some(info)),
        Err(err) => {
            tracing::warn!(
                error = %err,
                path = %path.display(),
                "machine identity is corrupt; will generate a new one"
            );
            Ok(None)
        }
    }
}

/// Persist the machine identity. Written once and then left alone; no code path
/// deletes this file, so the identity is stable across logouts and restarts.
///
/// Callers that need "read or create" as one step want
/// [`load_or_create_client_info`] instead: this half does no locking, so two
/// processes calling it concurrently can each write a different identity.
pub async fn save_client_info(info: &ClientInfo) -> Result<()> {
    let path = machine_id_path()?;
    let body = serde_json::to_string_pretty(info)?;
    write_secret_file(&path, body.as_bytes()).await
}

/// Path of the cross-process machine-identity lock file.
fn identity_lock_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("machine_id.lock"))
}

/// An exclusive, crash-safe lock over first-time identity initialization.
///
/// `flock(2)`, not a lock file whose mere existence means "locked": the kernel
/// releases an `flock` when the holding process exits for any reason, including
/// `SIGKILL` and power loss. A presence-based lock file would survive a crash
/// and then block every later login permanently — precisely the failure this
/// has to not have, since the identity is required before a login can proceed.
///
/// The file itself is only a handle for the lock. It is created `0600` and is
/// never read for meaning; it may outlive any process.
struct IdentityLock(std::fs::File);

impl IdentityLock {
    /// Acquire the lock without blocking a runtime worker.
    ///
    /// `flock` is a blocking syscall, and it can block for as long as another
    /// process holds the lock — unbounded and unpredictable. Calling it
    /// directly from an async task is therefore wrong in a way that deadlocks:
    /// concurrent identity initializations on a multi-thread runtime all block
    /// their workers in `flock`, including the one that would release the lock
    /// and let the others proceed, and the runtime never schedules anyone to
    /// make progress. `spawn_blocking` moves the wait to the blocking pool,
    /// which is sized for exactly this.
    async fn acquire(path: PathBuf) -> Result<Self> {
        let display = path.display().to_string();
        tokio::task::spawn_blocking(move || Self::acquire_blocking(&path))
            .await
            .with_context(|| format!("failed locking {display}"))?
    }

    fn acquire_blocking(path: &Path) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(SECRET_MODE)
            .open(path)
            .with_context(|| format!("failed opening {}", path.display()))?;
        // SAFETY: `file` owns a valid fd for the whole call.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed locking {}", path.display()));
        }
        Ok(Self(file))
    }
}

impl Drop for IdentityLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // SAFETY: the fd is still open; a failed unlock is not actionable and
        // the kernel releases it on close regardless.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Load the machine identity, creating and persisting one on first use.
///
/// The single entry point `login` uses, because the interesting part is not
/// "read a file" but "make sure exactly one identity exists".
///
/// The lock is held across the whole load/create/save sequence, and the file is
/// RE-READ after it is taken. Both parts are necessary:
///
/// - Without re-reading, two processes that both saw "no identity" would each
///   generate one, and the loser's identity would be the one Steam saw. The
///   winner's would be on disk, so the next login would present yet another.
/// - Without holding the lock across the save, the same race happens even with
///   re-reading, because the window between "read" and "write" is where the
///   second process slips in.
///
/// Errors are propagated, not degraded. The caller uses this identity to
/// authenticate, and an identity that could not be persisted is one that cannot
/// be reused next time; sending it anyway would present a machine to Steam and
/// then forget it. Failing closed here is what makes the identity stable.
pub async fn load_or_create_client_info() -> Result<ClientInfo> {
    // The `File` holds the `flock` and is carried across the awaits below, so
    // the lock is held across the whole load/create/save without any async task
    // ever blocking on it.
    let _lock = IdentityLock::acquire(identity_lock_path()?).await?;

    if let Some(existing) = load_client_info().await? {
        tracing::debug!("reusing persisted machine identity");
        return Ok(existing);
    }

    let generated = ClientInfo::default();
    tracing::debug!("no persisted machine identity; generating one");
    save_client_info(&generated).await?;
    Ok(generated)
}

pub async fn load_launcher_config() -> Result<LauncherConfig> {
    let path = config_dir()?.join("config.json");
    if !path.exists() {
        let mut config = LauncherConfig::default();
        if let Some(detected) = detect_steam_path() {
            config.steam_library_path = detected.to_string_lossy().to_string();
        }
        return Ok(config);
    }

    let raw = fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed reading {}", path.display()))?;
    let parsed = serde_json::from_str::<LauncherConfig>(&raw)
        .with_context(|| format!("failed parsing {}", path.display()))?;
    Ok(parsed)
}

pub async fn save_launcher_config(config: &LauncherConfig) -> Result<()> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed creating {}", dir.display()))?;

    let path = dir.join("config.json");
    let body = serde_json::to_string_pretty(config)?;
    fs::write(&path, body)
        .await
        .with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

pub fn library_cache_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("library_cache.json"))
}

pub async fn save_library_cache(owned_games: &[OwnedGame]) -> Result<()> {
    let dir = data_dir()?;
    fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed creating {}", dir.display()))?;

    let path = library_cache_path()?;
    let body = serde_json::to_string_pretty(owned_games)?;
    fs::write(&path, body)
        .await
        .with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

pub async fn load_library_cache() -> Result<Vec<OwnedGame>> {
    let path = library_cache_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }

    let raw = fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed reading {}", path.display()))?;
    let cached = serde_json::from_str::<Vec<OwnedGame>>(&raw)
        .with_context(|| format!("failed parsing {}", path.display()))?;
    Ok(cached)
}

pub async fn load_user_configs() -> Result<UserConfigStore> {
    let path = config_dir()?.join("user_apps.json");
    if !path.exists() {
        return Ok(UserConfigStore::new());
    }

    let raw = fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed reading {}", path.display()))?;
    let parsed = serde_json::from_str::<UserConfigStore>(&raw)
        .with_context(|| format!("failed parsing {}", path.display()))?;
    Ok(parsed)
}

pub async fn save_user_configs(configs: &UserConfigStore) -> Result<()> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed creating {}", dir.display()))?;

    let path = dir.join("user_apps.json");
    let body = serde_json::to_string_pretty(configs)?;
    fs::write(&path, body)
        .await
        .with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

/// Validate a per-game Steam-mode configuration against the effective runner
/// (Phase 5 — `OnlineContainerized` guard).
///
/// The containerized launch path (`OnlineContainerized`) runs the game through
/// `<proton>/proton run` inside the Steam Linux Runtime (see
/// [`crate::container::launch`]); a plain Wine runner has no `proton` entry
/// script and would fail at launch time with "OnlineContainerized requires a
/// Proton compatibility tool". Validating at config-save time surfaces the
/// misconfiguration in the UI/CLI before the user hits that launch error.
///
/// The effective runner mirrors [`crate::utils::resolve_effective_proton_name`]
/// precedence: per-game `forced_proton_version` → global `proton_version`.
pub fn validate_online_containerized_runner(
    steam_mode: crate::models::SteamMode,
    forced_proton_version: Option<&str>,
    global_proton_version: &str,
    library_root: &std::path::Path,
) -> Result<(), String> {
    if steam_mode != crate::models::SteamMode::OnlineContainerized {
        return Ok(());
    }
    let runner_name = forced_proton_version
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(global_proton_version);
    let runner_path = crate::utils::resolve_runner(runner_name, library_root);
    if matches!(
        crate::utils::classify_runner(&runner_path),
        crate::utils::RunnerKind::Proton { .. }
    ) {
        Ok(())
    } else {
        Err("OnlineContainerized mode requires a Proton compatibility tool runner (e.g., steamflow-proton-11.0-purepe). Bare Wine runners are not supported in container mode.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SteamMode;
    use std::path::Path;

    /// Create a fake runner root (with or without a `proton` entry script).
    fn write_runner(dir: &Path, name: &str, with_proton_script: bool) -> std::path::PathBuf {
        let root = dir.join(name);
        std::fs::create_dir_all(&root).expect("create runner dir");
        if with_proton_script {
            std::fs::write(root.join("proton"), "#!/bin/sh\n").expect("write proton script");
        }
        root
    }

    #[test]
    fn online_containerized_rejects_bare_wine_and_accepts_proton() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let purepe = write_runner(tmp.path(), "steamflow-proton-11.0-purepe", true);
        let wine11 = write_runner(tmp.path(), "steamflow-runner-wine11-wow64", false);

        // Proton runner as the per-game forced override → accepted.
        assert!(validate_online_containerized_runner(
            SteamMode::OnlineContainerized,
            Some(purepe.to_str().unwrap()),
            "global-default",
            tmp.path(),
        )
        .is_ok());

        // Proton runner via the global default (no forced override) → accepted.
        assert!(validate_online_containerized_runner(
            SteamMode::OnlineContainerized,
            None,
            purepe.to_str().unwrap(),
            tmp.path(),
        )
        .is_ok());

        // Bare Wine runner as the per-game forced override → rejected with the
        // exact user-facing message.
        let err = validate_online_containerized_runner(
            SteamMode::OnlineContainerized,
            Some(wine11.to_str().unwrap()),
            purepe.to_str().unwrap(),
            tmp.path(),
        )
        .unwrap_err();
        assert!(
            err.contains("OnlineContainerized mode requires a Proton compatibility tool runner")
        );
        assert!(err.contains("Bare Wine runners are not supported in container mode"));

        // Bare Wine runner via the global default → rejected too.
        assert!(validate_online_containerized_runner(
            SteamMode::OnlineContainerized,
            None,
            wine11.to_str().unwrap(),
            tmp.path(),
        )
        .is_err());

        // Non-containerized modes are never blocked, even with a bare runner.
        assert!(validate_online_containerized_runner(
            SteamMode::OfflineEmulated,
            Some(wine11.to_str().unwrap()),
            wine11.to_str().unwrap(),
            tmp.path(),
        )
        .is_ok());
        assert!(validate_online_containerized_runner(
            SteamMode::Auto,
            Some(wine11.to_str().unwrap()),
            wine11.to_str().unwrap(),
            tmp.path(),
        )
        .is_ok());

        // An empty forced override falls back to the global runner.
        assert!(validate_online_containerized_runner(
            SteamMode::OnlineContainerized,
            Some(""),
            purepe.to_str().unwrap(),
            tmp.path(),
        )
        .is_ok());
    }
}
