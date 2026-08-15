//! Steam Linux Runtime provisioning (Phase 4.2 — `OnlineContainerized`).
//!
//! [`RuntimeManager`] owns the on-disk deployment of Valve's official Steam
//! Linux Runtime (SLR) images. The provisioned runtime lives at
//! `~/.config/SteamFlow/runtimes/<id>/` (e.g. `runtimes/steamrt4/`) and
//! mirrors the layout Valve ships through Steam:
//!
//! ```text
//! <root>/
//!   VERSIONS.txt          # one line per component: `VERSION <name> <revision>`
//!   run                   # entry point (symlink to _v2-entry-point)
//!   _v2-entry-point       # the actual pressure-vessel launcher script
//!   <component>/          # e.g. sniper_platform, sniper_tools
//!     manifest.json       # { "name", "version", "architecture", ... }
//!     files/
//! ```
//!
//! Acquisition has two pluggable sources:
//!
//! 1. [`RuntimeManager::provision_from_url`] — plain HTTPS download (e.g.
//!    Valve's `repo.steampowered.com` runtime tarballs), mirroring the
//!    existing GitHub-package installer in `src/proton.rs`.
//! 2. [`RuntimeManager::provision_from_archive`] — provision a local archive
//!    already fetched through the Steam CDN depot pipeline (the Phase 3
//!    `steam-cdn` machinery). This is the hook the depot-based acquisition
//!    (Phase 4.3) feeds.
//!
//! Both paths verify archive integrity first (SHA256 when an expected digest
//! is supplied, and/or a detached GPG signature via `gpgv`), then extract
//! with the system `tar` binary (project convention, same as `src/proton.rs`),
//! then rescan the tree into a [`RuntimeDeploymentState`].

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Valve's Steam Linux Runtime lines, oldest to newest.
///
/// The Steam client installs these under
/// `steamapps/common/SteamLinuxRuntime_<dir_name>`. `steamrt4` is the
/// current default; `sniper` (SteamRT 3.0) is its direct predecessor and the
/// two share the same component metadata formats, so parsing is
/// data-driven (nothing here hardcodes component names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SteamRuntimeId {
    /// SteamRT 1.0 (scout) — legacy, Steam app 1070560.
    Steamrt1,
    /// SteamRT 2.0 (soldier) — legacy, Steam app 1391110.
    Steamrt2,
    /// SteamRT 3.0 (sniper) — Steam app 1628350.
    Steamrt3,
    /// SteamRT 4.0 — the current line.
    #[default]
    Steamrt4,
}

impl SteamRuntimeId {
    /// On-disk component/directory name for this runtime line.
    pub fn dir_name(self) -> &'static str {
        match self {
            SteamRuntimeId::Steamrt1 => "steamrt1",
            SteamRuntimeId::Steamrt2 => "steamrt2",
            SteamRuntimeId::Steamrt3 => "sniper",
            SteamRuntimeId::Steamrt4 => "steamrt4",
        }
    }

    /// Parse a user/API-supplied runtime name, accepting the common aliases
    /// (`"sniper"` → Steamrt3, `"steamrt4"` → Steamrt4). Unknown names fall
    /// back to the default line instead of erroring — a future runtime name
    /// must not brick metadata display.
    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "scout" | "steamrt1" | "steamrt_1" => SteamRuntimeId::Steamrt1,
            "soldier" | "steamrt2" | "steamrt_2" => SteamRuntimeId::Steamrt2,
            "sniper" | "steamrt3" | "steamrt_3" => SteamRuntimeId::Steamrt3,
            _ => SteamRuntimeId::Steamrt4,
        }
    }

    /// The Steam appid that ships this runtime line (for Steam-CDN depot
    /// acquisition). Verified against SteamDB:
    /// - scout → 1070560, soldier → 1391110, sniper → 1628350,
    /// - steamrt4 → 4183110 (Steam Linux Runtime 4.0).
    pub fn app_id(self) -> u32 {
        match self {
            SteamRuntimeId::Steamrt1 => 1070560,
            SteamRuntimeId::Steamrt2 => 1391110,
            SteamRuntimeId::Steamrt3 => 1628350,
            SteamRuntimeId::Steamrt4 => 4183110,
        }
    }

    /// Directory names the Steam client uses for this line under
    /// `steamapps/common/`. A line may ship under more than one name across
    /// Steam client versions (scout historically lived in a bare
    /// `SteamLinuxRuntime` dir). Verified against SteamDB `installdir`.
    pub fn client_dir_names(self) -> &'static [&'static str] {
        match self {
            SteamRuntimeId::Steamrt1 => &["SteamLinuxRuntime", "SteamLinuxRuntime_scout"],
            SteamRuntimeId::Steamrt2 => &["SteamLinuxRuntime_soldier"],
            SteamRuntimeId::Steamrt3 => &["SteamLinuxRuntime_sniper"],
            SteamRuntimeId::Steamrt4 => &["SteamLinuxRuntime_4"],
        }
    }
}

/// One `VERSIONS.txt` entry: a runtime component and its revision.
///
/// Valve's format is space-separated — `VERSION <name> <revision>` — while
/// SteamFlow's own runner `VERSIONS.txt` files use `KEY=VALUE`; the parser
/// accepts both (see [`parse_versions_txt`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeComponentVersion {
    pub name: String,
    pub version: String,
}

/// A component `manifest.json` as shipped inside each runtime component dir.
///
/// All fields are optional so that unknown schema variants degrade
/// gracefully instead of failing the whole deployment scan.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeManifest {
    pub name: Option<String>,
    pub version: Option<String>,
    pub architecture: Option<String>,
    pub os: Option<String>,
}

/// Parsed state of one provisioned runtime root — what the application
/// displays and gates containerized launches on.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeDeploymentState {
    /// Runtime line identifier (`steamrt4`, `sniper`, …).
    pub id: String,
    /// Absolute path of the provisioned root.
    pub root: String,
    /// The root directory exists on disk.
    pub present: bool,
    /// All completeness checks passed (entry point, VERSIONS.txt, ≥1
    /// component manifest, no scan errors).
    pub complete: bool,
    /// Aggregate runtime revision — the lexicographically greatest component
    /// revision from `VERSIONS.txt` (Valve's `0.YYYYMMDD.N` revisions are
    /// zero-padded so string ordering matches date ordering).
    pub revision: Option<String>,
    /// Absolute path of the launcher entry point (`run` / `_v2-entry-point`).
    pub entry_point: Option<String>,
    /// Component revisions parsed from `VERSIONS.txt`.
    pub versions: Vec<RuntimeComponentVersion>,
    /// Manifests parsed from each component's `manifest.json`.
    pub manifests: Vec<RuntimeManifest>,
    /// Non-fatal scan problems (missing entry point, empty VERSIONS.txt, …).
    pub errors: Vec<String>,
}

impl RuntimeDeploymentState {
    /// Whether the deployment is usable as a container base right now.
    pub fn is_usable(&self) -> bool {
        self.present && self.complete && self.errors.is_empty()
    }
}

/// Integrity checks to run against a downloaded runtime archive before
/// extraction. Both are optional: SHA256 is the primary check (cheap, pure
/// Rust); a detached GPG signature (`gpgv --keyring …`) is used when Valve
/// ships one alongside the archive. At least one should normally be present;
/// with neither, provisioning proceeds with a warning (Steam CDN depot
/// delivery is already authenticated by Valve's own depot signature
/// machinery — that trust is inherited by the Phase 4.3 depot path).
#[derive(Debug, Clone, Default)]
pub struct ArchiveVerification {
    /// Expected SHA256 digest of the archive, lowercase hex.
    pub expected_sha256: Option<String>,
    /// Detached GPG signature file (`<archive>.sig` style).
    pub gpg_signature: Option<PathBuf>,
    /// GPG keyring containing Valve's signing key.
    pub gpg_keyring: Option<PathBuf>,
}

/// Owns the provisioned runtime at `~/.config/SteamFlow/runtimes/<id>/`.
#[derive(Debug, Clone)]
pub struct RuntimeManager {
    pub id: SteamRuntimeId,
    /// Provision target root (`runtimes/<id>/`).
    pub root: PathBuf,
}

/// Base directory for ALL SteamFlow-provisioned runtimes
/// (`~/.config/SteamFlow/runtimes/`). Lives under the SteamFlow config dir
/// (project convention — `data_dir()` and the steam_emulator staging dir
/// use the same root).
pub fn runtimes_root() -> PathBuf {
    crate::config::config_dir()
        .map(|d| d.join("runtimes"))
        .unwrap_or_else(|_| PathBuf::from("runtimes"))
}

/// Directory for intermediate downloads (archives waiting for verification).
pub fn downloads_dir() -> PathBuf {
    runtimes_root().join("downloads")
}

impl Default for RuntimeManager {
    fn default() -> Self {
        Self::for_id(SteamRuntimeId::Steamrt4)
    }
}

impl RuntimeManager {
    /// A manager for `id` rooted at `runtimes/<id>/`.
    pub fn for_id(id: SteamRuntimeId) -> Self {
        Self::new(id, runtimes_root().join(id.dir_name()))
    }

    /// Manager with an explicit root (used by tests and non-standard layouts).
    pub fn new(id: SteamRuntimeId, root: PathBuf) -> Self {
        Self { id, root }
    }

    /// Scan the provisioned tree and return its current deployment state.
    ///
    /// Never fails — a missing or half-provisioned runtime is reported as a
    /// state with `present: false` / `complete: false` and `errors` entries.
    /// The scan resolves the true runtime root first
    /// ([`find_runtime_root`]), so archives that wrap the runtime in a
    /// single top-level directory are handled transparently.
    pub fn deployment_state(&self) -> RuntimeDeploymentState {
        let root = find_runtime_root(&self.root);
        let mut state = RuntimeDeploymentState {
            id: self.id.dir_name().to_string(),
            root: root.display().to_string(),
            ..Default::default()
        };

        if !root.is_dir() {
            state.errors.push(format!(
                "runtime root {} does not exist — not provisioned yet",
                root.display()
            ));
            return state;
        }
        state.present = true;

        // Component manifests: every subdirectory with a manifest.json.
        if let Ok(entries) = std::fs::read_dir(&root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let manifest_path = path.join("manifest.json");
                if manifest_path.is_file() {
                    match parse_manifest(&manifest_path) {
                        Ok(manifest) => state.manifests.push(manifest),
                        Err(e) => state
                            .errors
                            .push(format!("failed parsing {}: {e:#}", manifest_path.display())),
                    }
                }
            }
        } else {
            state
                .errors
                .push(format!("failed listing {}", root.display()));
        }

        // Entry point: Valve ships `run` (a symlink) and/or `_v2-entry-point`.
        for name in ["run", "_v2-entry-point"] {
            let candidate = root.join(name);
            if candidate.exists() {
                state.entry_point = Some(candidate.display().to_string());
                break;
            }
        }

        // VERSIONS.txt → component revisions + aggregate revision.
        state.versions = read_versions_txt(&root);
        state.revision = state.versions.iter().map(|v| v.version.clone()).max();

        // Completeness gate.
        if state.entry_point.is_none() {
            state.errors.push(format!(
                "no entry point found in {} (expected `run` or `_v2-entry-point`)",
                root.display()
            ));
        }
        if state.versions.is_empty() {
            state.errors.push(format!(
                "VERSIONS.txt missing or empty in {}",
                root.display()
            ));
        }
        // NOTE: no manifest.json requirement. The real steamrt4 component
        // layout ships a `metadata` file (not `manifest.json`) alongside
        // `files/` + `usr-mtree.txt.gz`, so `manifests` may legitimately be
        // empty. Completeness is gated on the entry point + a parseable
        // VERSIONS.txt (the same contract as `is_usable_runtime_root`).

        state.complete = state.errors.is_empty();
        state
    }

    /// Locate a **client-managed** Steam Linux Runtime installation under the
    /// Steam library (`<library>/steamapps/common/SteamLinuxRuntime_<line>/`).
    ///
    /// The Steam client keeps these self-updating, so a client-managed copy is
    /// preferred over SteamFlow's own provisioned copy (Phase 4.3). Returns
    /// the first candidate that is a usable runtime root (entry point +
    /// `VERSIONS.txt`), or `None` when the client has not installed this line.
    pub fn client_managed_runtime(&self, library_root: &Path) -> Option<PathBuf> {
        let common = library_root.join("steamapps").join("common");
        for name in self.id.client_dir_names() {
            let candidate = common.join(name);
            if is_usable_runtime_root(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    /// Resolve the runtime root to use for a containerized launch:
    /// the client-managed copy first (self-updating), then the
    /// SteamFlow-provisioned copy. Returns `None` when neither is usable —
    /// the caller must then trigger provisioning (depot acquisition).
    pub fn resolve_runtime_root(&self, library_root: &Path) -> Option<PathBuf> {
        if let Some(client) = self.client_managed_runtime(library_root) {
            return Some(client);
        }
        let state = self.deployment_state();
        if state.is_usable() {
            return Some(find_runtime_root(&self.root));
        }
        None
    }

    /// Remove the provisioned runtime root (and this line's staged downloads
    /// archive) so a corrupt or truncated extraction can never be re-used.
    /// Used by [`RuntimeManager::force_reprovision`] and the `steamflow
    /// runtime repair` CLI. Never fails on an already-absent root.
    pub fn purge(&self) -> Result<()> {
        if self.root.exists() {
            std::fs::remove_dir_all(&self.root)
                .with_context(|| format!("failed removing {}", self.root.display()))?;
        }
        let archive = downloads_dir().join(format!("{}.tar", self.id.dir_name()));
        if archive.exists() {
            std::fs::remove_file(&archive)
                .with_context(|| format!("failed removing {}", archive.display()))?;
        }
        Ok(())
    }

    /// Force-reprovision this runtime from `source`.
    ///
    /// Purges the existing provisioned root unconditionally — regardless of
    /// whether its checksum/manifest scan currently passes — then re-fetches
    /// and extracts from `source`, a freshly depot-downloaded runtime tree
    /// (the client-managed `SteamLinuxRuntime_<line>/` directory). Returns the
    /// resulting deployment state. The `steamflow runtime repair <line>` CLI
    /// binds the line name to a manager via [`SteamRuntimeId::from_name`] +
    /// [`RuntimeManager::for_id`] before calling this.
    pub async fn force_reprovision(
        &self,
        source: &Path,
        verification: &ArchiveVerification,
    ) -> Result<RuntimeDeploymentState> {
        self.purge()
            .with_context(|| format!("failed purging runtime {}", self.id.dir_name()))?;
        self.provision_from_depot_dir(source, verification, false)
            .await
    }

    /// Depot hook (Phase 4.3): acquire a runtime through the Steam-CDN depot
    /// pipeline — the asset fetcher downloads the SLR depot files into a
    /// directory — then wrap that directory as an archive and provision it via
    /// [`RuntimeManager::provision_from_archive`].
    pub async fn provision_from_depot_dir(
        &self,
        depot_dir: &Path,
        verification: &ArchiveVerification,
        keep_archive: bool,
    ) -> Result<RuntimeDeploymentState> {
        if !depot_dir.is_dir() {
            bail!("runtime depot dir {} does not exist", depot_dir.display());
        }
        let archive = self.archive_dir(depot_dir)?;
        self.provision_from_archive(&archive, verification, keep_archive)
            .await
    }

    /// Wrap a downloaded depot tree (`src`) into a tar archive under
    /// `runtimes/downloads/`, ready for `provision_from_archive`. Uses the
    /// system `tar` binary (project extraction/archiving convention).
    pub fn archive_dir(&self, src: &Path) -> Result<PathBuf> {
        let dest_dir = downloads_dir();
        std::fs::create_dir_all(&dest_dir)
            .with_context(|| format!("failed creating {}", dest_dir.display()))?;
        let archive = dest_dir.join(format!("{}.tar", self.id.dir_name()));
        let output = std::process::Command::new("tar")
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(src)
            .arg(".")
            .output()
            .with_context(|| format!("failed spawning tar to archive {}", src.display()))?;
        if !output.status.success() {
            bail!(
                "tar archiving of {} failed: {}",
                src.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(archive)
    }

    /// Verify + extract a local runtime archive into the provision root, then
    /// return the resulting deployment state.
    ///
    /// The archive is removed after a successful extraction (unless
    /// `keep_archive` is set); on failure it is kept for inspection.
    pub async fn provision_from_archive(
        &self,
        archive: &Path,
        verification: &ArchiveVerification,
        keep_archive: bool,
    ) -> Result<RuntimeDeploymentState> {
        if !archive.is_file() {
            bail!("runtime archive {} does not exist", archive.display());
        }

        if let Some(expected) = &verification.expected_sha256 {
            verify_sha256_file(archive, expected)
                .with_context(|| format!("SHA256 check failed for {}", archive.display()))?;
        }
        if let (Some(sig), Some(keyring)) = (&verification.gpg_signature, &verification.gpg_keyring)
        {
            verify_gpg_detached(archive, sig, keyring)
                .with_context(|| format!("GPG check failed for {}", archive.display()))?;
        }
        if verification.expected_sha256.is_none() && verification.gpg_signature.is_none() {
            tracing::warn!(
                "provisioning {} with NO integrity check (no SHA256 digest, no GPG signature)",
                archive.display()
            );
        }

        let _runtime_root = self.extract_archive(archive).await?;

        if !keep_archive {
            let _ = std::fs::remove_file(archive);
        }

        Ok(self.deployment_state())
    }

    /// Download a runtime archive over HTTPS and provision it.
    ///
    /// `url` is a direct tarball URL (e.g. Valve's
    /// `https://repo.steampowered.com/steamrt3/sniper/…`); `progress` receives
    /// `(downloaded, total)` during the transfer. The archive is stored under
    /// `runtimes/downloads/` and removed after successful extraction.
    pub async fn provision_from_url<F>(
        &self,
        url: &str,
        verification: &ArchiveVerification,
        keep_archive: bool,
        mut progress: F,
    ) -> Result<RuntimeDeploymentState>
    where
        F: FnMut(u64, u64) + Send + 'static,
    {
        let dest = downloads_dir();
        tokio::fs::create_dir_all(&dest)
            .await
            .context("failed creating downloads dir")?;
        let file_name = url
            .rsplit('/')
            .find(|s| !s.is_empty())
            .unwrap_or("runtime.tar");
        let archive = dest.join(file_name);
        self.download_to(url, &archive, &mut progress).await?;
        self.provision_from_archive(&archive, verification, keep_archive)
            .await
    }

    /// Stream `url` to `dest` (reqwest chunk loop, mirroring
    /// `src/proton.rs::install_github_package`).
    pub async fn download_to<F>(&self, url: &str, dest: &Path, progress: &mut F) -> Result<()>
    where
        F: FnMut(u64, u64) + Send,
    {
        let client = reqwest::Client::new();
        let mut response = client
            .get(url)
            .send()
            .await
            .with_context(|| format!("failed downloading {url}"))?;
        if !response.status().is_success() {
            bail!("download of {url} failed with HTTP {}", response.status());
        }
        let total = response.content_length().unwrap_or(0);
        let mut file = tokio::fs::File::create(dest)
            .await
            .with_context(|| format!("failed creating {}", dest.display()))?;
        let mut downloaded = 0u64;
        while let Some(chunk) = response.chunk().await? {
            tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await?;
            downloaded += chunk.len() as u64;
            progress(downloaded, total);
        }
        tracing::info!("downloaded {} ({} bytes)", dest.display(), downloaded);
        Ok(())
    }

    /// Extract `archive` into the provision root with the system `tar`
    /// binary (project convention — same call shape as `src/proton.rs`).
    /// Returns the runtime root after normalizing nested tarball layouts.
    pub async fn extract_archive(&self, archive: &Path) -> Result<PathBuf> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .with_context(|| format!("failed creating {}", self.root.display()))?;

        let output = std::process::Command::new("tar")
            .arg("-xf")
            .arg(archive)
            .arg("-C")
            .arg(&self.root)
            .output()
            .with_context(|| format!("failed spawning tar for {}", archive.display()))?;
        if !output.status.success() {
            bail!(
                "tar extraction of {} failed: {}",
                archive.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(find_runtime_root(&self.root))
    }
}

/// Whether `root` is a usable runtime root: it has a non-empty entry point
/// (`run` or `_v2-entry-point`) and a non-empty `VERSIONS.txt` (so its
/// revision is known). Used by the client-managed fallback to accept only
/// complete client installs — a 0-byte `VERSIONS.txt` / entry point left by a
/// truncated download (e.g. the host's corrupt steamrt4) is rejected.
pub fn is_usable_runtime_root(root: &Path) -> bool {
    let has_entry = non_empty_file(&root.join("run")) || non_empty_file(&root.join("_v2-entry-point"));
    has_entry && non_empty_file(&root.join("VERSIONS.txt"))
}

/// Whether `path` is a regular file with non-zero length.
fn non_empty_file(path: &Path) -> bool {
    path.is_file() && path.metadata().map(|m| m.len() > 0).unwrap_or(false)
}

/// Normalize a freshly-extracted tree: if the tarball wrapped everything in a
/// single top-level directory (Valve's depot tarballs often do), descend to
/// it so the caller operates on the true runtime root.
pub fn find_runtime_root(root: &Path) -> PathBuf {
    let mut current = root.to_path_buf();
    loop {
        let has_marker = current.join("VERSIONS.txt").is_file()
            || current.join("run").exists()
            || current.join("_v2-entry-point").exists();
        if has_marker {
            return current;
        }
        let subdirs: Vec<PathBuf> = std::fs::read_dir(&current)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_dir())
                    .collect()
            })
            .unwrap_or_default();
        if subdirs.len() == 1 {
            current = subdirs.into_iter().next().expect("len checked");
        } else {
            return current;
        }
    }
}

/// Parse a runtime `VERSIONS.txt` document.
///
/// Accepts three formats:
/// 1. Valve's legacy space-separated `VERSION <name> <revision>` lines.
/// 2. SteamFlow's `KEY=VALUE` runner form.
/// 3. Valve's **current** tab-separated table (the real SLR 3.0/4.0 layout):
///
///    ```text
///    #Name	Version		Runtime	Runtime_Version	Comment
///    steamrt4	4.0.20260805.254769	steamrt4	4.0.20260805.254769	# …
///    ```
///
/// Comments (`#`) and blank lines are skipped; unrecognized lines are
/// ignored (never fatal). The first two whitespace-separated fields of a
/// table row are taken as `(name, version)`.
pub fn parse_versions_txt(content: &str) -> Vec<RuntimeComponentVersion> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("VERSION ")
            .or_else(|| line.strip_prefix("version "))
        {
            let mut parts = rest.split_whitespace();
            let (name, version) = match (parts.next(), parts.next()) {
                (Some(n), Some(v)) => (n.to_string(), v.to_string()),
                _ => continue,
            };
            if !name.is_empty() && !version.is_empty() {
                out.push(RuntimeComponentVersion { name, version });
            }
        } else if let Some((name, version)) = line.split_once('=') {
            let (name, version) = (name.trim(), version.trim());
            if !name.is_empty() && !version.is_empty() {
                out.push(RuntimeComponentVersion {
                    name: name.to_string(),
                    version: version.to_string(),
                });
            }
        } else if line.contains('\t') {
            // Tab-separated Valve table row (`name<TAB>version<TAB>…`). The
            // tab check keeps this branch from swallowing arbitrary
            // space-separated lines.
            let mut parts = line.split_whitespace();
            if let (Some(name), Some(version)) = (parts.next(), parts.next()) {
                if !name.is_empty() && !version.is_empty() {
                    out.push(RuntimeComponentVersion {
                        name: name.to_string(),
                        version: version.to_string(),
                    });
                }
            }
        }
    }
    out
}

/// Read and parse `VERSIONS.txt` from a runtime root (missing file → empty).
pub fn read_versions_txt(root: &Path) -> Vec<RuntimeComponentVersion> {
    let path = root.join("VERSIONS.txt");
    match std::fs::read_to_string(&path) {
        Ok(content) => parse_versions_txt(&content),
        Err(_) => Vec::new(),
    }
}

/// Parse a component `manifest.json`. All fields are optional; unknown fields
/// are ignored by serde.
pub fn parse_manifest(path: &Path) -> Result<RuntimeManifest> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading {}", path.display()))?;
    let manifest = serde_json::from_str(&content)
        .with_context(|| format!("failed parsing manifest {}", path.display()))?;
    Ok(manifest)
}

/// Verify `path` against an expected lowercase-hex SHA256 digest (pure Rust).
pub fn verify_sha256_file(path: &Path, expected_hex: &str) -> Result<()> {
    use sha2::{Digest, Sha256};

    let mut file =
        std::fs::File::open(path).with_context(|| format!("failed opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)
        .with_context(|| format!("failed hashing {}", path.display()))?;
    let actual = hex::encode(hasher.finalize());
    let expected = expected_hex.trim().to_ascii_lowercase();
    if actual != expected {
        bail!(
            "SHA256 mismatch for {}: expected {}, got {}",
            path.display(),
            expected,
            actual
        );
    }
    Ok(())
}

/// Verify `archive` against a detached GPG signature using `gpgv` (part of
/// the `gnupg` package, standard on all Linux distros). Fails with a clear
/// error if `gpgv` is not installed.
pub fn verify_gpg_detached(archive: &Path, signature: &Path, keyring: &Path) -> Result<()> {
    if !signature.is_file() {
        bail!("GPG signature file {} does not exist", signature.display());
    }
    if !keyring.is_file() {
        bail!("GPG keyring {} does not exist", keyring.display());
    }
    let output = std::process::Command::new("gpgv")
        .arg("--keyring")
        .arg(keyring)
        .arg("--output")
        .arg("/dev/null")
        .arg(signature)
        .arg(archive)
        .output()
        .with_context(|| {
            "failed spawning gpgv (is gnupg installed?) — cannot verify the \
             detached signature"
        })?;
    if !output.status.success() {
        bail!(
            "GPG signature verification failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_runtime_version_parsing() {
        // Valve's space-separated format.
        let valve = "\
# comment line
VERSION sniper_platform 0.20240304.0
VERSION sniper_tools 0.20240304.0
VERSION sniper_platform_i386 0.20240304.0

VERSION steamrt4_platform 0.20250701.0
";
        let parsed = parse_versions_txt(valve);
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0].name, "sniper_platform");
        assert_eq!(parsed[0].version, "0.20240304.0");
        assert_eq!(parsed[2].name, "sniper_platform_i386");
        assert_eq!(parsed[3].name, "steamrt4_platform");
        assert_eq!(parsed[3].version, "0.20250701.0");

        // SteamFlow's KEY=VALUE form mixed in (tolerant parser).
        let mixed = "\
VERSION sniper_platform 0.20240304.0
STEAMRT4_PLATFORM=0.20250701.0
garbage line that is neither
=";
        let parsed = parse_versions_txt(mixed);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "sniper_platform");
        assert_eq!(parsed[1].name, "STEAMRT4_PLATFORM");
        assert_eq!(parsed[1].version, "0.20250701.0");

        // Empty / comment-only → empty.
        assert!(parse_versions_txt("").is_empty());
        assert!(parse_versions_txt("# only a comment\n\n").is_empty());

        // CRLF tolerance.
        let crlf = "VERSION sniper_platform 0.20240304.0\r\n";
        let parsed = parse_versions_txt(crlf);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].version, "0.20240304.0");
    }

    #[test]
    fn test_versions_txt_tab_separated_valve_table() {
        // The real SLR 3.0/4.0 VERSIONS.txt is a tab-separated table (the
        // format `read_versions_txt` encounters on a live runtime).
        let valve = "#Name\tVersion\t\tRuntime\tRuntime_Version\tComment\n\
                     depot\t4.0.20260805.254769\t\t\t# Overall version number\n\
                     pressure-vessel\t0.20260805.0\t\t\t\n\
                     steamrt4\t4.0.20260805.254769\tsteamrt4\t4.0.20260805.254769\t# steamrt4_platform_4.0.20260805.254769/\n";
        let parsed = parse_versions_txt(valve);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].name, "depot");
        assert_eq!(parsed[0].version, "4.0.20260805.254769");
        assert_eq!(parsed[1].name, "pressure-vessel");
        assert_eq!(parsed[2].name, "steamrt4");
        assert_eq!(parsed[2].version, "4.0.20260805.254769");
    }

    #[test]
    fn test_runtime_id_alias_resolution() {
        assert_eq!(
            SteamRuntimeId::from_name("sniper"),
            SteamRuntimeId::Steamrt3
        );
        assert_eq!(
            SteamRuntimeId::from_name("SteamRT4"),
            SteamRuntimeId::Steamrt4
        );
        assert_eq!(SteamRuntimeId::from_name("scout"), SteamRuntimeId::Steamrt1);
        // Unknown names fall back to the default line, never error.
        assert_eq!(
            SteamRuntimeId::from_name("future-runtime"),
            SteamRuntimeId::Steamrt4
        );
        assert_eq!(SteamRuntimeId::Steamrt3.dir_name(), "sniper");
        assert_eq!(SteamRuntimeId::Steamrt4.dir_name(), "steamrt4");
        assert_eq!(
            runtimes_root(),
            PathBuf::from(std::env::var("HOME").unwrap()).join(".config/SteamFlow/runtimes")
        );
        assert_eq!(
            RuntimeManager::default().root,
            runtimes_root().join("steamrt4")
        );
    }

    #[test]
    fn test_manifest_json_parsing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("manifest.json");

        // Full manifest.
        std::fs::write(
            &path,
            r#"{"name":"sniper_platform","version":"0.20240304.0","architecture":"amd64","os":"linux"}"#,
        )
        .unwrap();
        let m = parse_manifest(&path).unwrap();
        assert_eq!(m.name.as_deref(), Some("sniper_platform"));
        assert_eq!(m.version.as_deref(), Some("0.20240304.0"));
        assert_eq!(m.architecture.as_deref(), Some("amd64"));

        // Minimal manifest (unknown schema variants degrade gracefully).
        std::fs::write(&path, r#"{"name":"steamrt4_platform"}"#).unwrap();
        let m = parse_manifest(&path).unwrap();
        assert_eq!(m.name.as_deref(), Some("steamrt4_platform"));
        assert_eq!(m.version, None);

        // Unknown fields are ignored.
        std::fs::write(
            &path,
            r#"{"name":"x","version":"1","future_field":{"a":1}}"#,
        )
        .unwrap();
        let m = parse_manifest(&path).unwrap();
        assert_eq!(m.name.as_deref(), Some("x"));

        // Malformed JSON → error with context.
        std::fs::write(&path, "{ not json").unwrap();
        assert!(parse_manifest(&path).is_err());
    }

    #[test]
    fn test_deployment_state_scan() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("steamrt4");
        let mgr = RuntimeManager::new(SteamRuntimeId::Steamrt4, root.clone());

        // Not provisioned.
        let state = mgr.deployment_state();
        assert!(!state.present);
        assert!(!state.complete);
        assert!(!state.is_usable());
        assert!(!state.errors.is_empty());

        // Half-provisioned: entry point but no metadata.
        std::fs::create_dir_all(root.join("sniper_platform/files")).unwrap();
        std::fs::write(root.join("run"), "#!/bin/sh\n").unwrap();
        let state = mgr.deployment_state();
        assert!(state.present);
        assert!(!state.complete);
        assert!(state.entry_point.is_some());

        // Complete: VERSIONS.txt + component manifest + entry point.
        std::fs::create_dir_all(root.join("sniper_tools")).unwrap();
        std::fs::write(
            root.join("VERSIONS.txt"),
            "VERSION sniper_platform 0.20240304.0\nVERSION sniper_tools 0.20240304.0\n",
        )
        .unwrap();
        std::fs::write(
            root.join("sniper_platform/manifest.json"),
            r#"{"name":"sniper_platform","version":"0.20240304.0","architecture":"amd64"}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("sniper_tools/manifest.json"),
            r#"{"name":"sniper_tools","version":"0.20240304.0"}"#,
        )
        .unwrap();

        let state = mgr.deployment_state();
        assert!(state.present);
        assert!(state.complete);
        assert!(state.is_usable());
        assert!(state.errors.is_empty());
        assert_eq!(state.versions.len(), 2);
        assert_eq!(state.manifests.len(), 2);
        assert_eq!(state.revision.as_deref(), Some("0.20240304.0"));
        assert!(state.entry_point.as_deref().unwrap().ends_with("run"));

        // Broken manifest degrades to a scan error, not a panic.
        std::fs::write(root.join("sniper_tools/manifest.json"), "{ nope").unwrap();
        let state = mgr.deployment_state();
        assert!(!state.complete);
        assert!(state.errors.iter().any(|e| e.contains("manifest")));
    }

    #[test]
    fn test_sha256_verification() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("runtime.tar");
        std::fs::write(&file, b"fake runtime archive bytes").unwrap();

        // Correct digest passes.
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"fake runtime archive bytes");
        let expected = hex::encode(h.finalize());
        verify_sha256_file(&file, &expected).unwrap();
        // Uppercase input is normalized.
        verify_sha256_file(&file, &expected.to_uppercase()).unwrap();

        // Wrong digest fails with a useful message.
        let err = verify_sha256_file(&file, &"0".repeat(64)).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("SHA256 mismatch"));
        assert!(text.contains("expected"));
        assert!(text.contains("got"));
    }

    #[test]
    fn test_find_runtime_root_nested_and_flat() {
        let dir = tempdir().unwrap();

        // Nested: tarball wrapped everything in one top-level dir.
        let nested = dir.path().join("nested");
        let wrapped = nested.join("steamrt4");
        std::fs::create_dir_all(&wrapped).unwrap();
        std::fs::write(wrapped.join("VERSIONS.txt"), "VERSION x 1\n").unwrap();
        assert_eq!(find_runtime_root(&nested), wrapped);

        // Flat: markers directly at root.
        std::fs::write(nested.join("VERSIONS.txt"), "VERSION x 1\n").unwrap();
        assert_eq!(find_runtime_root(&nested), nested);

        // Ambiguous (no markers, many dirs) → returns the given root.
        let ambiguous = dir.path().join("ambiguous");
        std::fs::create_dir_all(ambiguous.join("a")).unwrap();
        std::fs::create_dir_all(ambiguous.join("b")).unwrap();
        assert_eq!(find_runtime_root(&ambiguous), ambiguous);
    }

    #[test]
    fn test_runtime_app_id_and_client_dir_names() {
        assert_eq!(SteamRuntimeId::Steamrt1.app_id(), 1070560);
        assert_eq!(SteamRuntimeId::Steamrt2.app_id(), 1391110);
        assert_eq!(SteamRuntimeId::Steamrt3.app_id(), 1628350);
        assert_eq!(SteamRuntimeId::Steamrt4.app_id(), 4183110);
        assert!(SteamRuntimeId::Steamrt3
            .client_dir_names()
            .contains(&"SteamLinuxRuntime_sniper"));
        assert!(SteamRuntimeId::Steamrt4
            .client_dir_names()
            .contains(&"SteamLinuxRuntime_4"));
    }

    #[test]
    fn test_is_usable_runtime_root() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("SteamLinuxRuntime_sniper");
        assert!(!is_usable_runtime_root(&root));

        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("VERSIONS.txt"), "VERSION x 1\n").unwrap();
        assert!(!is_usable_runtime_root(&root), "entry point still missing");

        std::fs::write(root.join("run"), "#!/bin/sh\n").unwrap();
        assert!(is_usable_runtime_root(&root));

        // `_v2-entry-point` alone (no `run`) is also acceptable.
        let root2 = dir.path().join("SteamLinuxRuntime_4");
        std::fs::create_dir_all(&root2).unwrap();
        std::fs::write(root2.join("_v2-entry-point"), "#!/bin/sh\n").unwrap();
        std::fs::write(root2.join("VERSIONS.txt"), "VERSION x 1\n").unwrap();
        assert!(is_usable_runtime_root(&root2));
    }

    #[test]
    fn test_client_managed_runtime_detection() {
        let dir = tempdir().unwrap();
        let library = dir.path().join("Steam");
        let common = library.join("steamapps/common");

        // Client-managed sniper runtime.
        let sniper = common.join("SteamLinuxRuntime_sniper");
        std::fs::create_dir_all(&sniper).unwrap();
        std::fs::write(sniper.join("run"), "#!/bin/sh\n").unwrap();
        std::fs::write(sniper.join("VERSIONS.txt"), "VERSION sniper_platform 1\n").unwrap();

        let mgr = RuntimeManager::for_id(SteamRuntimeId::Steamrt3);
        assert_eq!(
            mgr.client_managed_runtime(&library),
            Some(sniper.clone()),
            "must find the client-managed sniper runtime"
        );

        // The default steamrt4 manager looks for SteamLinuxRuntime_4, not
        // sniper — so a sniper-only library is NOT a steamrt4 hit.
        let mgr4 = RuntimeManager::default();
        assert_eq!(mgr4.client_managed_runtime(&library), None);
    }

    #[test]
    fn test_resolve_runtime_root_preference_order() {
        let dir = tempdir().unwrap();
        let library = dir.path().join("Steam");

        // Nothing at all → None.
        let mgr = RuntimeManager::new(SteamRuntimeId::Steamrt3, dir.path().join("runtimes/sniper"));
        assert_eq!(mgr.resolve_runtime_root(&library), None);

        // Client-managed present → preferred even with a provisioned copy.
        let common = library.join("steamapps/common");
        let sniper = common.join("SteamLinuxRuntime_sniper");
        std::fs::create_dir_all(&sniper).unwrap();
        std::fs::write(sniper.join("run"), "#!/bin/sh\n").unwrap();
        std::fs::write(sniper.join("VERSIONS.txt"), "VERSION sniper_platform 1\n").unwrap();
        assert_eq!(mgr.resolve_runtime_root(&library), Some(sniper.clone()));

        // Provisioned-only → falls back to the provisioned root.
        let mgr2 = RuntimeManager::new(SteamRuntimeId::Steamrt4, dir.path().join("runtimes/steamrt4"));
        let provisioned = dir.path().join("runtimes/steamrt4");
        std::fs::create_dir_all(provisioned.join("sniper_platform")).unwrap();
        std::fs::write(provisioned.join("run"), "#!/bin/sh\n").unwrap();
        std::fs::write(
            provisioned.join("VERSIONS.txt"),
            "VERSION sniper_platform 0.20240304.0\n",
        )
        .unwrap();
        std::fs::write(
            provisioned.join("sniper_platform/manifest.json"),
            r#"{"name":"sniper_platform","version":"0.20240304.0"}"#,
        )
        .unwrap();
        assert_eq!(mgr2.resolve_runtime_root(&library), Some(provisioned));
    }

    #[test]
    fn test_is_usable_runtime_root_rejects_truncated() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("SteamLinuxRuntime_4");

        // Truncated download: 0-byte `run`, 0-byte VERSIONS.txt (the host's
        // corrupt steamrt4 shape) — must NOT be usable.
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("run"), "").unwrap();
        std::fs::write(root.join("_v2-entry-point"), "").unwrap();
        std::fs::write(root.join("VERSIONS.txt"), "").unwrap();
        assert!(!is_usable_runtime_root(&root), "0-byte entry point + VERSIONS.txt must be rejected");

        // Healed: non-empty entry point + VERSIONS.txt → usable.
        std::fs::write(root.join("run"), "#!/bin/sh\n").unwrap();
        std::fs::write(root.join("VERSIONS.txt"), "VERSION steamrt4_platform 1\n").unwrap();
        assert!(is_usable_runtime_root(&root));
    }

    #[test]
    fn test_purge_removes_provisioned_root() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("runtimes/steamrt4");
        let mgr = RuntimeManager::new(SteamRuntimeId::Steamrt4, root.clone());

        // Seed a corrupt/half-provisioned root, then purge it.
        std::fs::create_dir_all(root.join("steamrt4_platform/files")).unwrap();
        std::fs::write(root.join("VERSIONS.txt"), "").unwrap();
        assert!(root.exists());

        mgr.purge().unwrap();
        assert!(!root.exists(), "purge must remove the provisioned root");

        // Purging an already-absent root is a no-op, not an error.
        mgr.purge().unwrap();
    }
}
