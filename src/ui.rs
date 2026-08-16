use crate::config::{load_launcher_config, opensteam_image_cache_dir, LauncherConfig};
use crate::depot_browser::{DepotInfo as BrowserDepotInfo, ManifestFileEntry};
use crate::library::{build_game_library, scan_installed_app_paths};
use crate::models::{
    DepotPlatform, DownloadProgress, DownloadProgressState, DownloadState, LibraryGame,
    SteamGuardReq, UserProfile,
};
use crate::steam_client::SteamClient;
use anyhow::anyhow;
use eframe::egui;
use egui::{ColorImage, TextureHandle};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::mpsc::{self, Receiver, Sender};
use tokio::runtime::Runtime;
use serde::{Deserialize, Serialize};

pub type AppId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtonSource {
    Steam,
    Custom,
}


#[derive(Debug, Clone)]
struct UninstallModalState {
    app_id: u32,
    game_name: String,
    delete_prefix: bool,
}

#[derive(Debug, Clone)]
struct DepotBrowserState {
    app_id: u32,
    game_name: String,
    depots: Vec<BrowserDepotInfo>,
    selected_depot: Option<u32>,
    manifest_input: String,
    files: Vec<ManifestFileEntry>,
}

#[derive(Debug, Clone)]
struct PlatformSelectionState {
    app_id: u32,
    game_name: String,
    available: Vec<DepotPlatform>,
    cached_vdf: Vec<u8>,
}

#[derive(Debug, Clone)]
struct DepotInstallSelectionState {
    app_id: u32,
    game_name: String,
    platform: DepotPlatform,
    cached_vdf: Vec<u8>,
    depots: Vec<crate::steam_client::DepotInfo>,
}

#[derive(Debug, Clone)]
struct LaunchSelectorState {
    app_id: u32,
    game_name: String,
    options: Vec<crate::steam_client::LaunchInfo>,
    selected_id: String,
    always_use: bool,
}

/// Phase 4 Task 3 — a launch that was deferred because the effective prefix's
/// Windows Steam client had no persisted login session. Auto-retried after the
/// Stage-1 one-time login completes.
#[derive(Debug, Clone)]
struct PendingLoginLaunch {
    game: LibraryGame,
    launch_info: crate::steam_client::LaunchInfo,
    proton_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GameTab {
    Options,
    Properties,
    Mods,
    Info,
    Misc,
}

#[derive(Debug, Clone)]
struct ProtonManagerState {
    available: Vec<crate::proton::ProtonPackage>,
    installed: Vec<crate::proton::InstalledProton>,
    loading: bool,
    install_progress: Option<(String, u64, u64)>, // (package_name, downloaded, total)
    filter_label: Option<String>,
    error: Option<String>,
}

impl Default for ProtonManagerState {
    fn default() -> Self {
        Self {
            available: Vec::new(),
            installed: Vec::new(),
            loading: false,
            install_progress: None,
            filter_label: None,
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
struct ProtonRemoveConfirmState {
    name: String,
    is_default: bool,
    affected_games: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MainTab {
    Library,
    Account,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GameProcessState {
    Launching,
    Running(u32),
}

pub enum AsyncOp {
    DownloadStarted(
        u32,
        tokio::sync::mpsc::Receiver<DownloadProgress>,
        Arc<RwLock<DownloadState>>,
    ),
    BranchUpdated(u32, String),
    AccountDataFetched(crate::steam_client::AccountData),
    Uninstalled(u32, String),
    PlatformsFetched(u32, Vec<DepotPlatform>, Vec<u8>),
    ExtendedInfoFetched(u32, crate::steam_client::ExtendedAppInfo),
    LibraryFetched(Vec<LibraryGame>),
    Authenticated(crate::models::SessionState),
    BranchesFetched(u32, Vec<String>),
    DepotsFetched(u32, Vec<BrowserDepotInfo>),
    DepotListFetched(u32, Vec<crate::steam_client::DepotInfo>),
    InstallDepotsFetched(
        u32,
        DepotPlatform,
        Vec<u8>,
        Vec<crate::steam_client::DepotInfo>,
    ),
    DepotOwnershipVerified(HashMap<u64, bool>),
    ManifestFilesFetched(Vec<ManifestFileEntry>),
    LaunchOptionsFetched(u32, Vec<crate::steam_client::LaunchInfo>, Option<String>),
    AuthFailed(String),
    UserProfileFetched(crate::models::UserProfile),
    SettingsSaved(bool),
    WineControlPanelLaunched,
    WineCfgLaunched,
    WineFileManagerLaunched,
    WineRegeditLaunched,
    WineTaskManagerLaunched,
    /// Result of the Mods-tab native file picker (zenity/kdialog/…).
    CustomExecPicked(u32, Option<String>),
    ModLauncherLaunched,
    WindowsClientLoginResult(Result<std::path::PathBuf, String>),
    ScanCompleted(u32, HashMap<u32, String>),
    MasterSteamRepaired,
    MasterSteamBackedUp,
    MasterSteamRestored,
    /// Phase 4.4: result of the inline Steam Linux Runtime repair action.
    RuntimeRepaired(String),
    MetadataFetched(u32, crate::steam_client::AppMetadata),
    UserConfigsFetched(crate::models::UserConfigStore),
    ProtonListFetched(Vec<crate::proton::ProtonPackage>, Vec<crate::proton::InstalledProton>),
    ProtonInstallProgress(String, u64, u64),
    ProtonInstallComplete(String),
    ProtonInstallFailed(String, String),
    ProtonRemoved(String),
    Error(String),
    GameRunning(u32, u32),
    GameIdle(u32),
}

/// One active background operation (install/update/verify) bound to a single
/// AppID. Each task owns its own receiver, progress snapshot, ETA samples, and
/// `DownloadState` (its own abort signal + operation controller) so multiple
/// concurrent operations never clobber each other.
struct ActiveDownloadTask {
    app_id: u32,
    game_name: String,
    rx: tokio::sync::mpsc::Receiver<DownloadProgress>,
    progress: Option<DownloadProgress>,
    state: Arc<RwLock<DownloadState>>,
    /// (timestamp, depot bytes downloaded) samples for ETA estimation.
    samples: VecDeque<(std::time::Instant, u64)>,
}

/// Cover-art image variant, ordered by preference (Steam client / Proton 10.0
/// convention): hero capsule (landscape) → library capsule → small header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CoverVariant {
    HeroCapsule2x,
    HeroCapsule,
    LibraryHero2x,
    LibraryHero,
    LibraryCapsule2x,
    LibraryCapsule,
    HeaderImage,
}

impl CoverVariant {
    const ALL: [CoverVariant; 7] = [
        CoverVariant::HeroCapsule2x,
        CoverVariant::HeroCapsule,
        CoverVariant::LibraryHero2x,
        CoverVariant::LibraryHero,
        CoverVariant::LibraryCapsule2x,
        CoverVariant::LibraryCapsule,
        CoverVariant::HeaderImage,
    ];

    fn tier(self) -> usize {
        match self {
            CoverVariant::HeroCapsule2x | CoverVariant::HeroCapsule => 0,
            CoverVariant::LibraryHero2x
            | CoverVariant::LibraryHero
            | CoverVariant::LibraryCapsule2x
            | CoverVariant::LibraryCapsule => 1,
            CoverVariant::HeaderImage => 2,
        }
    }

    fn file_suffix(self) -> &'static str {
        match self {
            CoverVariant::HeroCapsule2x => "hero_capsule_2x",
            CoverVariant::HeroCapsule => "hero_capsule",
            CoverVariant::LibraryHero2x => "library_hero_2x",
            CoverVariant::LibraryHero => "library_hero",
            CoverVariant::LibraryCapsule2x => "library_capsule_2x",
            CoverVariant::LibraryCapsule => "library_capsule",
            CoverVariant::HeaderImage => "header_image",
        }
    }

    fn url(self, appid: AppId) -> String {
        match self {
            CoverVariant::HeroCapsule2x => {
                format!("https://cdn.akamai.steamstatic.com/steam/apps/{appid}/hero_capsule_2x.jpg")
            }
            CoverVariant::HeroCapsule => {
                format!("https://cdn.akamai.steamstatic.com/steam/apps/{appid}/hero_capsule.jpg")
            }
            CoverVariant::LibraryHero2x => {
                format!("https://cdn.akamai.steamstatic.com/steam/apps/{appid}/library_hero_2x.jpg")
            }
            CoverVariant::LibraryHero => {
                format!("https://cdn.akamai.steamstatic.com/steam/apps/{appid}/library_hero.jpg")
            }
            CoverVariant::LibraryCapsule2x => {
                format!("https://cdn.akamai.steamstatic.com/steam/apps/{appid}/library_capsule_2x.jpg")
            }
            CoverVariant::LibraryCapsule => {
                format!("https://cdn.akamai.steamstatic.com/steam/apps/{appid}/library_capsule.jpg")
            }
            CoverVariant::HeaderImage => {
                format!("https://cdn.akamai.steamstatic.com/steam/apps/{appid}/header.jpg")
            }
        }
    }

    /// Strictly-better variants (lower index = higher priority).
    fn better_than(self, other: CoverVariant) -> bool {
        Self::ALL.iter().position(|v| *v == self) < Self::ALL.iter().position(|v| *v == other)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoverFetchState {
    cached_variant: Option<String>,
    last_checked_unix_secs: u64,
    failed: bool,
}

const COVER_RECHECK_INTERVAL_SECS: u64 = 24 * 60 * 60;

pub struct SteamLauncher {
    runtime: Runtime,
    pub client: SteamClient,
    pub library: Vec<LibraryGame>,
    pub image_cache: HashMap<AppId, TextureHandle>,
    /// Which variant the texture in `image_cache` was loaded from (used to
    /// decide whether a better variant should be fetched/upgraded).
    image_variant: HashMap<AppId, CoverVariant>,
    pending_images: HashSet<AppId>,
    pending_metadata: HashSet<AppId>,
    /// Session-only record of variants that failed to fetch (offline, timeout,
    /// 404). Skipped on retry within the session; cleared by Refresh Library so
    /// nothing is permanently negative-cached.
    cover_fetch_failures: HashSet<(AppId, CoverVariant)>,
    /// Per-appid unix-seconds of the last `ensure_image_requested` spawn.
    /// Gates the per-frame spawn in the game detail view: the spawned task
    /// completes within the same frame and `pending_images` is cleared, so
    /// without this the selected game's cover task respawns EVERY frame —
    /// re-decoding the cached JPEG + re-uploading the texture at full repaint
    /// rate (~165 Hz = a pegged core). Refresh Library clears it to force a
    /// full recheck.
    last_cover_request: HashMap<AppId, u64>,
    image_tx: Sender<(AppId, CoverVariant, Option<String>)>,
    image_rx: Receiver<(AppId, CoverVariant, Option<String>)>,
    selected_app: Option<AppId>,
    show_installed_only: bool,
    search_text: String,
    status: String,
    auth_username: String,
    auth_password: String,
    auth_guard_code: String,
    needs_reauth: bool,
    install_log: Vec<String>,
    /// One active background operation per AppID (install/update/verify) —
    /// progress bars are rendered per task, each bound to its own game title.
    download_tasks: HashMap<u32, ActiveDownloadTask>,
    play_result_rx: Option<Receiver<String>>,
    show_settings: bool,
    launcher_config: LauncherConfig,
    proton_source: ProtonSource,
    steam_protons: Vec<String>,
    custom_protons: Vec<String>,
    user_profile: Option<UserProfile>,
    refreshing_account_data: bool,
    uninstall_modal: Option<UninstallModalState>,
    depot_browser: Option<DepotBrowserState>,
    platform_selection: Option<PlatformSelectionState>,
    depot_install_selection: Option<DepotInstallSelectionState>,
    launch_selector: Option<LaunchSelectorState>,
    proton_manager: ProtonManagerState,
    proton_remove_confirm: Option<ProtonRemoveConfirmState>,
    current_tab: GameTab,
    main_tab: MainTab,
    account_data: Option<crate::steam_client::AccountData>,
    extended_info: HashMap<u32, crate::steam_client::ExtendedAppInfo>,
    depot_list: Vec<crate::steam_client::DepotInfo>,
    depot_selection: HashSet<u64>,
    available_branches: HashMap<u32, Vec<String>>,
    is_verifying: bool,
    user_configs: crate::models::UserConfigStore,
    env_vars_edit_buffer: String,
    runner_components: Option<crate::utils::RunnerComponents>,
    last_scanned_runner: PathBuf,
    last_scanned_appid: Option<u32>,
    available_gpus: Vec<crate::utils::DetectedGpu>,
    show_repair_confirmation: bool,
    show_restore_confirmation: bool,
    operation_tx: Sender<AsyncOp>,
    operation_rx: Receiver<AsyncOp>,
    game_processes: HashMap<u32, GameProcessState>,
    /// Phase 4 Task 3 — one-time login onboarding as shipped default: when a
    /// launch fails because the effective prefix's Windows Steam client has no
    /// persisted session, remember the launch here and auto-trigger the
    /// Stage-1 login; on success, retry the launch automatically.
    pending_login_launch: Option<PendingLoginLaunch>,
    /// The prefix the auto-onboarding login must target (master or per-game).
    pending_login_prefix: Option<PathBuf>,
}

impl SteamLauncher {
    pub fn new(runtime: Runtime, client: SteamClient, library: Vec<LibraryGame>) -> Self {
        let (image_tx, image_rx) = mpsc::channel();
        let (operation_tx, operation_rx) = mpsc::channel();
        let authenticated = client.is_authenticated();
        let launcher_config = runtime.block_on(load_launcher_config()).unwrap_or_default();
        let mut user_configs = runtime.block_on(crate::config::load_user_configs()).unwrap_or_default();

        // Migration logic: Map legacy DXVK/VKD3D toggles to GraphicsBackendPolicy
        for cfg in user_configs.values_mut() {
            if cfg.graphics_layers.graphics_backend_policy == crate::models::GraphicsBackendPolicy::Auto {
                 if cfg.graphics_layers.dxvk_enabled {
                     cfg.graphics_layers.graphics_backend_policy = crate::models::GraphicsBackendPolicy::DXVK;
                 }
            }
        }

        let (steam_protons, custom_protons) = scan_proton_runtimes(&launcher_config);
        let user_profile = runtime
            .block_on(client.get_user_profile(library.len()))
            .ok();

        // Initial component scan for default runner
        let library_root = PathBuf::from(&launcher_config.steam_library_path);
        let resolved = crate::utils::resolve_runner(&launcher_config.proton_version, &library_root);
        let runner_components = Some(crate::utils::detect_runner_components(&resolved, None));

        Self {
            runtime,
            client,
            library,
            image_cache: HashMap::new(),
            image_variant: HashMap::new(),
            pending_images: HashSet::new(),
            pending_metadata: HashSet::new(),
            cover_fetch_failures: HashSet::new(),
            last_cover_request: HashMap::new(),
            image_tx,
            image_rx,
            selected_app: None,
            show_installed_only: false,
            search_text: String::new(),
            status: if authenticated {
                "Ready".to_string()
            } else {
                "Login required".to_string()
            },
            auth_username: String::new(),
            auth_password: String::new(),
            auth_guard_code: String::new(),
            needs_reauth: !authenticated,
            install_log: Vec::new(),
            download_tasks: HashMap::new(),
            play_result_rx: None,
            show_settings: false,
            launcher_config,
            proton_source: ProtonSource::Steam,
            steam_protons,
            custom_protons,
            user_profile,
            refreshing_account_data: false,
            uninstall_modal: None,
            depot_browser: None,
            platform_selection: None,
            depot_install_selection: None,
            launch_selector: None,
            proton_manager: ProtonManagerState::default(),
            proton_remove_confirm: None,
            current_tab: GameTab::Options,
            main_tab: MainTab::Library,
            account_data: None,
            extended_info: HashMap::new(),
            depot_list: Vec::new(),
            depot_selection: HashSet::new(),
            available_branches: HashMap::new(),
            is_verifying: false,
            user_configs,
            env_vars_edit_buffer: String::new(),
            pending_login_launch: None,
            pending_login_prefix: None,
            runner_components,
            last_scanned_runner: resolved,
            last_scanned_appid: None,
            available_gpus: crate::utils::list_available_gpus(),
            show_repair_confirmation: false,
            show_restore_confirmation: false,
            operation_tx,
            operation_rx,
            game_processes: HashMap::new(),
        }
    }

    fn visible_games(&self) -> Vec<&LibraryGame> {
        self.library
            .iter()
            .filter(|g| !self.show_installed_only || g.is_installed)
            .filter(|g| {
                self.search_text.trim().is_empty()
                    || g.name
                        .to_ascii_lowercase()
                        .contains(&self.search_text.to_ascii_lowercase())
            })
            .collect()
    }

    fn selected_game(&self) -> Option<&LibraryGame> {
        let appid = self.selected_app?;
        self.library.iter().find(|g| g.app_id == appid)
    }

    fn poll_image_results(&mut self, ctx: &egui::Context) -> bool {
        let mut drained = false;
        while let Ok((appid, variant, result)) = self.image_rx.try_recv() {
            drained = true;
            match result {
                Some(path) => {
                    self.cover_fetch_failures.remove(&(appid, variant));
                    if let Ok(bytes) = std::fs::read(&path) {
                        if let Ok(img) = image::load_from_memory(&bytes) {
                            let rgba = img.to_rgba8();
                            let size = [rgba.width() as usize, rgba.height() as usize];
                            let color = ColorImage::from_rgba_unmultiplied(size, rgba.as_raw());
                            let texture = ctx.load_texture(
                                format!("cover_{appid}"),
                                color,
                                egui::TextureOptions::LINEAR,
                            );
                            self.image_cache.insert(appid, texture);
                            self.image_variant.insert(appid, variant);
                        } else {
                            // Cache file exists but cannot be decoded — remove
                            // it so a later selection/refresh can re-download
                            // instead of looping on the corrupt file forever.
                            let _ = std::fs::remove_file(&path);
                        }
                    }
                }
                None => {
                    // Fetch failed (offline, timeout, or non-200 response).
                    // Remember the variant for THIS session only, so we don't
                    // hammer the CDN every frame; Refresh Library clears it.
                    // Any lower-priority cached texture stays visible meanwhile.
                    // No permanent negative caching.
                    self.cover_fetch_failures.insert((appid, variant));
                }
            }
            self.pending_images.remove(&appid);
        }
        drained
    }

    fn ensure_metadata_requested(&mut self, appid: AppId) {
        if let Some(game) = self.library.iter().find(|g| g.app_id == appid) {
            if !game.name.starts_with("App ") {
                return;
            }
        } else {
            return;
        }

        if self.pending_metadata.contains(&appid) {
            return;
        }

        self.pending_metadata.insert(appid);
        let client = self.client.clone();
        let tx = self.operation_tx.clone();
        self.runtime.spawn(async move {
            if let Some(metadata) = client.fetch_app_metadata(appid).await {
                let _ = tx.send(AsyncOp::MetadataFetched(appid, metadata));
            }
        });
    }

    fn ensure_image_requested(&mut self, appid: AppId) {
        if self.pending_images.contains(&appid) {
            return;
        }

        // Cover fetch cadence gate: only (re)spawn the fetch task once per
        // COVER_RECHECK_INTERVAL_SECS per appid. Without this gate the task
        // completes within the same frame it is spawned (state file says the
        // 24h window is still fresh → cached path sent back → pending_images
        // cleared in poll_image_results), so the selected game's cover task
        // respawns EVERY UI frame — re-decoding the cached JPEG in the tokio
        // worker and re-uploading the texture on the UI thread at full repaint
        // rate (165 Hz on a high-refresh display ≈ one pegged core). The
        // once-per-day availability recheck still runs: when the interval
        // elapses, the next spawn re-validates via HEAD. Refresh Library
        // clears the map to force an immediate full recheck.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        if self
            .last_cover_request
            .get(&appid)
            .is_some_and(|t| now.saturating_sub(*t) < COVER_RECHECK_INTERVAL_SECS)
        {
            return;
        }
        self.last_cover_request.insert(appid, now);

        let best = self.image_variant.get(&appid).copied();
        // The top variant still needs a once-per-day availability check.
        let variant = best.unwrap_or(CoverVariant::HeroCapsule2x);

        self.pending_images.insert(appid);
        let tx = self.image_tx.clone();
        let appid_for_task = appid;

        self.runtime.spawn(async move {
            let Ok(cache_dir) = opensteam_image_cache_dir() else {
                return;
            };

            if tokio::fs::create_dir_all(&cache_dir).await.is_err() {
                return;
            }

            let state_path = cache_dir.join(format!("{appid_for_task}_cover_state.json"));
            let mut state = tokio::fs::read(&state_path)
                .await
                .ok()
                .and_then(|bytes| serde_json::from_slice::<CoverFetchState>(&bytes).ok());
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default();
            let cached = state.as_ref().and_then(|s| {
                s.cached_variant.as_deref().and_then(|name| {
                    CoverVariant::ALL
                        .iter()
                        .copied()
                        .find(|v| v.file_suffix() == name)
                })
            });

            let cache_path = |v: CoverVariant| {
                cache_dir.join(format!("{appid_for_task}_{}.jpg", v.file_suffix()))
            };
            let valid_cache = |path: PathBuf| async move {
                let Ok(bytes) = tokio::fs::read(path).await else {
                    return false;
                };
                !bytes.is_empty() && image::load_from_memory(&bytes).is_ok()
            };

            if state
                .as_ref()
                .is_some_and(|s| now.saturating_sub(s.last_checked_unix_secs) < COVER_RECHECK_INTERVAL_SECS)
            {
                if let Some(cached) = cached {
                    let path = cache_path(cached);
                    if valid_cache(path.clone()).await {
                        let _ = tx.send((
                            appid_for_task,
                            cached,
                            Some(path.to_string_lossy().to_string()),
                        ));
                        return;
                    }
                }
                let _ = tx.send((appid_for_task, variant, None));
                return;
            }

            let cached = match cached {
                Some(cached) if valid_cache(cache_path(cached)).await => Some(cached),
                _ => None,
            };
            let candidates: Vec<CoverVariant> = CoverVariant::ALL
                .iter()
                .copied()
                .filter(|v| {
                    cached
                        .map(|c| v.better_than(c) || (c.tier() == 0 && *v == c))
                        .unwrap_or(true)
                })
                .collect();
            let mut selected = cached;
            for candidate in candidates {
                let path = cache_path(candidate);
                let should_revalidate = cached == Some(candidate) && candidate.tier() == 0;
                if should_revalidate {
                    let client = reqwest::Client::new();
                    let check = async { client.head(candidate.url(appid_for_task)).send().await };
                    if let Ok(Ok(response)) =
                        tokio::time::timeout(std::time::Duration::from_secs(5), check).await
                    {
                        if response.status().is_success() {
                            selected = Some(candidate);
                            break;
                        }
                    }
                    continue;
                }
                if !should_revalidate && valid_cache(path.clone()).await {
                    selected = Some(candidate);
                    break;
                }

                let fetch = async { reqwest::get(candidate.url(appid_for_task)).await };
                let Ok(Ok(response)) =
                    tokio::time::timeout(std::time::Duration::from_secs(5), fetch).await
                else {
                    continue;
                };
                if !response.status().is_success() {
                    continue;
                }
                let Ok(bytes) = response.bytes().await else {
                    continue;
                };
                if bytes.is_empty() || image::load_from_memory(&bytes).is_err() {
                    continue;
                }
                if tokio::fs::write(&path, bytes).await.is_ok() {
                    selected = Some(candidate);
                    for lower in CoverVariant::ALL
                        .iter()
                        .filter(|v| candidate.tier() < v.tier())
                    {
                        let _ = tokio::fs::remove_file(cache_path(*lower)).await;
                    }
                    break;
                }
            }

            state = Some(CoverFetchState {
                cached_variant: selected.map(|v| v.file_suffix().to_string()),
                last_checked_unix_secs: now,
                failed: selected.is_none(),
            });
            if let Some(state) = &state {
                if let Ok(bytes) = serde_json::to_vec(state) {
                    let _ = tokio::fs::write(&state_path, bytes).await;
                }
            }
            let result = selected.map(|v| cache_path(v).to_string_lossy().to_string());
            let _ = tx.send((appid_for_task, selected.unwrap_or(variant), result));
        });
    }

    fn refresh_account_data(&mut self) {
        if self.refreshing_account_data {
            return;
        }
        self.refreshing_account_data = true;
        let client = self.client.clone();
        let tx = self.operation_tx.clone();
        self.runtime.spawn(async move {
            let data = client.get_account_data().await;
            let _ = tx.send(AsyncOp::AccountDataFetched(data));
        });
    }

    fn logout(&mut self) {
        let mut client = self.client.clone();
        let _ = self.runtime.block_on(client.logout());
        self.client = client;
        self.needs_reauth = true;
        self.user_profile = None;
        self.account_data = None;
        self.library.clear();
        self.status = "Logged out".to_string();
    }

    fn poll_download_progress(&mut self) -> bool {
        let mut finished: Vec<u32> = Vec::new();
        let mut drained = false;

        // Drain every active task's channel independently — each task is
        // strictly bound to its own AppID + game title.
        for (appid, task) in self.download_tasks.iter_mut() {
            while let Ok(progress) = task.rx.try_recv() {
                drained = true;
                task.progress = Some(progress.clone());
                let game_name = task.game_name.clone();
                match progress.state {
                    DownloadProgressState::Queued => {
                        // New operation: reset the rate estimator.
                        task.samples.clear();
                        self.status = format!("{game_name}: queued");
                    }
                    DownloadProgressState::Downloading => {
                        // Record a (time, bytes) sample for ETA estimation.
                        Self::record_progress_sample(&mut task.samples, progress.bytes_downloaded);
                        // Prefer file-level detail (active file + its byte
                        // offsets) over the depot aggregate in status text.
                        let (file_label, cur, tot) = if progress.file_total_bytes > 0 {
                            (
                                progress.file_path.clone(),
                                progress.file_bytes_downloaded,
                                progress.file_total_bytes,
                            )
                        } else {
                            (
                                progress.current_file.clone(),
                                progress.bytes_downloaded,
                                progress.total_bytes,
                            )
                        };
                        self.install_log.push(format!(
                            "App {} — downloading {}: {} / {} bytes",
                            appid,
                            file_label,
                            cur,
                            tot
                        ));
                        if self.install_log.len() > 8 {
                            self.install_log.drain(0..self.install_log.len() - 8);
                        }
                        self.status = format!(
                            "Downloading {}: {} / {} bytes",
                            progress.current_file, cur, tot
                        );
                    }
                    DownloadProgressState::Verifying => {
                        Self::record_progress_sample(&mut task.samples, progress.bytes_downloaded);
                        let (_file_label, cur, tot) = if progress.file_total_bytes > 0 {
                            (
                                progress.file_path.clone(),
                                progress.file_bytes_downloaded,
                                progress.file_total_bytes,
                            )
                        } else {
                            (
                                progress.current_file.clone(),
                                progress.bytes_downloaded,
                                progress.total_bytes,
                            )
                        };
                        self.status = format!(
                            "Verifying {}: {} / {} bytes",
                            progress.current_file, cur, tot
                        );
                    }
                    DownloadProgressState::Completed => {
                        self.status = format!("{game_name}: operation complete");
                        if let Ok(mut state) = task.state.write() {
                            state.is_downloading = false;
                            state.is_paused = false;
                        }
                        let app_id = *appid;
                        let tx = self.operation_tx.clone();
                        self.runtime.spawn(async move {
                            let installed_paths =
                                scan_installed_app_paths().await.unwrap_or_default();
                            let _ = tx.send(AsyncOp::ScanCompleted(app_id, installed_paths));
                        });
                        finished.push(*appid);
                    }
                    DownloadProgressState::Failed => {
                        self.status = format!("Install failed: {}", progress.current_file);
                        if let Ok(mut state) = task.state.write() {
                            state.is_downloading = false;
                            state.is_paused = false;
                        }
                        finished.push(*appid);
                    }
                }
            }
        }

        for appid in finished {
            self.download_tasks.remove(&appid);
        }
        drained
    }


    fn poll_play_result(&mut self) -> bool {
        let mut drained = false;
        if let Some(rx) = &self.play_result_rx {
            match rx.try_recv() {
                Ok(message) => {
                    drained = true;
                    let mut finished = true;
                    if let Some(value) = message.strip_prefix("__RUNNING__") {
                        finished = false;
                        self.pending_login_launch = None;
                        self.pending_login_prefix = None;
                        if let Some((appid, pid)) = value.split_once(':') {
                            if let (Ok(appid), Ok(pid)) = (appid.parse(), pid.parse()) {
                                self.game_processes.insert(appid, GameProcessState::Running(pid));
                            }
                        }
                    } else if let Some(appid) = message.strip_prefix("__IDLE__").and_then(|v| v.parse().ok()) {
                        self.game_processes.remove(&appid);
                    } else if let Some(prefix) = message.strip_prefix("__LOGIN_REQUIRED__") {
                        // Phase 4 Task 3 — one-time login onboarding as shipped
                        // default: the effective prefix's Windows Steam client
                        // has no persisted session. Remember the target prefix
                        // and auto-trigger the Stage-1 login; on success the
                        // pending launch is retried automatically.
                        self.pending_login_prefix = Some(PathBuf::from(prefix));
                        self.status = format!(
                            "Windows Steam has no login session in {} — starting one-time login…",
                            prefix
                        );
                        self.handle_windows_client_login();
                    } else {
                        self.status = message;
                    }
                    if finished {
                        self.play_result_rx = None;
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.status = "Play task disconnected".to_string();
                    self.play_result_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        drained
    }

    fn start_install(&mut self, app_id: u32, platform: DepotPlatform, cached_vdf: Option<Vec<u8>>, filter_depots: Option<Vec<u64>>) {
        let client = self.client.clone();
        let tx = self.operation_tx.clone();
        // Per-task DownloadState: its own abort signal + operation controller,
        // so concurrent installs/verifies never cancel each other.
        let download_state = Arc::new(RwLock::new(DownloadState::default()));
        self.runtime.spawn(async move {
            match client.install_game(app_id, platform, cached_vdf, filter_depots, download_state.clone()).await {
                Ok(rx) => {
                    let _ = tx.send(AsyncOp::DownloadStarted(app_id, rx, download_state));
                }
                Err(err) => {
                    let _ = tx.send(AsyncOp::Error(format!(
                        "Failed to start install for {app_id}: {err}"
                    )));
                }
            }
        });
    }

    fn begin_depot_selection(
        &mut self,
        app_id: u32,
        platform: DepotPlatform,
        cached_vdf: Vec<u8>,
    ) {
        let client = self.client.clone();
        let tx = self.operation_tx.clone();
        self.status = "Loading depot access...".to_string();
        self.runtime.spawn(async move {
            match client.get_depot_list_with_access(app_id).await {
                Ok(depots) => {
                    let _ = tx.send(AsyncOp::InstallDepotsFetched(
                        app_id, platform, cached_vdf, depots,
                    ));
                }
                Err(err) => {
                    let _ = tx.send(AsyncOp::Error(format!(
                        "Failed to load depots for {app_id}: {err}"
                    )));
                }
            }
        });
    }

    fn poll_async_ops(&mut self) -> bool {
        let mut drained = false;
        while let Ok(op) = self.operation_rx.try_recv() {
            drained = true;
            match op {
                AsyncOp::DownloadStarted(appid, rx, state) => {
                    // Register a new per-AppID task. If one already exists for
                    // this app (e.g. a re-triggered verify), replace it.
                    let game_name = self
                        .library
                        .iter()
                        .find(|g| g.app_id == appid)
                        .map(|g| g.name.clone())
                        .unwrap_or_else(|| format!("App {appid}"));
                    self.download_tasks.insert(
                        appid,
                        ActiveDownloadTask {
                            app_id: appid,
                            game_name: game_name.clone(),
                            rx,
                            progress: None,
                            state,
                            samples: VecDeque::new(),
                        },
                    );
                    self.status = format!("Operation started for {game_name}");
                }
                AsyncOp::BranchUpdated(appid, branch) => {
                    if let Some(game) = self.library.iter_mut().find(|g| g.app_id == appid) {
                        game.active_branch = branch.clone();
                        game.update_available = true;
                        game.update_queued = true;
                    }
                    self.status = format!("Switched to branch {branch}");
                }
                AsyncOp::Uninstalled(appid, name) => {
                    if let Some(game) = self.library.iter_mut().find(|g| g.app_id == appid) {
                        game.is_installed = false;
                        game.install_path = None;
                        game.update_available = false;
                        game.local_manifest_ids.clear();
                    }
                    self.status = format!("Uninstalled {name}");
                }
                AsyncOp::PlatformsFetched(appid, platforms, buffer) => {
                    if platforms.len() > 1 {
                        let game_name = self
                            .library
                            .iter()
                            .find(|g| g.app_id == appid)
                            .map(|g| g.name.clone())
                            .unwrap_or_else(|| format!("App {appid}"));
                        self.platform_selection = Some(PlatformSelectionState {
                            app_id: appid,
                            game_name,
                            available: platforms,
                            cached_vdf: buffer,
                        });
                    } else {
                        let platform = platforms.first().cloned().unwrap_or(DepotPlatform::Windows);
                        self.begin_depot_selection(appid, platform, buffer);
                    }
                }
                AsyncOp::InstallDepotsFetched(appid, platform, cached_vdf, depots) => {
                    let game_name = self
                        .library
                        .iter()
                        .find(|g| g.app_id == appid)
                        .map(|g| g.name.clone())
                        .unwrap_or_else(|| format!("App {appid}"));
                    self.depot_selection = depots
                        .iter()
                        .filter(|depot| depot.is_owned == Some(true))
                        .map(|depot| depot.id)
                        .collect();
                    self.depot_install_selection = Some(DepotInstallSelectionState {
                        app_id: appid,
                        game_name,
                        platform,
                        cached_vdf,
                        depots,
                    });
                }
                AsyncOp::ExtendedInfoFetched(appid, info) => {
                    self.extended_info.insert(appid, info);
                }
                AsyncOp::LibraryFetched(library) => {
                    self.library = library;
                    self.status = format!("Library refreshed ({})", self.library.len());
                    self.refresh_user_profile();
                }
                AsyncOp::Authenticated(_session) => {
                    self.needs_reauth = false;
                    self.auth_guard_code.clear();
                    self.client.clear_pending_confirmations();
                    self.status = if self.client.is_offline() {
                        "OFFLINE MODE".to_string()
                    } else {
                        "Login successful".to_string()
                    };
                    self.refresh_library();
                }
                AsyncOp::WindowsClientLoginResult(result) => {
                    match result {
                        Ok(path) => {
                            self.status = format!(
                                "Windows Steam client logged in (sentry file present at {})",
                                path.display()
                            );
                            // Phase 4 Task 3: one-time login onboarding as
                            // shipped default — the deferred launch is retried
                            // automatically now that the effective prefix has a
                            // persisted session.
                            if let Some(pending) = self.pending_login_launch.take() {
                                let game = pending.game;
                                let launch_info = pending.launch_info;
                                let proton_path = pending.proton_path;
                                self.start_launch_task(&game, launch_info, proton_path);
                            }
                        }
                        Err(err) => {
                            self.status = format!("Windows Steam client login failed: {err}");
                            self.pending_login_launch = None;
                        }
                    }
                }
                AsyncOp::AuthFailed(err) => {
                    if self.client.is_offline() {
                        self.needs_reauth = false;
                        self.status = "OFFLINE MODE".to_string();
                        self.refresh_library();
                    } else {
                        self.status = format!("Login failed: {err}");
                        self.needs_reauth = true;
                    }
                }
                AsyncOp::UserProfileFetched(profile) => {
                    self.user_profile = Some(profile);
                }
                AsyncOp::AccountDataFetched(data) => {
                    self.account_data = Some(data);
                    self.refreshing_account_data = false;
                }
                AsyncOp::SettingsSaved(success) => {
                    self.status = if success {
                        "Settings saved".to_string()
                    } else {
                        "Failed to save settings".to_string()
                    };
                }
                AsyncOp::MasterSteamRepaired => {
                    self.status = "Windows Steam Runtime repaired successfully".to_string();
                }
                AsyncOp::MasterSteamBackedUp => {
                    self.status = "Windows Steam Runtime backed up successfully".to_string();
                }
                AsyncOp::MasterSteamRestored => {
                    self.status = "Windows Steam Runtime restored successfully".to_string();
                }
                AsyncOp::RuntimeRepaired(msg) => {
                    self.status = msg;
                }
                AsyncOp::WineControlPanelLaunched => {
                    self.status = "Wine Control Panel launched".to_string();
                }
                AsyncOp::WineCfgLaunched => {
                    self.status = "Wine Configuration launched".to_string();
                }
                AsyncOp::WineFileManagerLaunched => {
                    self.status = "Wine File Manager launched".to_string();
                }
                AsyncOp::WineRegeditLaunched => {
                    self.status = "Wine Registry Editor launched".to_string();
                }
                AsyncOp::WineTaskManagerLaunched => {
                    self.status = "Wine Task Manager launched".to_string();
                }
                AsyncOp::CustomExecPicked(appid, picked) => {
                    match picked {
                        Some(path) => {
                            let mut cfg =
                                self.user_configs.get(&appid).cloned().unwrap_or_default();
                            cfg.custom_exec_path = Some(path.clone());
                            self.user_configs.insert(appid, cfg);
                            let store = self.user_configs.clone();
                            self.runtime.spawn(async move {
                                let _ = crate::config::save_user_configs(&store).await;
                            });
                            self.status = format!("Custom mod executable set: {path}");
                        }
                        None => {
                            self.status = "File picker cancelled".to_string();
                        }
                    }
                }
                AsyncOp::ModLauncherLaunched => {
                    self.status = "Custom mod executable launched".to_string();
                }
                AsyncOp::ScanCompleted(appid, installed_paths) => {
                    for g in &mut self.library {
                        if g.app_id == appid {
                            g.install_path = installed_paths.get(&appid).cloned();
                            g.is_installed = g.install_path.is_some();
                        }
                    }
                }
                AsyncOp::MetadataFetched(appid, metadata) => {
                    if let Some(game) = self.library.iter_mut().find(|g| g.app_id == appid) {
                        game.name = metadata.name.clone();
                    }
                    let owned: Vec<_> = self
                        .library
                        .iter()
                        .map(|g| crate::models::OwnedGame {
                            app_id: g.app_id,
                            name: g.name.clone(),
                            playtime_forever_minutes: g.playtime_forever_minutes.unwrap_or(0),
                            local_manifest_ids: g.local_manifest_ids.clone(),
                            update_available: g.update_available,
                        })
                        .collect();
                    let owned_clone = owned.clone();
                    self.runtime.spawn(async move {
                        let _ = crate::config::save_library_cache(&owned_clone).await;
                    });
                    self.pending_metadata.remove(&appid);
                }
                AsyncOp::UserConfigsFetched(configs) => {
                    self.user_configs = configs;
                }
                AsyncOp::ProtonListFetched(available, installed) => {
                    self.proton_manager.available = available;
                    self.proton_manager.installed = installed;
                    self.proton_manager.loading = false;
                }
                AsyncOp::ProtonInstallProgress(name, downloaded, total) => {
                    self.proton_manager.install_progress = Some((name, downloaded, total));
                }
                AsyncOp::ProtonInstallComplete(name) => {
                    self.proton_manager.install_progress = None;
                    self.status = format!("Installed {}", name);
                    // Trigger refresh
                    let library_root = PathBuf::from(&self.launcher_config.steam_library_path);
                    let tx = self.operation_tx.clone();
                    self.runtime.spawn(async move {
                        let available = crate::proton::list_available().await.unwrap_or_default();
                        let installed = crate::proton::list_installed(&library_root).unwrap_or_default();
                        let _ = tx.send(AsyncOp::ProtonListFetched(available, installed));
                    });
                }
                AsyncOp::ProtonInstallFailed(name, err) => {
                    self.proton_manager.install_progress = None;
                    self.proton_manager.error = Some(format!("Failed to install {}: {}", name, err));
                }
                AsyncOp::ProtonRemoved(name) => {
                    self.status = format!("Removed {}", name);
                    // Trigger refresh
                    let library_root = PathBuf::from(&self.launcher_config.steam_library_path);
                    let tx = self.operation_tx.clone();
                    self.runtime.spawn(async move {
                        let available = crate::proton::list_available().await.unwrap_or_default();
                        let installed = crate::proton::list_installed(&library_root).unwrap_or_default();
                        let _ = tx.send(AsyncOp::ProtonListFetched(available, installed));
                    });
                }
                AsyncOp::BranchesFetched(appid, branches) => {
                    self.available_branches.insert(appid, branches);
                }
                AsyncOp::DepotListFetched(_appid, list) => {
                    self.depot_list = list;
                    self.depot_selection = self.depot_list.iter().map(|d| d.id).collect();
                }
                AsyncOp::DepotOwnershipVerified(results) => {
                    for depot in &mut self.depot_list {
                        if let Some(owned) = results.get(&depot.id) {
                            depot.is_owned = Some(*owned);
                        }
                    }
                    self.is_verifying = false;
                }
                AsyncOp::DepotsFetched(appid, depots) => {
                    if let Some(game) = self.library.iter().find(|g| g.app_id == appid) {
                        let selected_depot = depots.first().map(|d| d.depot_id);
                        let manifest_input = depots
                            .first()
                            .and_then(|d| d.public_manifest_id)
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "public".to_string());
                        self.depot_browser = Some(DepotBrowserState {
                            app_id: appid,
                            game_name: game.name.clone(),
                            depots,
                            selected_depot,
                            manifest_input,
                            files: Vec::new(),
                        });
                    }
                }
                AsyncOp::ManifestFilesFetched(files) => {
                    if let Some(state) = &mut self.depot_browser {
                        state.files = files;
                    }
                }
                AsyncOp::LaunchOptionsFetched(appid, options, proton_path) => {
                    let game = self.library.iter().find(|g| g.app_id == appid).cloned();
                    if let Some(game) = game {
                        if let Some(preferred_id) = self.launcher_config.preferred_launch_options.get(&appid) {
                            if let Some(option) = options.iter().find(|o| &o.id == preferred_id) {
                                self.start_launch_task(&game, option.clone(), proton_path);
                                return drained;
                            }
                        }

                        if options.len() > 1 {
                            self.launch_selector = Some(LaunchSelectorState {
                                app_id: appid,
                                game_name: game.name.clone(),
                                selected_id: options[0].id.clone(),
                                options,
                                always_use: false,
                            });
                        } else if let Some(option) = options.first() {
                            self.start_launch_task(&game, option.clone(), proton_path);
                        }
                    }
                }
                AsyncOp::Error(err) => {
                    if err.contains("wineserver is already running") {
                        self.status = "Runtime conflict: stop running games first, or use per-game prefix mode (Game Options → Runtime Settings → Per-game prefix).".to_string();
                    } else {
                        self.status = err;
                    }
                }
            AsyncOp::GameRunning(appid, pid) => {
                self.game_processes.insert(appid, GameProcessState::Running(pid));
            }
            AsyncOp::GameIdle(appid) => {
                self.game_processes.remove(&appid);
            }
            }
        }
        drained
    }

    fn confirmation_validation_message(&self) -> Option<String> {
        let prompts = self.client.pending_confirmations();
        if prompts.is_empty() {
            return None;
        }

        let requires_code = prompts.iter().any(|p| {
            matches!(
                p.requirement,
                SteamGuardReq::EmailCode { .. } | SteamGuardReq::DeviceCode
            )
        });

        if requires_code && self.auth_guard_code.trim().is_empty() {
            return Some(
                "A Steam Guard code is required. Enter email/device code and retry.".to_string(),
            );
        }

        if prompts
            .iter()
            .any(|p| matches!(p.requirement, SteamGuardReq::DeviceConfirmation))
        {
            return Some(
                "Approve this login in Steam Mobile if prompted, then retry login.".to_string(),
            );
        }

        None
    }

    fn refresh_user_profile(&mut self) {
        let client = self.client.clone();
        let tx = self.operation_tx.clone();
        let len = self.library.len();
        self.runtime.spawn(async move {
            if let Ok(profile) = client.get_user_profile(len).await {
                let _ = tx.send(AsyncOp::UserProfileFetched(profile));
            }
        });
    }

    /// Clears transient cover-art load failures and re-enqueues background
    /// downloads for every library game whose best cover variant is still
    /// missing or outdated. Games already showing the hero capsule are skipped;
    /// games with only a lower-priority image cached get the upgrade chain
    /// re-attempted (header_image → library_capsule_2x → hero_capsule_2x).
    fn recheck_missing_covers(&mut self) {
        self.pending_images.clear();
        self.cover_fetch_failures.clear();
        // Clear the cadence gate so Refresh Library forces an immediate
        // recheck of every game (bypasses the 24 h last_cover_request window).
        self.last_cover_request.clear();
        let appids: Vec<AppId> = self.library.iter().map(|g| g.app_id).collect();
        for appid in appids {
            self.ensure_image_requested(appid);
        }
    }

    fn refresh_library(&mut self) {
        // Refresh Library also retries cover art: drop transient image-load
        // error state and re-enqueue downloads for all missing covers (see
        // ensure_image_requested — it re-validates the cache file first and
        // deletes zero-byte/corrupt entries before re-downloading).
        self.recheck_missing_covers();
        let mut client = self.client.clone();
        let tx = self.operation_tx.clone();
        self.runtime.spawn(async move {
            let result = match client.fetch_owned_games().await {
                Ok(owned) => {
                    let installed = crate::library::scan_installed_app_info()
                        .await
                        .unwrap_or_default();
                    let mut lib = build_game_library(owned, installed).games;
                    let _ = client.check_for_updates(&mut lib).await;
                    Ok(lib)
                }
                Err(err) => {
                    if client.is_offline() {
                        let cached = client.load_cached_owned_games().await.unwrap_or_default();
                        let installed = crate::library::scan_installed_app_info()
                            .await
                            .unwrap_or_default();
                        let mut lib = build_game_library(cached, installed).games;
                        let _ = client.check_for_updates(&mut lib).await;
                        Ok(lib)
                    } else {
                        Err(err)
                    }
                }
            };

            match result {
                Ok(lib) => {
                    let _ = tx.send(AsyncOp::LibraryFetched(lib));
                }
                Err(err) => {
                    let _ = tx.send(AsyncOp::Error(format!("Failed to refresh library: {err}")));
                }
            }
        });
    }

    fn handle_auth_submit(&mut self) {
        if self.auth_username.trim().is_empty() || self.auth_password.trim().is_empty() {
            self.status = "Enter username and password".to_string();
            return;
        }

        if let Some(validation) = self.confirmation_validation_message() {
            self.status = validation;
            return;
        }

        let mut client = self.client.clone();
        let tx = self.operation_tx.clone();
        let username = self.auth_username.trim().to_string();
        let password = self.auth_password.clone();
        let guard_code = if self.auth_guard_code.trim().is_empty() {
            None
        } else {
            Some(self.auth_guard_code.trim().to_string())
        };

        self.runtime.spawn(async move {
            match client.login(username, password, guard_code).await {
                Ok(session) => {
                    let _ = tx.send(AsyncOp::Authenticated(session));
                }
                Err(err) => {
                    let _ = tx.send(AsyncOp::AuthFailed(err.to_string()));
                }
            }
        });
    }

    fn handle_windows_client_login(&mut self) {
        if self.auth_username.trim().is_empty() || self.auth_password.is_empty() {
            self.status = "Enter username and password first".to_string();
            return;
        }
        let runner = self.launcher_config.steam_runtime_runner.clone();
        let username = self.auth_username.trim().to_string();
        let password = self.auth_password.clone();
        let tx = self.operation_tx.clone();
        // Phase 4 Task 3: target the effective prefix (per-game when the
        // launch was deferred for a per-game login), master by default.
        let prefix = self
            .pending_login_prefix
            .clone()
            .unwrap_or_else(crate::utils::resolve_master_wineprefix);
        self.status = "Logging into Windows Steam client (check for Steam Guard prompt)…".to_string();
        self.runtime.spawn(async move {
            let result = crate::steam_client::SteamClient::windows_client_login_in_prefix(
                &runner, &prefix, &username, &password,
            )
            .await
            .map_err(|e| e.to_string());
            let _ = tx.send(AsyncOp::WindowsClientLoginResult(result));
        });
    }

    fn handle_play_click(&mut self, game: &LibraryGame) {
        self.game_processes
            .insert(game.app_id, GameProcessState::Launching);
        let mut prefer_proton = false;
        if let Some(config) = self.launcher_config.game_configs.get(&game.app_id) {
            if let Some(pref) = &config.platform_preference {
                prefer_proton = pref == "windows";
            }

        }

        let mut client = self.client.clone();
        let tx = self.operation_tx.clone();
        let app_id = game.app_id;

        self.runtime.spawn(async move {
            match client.get_product_info(app_id, prefer_proton).await {
                Ok(options) => {
                    let _ = tx.send(AsyncOp::LaunchOptionsFetched(app_id, options, None));
                }
                Err(err) => {
                    let _ = tx.send(AsyncOp::Error(format!("Failed to get launch options: {err}")));
                }
            }
        });
    }

    fn stop_game(&mut self, appid: u32) {
        let Some(GameProcessState::Running(pid)) = self.game_processes.get(&appid).copied() else {
            return;
        };
        self.status = format!("Stopping game {appid}…");
        self.game_processes.insert(appid, GameProcessState::Launching);
        let tx = self.operation_tx.clone();
        self.runtime.spawn(async move {
            #[cfg(unix)]
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            #[cfg(not(unix))]
            let _ = pid;
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            #[cfg(unix)]
            unsafe {
                if libc::kill(pid as libc::pid_t, 0) == 0 {
                    libc::kill(pid as libc::pid_t, libc::SIGKILL);
                }
            }
            let _ = tx.send(AsyncOp::GameIdle(appid));
        });
    }

    fn start_launch_task(&mut self, game: &LibraryGame, launch_info: crate::steam_client::LaunchInfo, proton_path: Option<String>) {
        // Phase 4 Task 3: remember the launch so it can be auto-retried after
        // the one-time Windows Steam login completes (cleared on success).
        self.pending_login_launch = Some(PendingLoginLaunch {
            game: game.clone(),
            launch_info: launch_info.clone(),
            proton_path: proton_path.clone(),
        });
        let game = game.clone();
        let client = self.client.clone();
        let user_config = self.user_configs.get(&game.app_id).cloned();
        let (tx, rx) = mpsc::channel();
        self.play_result_rx = Some(rx);
        let cloud_enabled_pre = self.launcher_config.enable_cloud_sync && !self.client.is_offline();
        if cloud_enabled_pre {
            self.status = format!("Syncing Cloud... {}", game.name);
        } else {
            self.status = format!("Launching {}...", game.name);
        }

        self.runtime.spawn(async move {
            let launcher_config = load_launcher_config().await.unwrap_or_default();
            let chosen_proton_path = match launch_info.target {
                crate::steam_client::LaunchTarget::NativeLinux => None,
                crate::steam_client::LaunchTarget::WindowsProton => {
                    proton_path.as_deref().or(Some(launcher_config.proton_version.as_str()))
                }
            };

            let cloud_enabled = launcher_config.enable_cloud_sync && !client.is_offline();
            let mut cloud_client = None;
            let mut local_root = None;

            if cloud_enabled {
                let c = crate::cloud_sync::CloudClient::new(
                    client.connection()
                        .cloned()
                        .ok_or_else(|| anyhow!("steam connection not initialized"))
                        .unwrap()
                );
                let root = crate::cloud_sync::default_cloud_root(c.steam_id(), game.app_id).unwrap();
                tracing::info!(appid = game.app_id, path = %root.display(), "Syncing Cloud...");
                let _ = c.sync_down(game.app_id, &root).await;
                cloud_client = Some(c);
                local_root = Some(root);
            }

            let mut child: std::process::Child =
                match client.spawn_game_process(&game, &launch_info, chosen_proton_path, &launcher_config, user_config.as_ref()).await {
                    Ok(child) => child,
                    Err(e) => {
                        // Phase 4 Task 3: a missing Windows Steam session is a
                        // distinguishable error — signal auto-onboarding instead
                        // of a plain launch failure.
                        if let Some(login) = e.downcast_ref::<crate::launch::pipeline::LoginRequiredError>() {
                            let _ = tx.send(format!("__LOGIN_REQUIRED__{}", login.prefix));
                            return;
                        }
                        let _ = tx.send(format!("Launch failed for {}: {e}", game.name));
                        return;
                    }
                };

            let _ = tx.send(format!("__RUNNING__{}:{}", game.app_id, child.id()));
            let _ = child.wait();

            if cloud_enabled {
                if let (Some(c), Some(root)) = (cloud_client.as_ref(), local_root.as_ref()) {
                    let _ = c.sync_up(game.app_id, root).await;
                    tracing::info!(appid = game.app_id, "Upload Complete");
                }
            }

            let _ = tx.send(format!("__IDLE__{}", game.app_id));
        });
    }

    fn open_properties_modal(&mut self, game: &LibraryGame) {
        let client = self.client.clone();
        let tx = self.operation_tx.clone();
        let app_id = game.app_id;
        self.runtime.spawn(async move {
            match client.fetch_branches(app_id).await {
                Ok(branches) => {
                    let _ = tx.send(AsyncOp::BranchesFetched(app_id, branches));
                }
                Err(err) => {
                    let _ = tx.send(AsyncOp::Error(format!("Failed to fetch branches: {err}")));
                }
            }
        });
    }


    fn open_uninstall_modal(&mut self, game: &LibraryGame) {
        self.uninstall_modal = Some(UninstallModalState {
            app_id: game.app_id,
            game_name: game.name.clone(),
            delete_prefix: false,
        });
    }

    fn open_depot_browser(&mut self, game: &LibraryGame) {
        let client = self.client.clone();
        let tx = self.operation_tx.clone();
        let app_id = game.app_id;
        self.runtime.spawn(async move {
            match client.fetch_depots(app_id).await {
                Ok(depots) => {
                    let _ = tx.send(AsyncOp::DepotsFetched(app_id, depots));
                }
                Err(err) => {
                    let _ = tx.send(AsyncOp::Error(format!("Failed to load depots: {err}")));
                }
            }
        });
    }

    fn draw_launch_selector_modal(&mut self, ctx: &egui::Context) {
        let mut selection = None;
        let mut close = false;

        if let Some(state) = &mut self.launch_selector {
            egui::Window::new("Launch Configuration")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!("Select version of {} to launch:", state.game_name));
                    ui.add_space(8.0);

                    for option in &state.options {
                        ui.radio_value(&mut state.selected_id, option.id.clone(), &option.description);
                    }

                    ui.add_space(8.0);
                    ui.checkbox(&mut state.always_use, "Always use this option");

                    ui.horizontal(|ui| {
                        if ui.button("Play").clicked() {
                            if let Some(opt) = state.options.iter().find(|o| o.id == state.selected_id) {
                                selection = Some((state.app_id, opt.clone(), state.always_use));
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                });
        }

        if let Some((app_id, option, always_use)) = selection {
            if always_use {
                self.launcher_config.preferred_launch_options.insert(app_id, option.id.clone());
                let config = self.launcher_config.clone();
                self.runtime.spawn(async move {
                    let _ = config.save().await;
                });
            }
            let game = self.library.iter().find(|g| g.app_id == app_id).cloned();
            if let Some(game) = game {
                self.start_launch_task(&game, option, None);
            }
            self.launch_selector = None;
        } else if close {
            self.launch_selector = None;
        }
    }

    fn draw_platform_selection_modal(&mut self, ctx: &egui::Context) {
        let mut selection = None;
        let mut close = false;

        if let Some(state) = &self.platform_selection {
            egui::Window::new("Select Version to Install")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!("Select version of {} to install:", state.game_name));
                    ui.add_space(8.0);

                    for platform in &state.available {
                        let label = match platform {
                            DepotPlatform::Windows => "Windows (Proton)",
                            DepotPlatform::Linux => "Linux (Native)",
                        };
                        if ui.button(label).clicked() {
                            selection = Some((state.app_id, *platform, state.cached_vdf.clone()));
                        }
                    }

                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
        }

        if let Some((app_id, platform, cached_vdf)) = selection {
            let mut config = self
                .launcher_config
                .game_configs
                .get(&app_id)
                .cloned()
                .unwrap_or_default();
            config.platform_preference = Some(match platform {
                DepotPlatform::Windows => "windows".to_string(),
                DepotPlatform::Linux => "linux".to_string(),
            });
            self.launcher_config.game_configs.insert(app_id, config);
            let config_to_save = self.launcher_config.clone();
            self.runtime.spawn(async move {
                let _ = config_to_save.save().await;
            });

            self.extended_info.remove(&app_id);
            self.begin_depot_selection(app_id, platform, cached_vdf);
            self.platform_selection = None;
        } else if close {
            self.platform_selection = None;
        }
    }

    fn draw_depot_install_selection_modal(&mut self, ctx: &egui::Context) {
            let mut proceed = None;
            let mut close = false;
            if let Some(state) = &self.depot_install_selection {
                egui::Window::new("Select Depots to Install")
                    .collapsible(false)
                    .resizable(true)
                    .show(ctx, |ui| {
                        ui.label(format!("Select depots for {}:", state.game_name));
                        ui.small("Locked depots are not owned or have no available decryption key.");
                        ui.add_space(8.0);
                        egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                            for depot in &state.depots {
                                let accessible = depot.is_owned == Some(true);
                                let mut selected = self.depot_selection.contains(&depot.id);
                                ui.horizontal(|ui| {
                                    if ui
                                        .add_enabled(accessible, egui::Checkbox::new(&mut selected, ""))
                                        .changed()
                                    {
                                        if selected {
                                            self.depot_selection.insert(depot.id);
                                        } else {
                                            self.depot_selection.remove(&depot.id);
                                        }
                                    }
                                    ui.label(format!("Depot {} — {}", depot.id, depot.name));
                                    if !accessible {
                                        ui.colored_label(egui::Color32::RED, "Unavailable");
                                    } else if !depot.config.is_empty() {
                                        ui.small(&depot.config);
                                    }
                                });
                            }
                        });
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(
                                    !self.depot_selection.is_empty(),
                                    egui::Button::new("Proceed to Install"),
                                )
                                .clicked()
                            {
                                proceed = Some((
                                    state.app_id,
                                    state.platform,
                                    state.cached_vdf.clone(),
                                    self.depot_selection.iter().copied().collect::<Vec<_>>(),
                                ));
                            }
                            if ui.button("Cancel").clicked() {
                                close = true;
                            }
                        });
                    });
            }
            if let Some((app_id, platform, cached_vdf, depots)) = proceed {
                self.start_install(app_id, platform, Some(cached_vdf), Some(depots));
                self.depot_install_selection = None;
            } else if close {
                self.depot_install_selection = None;
            }
        }

    fn draw_properties_tab(&mut self, game: &LibraryGame, ui: &mut egui::Ui) {
        let mut config = self.user_configs.get(&game.app_id).cloned().unwrap_or_default();
        let mut changed = false;

        ui.vertical(|ui| {
            // Maintenance + live operation controls on top so Verify/Repair is
            // reachable from the game's Properties and the Pause/Cancel buttons
            // are visible during any download/verify/repair operation.
            ui.heading("Maintenance");
            ui.horizontal(|ui| {
                if ui.button("Verify Integrity").clicked() {
                    let app_id = game.app_id;
                    let client = self.client.clone();
                    let tx = self.operation_tx.clone();
                    // Per-task DownloadState (own abort signal + controller).
                    let download_state = Arc::new(RwLock::new(DownloadState::default()));
                    self.runtime.spawn(async move {
                        match client.verify_game(app_id, download_state.clone()).await {
                            Ok(rx) => {
                                let _ = tx.send(AsyncOp::DownloadStarted(app_id, rx, download_state));
                            }
                            Err(err) => {
                                let _ = tx.send(AsyncOp::Error(format!(
                                    "Failed to verify {app_id}: {err}"
                                )));
                            }
                        }
                    });
                }

                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("Uninstall").color(egui::Color32::WHITE),
                        )
                        .fill(egui::Color32::from_rgb(200, 45, 45)),
                    )
                    .clicked()
                {
                    self.open_uninstall_modal(game);
                }
            });

            // Live operation progress bar + Pause/Cancel — shown whenever a
            // download/verify is active for THIS game, independent of where the
            // operation was triggered from. Each task is bound to its own AppID
            // and game title (no cross-talk between concurrent operations).
            let mut cancel_this_task = false;
            if let Some(task) = self.download_tasks.get(&game.app_id) {
                let progress_opt = task.progress.clone();
                let game_name = task.game_name.clone();
                let samples = task.samples.clone();
                if let Some(progress) = progress_opt {
                    let action_word = if progress.state == DownloadProgressState::Verifying {
                        "Verifying"
                    } else {
                        "Downloading"
                    };
                    // FILE-LEVEL progress: the active file's relative path and
                    // its own byte offsets (wired through ManifestFile::download
                    // -> on_file_progress). Falls back to the depot aggregate
                    // until the first file-level message arrives.
                    let (label, denom, cur, _tot) = if progress.file_total_bytes > 0 {
                        let file_pct = progress.file_bytes_downloaded as f64 * 100.0
                            / progress.file_total_bytes as f64;
                        (
                            format!(
                                "{action_word} {}: {} / {} ({:.0}%)",
                                progress.current_file,
                                Self::format_bytes(progress.file_bytes_downloaded),
                                Self::format_bytes(progress.file_total_bytes),
                                file_pct
                            ),
                            progress.file_total_bytes as f32,
                            progress.file_bytes_downloaded,
                            progress.file_total_bytes,
                        )
                    } else {
                        let denom = if progress.total_bytes == 0 {
                            1.0
                        } else {
                            progress.total_bytes as f32
                        };
                        let pct = if progress.total_bytes == 0 {
                            0.0
                        } else {
                            (progress.bytes_downloaded as f64 * 100.0
                                / progress.total_bytes as f64)
                                .clamp(0.0, 100.0)
                        };
                        (
                            format!(
                                "{action_word} {}: {} / {} ({:.0}%)",
                                progress.current_file,
                                Self::format_bytes(progress.bytes_downloaded),
                                Self::format_bytes(progress.total_bytes),
                                pct
                            ),
                            denom,
                            progress.bytes_downloaded,
                            progress.total_bytes,
                        )
                    };
                    let fraction = (cur as f32 / denom).clamp(0.0, 1.0);

                    // ETA for the active file (falling back to the depot
                    // aggregate until file-level info arrives).
                    let eta_suffix = if progress.file_total_bytes > 0 {
                        Self::eta_seconds(
                            &samples,
                            progress
                                .file_total_bytes
                                .saturating_sub(progress.file_bytes_downloaded),
                        )
                    } else {
                        Self::eta_seconds(
                            &samples,
                            progress.total_bytes.saturating_sub(progress.bytes_downloaded),
                        )
                    }
                    .map(Self::format_eta)
                    .map(|e| format!(" · {e}"))
                    .unwrap_or_default();
                    let label = format!("{label}{eta_suffix}");

                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::ProgressBar::new(fraction)
                                .show_percentage()
                                .text(label),
                        );
                    });
                }

                let (is_downloading, is_paused, controller) = {
                    let state = task.state.read().unwrap();
                    (state.is_downloading, state.is_paused, state.operation_controller.clone())
                };
                if is_downloading || is_paused {
                    ui.horizontal(|ui| {
                        if ui.button(if is_paused { "▶ Resume" } else { "⏸ Pause" }).clicked() {
                            if let Ok(mut state) = task.state.write() {
                                state.is_paused = !is_paused;
                                if is_paused {
                                    state.operation_controller.resume();
                                } else {
                                    state.operation_controller.pause();
                                }
                            }
                        }
                        if ui.button("✖ Cancel").clicked() {
                            controller.cancel();
                            if let Ok(mut state) = task.state.write() {
                                state.is_downloading = false;
                                state.is_paused = false;
                                state.abort_signal.store(true, std::sync::atomic::Ordering::Release);
                            }
                            self.status = format!("Operation cancelled for {game_name}");
                            cancel_this_task = true;
                        }
                    });
                }
                ui.add_space(8.0);
            }
            if cancel_this_task {
                self.download_tasks.remove(&game.app_id);
            }

            ui.add_space(4.0);
            ui.heading("Launch Options");
            if ui.add(egui::TextEdit::singleline(&mut config.launch_options).desired_width(f32::INFINITY)).changed() {
                changed = true;
            }

            ui.add_space(8.0);
            ui.heading("Environment Variables");
            ui.label("KEY=VALUE (one per line)");

            if ui.add(egui::TextEdit::multiline(&mut self.env_vars_edit_buffer)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace))
                .changed()
            {
                let mut new_env = HashMap::new();
                for line in self.env_vars_edit_buffer.lines() {
                    if let Some((k, v)) = line.split_once('=') {
                        new_env.insert(k.trim().to_string(), v.trim().to_string());
                    }
                }
                config.env_variables = new_env;
                changed = true;
            }

            ui.add_space(8.0);
            ui.heading("Runtime Settings");
            ui.horizontal(|ui| {
                ui.label("Launch Mode:");
                egui::ComboBox::from_id_salt("launch_mode_selector")
                    .selected_text(format!("{:?}", config.launch_mode))
                    .show_ui(ui, |ui| {
                        use crate::models::LaunchMode;
                        for (mode, label) in [
                            (LaunchMode::DirectWine, "Direct Wine"),
                            (LaunchMode::SteamAppLaunch, "Steam App Launch"),
                            (LaunchMode::SteamProtocol, "Steam Protocol"),
                        ] {
                            if ui.selectable_value(&mut config.launch_mode, mode, label).clicked() {
                                changed = true;
                            }
                        }
                    });
            });
            ui.horizontal(|ui| {
                ui.label("Use Windows Steam Runtime:");
                egui::ComboBox::from_id_salt("steam_runtime_policy_selector")
                    .selected_text(format!("{:?}", config.steam_runtime_policy))
                    .show_ui(ui, |ui| {
                        use crate::models::SteamRuntimePolicy;
                        if ui.selectable_value(&mut config.steam_runtime_policy, SteamRuntimePolicy::Auto, "Auto (Recommended)").clicked() {
                            changed = true;
                        }
                        if ui.selectable_value(&mut config.steam_runtime_policy, SteamRuntimePolicy::Enabled, "Enabled").clicked() {
                            changed = true;
                        }
                        if ui.selectable_value(&mut config.steam_runtime_policy, SteamRuntimePolicy::Disabled, "Disabled").clicked() {
                            changed = true;
                        }
                    });
            }).response.on_hover_text("Required for DRM-protected games. Runs an official Steam client in the background.");

            ui.horizontal(|ui| {
                ui.label("Steam Client Mode:");
                let selected = match config.steam_mode {
                    crate::models::SteamMode::Auto => "Auto (Default)",
                    crate::models::SteamMode::OfflineEmulated => "Offline Emulated (Clientless)",
                    crate::models::SteamMode::OnlineContainerized => "Online Containerized (SteamRT4)",
                };
                egui::ComboBox::from_id_salt("steam_mode_selector")
                    .selected_text(selected)
                    .show_ui(ui, |ui| {
                        use crate::models::SteamMode;
                        if ui.selectable_value(&mut config.steam_mode, SteamMode::Auto, "Auto (Default)").clicked() {
                            changed = true;
                        }
                        if ui.selectable_value(&mut config.steam_mode, SteamMode::OfflineEmulated, "Offline Emulated (Clientless)").clicked() {
                            changed = true;
                        }
                        if ui.selectable_value(&mut config.steam_mode, SteamMode::OnlineContainerized, "Online Containerized (SteamRT4)").clicked() {
                            changed = true;
                        }
                    });
            })
            .response
            .on_hover_text("How the game talks to Steam. Auto uses the Windows Steam client when a host session is active and falls back to the offline emulator; Offline Emulated launches fully clientless via a local steam_api emulator; Online Containerized is reserved for the SteamRT4 pressure-vessel launch (Phase 4.2/4.3). Persisted to user_apps.json.");

            // Phase 4.4: active Steam Linux Runtime status + inline repair,
            // shown next to the Steam Client Mode selector.
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let library_root =
                    std::path::PathBuf::from(&self.launcher_config.steam_library_path);
                let mgr = crate::container::runtime::RuntimeManager::default();
                let active = mgr.resolve_runtime_root(&library_root);

                if let Some(root) = &active {
                    let revision = crate::container::runtime::read_versions_txt(root)
                        .into_iter()
                        .map(|v| v.version)
                        .max();
                    let label = match revision {
                        Some(r) => {
                            format!("Runtime: Steam Linux Runtime 4.0 (steamrt4) [Valid · {r}]")
                        }
                        None => "Runtime: Steam Linux Runtime 4.0 (steamrt4) [Valid]".to_string(),
                    };
                    ui.colored_label(egui::Color32::from_rgb(120, 220, 130), &label);
                } else {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 140, 120),
                        "Runtime: Steam Linux Runtime 4.0 (steamrt4) [Missing / Corrupt]",
                    );
                    if ui
                        .small_button("Repair Runtime")
                        .on_hover_text("Re-download + re-provision the Steam Linux Runtime 4.0 (app 4183110) from the Steam CDN.")
                        .clicked()
                    {
                        let client = self.client.clone();
                        let launcher_config = self.launcher_config.clone();
                        let tx = self.operation_tx.clone();
                        self.status = "Repairing Steam Linux Runtime…".to_string();
                        self.runtime.spawn(async move {
                            match crate::headless::repair_runtime(
                                &client,
                                &launcher_config,
                                crate::container::runtime::SteamRuntimeId::Steamrt4,
                            )
                            .await
                            {
                                Ok(msg) => {
                                    let _ = tx.send(AsyncOp::RuntimeRepaired(msg));
                                }
                                Err(e) => {
                                    let _ = tx.send(AsyncOp::Error(format!(
                                        "Steam Linux Runtime repair failed: {e:#}"
                                    )));
                                }
                            }
                        });
                    }
                }
            });

            let effective_runtime = match config.steam_runtime_policy {
                crate::models::SteamRuntimePolicy::Enabled => true,
                crate::models::SteamRuntimePolicy::Disabled => false,
                crate::models::SteamRuntimePolicy::Auto => config.use_steam_runtime,
            };

            if effective_runtime {
                ui.add_space(4.0);
                ui.label("Steam Prefix Mode:");
                if ui.radio_value(
                    &mut config.steam_prefix_mode,
                    crate::models::SteamPrefixMode::Shared,
                    "Shared — game uses master prefix directly (faster)",
                ).on_hover_text("All games share one WINEPREFIX. Steam is always visible to the game.").changed() {
                    changed = true;
                }
                if ui.radio_value(
                    &mut config.steam_prefix_mode,
                    crate::models::SteamPrefixMode::PerGame,
                    "Per-game — Steam copied/symlinked into game's own prefix (isolated)",
                ).on_hover_text("Each game gets its own WINEPREFIX with Steam symlinked in. Safer, uses more disk.").changed() {
                    changed = true;
                }
            }

            ui.add_space(8.0);
            ui.heading("Beta Branches");
            if let Some(branches) = self.available_branches.get(&game.app_id) {
                let mut active_branch = game.active_branch.clone();
                egui::ComboBox::from_id_salt("branch_selector_tab")
                    .selected_text(&active_branch)
                    .show_ui(ui, |ui| {
                        for branch in branches {
                            if ui.selectable_value(&mut active_branch, branch.clone(), branch).clicked() {
                                let app_id = game.app_id;
                                let branch = branch.clone();
                                let client = self.client.clone();
                                let tx = self.operation_tx.clone();
                                self.runtime.spawn(async move {
                                    match client.update_app_branch(app_id, &branch).await {
                                        Ok(()) => {
                                            let _ = tx.send(AsyncOp::BranchUpdated(app_id, branch));
                                        }
                                        Err(err) => {
                                            let _ = tx.send(AsyncOp::Error(format!("Failed to switch branch: {err}")));
                                        }
                                    }
                                });
                            }
                        }
                    });
            } else {
                if ui.button("Check for Beta Branches").clicked() {
                    let app_id = game.app_id;
                    let client = self.client.clone();
                    let tx = self.operation_tx.clone();
                    self.runtime.spawn(async move {
                        match client.fetch_branches(app_id).await {
                            Ok(branches) => {
                                let _ = tx.send(AsyncOp::BranchesFetched(app_id, branches));
                            }
                            Err(err) => {
                                let _ = tx.send(AsyncOp::Error(format!("Failed to fetch branches: {err}")));
                            }
                        }
                    });
                }
            }
        });

        // Per-game: Requires Steam API — informational status badge (not a
        // user toggle). Green checkmark when the game needs Steam API
        // (steam_api64.dll present in the install dir, or the per-game flag is
        // set); gray indicator when not required. The underlying flag still
        // feeds the launch pipeline's Steamworks readiness gate.
        ui.add_space(8.0);
        ui.separator();
        ui.label("Game Requirements");
        let steam_api_on_disk = game
            .install_path
            .as_ref()
            .map(|p| {
                let dir = std::path::Path::new(p);
                dir.join("steam_api64.dll").exists() || dir.join("steam_api.dll").exists()
            })
            .unwrap_or(false);
        let requires_steam = config.requires_steam_api || steam_api_on_disk;
        ui.horizontal(|ui| {
            egui::Frame::NONE
                .fill(if requires_steam {
                    egui::Color32::from_rgb(24, 62, 36)
                } else {
                    egui::Color32::from_gray(46)
                })
                .corner_radius(4.0)
                .inner_margin(egui::Margin::symmetric(8, 3))
                .show(ui, |ui| {
                    ui.colored_label(
                        if requires_steam {
                            egui::Color32::from_rgb(120, 220, 130)
                        } else {
                            egui::Color32::from_gray(150)
                        },
                        if requires_steam {
                            "✔ Requires Steam API"
                        } else {
                            "○ No Steam API"
                        },
                    );
                });
            ui.label(
                egui::RichText::new(if requires_steam {
                    "This game uses Steamworks (steam_api64.dll) — use Steam App Launch or Steam Protocol."
                } else {
                    "No Steam API dependency detected in the install folder."
                })
                .weak(),
            );
        });
        // NOTE: "Suppress overlay for DX12 games" was removed — the in-game
        // overlay is controlled by the CEF browser (steamwebhelper) toggle, and
        // DX12 overlay suppression is already auto-applied when VKD3D is active.
        // NOTE: "Compatibility Layer Override" was removed from this tab — the
        // per-game runner override lives in Options -> "Force specific
        // Proton/Wine version".

        if changed {
            // Phase 5: `OnlineContainerized` runs the game through
            // `<proton>/proton run` inside the Steam Linux Runtime — a bare
            // Wine runner cannot satisfy that. Reject the update at save time
            // with a clear message instead of failing at launch.
            if let Err(msg) = crate::config::validate_online_containerized_runner(
                config.steam_mode,
                self.launcher_config
                    .game_configs
                    .get(&game.app_id)
                    .and_then(|c| c.forced_proton_version.as_deref()),
                &self.launcher_config.proton_version,
                std::path::Path::new(&self.launcher_config.steam_library_path),
            ) {
                self.status = format!("Configuration rejected: {msg}");
            } else {
                self.user_configs.insert(game.app_id, config);
                let store = self.user_configs.clone();
                self.runtime.spawn(async move {
                    let _ = crate::config::save_user_configs(&store).await;
                });
            }
        }
    }

    /// Mods tab: launch a custom mod wrapper/executable/script through the
    /// game's runner environment. Path is persisted per-game in user_apps.json
    /// (`custom_exec_path`); the native file picker defaults to the game's
    /// install directory.
    fn draw_mods_tab(&mut self, game: &LibraryGame, ui: &mut egui::Ui) {
        let mut config = self.user_configs.get(&game.app_id).cloned().unwrap_or_default();
        let mut changed = false;

        ui.vertical(|ui| {
            ui.heading("Mod Launcher");
            ui.label(
                egui::RichText::new(
                    "Run a custom wrapper, executable, or launch script (e.g. ./start_mod.sh, custom_launcher.exe) \
                     through this game's runner environment.",
                )
                .weak(),
            );

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let mut path = config.custom_exec_path.clone().unwrap_or_default();
                let path_edit = ui.add(
                    egui::TextEdit::singleline(&mut path)
                        .hint_text("Path to custom mod executable/script…")
                        .desired_width(f32::INFINITY),
                );
                if path_edit.changed() {
                    config.custom_exec_path =
                        if path.trim().is_empty() { None } else { Some(path.trim().to_string()) };
                    changed = true;
                }

                if ui.button("Browse…").clicked() {
                    let initial_dir = game
                        .install_path
                        .as_ref()
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|| {
                            std::path::PathBuf::from(&self.launcher_config.steam_library_path)
                        });
                    let app_id = game.app_id;
                    let tx = self.operation_tx.clone();
                    self.runtime.spawn(async move {
                        let picked = crate::utils::open_file_dialog(&initial_dir);
                        let _ = tx.send(AsyncOp::CustomExecPicked(app_id, picked));
                    });
                }
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let has_exec = config
                    .custom_exec_path
                    .as_ref()
                    .map(|p| !p.trim().is_empty())
                    .unwrap_or(false);
                let launch_btn = egui::Button::new(
                    egui::RichText::new("▶ Play Mod").color(egui::Color32::WHITE).strong(),
                )
                .fill(egui::Color32::from_rgb(46, 125, 50))
                .min_size(egui::vec2(120.0, 36.0));
                if ui.add_enabled(has_exec, launch_btn).clicked() {
                    let config_for_launch = self.launcher_config.clone();
                    let user_config = config.clone();
                    let app_id = game.app_id;
                    let game_name = game.name.clone();
                    let exec_path = user_config
                        .custom_exec_path
                        .clone()
                        .unwrap_or_default();
                    let tx = self.operation_tx.clone();
                    self.runtime.spawn(async move {
                        match crate::launch::launch_custom_exec(
                            &config_for_launch,
                            &user_config,
                            app_id,
                            &game_name,
                            std::path::Path::new(&exec_path),
                        ) {
                            Ok(_child) => {
                                let _ = tx.send(AsyncOp::ModLauncherLaunched);
                            }
                            Err(e) => {
                                let _ = tx.send(AsyncOp::Error(format!("Mod launch failed: {e}")));
                            }
                        }
                    });
                }
                ui.label(
                    egui::RichText::new(match config.custom_exec_path.as_deref() {
                        Some(p) if !p.trim().is_empty() => {
                            format!("Will run: {p} (via the game's runner environment)")
                        }
                        _ => "Select a custom executable first.".to_string(),
                    })
                    .weak(),
                );
            });

            if changed {
                self.user_configs.insert(game.app_id, config);
                let store = self.user_configs.clone();
                self.runtime.spawn(async move {
                    let _ = crate::config::save_user_configs(&store).await;
                });
            }
        });
    }

    fn draw_options_tab(&mut self, game: &LibraryGame, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.heading("Compatibility Layer");
            let mut config = self
                .launcher_config
                .game_configs
                .get(&game.app_id)
                .cloned()
                .unwrap_or_default();
            let mut force_proton = config.forced_proton_version.is_some();
            if ui
                .checkbox(&mut force_proton, "Force specific Proton/Wine version")
                .changed()
            {
                if force_proton {
                    config.forced_proton_version = Some(self.launcher_config.proton_version.clone());
                } else {
                    config.forced_proton_version = None;
                }
            }

            if let Some(ref mut version) = config.forced_proton_version {
                let selected_list = if self.proton_source == ProtonSource::Steam {
                    &self.steam_protons
                } else {
                    &self.custom_protons
                };

                egui::ComboBox::from_id_salt("forced_proton_selector")
                    .selected_text(version.clone())
                    .show_ui(ui, |ui| {
                        for entry in selected_list {
                            ui.selectable_value(version, entry.clone(), entry);
                        }
                    });
            }

            if self.launcher_config.game_configs.get(&game.app_id) != Some(&config) {
                self.launcher_config.game_configs.insert(game.app_id, config);
                let config_to_save = self.launcher_config.clone();
                self.runtime.spawn(async move {
                    let _ = config_to_save.save().await;
                });
            }

            if !self.available_gpus.is_empty() {
                ui.add_space(16.0);
                ui.heading("Graphics Device");
                let mut user_cfg = self.user_configs.get(&game.app_id).cloned().unwrap_or_default();
                let mut gpu_changed = false;

                let selected_text = user_cfg.gpu_preference.clone().unwrap_or_else(|| {
                    if self.available_gpus.len() > 1 {
                        "Auto (System Default)".to_string()
                    } else {
                        self.available_gpus[0].name.clone()
                    }
                });

                egui::ComboBox::from_id_salt("gpu_selector")
                    .selected_text(selected_text)
                    .show_ui(ui, |ui| {
                        if self.available_gpus.len() > 1 {
                            if ui.selectable_value(&mut user_cfg.gpu_preference, None, "Auto (System Default)").clicked() {
                                gpu_changed = true;
                            }
                        }
                        for gpu in &self.available_gpus {
                            let label = &gpu.name;
                            if ui.selectable_value(&mut user_cfg.gpu_preference, Some(gpu.name.clone()), label).clicked() {
                                gpu_changed = true;
                            }
                        }
                    });

                if gpu_changed {
                    self.user_configs.insert(game.app_id, user_cfg);
                    let store = self.user_configs.clone();
                    self.runtime.spawn(async move {
                        let _ = crate::config::save_user_configs(&store).await;
                    });
                }
            }

            ui.add_space(16.0);

            // In Steam-mediated launch modes the game is launched through steam.exe
            // itself, so SteamFlow must not inject client feature flags (steamwebhelper
            // suppression, etc.) — Steam manages its own browser/session. Hide the
            // section entirely in that case. Per-game launch mode wins, falling back
            // to the global default (mirrors the launch pipeline's precedence).
            let game_app_id = game.app_id;
            let mut user_cfg = self
                .user_configs
                .get(&game_app_id)
                .cloned()
                .unwrap_or_default();
            let mut steam_cfg_changed = false;
            let effective_launch_mode = if self.user_configs.contains_key(&game_app_id) {
                user_cfg.launch_mode
            } else {
                self.launcher_config.launch_mode
            };
            if !matches!(effective_launch_mode, crate::models::LaunchMode::DirectWine) {
                ui.heading("Steam Features");
                ui.label(
                    egui::RichText::new(
                        "Steam-mediated launch (via the installed Windows Steam client) — Steam owns its own browser, friends, and overlay. Client feature flags are managed inside Steam.",
                    ).weak().small(),
                );
            } else {
                let slc = &mut user_cfg.steam_launch_config;

                ui.heading("Steam Features");
                ui.label("CEF browser (steamwebhelper) powers Friends, Chat, and In-Game Overlay.");
                ui.add_space(4.0);

                let mut cef_enabled = !slc.no_browser;
                if ui
                    .checkbox(&mut cef_enabled, "CEF browser (steamwebhelper)")
                    .on_hover_text("Unchecking it disables Friends, Chat, and In-Game Overlay.")
                    .changed()
                {
                    slc.no_browser = !cef_enabled;
                    steam_cfg_changed = true;
                }

                if !cef_enabled {
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        "Unchecking it disables Friends, Chat, and In-Game Overlay.",
                    );
                }
            }

            ui.add_space(8.0);
            ui.heading("Steam Process");

            if ui.button("⏹  Stop Steam in this prefix").clicked() {
                let prefix = crate::utils::steam_wineprefix_for_game(
                    &self.launcher_config,
                    game_app_id,
                    &self.user_configs,
                    None, // UI ops use the configured mode (display/management)
                );
                SteamClient::kill_steam_in_prefix(&prefix, true);
                self.status = "Steam stopped".to_string();
            }

            if ui.button("☠  Kill all Wine processes in prefix")
                .on_hover_text("Emergency stop: kills all Wine, wineserver, Steam, and game processes running in this prefix. Use if a game crash leaves processes stuck.")
                .clicked() {
                let prefix = crate::utils::steam_wineprefix_for_game(
                    &self.launcher_config,
                    game_app_id,
                    &self.user_configs,
                    None, // UI ops use the configured mode (display/management)
                );
                crate::utils::kill_all_wine_in_prefix(&prefix, false);
                self.status = "All Wine processes in prefix terminated".to_string();
            }

            ui.add_space(8.0);
            ui.separator();
            ui.heading("Graphics Rendering");
            ui.label(
                egui::RichText::new(
                    "Configure how graphics APIs are translated to Vulkan or OpenGL.",
                )
                .weak()
                .italics(),
            );
            ui.add_space(4.0);

            let mut user_cfg_gl = self.user_configs.get(&game.app_id).cloned().unwrap_or_default();
            let glc = &mut user_cfg_gl.graphics_layers;
            let mut gl_changed = false;

            ui.horizontal(|ui| {
                ui.label("Graphics Backend Policy (DX8-11):");
                egui::ComboBox::from_id_salt("graphics_backend_policy_selector")
                    .selected_text(format!("{:?}", glc.graphics_backend_policy))
                    .show_ui(ui, |ui| {
                        use crate::models::GraphicsBackendPolicy;
                        if ui.selectable_value(&mut glc.graphics_backend_policy, GraphicsBackendPolicy::Auto, "Auto (Recommended)").clicked() {
                            gl_changed = true;
                        }
                        if ui.selectable_value(&mut glc.graphics_backend_policy, GraphicsBackendPolicy::WineD3D, "WineD3D (OpenGL)").clicked() {
                            gl_changed = true;
                        }
                        if ui.selectable_value(&mut glc.graphics_backend_policy, GraphicsBackendPolicy::DXVK, "DXVK (Vulkan)").clicked() {
                            gl_changed = true;
                        }
                    });
            });

            {
                ui.horizontal(|ui| {
                    ui.label("Graphics Backend Policy (DX3-7):");
                    egui::ComboBox::from_id_salt("d3d7_backend_policy_selector")
                        .selected_text(format!("{:?}", glc.d3d7_policy))
                        .show_ui(ui, |ui| {
                            use crate::models::D3D7BackendPolicy;
                            if ui.selectable_value(&mut glc.d3d7_policy, D3D7BackendPolicy::Auto, "Auto (Recommended)").clicked() {
                                gl_changed = true;
                            }
                            if ui.selectable_value(&mut glc.d3d7_policy, D3D7BackendPolicy::WineD3D, "WineD3D (OpenGL)").clicked() {
                                gl_changed = true;
                            }
                            if ui.selectable_value(&mut glc.d3d7_policy, D3D7BackendPolicy::D7VK, "D7VK (Vulkan)").clicked() {
                                gl_changed = true;
                            }
                        });
                });
            }

            {
                ui.horizontal(|ui| {
                    ui.label("D3D12 Provider Policy (DX12):");
                    egui::ComboBox::from_id_salt("d3d12_provider_policy_selector")
                        .selected_text(format!("{:?}", glc.d3d12_policy))
                        .show_ui(ui, |ui| {
                            use crate::models::D3D12ProviderPolicy;
                            if ui.selectable_value(&mut glc.d3d12_policy, D3D12ProviderPolicy::Auto, "Auto (Prefer Proton)").clicked() {
                                gl_changed = true;
                            }
                            if ui.selectable_value(&mut glc.d3d12_policy, D3D12ProviderPolicy::Vkd3dProton, "VKD3D-Proton").clicked() {
                                gl_changed = true;
                            }
                            if ui.selectable_value(&mut glc.d3d12_policy, D3D12ProviderPolicy::Vkd3dWine, "VKD3D (Wine)").clicked() {
                                gl_changed = true;
                            }
                        });
                });
            }

            ui.add_space(8.0);
            ui.heading("Deployment Mode");
            if ui.checkbox(&mut glc.use_symlinks_in_prefix, "Use symlinks instead of WINEDLLPATH")
                .on_hover_text("Deploys translation DLLs directly into the Wine prefix system directories. \
                                Recommended for games that ignore environment-based DLL injection.")
                .changed() {
                gl_changed = true;
            }

            ui.add_space(8.0);
            ui.heading("Custom Components");
            ui.label(egui::RichText::new("Point to a directory containing x86_64-windows and i386-windows subfolders.").small());

            ui.horizontal(|ui| {
                ui.label("Custom DXVK Path:");
                let mut path_str = glc.custom_dxvk_path.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                if ui.text_edit_singleline(&mut path_str).changed() {
                    glc.custom_dxvk_path = if path_str.is_empty() { None } else { Some(PathBuf::from(path_str)) };
                    gl_changed = true;
                }
            });

            ui.horizontal(|ui| {
                ui.label("Custom VKD3D Path:");
                let mut path_str = glc.custom_vkd3d_path.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                if ui.text_edit_singleline(&mut path_str).changed() {
                    glc.custom_vkd3d_path = if path_str.is_empty() { None } else { Some(PathBuf::from(path_str)) };
                    gl_changed = true;
                }
            });

            ui.horizontal(|ui| {
                ui.label("Custom VKD3D-Proton Path:");
                let mut path_str = glc.custom_vkd3d_proton_path.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                if ui.text_edit_singleline(&mut path_str).changed() {
                    glc.custom_vkd3d_proton_path = if path_str.is_empty() { None } else { Some(PathBuf::from(path_str)) };
                    gl_changed = true;
                }
            });

            ui.add_space(8.0);

            ui.horizontal(|ui| {
                if ui.checkbox(&mut glc.nvapi_enabled, "Enable NVAPI").on_hover_text("Expose NVIDIA API to the game (requires runner support).").changed() {
                    gl_changed = true;
                }
            });

            if let Some(components) = &self.runner_components {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.label(egui::RichText::new("Detected Graphics Components").strong());
                    ui.add_space(4.0);
                    egui::Grid::new("game_runner_components_grid")
                        .num_columns(3)
                        .spacing([16.0, 4.0])
                        .show(ui, |ui| {
                            let mut row =
                                |label: &str, info: &Option<crate::utils::ComponentInfo>| {
                                    ui.label(label);
                                    match info {
                                        Some(c) => {
                                            ui.colored_label(egui::Color32::GREEN, &c.version);
                                            let source_text = if c.source == crate::utils::ComponentSource::BundledWithRunner {
                                                "bundled".to_string()
                                            } else {
                                                format!("{}", c.source)
                                            };
                                            let label = ui.colored_label(
                                                egui::Color32::GRAY,
                                                format!("({})", source_text),
                                            );
                                            if let Some(path) = &c.path {
                                                label.on_hover_text(path.to_string_lossy());
                                            }
                                        }
                                        None => {
                                            ui.colored_label(egui::Color32::GRAY, "not found");
                                            ui.label("wined3d fallback");
                                        }
                                    }
                                    ui.end_row();
                                };
                            let c = components.clone();
                            row("DXVK:", &c.dxvk);
                            row("D7VK:", &c.d7vk);
                            row("VKD3D-Proton:", &c.vkd3d_proton);
                            row("VKD3D:", &c.vkd3d);
                            row("DXVK-NVAPI:", &c.dxvk_nvapi);
                            row("NVAPI:", &c.nvapi);
                        });
                });
            }

            if gl_changed {
                self.user_configs.insert(game.app_id, user_cfg_gl);
                let store = self.user_configs.clone();
                self.runtime.spawn(async move {
                    let _ = crate::config::save_user_configs(&store).await;
                });
                // Invalidate component cache so display refreshes
                self.last_scanned_runner = PathBuf::new();
            }
            if steam_cfg_changed {
                let kill_webhelper = user_cfg.steam_launch_config.no_browser;
                self.user_configs.insert(game_app_id, user_cfg);
                let prefix = crate::utils::steam_wineprefix_for_game(
                    &self.launcher_config,
                    game_app_id,
                    &self.user_configs,
                    None, // UI ops use the configured mode (display/management)
                );
                SteamClient::kill_steam_in_prefix(&prefix, kill_webhelper);
                self.status = "Steam feature settings changed; Steam will restart on next launch".to_string();
                let store = self.user_configs.clone();
                self.runtime.spawn(async move {
                    let _ = crate::config::save_user_configs(&store).await;
                });
            }

            ui.add_space(16.0);
            ui.heading("Platform Preference");
            let current_platform = if game.is_installed {
                let mut is_proton = game.active_branch.contains("experimental")
                    || game
                        .install_path
                        .as_ref()
                        .map(|p| p.contains("compatdata"))
                        .unwrap_or(false);

                if let Some(config) = self.launcher_config.game_configs.get(&game.app_id) {
                    if let Some(pref) = &config.platform_preference {
                        is_proton = pref == "windows";
                    }
                }

                if is_proton {
                    "Windows (Proton)"
                } else {
                    "Linux Native"
                }
            } else {
                "Not Installed"
            };
            ui.label(format!("Current Version: {}", current_platform));
            if ui.button("Switch Platform").clicked() {
                let app_id = game.app_id;
                let mut client = self.client.clone();
                let tx = self.operation_tx.clone();
                self.runtime.spawn(async move {
                    match client.get_available_platforms(app_id).await {
                        Ok((platforms, buffer)) => {
                            let _ = tx.send(AsyncOp::PlatformsFetched(app_id, platforms, buffer));
                        }
                        Err(err) => {
                            let _ = tx.send(AsyncOp::Error(format!(
                                "Failed to fetch platforms for {app_id}: {err}"
                            )));
                        }
                    }
                });
            }

            ui.add_space(16.0);
        });
    }

    fn draw_misc_tab(&mut self, game: &LibraryGame, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.heading("Depot Manager");
            ui.horizontal(|ui| {
                if ui.button("Load Depots").clicked() {
                    let client = self.client.clone();
                    let tx = self.operation_tx.clone();
                    let app_id = game.app_id;
                    self.runtime.spawn(async move {
                        match client.get_depot_list(app_id).await {
                            Ok(list) => {
                                let _ = tx.send(AsyncOp::DepotListFetched(app_id, list));
                            }
                            Err(e) => {
                                let _ = tx.send(AsyncOp::Error(format!("Failed to load depots: {e}")));
                            }
                        }
                    });
                }

                if !self.depot_list.is_empty() {
                    if ui
                        .add_enabled(!self.is_verifying, egui::Button::new("Verify Ownership"))
                        .clicked()
                    {
                        self.is_verifying = true;
                        let client = self.client.clone();
                        let tx = self.operation_tx.clone();
                        let app_id = game.app_id;
                        let depot_ids: Vec<u64> = self.depot_list.iter().map(|d| d.id).collect();
                        self.runtime.spawn(async move {
                            let results = client.verify_depot_ownership(app_id, depot_ids).await;
                            let _ = tx.send(AsyncOp::DepotOwnershipVerified(results));
                        });
                    }
                }
            });

            if !self.depot_list.is_empty() {
                ui.add_space(10.0);
                egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                    egui::Grid::new("depot_list_grid")
                        .num_columns(5)
                        .spacing([10.0, 4.0])
                        .striped(true)
                        .show(ui, |ui| {
                            ui.label("Sel");
                            ui.label("ID");
                            ui.label("Name");
                            ui.label("Config");
                            ui.label("Status");
                            ui.end_row();

                            for depot in &self.depot_list {
                                let mut selected = self.depot_selection.contains(&depot.id);
                                if ui.checkbox(&mut selected, "").changed() {
                                    if selected {
                                        self.depot_selection.insert(depot.id);
                                    } else {
                                        self.depot_selection.remove(&depot.id);
                                    }
                                }
                                ui.label(depot.id.to_string());
                                ui.label(&depot.name);
                                ui.label(&depot.config);

                                match depot.is_owned {
                                    None => {
                                        ui.label(egui::RichText::new("?").color(egui::Color32::GRAY));
                                    }
                                    Some(true) => {
                                        ui.label(
                                            egui::RichText::new("Owned").color(egui::Color32::GREEN),
                                        );
                                    }
                                    Some(false) => {
                                        ui.label(
                                            egui::RichText::new("Locked").color(egui::Color32::RED),
                                        );
                                    }
                                }
                                ui.end_row();
                            }
                        });
                });

                ui.add_space(10.0);
                if ui.button("Install Selected").clicked() {
                    let selected_ids: Vec<u64> = self.depot_selection.iter().cloned().collect();
                    if selected_ids.is_empty() {
                        self.status = "No depots selected".to_string();
                    } else {
                        let platform = if cfg!(target_os = "linux") {
                            DepotPlatform::Linux
                        } else {
                            DepotPlatform::Windows
                        };
                        self.start_install(game.app_id, platform, None, Some(selected_ids));
                    }
                }
            }
        });
    }

    fn draw_account_tab(&mut self, ui: &mut egui::Ui) {
        if self.account_data.is_none() {
            self.refresh_account_data();
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                ui.add(egui::Spinner::new());
                ui.label("Loading account data...");
            });
            return;
        }

        let data = self.account_data.clone().unwrap();
        let mut should_logout = false;

        ui.columns(2, |columns| {
            // Left Column
            columns[0].vertical_centered(|ui| {
                ui.add_space(20.0);
                // Persona placeholder
                let initials: String = data.account_name.chars().take(2).collect();
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_min_size(egui::vec2(100.0, 100.0));
                    ui.heading(egui::RichText::new(initials.to_uppercase()).size(40.0));
                });

                ui.add_space(10.0);
                ui.heading(&data.account_name);

                ui.add_space(20.0);
                if ui
                    .add(
                        egui::Button::new(egui::RichText::new("Logout").color(egui::Color32::WHITE))
                            .fill(egui::Color32::from_rgb(200, 45, 45))
                            .min_size(egui::vec2(120.0, 30.0)),
                    )
                    .clicked()
                {
                    should_logout = true;
                }
            });

            // Right Column
            columns[1].vertical(|ui| {
                ui.add_space(20.0);
                ui.heading("Account Details");
                ui.add_space(10.0);

                egui::Grid::new("account_details_grid")
                    .num_columns(2)
                    .spacing([20.0, 10.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label("Steam ID:");
                        ui.label(data.steam_id.to_string());
                        ui.end_row();

                        ui.label("Country:");
                        ui.label(&data.country);
                        ui.end_row();

                        ui.label("Email Status:");
                        if data.email_validated {
                            ui.colored_label(egui::Color32::GREEN, "Verified");
                        } else {
                            ui.label("Unverified");
                        }
                        ui.end_row();

                        ui.label("VAC Status:");
                        if data.vac_bans > 0 {
                            ui.colored_label(
                                egui::Color32::RED,
                                format!("{} VAC bans on record", data.vac_bans),
                            );
                        } else {
                            ui.colored_label(egui::Color32::GREEN, "In Good Standing");
                        }
                        ui.end_row();

                        ui.label("Steam Guard:");
                        ui.label(format!("{} authorized machines", data.authed_machines));
                        ui.end_row();

                        ui.label("Account Flags:");
                        ui.label(format!("{:#X}", data.flags));
                        ui.end_row();
                    });
            });
        });

        if should_logout {
            self.logout();
        }
    }

    fn draw_info_tab(&mut self, game: &LibraryGame, ui: &mut egui::Ui) {
        if !self.extended_info.contains_key(&game.app_id) {
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                if ui.button("Fetch Extended Info").clicked() {
                    let app_id = game.app_id;
                    let client = self.client.clone();
                    let tx = self.operation_tx.clone();
                    self.runtime.spawn(async move {
                        match client.get_extended_app_info(app_id).await {
                            Ok(info) => {
                                let _ = tx.send(AsyncOp::ExtendedInfoFetched(app_id, info));
                            }
                            Err(e) => {
                                let _ = tx.send(AsyncOp::Error(format!(
                                    "Failed to fetch extended info for {app_id}: {e}"
                                )));
                            }
                        }
                    });
                }
            });
            return;
        }

        let info = self.extended_info.get(&game.app_id).cloned().unwrap();

        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Branches");
            ui.label(format!("Active Branch: {}", info.active_branch));
            if ui.button("Switch Branch...").clicked() {
                self.open_properties_modal(game);
            }

            ui.add_space(8.0);
            ui.heading("DLCs");
            if info.dlcs.is_empty() {
                ui.label("None found");
            } else {
                for dlc_id in &info.dlcs {
                    ui.label(format!("AppID: {}", dlc_id));
                }
            }

            ui.add_space(8.0);
            ui.heading("Depots");
            if ui.button("Open Depot Browser...").clicked() {
                self.open_depot_browser(game);
            }
            for (id, name) in &info.depots {
                ui.label(format!("{}: {}", id, name));
            }

            ui.add_space(8.0);
            ui.heading("Launch Options");
            for opt in &info.launch_options {
                ui.group(|ui| {
                    ui.label(format!("Executable: {}", opt.executable));
                    ui.label(format!("Arguments: {}", opt.arguments));
                });
            }
        });
    }

    fn refresh_runner_components(&mut self, runner_path: &Path, app_id: u32) {
        if self.last_scanned_runner == runner_path && self.last_scanned_appid == Some(app_id) {
            return;
        }

        self.last_scanned_runner = runner_path.to_path_buf();
        self.last_scanned_appid = Some(app_id);

        // Use the same prefix that will actually be used at launch
        let user_cfg = self.user_configs.get(&app_id).cloned().unwrap_or_default();
        let effective_prefix = if user_cfg.use_steam_runtime {
            crate::utils::steam_wineprefix_for_game(
                &self.launcher_config,
                app_id,
                &self.user_configs,
                None, // UI ops use the configured mode (display/management)
            )
        } else {
            std::path::PathBuf::from(&self.launcher_config.steam_library_path)
                .join("steamapps/compatdata")
                .join(app_id.to_string())
                .join("pfx")
        };

        let wineprefix = if effective_prefix.exists() {
            Some(effective_prefix)
        } else {
            None
        };
        let mut components = crate::utils::detect_runner_components(
            runner_path,
            wineprefix.as_deref(),
        );

        // Overlay custom components if set
        if let Some(config) = self.user_configs.get(&app_id) {
            if let Some(path) = &config.graphics_layers.custom_dxvk_path {
                let custom = crate::utils::detect_custom_components(path);
                if let Some(mut info) = custom.dxvk {
                    info.source = crate::utils::ComponentSource::SystemWide; // Hack: display as custom/system
                    info.path = Some(path.clone());
                    components.dxvk = Some(info);
                }
            }
            if let Some(path) = &config.graphics_layers.custom_vkd3d_proton_path {
                let custom = crate::utils::detect_custom_components(path);
                if let Some(mut info) = custom.vkd3d_proton {
                    info.source = crate::utils::ComponentSource::SystemWide;
                    info.path = Some(path.clone());
                    components.vkd3d_proton = Some(info);
                }
            }
            if let Some(path) = &config.graphics_layers.custom_vkd3d_path {
                let custom = crate::utils::detect_custom_components(path);
                if let Some(mut info) = custom.vkd3d {
                    info.source = crate::utils::ComponentSource::SystemWide;
                    info.path = Some(path.clone());
                    components.vkd3d = Some(info);
                }
            }
        }

        self.runner_components = Some(components);
    }

    fn draw_uninstall_modal(&mut self, ctx: &egui::Context) {
        let mut do_uninstall = None;
        let mut close = false;
        if let Some(modal) = &mut self.uninstall_modal {
            egui::Window::new(format!("Uninstall {}?", modal.game_name))
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!("Uninstall {}?", modal.game_name));
                    ui.checkbox(
                        &mut modal.delete_prefix,
                        "Also delete Compatibility Data (Saves & Prefixes)",
                    )
                    .on_hover_text(
                        "Check this to perform a clean wipe. Uncheck to keep saves for later.",
                    );
                    ui.small(
                        "Check this to perform a clean wipe. Uncheck to keep saves for later.",
                    );
                    ui.small("Steam userdata/cloud local cache is intentionally preserved.");

                    ui.horizontal(|ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new("Uninstall")
                                        .color(egui::Color32::WHITE)
                                        .strong(),
                                )
                                .fill(egui::Color32::from_rgb(200, 45, 45)),
                            )
                            .clicked()
                        {
                            do_uninstall =
                                Some((modal.app_id, modal.game_name.clone(), modal.delete_prefix));
                        }

                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                });
        }

        if let Some((app_id, game_name, delete_prefix)) = do_uninstall {
            let client = self.client.clone();
            let tx = self.operation_tx.clone();
            self.runtime.spawn(async move {
                match client.uninstall_game(app_id, delete_prefix).await {
                    Ok(()) => {
                        let _ = tx.send(AsyncOp::Uninstalled(app_id, game_name));
                    }
                    Err(err) => {
                        let _ = tx.send(AsyncOp::Error(format!(
                            "Failed to uninstall {game_name}: {err}"
                        )));
                    }
                }
            });
            self.uninstall_modal = None;
        } else if close {
            self.uninstall_modal = None;
        }
    }

    fn draw_depot_browser_window(&mut self, ctx: &egui::Context) {
        let mut close = false;
        let mut request_refresh: Option<(u32, u32, String)> = None;
        let mut request_download: Option<(u32, u32, String, String)> = None;

        if let Some(state) = &mut self.depot_browser {
            egui::Window::new(format!(
                "Depot Browser - {} ({})",
                state.game_name, state.app_id
            ))
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Manifest ID:");
                    ui.add(
                        egui::TextEdit::singleline(&mut state.manifest_input)
                            .hint_text("public or numeric manifest id"),
                    );
                    if ui.button("Load Manifest").clicked() {
                        if let Some(depot_id) = state.selected_depot {
                            request_refresh =
                                Some((state.app_id, depot_id, state.manifest_input.clone()));
                        }
                    }
                });

                ui.separator();
                ui.columns(2, |columns| {
                    columns[0].heading("Depots");
                    egui::ScrollArea::vertical().show(&mut columns[0], |ui| {
                        for depot in &state.depots {
                            let label = format!(
                                "{} - {} ({} bytes)",
                                depot.depot_id, depot.name, depot.max_size
                            );
                            if ui
                                .selectable_label(
                                    state.selected_depot == Some(depot.depot_id),
                                    label,
                                )
                                .clicked()
                            {
                                state.selected_depot = Some(depot.depot_id);
                                if let Some(public_id) = depot.public_manifest_id {
                                    state.manifest_input = public_id.to_string();
                                }
                            }
                        }
                    });

                    columns[1].heading("Files");
                    egui::ScrollArea::vertical().show(&mut columns[1], |ui| {
                        for file in &state.files {
                            ui.horizontal(|ui| {
                                ui.label(format!("{} ({} bytes)", file.filename, file.size));
                                ui.small(format!("sha:{} chunks:{}", file.sha_hash, file.chunks));
                                if ui.button("Download").clicked() {
                                    if let Some(depot_id) = state.selected_depot {
                                        request_download = Some((
                                            state.app_id,
                                            depot_id,
                                            state.manifest_input.clone(),
                                            file.filename.clone(),
                                        ));
                                    }
                                }
                            });
                        }
                    });
                });

                if ui.button("Close").clicked() {
                    close = true;
                }
            });
        }

        if let Some((appid, depot_id, manifest, file)) = request_download {
            let out = std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("depot_downloads")
                .join(appid.to_string());
            match self
                .client
                .download_single_file(appid, depot_id, &manifest, &file, &out)
            {
                Ok(()) => self.status = format!("Downloaded {file} to {}", out.display()),
                Err(err) => self.status = format!("Single-file download failed: {err}"),
            }
        }

        if let Some((appid, depot_id, manifest)) = request_refresh {
            let client = self.client.clone();
            let tx = self.operation_tx.clone();
            self.runtime.spawn(async move {
                match client.fetch_manifest_files(appid, depot_id, &manifest).await {
                    Ok(files) => {
                        let _ = tx.send(AsyncOp::ManifestFilesFetched(files));
                    }
                    Err(err) => {
                        let _ = tx.send(AsyncOp::Error(format!("Failed to fetch manifest files: {err}")));
                    }
                }
            });
        }

        if close {
            self.depot_browser = None;
        }
    }

    fn format_bytes(bytes: u64) -> String {
        if bytes == 0 { return "0 B".to_string(); }
        let units = ["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_idx = 0;
        while size >= 1024.0 && unit_idx < units.len() - 1 {
            size /= 1024.0;
            unit_idx += 1;
        }
        format!("{:.2} {}", size, units[unit_idx])
    }

    /// Record a (timestamp, depot-bytes-downloaded) sample used to estimate the
    /// download rate for the ETA display. Samples older than ~15s are dropped.
    /// Takes the sample deque directly (not `&mut self`) so it can be called
    /// while draining a task receiver inside the poll loop.
    fn record_progress_sample(
        samples: &mut VecDeque<(std::time::Instant, u64)>,
        bytes_downloaded: u64,
    ) {
        let now = std::time::Instant::now();
        samples.push_back((now, bytes_downloaded));
        while samples.len() > 30
            || (samples.len() > 2
                && now.duration_since(samples.front().unwrap().0).as_secs() > 15)
        {
            samples.pop_front();
        }
    }

    /// Estimate the remaining time (seconds) needed to transfer `remaining_bytes`
    /// based on the given sample window. Returns None until a reliable rate is
    /// available (or when the download is stalled).
    fn eta_seconds(
        samples: &VecDeque<(std::time::Instant, u64)>,
        remaining_bytes: u64,
    ) -> Option<u64> {
        if remaining_bytes == 0 {
            return Some(0);
        }
        let now = std::time::Instant::now();
        let window: Vec<(std::time::Instant, u64)> = samples
            .iter()
            .filter(|(t, _)| now.duration_since(*t).as_secs_f64() < 15.0)
            .copied()
            .collect();
        if window.len() < 2 {
            return None;
        }
        let (t0, b0) = window[0];
        let (t1, b1) = *window.last().unwrap();
        let dt = t1.duration_since(t0).as_secs_f64();
        let db = b1.saturating_sub(b0) as f64;
        if dt <= 0.0 || db <= 0.0 {
            return None;
        }
        let rate = db / dt;
        if rate <= 0.0 {
            return None;
        }
        Some((remaining_bytes as f64 / rate).ceil() as u64)
    }

    fn format_eta(secs: u64) -> String {
        if secs < 60 {
            format!("ETA {secs}s")
        } else if secs < 3600 {
            format!("ETA {}m {:02}s", secs / 60, secs % 60)
        } else {
            format!("ETA {}h {:02}m", secs / 3600, (secs % 3600) / 60)
        }
    }

    fn draw_proton_manager(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Refresh").clicked() {
                self.proton_manager.loading = true;
                let library_root = PathBuf::from(&self.launcher_config.steam_library_path);
                let tx = self.operation_tx.clone();
                self.runtime.spawn(async move {
                    let available = crate::proton::list_available().await.unwrap_or_default();
                    let installed = crate::proton::list_installed(&library_root).unwrap_or_default();
                    let _ = tx.send(AsyncOp::ProtonListFetched(available, installed));
                });
            }
            if self.proton_manager.loading {
                ui.add(egui::Spinner::new());
            }
        });

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label("Filter:");
            if ui.selectable_label(self.proton_manager.filter_label.is_none(), "All").clicked() {
                self.proton_manager.filter_label = None;
            }
            for label in ["Valve", "Proton-GE", "Wine-GE", "Proton-CachyOS"] {
                if ui.selectable_label(self.proton_manager.filter_label.as_deref() == Some(label), label).clicked() {
                    self.proton_manager.filter_label = Some(label.to_string());
                }
            }
        });

        ui.add_space(8.0);
        let mut clear_error = false;
        if let Some(err) = &self.proton_manager.error {
            ui.horizontal(|ui| {
                ui.colored_label(egui::Color32::RED, err);
                if ui.button("x").clicked() {
                    clear_error = true;
                }
            });
        }
        if clear_error {
            self.proton_manager.error = None;
        }

        egui::ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
            let filter_label = self.proton_manager.filter_label.clone();
            let available = self.proton_manager.available.clone();
            let installed = self.proton_manager.installed.clone();
            let install_progress = self.proton_manager.install_progress.clone();

            for pkg in available {
                if let Some(f) = &filter_label {
                    if !pkg.label.contains(f) { continue; }
                }

                let is_installed = installed.iter().any(|i| i.name == pkg.name);
                let pkg_name = pkg.name.clone();

                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(&pkg.name).strong());
                        ui.small(format!("{} • {}", pkg.label, Self::format_bytes(pkg.size)));
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if is_installed {
                            ui.label("Installed ✓");
                            if ui.button("Remove").clicked() {
                                let mut affected = Vec::new();
                                let is_default = self.launcher_config.proton_version == pkg_name;
                                for (appid, cfg) in &self.launcher_config.game_configs {
                                    if cfg.forced_proton_version.as_deref() == Some(&pkg_name) {
                                        if let Some(game) = self.library.iter().find(|g| g.app_id == *appid) {
                                            affected.push(game.name.clone());
                                        } else {
                                            affected.push(format!("AppID {}", appid));
                                        }
                                    }
                                }
                                self.proton_remove_confirm = Some(ProtonRemoveConfirmState {
                                    name: pkg_name.clone(),
                                    is_default,
                                    affected_games: affected,
                                });
                            }
                        } else if let Some((progress_name, _, _)) = &install_progress {
                            if progress_name == &pkg_name {
                                ui.label("Installing...");
                            } else {
                                ui.add_enabled(false, egui::Button::new("Install"));
                            }
                        } else {
                            if ui.button("Install").clicked() {
                                match pkg.source {
                                    crate::proton::ProtonSource::Steam => {
                                        let appid = crate::proton::VALVE_PROTONS.iter()
                                            .find(|(label, _)| *label == pkg_name)
                                            .map(|(_, id)| *id);
                                        if let Some(id) = appid {
                                            self.start_install(id, DepotPlatform::Linux, None, None);
                                        }
                                    }
                                    crate::proton::ProtonSource::Github => {
                                        let tx = self.operation_tx.clone();
                                        let pkg_clone = pkg.clone();
                                        let name = pkg_name.clone();
                                        self.runtime.spawn(async move {
                                            let name_inner = name.clone();
                                            let tx_inner = tx.clone();
                                            let res = crate::proton::install_github_package(pkg_clone, move |dl, tot| {
                                                let _ = tx_inner.send(AsyncOp::ProtonInstallProgress(name_inner.clone(), dl, tot));
                                            }).await;
                                            match res {
                                                Ok(_) => { let _ = tx.send(AsyncOp::ProtonInstallComplete(name)); }
                                                Err(e) => { let _ = tx.send(AsyncOp::ProtonInstallFailed(name, e.to_string())); }
                                            }
                                        });
                                    }
                                }
                            }
                        }
                    });
                });

                if let Some((progress_name, dl, tot)) = &install_progress {
                    if progress_name == &pkg_name {
                        let fraction = if *tot > 0 { *dl as f32 / *tot as f32 } else { 0.0 };
                        ui.add(egui::ProgressBar::new(fraction).text(format!("{}/{}", Self::format_bytes(*dl), Self::format_bytes(*tot))));
                    }
                }
                ui.separator();
            }
        });
    }

    fn draw_proton_remove_confirm_modal(&mut self, ctx: &egui::Context) {
        let mut confirm = false;
        let mut close = false;
        if let Some(state) = &self.proton_remove_confirm {
            egui::Window::new("Confirm Removal")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!("Are you sure you want to remove {}?", state.name));
                    if state.is_default {
                        ui.colored_label(egui::Color32::YELLOW, "This is currently set as the global default Proton version.");
                    }
                    if !state.affected_games.is_empty() {
                        ui.add_space(4.0);
                        ui.label("The following games are configured to use this version:");
                        for game in &state.affected_games {
                            ui.label(format!("• {}", game));
                        }
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Remove").clicked() { confirm = true; }
                        if ui.button("Cancel").clicked() { close = true; }
                    });
                });
        }

        if confirm {
            if let Some(state) = self.proton_remove_confirm.take() {
                let library_root = PathBuf::from(&self.launcher_config.steam_library_path);
                let tx = self.operation_tx.clone();
                let name = state.name.clone();
                self.runtime.spawn(async move {
                    match crate::proton::remove(&name, &library_root) {
                        Ok(_) => { let _ = tx.send(AsyncOp::ProtonRemoved(name)); }
                        Err(e) => { let _ = tx.send(AsyncOp::Error(format!("Failed to remove {}: {}", name, e))); }
                    }
                });
            }
        } else if close {
            self.proton_remove_confirm = None;
        }
    }

    fn auth_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Steam authentication");
        ui.horizontal(|ui| {
            ui.label("Account:");
            ui.text_edit_singleline(&mut self.auth_username);
        });
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut self.auth_password).password(true));
        });

        let prompts = self.client.pending_confirmations();
        if !prompts.is_empty() {
            ui.separator();
            ui.label("Steam Guard confirmation required:");

            let mut show_code_input = false;
            for prompt in prompts {
                match &prompt.requirement {
                    SteamGuardReq::EmailCode { domain_hint } => {
                        show_code_input = true;
                        let hint = if domain_hint.trim().is_empty() {
                            "your email".to_string()
                        } else {
                            domain_hint.clone()
                        };
                        ui.label(format!("Email code required (sent to {hint})."));
                    }
                    SteamGuardReq::DeviceCode => {
                        show_code_input = true;
                        ui.label("Steam Guard device code required from your authenticator.");
                    }
                    SteamGuardReq::DeviceConfirmation => {
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new());
                            ui.label("Approve this sign-in on your phone in Steam Mobile.");
                        });
                    }
                }
                if !prompt.details.trim().is_empty() {
                    ui.small(format!("Details: {}", prompt.details));
                }
            }

            if show_code_input {
                ui.horizontal(|ui| {
                    ui.label("Guard code:");
                    ui.text_edit_singleline(&mut self.auth_guard_code);
                });
            }
        }

        if ui.button("Login / Re-authenticate").clicked() {
            self.handle_auth_submit();
        }

        ui.add_space(4.0);
        let master_prefix = crate::utils::resolve_master_wineprefix();
        let client_logged_in =
            crate::steam_client::SteamClient::windows_client_has_session(&master_prefix);
        if client_logged_in {
            ui.label("✅ Windows Steam client: logged in (sentry file present)");
        } else {
            ui.label("❌ Windows Steam client: not logged in — Steamworks games (e.g. RE2) will exit immediately");
        }
        if ui
            .button("Login Windows Steam client (one-time, creates sentry file)")
            .clicked()
        {
            self.handle_windows_client_login();
        }
    }
}

fn scan_proton_runtimes(config: &LauncherConfig) -> (Vec<String>, Vec<String>) {
    // Official Valve list from VALVE_PROTONS constant
    let library_root = PathBuf::from(&config.steam_library_path);
    let common_dir = library_root.join("steamapps/common");

    let steam_protons = crate::proton::VALVE_PROTONS
        .iter()
        .filter(|(name, _)| common_dir.join(name).exists())
        .map(|(name, _)| name.to_string())
        .collect();

    // Custom: compatibilitytools.d + runtimes/
    let home = std::env::var("HOME").unwrap_or_default();
    let custom_paths = vec![
        PathBuf::from(&home).join(".local/share/Steam/compatibilitytools.d"),
        PathBuf::from(&home).join(".steam/steam/compatibilitytools.d"),
        crate::config::config_dir().unwrap_or_default().join("runtimes"),
    ];

    let mut unique_paths = Vec::new();
    for p in custom_paths {
        if let Ok(can) = std::fs::canonicalize(&p) {
            unique_paths.push(can);
        }
    }
    unique_paths.sort();
    unique_paths.dedup();

    let mut custom = Vec::new();
    for path in unique_paths {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let p = entry.path();
                    if crate::utils::build_runner_command(&p).is_ok() {
                        custom.push(entry.file_name().to_string_lossy().to_string());
                    }
                }
            }
        }
    }

    custom.sort();
    custom.dedup();
    (steam_protons, custom)
}

impl eframe::App for SteamLauncher {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let drained_images = self.poll_image_results(ctx);
        let drained_progress = self.poll_download_progress();
        let drained_play = self.poll_play_result();
        let drained_ops = self.poll_async_ops();

        egui::TopBottomPanel::top("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Refresh Library").clicked() {
                    self.refresh_library();
                }
                ui.separator();
                if ui.button("Settings").clicked() {
                    self.show_settings = !self.show_settings;
                }
            });
            if self.client.is_offline() {
                ui.colored_label(egui::Color32::YELLOW, "OFFLINE MODE");
            }
            if let Some(last) = self.install_log.last() {
                ui.label(last);
            }
        });

        egui::SidePanel::left("sidebar")
            .resizable(true)
            .default_width(280.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.main_tab, MainTab::Library, "Library");
                    ui.selectable_value(&mut self.main_tab, MainTab::Account, "Account");
                });
                ui.separator();

                if self.needs_reauth {
                    self.auth_ui(ui);
                    return;
                }

                if let Some(profile) = &self.user_profile {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            let status_color = if profile.is_online {
                                egui::Color32::GREEN
                            } else {
                                egui::Color32::RED
                            };
                            ui.colored_label(status_color, "●");
                            ui.label(egui::RichText::new(&profile.account_name).strong());
                        });
                        ui.small(format!("Steam ID: {}", profile.steam_id));
                        ui.label(format!("{} Games Owned", profile.game_count));
                    });
                    ui.separator();
                }

                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search_text)
                            .hint_text("Search library..."),
                    );
                    if !self.search_text.is_empty() && ui.button("x").clicked() {
                        self.search_text.clear();
                    }
                });
                ui.separator();


                ui.heading("Games");
                ui.checkbox(&mut self.show_installed_only, "Show Installed Only");
                ui.separator();

                let visible_games: Vec<LibraryGame> =
                    self.visible_games().into_iter().cloned().collect();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    for game in &visible_games {
                        self.ensure_metadata_requested(game.app_id);
                        let selected = self.selected_app == Some(game.app_id);
                        let app_id = game.app_id;

                        let mut job = egui::text::LayoutJob::default();
                        job.append(&game.name, 0.0, egui::TextFormat {
                            color: ui.visuals().text_color(),
                            ..Default::default()
                        });
                        if game.active_branch != "public" {
                            job.append(
                                &format!(" [{}]", game.active_branch),
                                0.0,
                                egui::TextFormat {
                                    color: egui::Color32::GRAY,
                                    ..Default::default()
                                },
                            );
                        }

                        let response = ui.selectable_label(selected, job);
                        if response.clicked() {
                            if self.selected_app != Some(app_id) {
                                self.selected_app = Some(app_id);
                                self.env_vars_edit_buffer = self.user_configs.get(&app_id)
                                    .map(|cfg| {
                                        let mut keys: Vec<_> = cfg.env_variables.keys().collect();
                                        keys.sort();
                                        keys.iter().map(|k| format!("{}={}", k, cfg.env_variables.get(*k).unwrap())).collect::<Vec<_>>().join("\n")
                                    })
                                    .unwrap_or_default();
                            }
                        }

                        response.context_menu(|ui| {
                            if ui.button("Play").clicked() {
                                if game.is_installed {
                                    self.handle_play_click(game);
                                } else {
                                    self.status = "Game not installed".to_string();
                                }
                                ui.close();
                            }
                            if ui.button("Cloud Saves").clicked() {
                                self.status = "Cloud Saves modal (placeholder)".to_string();
                                ui.close();
                            }
                            if ui.button("Properties").clicked() {
                                if self.selected_app != Some(game.app_id) {
                                    self.selected_app = Some(game.app_id);
                                    self.env_vars_edit_buffer = self.user_configs.get(&game.app_id)
                                        .map(|cfg| {
                                            let mut keys: Vec<_> = cfg.env_variables.keys().collect();
                                            keys.sort();
                                            keys.iter().map(|k| format!("{}={}", k, cfg.env_variables.get(*k).unwrap())).collect::<Vec<_>>().join("\n")
                                        })
                                        .unwrap_or_default();
                                }
                                self.current_tab = GameTab::Properties;
                                ui.close();
                            }
                        });

                        if game.update_available {
                            ui.colored_label(
                                egui::Color32::from_rgb(66, 133, 244),
                                "Update Available",
                            );
                        }
                    }
                });
            });

        let mut show_settings = self.show_settings;
        if show_settings {
            egui::Window::new("Settings")
                .open(&mut show_settings)
                .resizable(true)
                .default_size([420.0, 600.0])
                .min_width(320.0)
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.heading("Library");
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("📂  Open Config Folder").on_hover_text("Open application configuration directory").clicked() {
                                    if let Ok(dir) = crate::config::config_dir() {
                                        let _ = std::process::Command::new("xdg-open").arg(&dir).status().or_else(|_| std::process::Command::new("open").arg(&dir).status());
                                    }
                                }
                            });
                        });
                        ui.label("Steam Library Path");
                        ui.text_edit_singleline(&mut self.launcher_config.steam_library_path);

                        ui.add_space(8.0);
                        ui.add_enabled_ui(!self.client.is_offline(), |ui| {
                            ui.checkbox(&mut self.launcher_config.enable_cloud_sync, "Enable Cloud Sync");
                        });

                        ui.checkbox(&mut self.launcher_config.windows_steam_discovery_enabled, "Discover installed games from Windows Steam");

                        let shield_color = if self.launcher_config.use_shared_compat_data {
                            egui::Color32::from_rgb(220, 80, 80)
                        } else {
                            egui::Color32::from_rgb(80, 180, 120)
                        };
                        ui.horizontal(|ui| {
                            ui.colored_label(shield_color, "🛡");
                            ui.checkbox(
                                &mut self.launcher_config.use_shared_compat_data,
                                "Use Shared Steam Compatibility Data",
                            )
                            .on_hover_text("WARNING: Shares prefix with official Steam.");
                        });

                        ui.add_space(8.0);
                        ui.separator();
                        ui.heading("Steam Runtime");

                        let mut global_cfg_changed = false;
                        ui.label("Launch Mode (global default — per-game overrides apply):");
                        egui::ComboBox::from_id_salt("global_launch_mode_selector")
                            .selected_text(format!("{:?}", self.launcher_config.launch_mode))
                            .show_ui(ui, |ui| {
                                use crate::models::LaunchMode;
                                if ui.selectable_value(&mut self.launcher_config.launch_mode, LaunchMode::DirectWine, "Direct Wine").clicked() {
                                    global_cfg_changed = true;
                                }
                                if ui.selectable_value(&mut self.launcher_config.launch_mode, LaunchMode::SteamAppLaunch, "Steam App Launch").clicked() {
                                    global_cfg_changed = true;
                                }
                                if ui.selectable_value(&mut self.launcher_config.launch_mode, LaunchMode::SteamProtocol, "Steam Protocol").clicked() {
                                    global_cfg_changed = true;
                                }
                            });
                        ui.label(
                            egui::RichText::new(
                                "Direct Wine launches the game binary directly. Steam App Launch / Steam Protocol route the launch through the installed Windows Steam client (required for DRM/steamworks and mods that need Steam).",
                            ).weak().small(),
                        );

                        ui.add_space(8.0);
                        ui.label("Prefix Mode:");
                        ui.radio_value(
                            &mut self.launcher_config.steam_prefix_mode,
                            crate::models::SteamPrefixMode::Shared,
                            "Shared — all games share master_steam_prefix",
                        );
                        ui.radio_value(
                            &mut self.launcher_config.steam_prefix_mode,
                            crate::models::SteamPrefixMode::PerGame,
                            "Per-game — copy/symlink Steam into each compatdata",
                        );

                        ui.add_space(8.0);
                        ui.label("Steam Client Features (global — applies to Manage / Repair / Reinstall):");
                        ui.label("CEF browser (steamwebhelper) powers Friends, Chat, and In-Game Overlay.");
                        if ui
                            .checkbox(
                                &mut self.launcher_config.steam_launch_config.no_browser,
                                "Disable CEF browser (kills steamwebhelper)",
                            )
                            .on_hover_text("Unchecking it disables Friends, Chat, and In-Game Overlay.")
                            .changed()
                        {
                            global_cfg_changed = true;
                        }
                        if global_cfg_changed {
                            let config_to_save = self.launcher_config.clone();
                            self.runtime.spawn(async move {
                                let _ = crate::config::save_launcher_config(&config_to_save).await;
                            });
                        }

                        ui.add_space(8.0);
                        ui.label("Steam Runtime Runner:");

                        ui.horizontal(|ui| {
                            use crate::models::RunnerSource;
                            ui.radio_value(&mut self.launcher_config.steam_runtime_runner_source, RunnerSource::Official, "Official Proton (Valve)");
                            ui.radio_value(&mut self.launcher_config.steam_runtime_runner_source, RunnerSource::Custom, "Custom (compatibilitytools.d)");
                        });

                        let runner_display_name = if self.launcher_config.steam_runtime_runner.as_os_str().is_empty() {
                            "None Selected".to_string()
                        } else {
                            self.launcher_config.steam_runtime_runner.file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| "Unknown".to_string())
                        };

                        egui::ComboBox::from_id_salt("runtime_runner_selector")
                            .selected_text(runner_display_name)
                            .show_ui(ui, |ui| {
                                use crate::models::RunnerSource;
                                if self.launcher_config.steam_runtime_runner_source == RunnerSource::Official {
                                    let (steam_protons, _) = scan_proton_runtimes(&self.launcher_config);
                                    let library_root = PathBuf::from(&self.launcher_config.steam_library_path);
                                    let common_dir = library_root.join("steamapps/common");

                                    for name in steam_protons {
                                        let p = common_dir.join(&name);
                                        if ui.selectable_label(self.launcher_config.steam_runtime_runner == p, &name).clicked() {
                                            self.launcher_config.steam_runtime_runner = p;
                                        }
                                    }
                                } else {
                                    let home = std::env::var("HOME").unwrap_or_default();
                                    let custom_tools_paths = vec![
                                        PathBuf::from(&home).join(".local/share/Steam/compatibilitytools.d"),
                                        PathBuf::from(&home).join(".steam/steam/compatibilitytools.d"),
                                        crate::config::config_dir().unwrap_or_default().join("runtimes"),
                                    ];

                                    let mut unique_paths = Vec::new();
                                    for p in custom_tools_paths {
                                        if let Ok(can) = std::fs::canonicalize(&p) {
                                        unique_paths.push(can);
                                        }
                                    }
                                unique_paths.sort();
                                unique_paths.dedup();

                                    for path in unique_paths {
                                        if let Ok(entries) = std::fs::read_dir(path) {
                                            for entry in entries.flatten() {
                                                if entry.path().is_dir() {
                                                    let p = entry.path();
                                                    if crate::utils::build_runner_command(&p).is_ok() {
                                                        let name = p.file_name().unwrap().to_string_lossy().to_string();
                                                        if ui.selectable_label(self.launcher_config.steam_runtime_runner == p, name).clicked() {
                                                            self.launcher_config.steam_runtime_runner = p;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            });
                        if let Some(warning) = crate::utils::validate_steam_runtime_runner_path(&self.launcher_config.steam_runtime_runner) {
                            ui.colored_label(egui::Color32::YELLOW, warning);
                        }

                        ui.add_space(4.0);
                        let steam_cfg = crate::utils::get_master_steam_config();
                        let prefix_exists = steam_cfg.root_dir.exists();
                        let latest_backup = crate::launch::get_latest_backup();

                        ui.add_space(4.0);
                        let mut skip_update = self.launcher_config.skip_steam_self_update;
                        if ui
                            .checkbox(&mut skip_update, "Skip Steam self-update (Proton-safe)")
                            .on_hover_text(
                                "Pin the Windows Steam client to skip its in-client updater.                                  Under Proton the updater fails to apply a new client (rename of                                  steamwebhelper.exe is denied) and the launch aborts before                                  connecting. Leave on unless you specifically need auto-updates.",
                            )
                            .changed()
                        {
                            self.launcher_config.skip_steam_self_update = skip_update;
                            let config_to_save = self.launcher_config.clone();
                            self.runtime.spawn(async move {
                                let _ = config_to_save.save().await;
                            });
                        }

                        ui.horizontal(|ui| {
                            if !prefix_exists {
                                if ui.button("Install Windows Steam Runtime").clicked() {
                                    let config = self.launcher_config.clone();
                                    let tx = self.operation_tx.clone();
                                    self.runtime.spawn(async move {
                                        if let Err(e) = crate::launch::install_master_steam(&config).await {
                                            let _ = tx.send(AsyncOp::Error(format!("Runtime error: {e}")));
                                        }
                                    });
                                }
                            } else {
                                if ui.button("Manage Windows Steam Runtime").clicked() {
                                    let config = self.launcher_config.clone();
                                    let tx = self.operation_tx.clone();
                                    self.runtime.spawn(async move {
                                        if let Err(e) = crate::launch::install_master_steam(&config).await {
                                            let _ = tx.send(AsyncOp::Error(format!("Runtime error: {e}")));
                                        }
                                    });
                                }

                                if ui.button("Repair / Reinstall").clicked() {
                                    self.show_repair_confirmation = !self.show_repair_confirmation;
                                }

                                if ui.button("Backup Runtime").clicked() {
                                    let tx = self.operation_tx.clone();
                                    self.runtime.spawn(async move {
                                        if let Err(e) = crate::launch::backup_master_steam().await {
                                            let _ = tx.send(AsyncOp::Error(format!("Backup failed: {e}")));
                                        } else {
                                            let _ = tx.send(AsyncOp::MasterSteamBackedUp);
                                        }
                                    });
                                }
                            }

                            if let Some(backup_path) = latest_backup {
                                if ui.button("Restore from Backup").clicked() {
                                    self.show_restore_confirmation = !self.show_restore_confirmation;
                                }
                                ui.label(format!("Latest: {}", backup_path.file_name().unwrap_or_default().to_string_lossy()))
                                    .on_hover_text(backup_path.to_string_lossy());
                            }
                        });

                        if self.show_restore_confirmation {
                            egui::Frame::group(ui.style()).show(ui, |ui| {
                                ui.colored_label(egui::Color32::YELLOW, "⚠ Restoring will replace your current Steam prefix with the backup.");
                                if prefix_exists {
                                    ui.label("The current prefix will be moved to a temporary .old directory.");
                                }
                                ui.horizontal(|ui| {
                                    if ui.button("Confirm Restore").clicked() {
                                        self.show_restore_confirmation = false;
                                        let tx = self.operation_tx.clone();
                                        self.runtime.spawn(async move {
                                            if let Err(e) = crate::launch::restore_master_steam().await {
                                                let _ = tx.send(AsyncOp::Error(format!("Restore failed: {e}")));
                                            } else {
                                                let _ = tx.send(AsyncOp::MasterSteamRestored);
                                            }
                                        });
                                    }
                                    if ui.button("Cancel").clicked() {
                                        self.show_restore_confirmation = false;
                                    }
                                });
                            });
                        }

                        if self.show_repair_confirmation {
                            egui::Frame::group(ui.style()).show(ui, |ui| {
                                ui.colored_label(egui::Color32::YELLOW, "⚠ Repair will REINSTALL the Windows Steam client over the existing prefix.");
                                ui.label("Your game library (steamapps/) and saves (userdata/) are preserved — only the client is replaced.");
                                ui.label("SteamFlow removes the broken client, runs the Windows Steam installer, then restores your library and saves.");
                                ui.label("If 'Skip Steam self-update' is enabled, the fresh client is pinned to avoid the Proton rename failure.");
                                ui.horizontal(|ui| {
                                    if ui.button("Confirm Repair").clicked() {
                                        self.show_repair_confirmation = false;
                                        let config = self.launcher_config.clone();
                                        let tx = self.operation_tx.clone();
                                        self.runtime.spawn(async move {
                                            if let Err(e) = crate::launch::repair_master_steam(&config).await {
                                                let _ = tx.send(AsyncOp::Error(format!("Repair failed: {e}")));
                                            } else {
                                                let _ = tx.send(AsyncOp::MasterSteamRepaired);
                                            }
                                        });
                                    }
                                    if ui.button("Cancel").clicked() {
                                        self.show_repair_confirmation = false;
                                    }
                                });
                            });
                        }

                        ui.add_space(8.0);
                        ui.separator();
                        ui.heading("Compatibility Layer");

                        ui.radio_value(&mut self.proton_source, ProtonSource::Steam, "Official Proton (Valve)");
                        ui.radio_value(
                            &mut self.proton_source,
                            ProtonSource::Custom,
                            "Custom (compatibilitytools.d)",
                        );

                        let selected_list = if self.proton_source == ProtonSource::Steam {
                            &self.steam_protons
                        } else {
                            &self.custom_protons
                        };
                        egui::ComboBox::from_label("Default Proton Version")
                            .selected_text(self.launcher_config.proton_version.clone())
                            .show_ui(ui, |ui| {
                                for entry in selected_list {
                                    ui.selectable_value(
                                        &mut self.launcher_config.proton_version,
                                        entry.clone(),
                                        entry,
                                    );
                                }
                            });

                        // Runner components for selected game OR default runner
                        let active_runner_name = if let Some(game) = self.selected_game() {
                             self.launcher_config
                                .game_configs
                                .get(&game.app_id)
                                .and_then(|c| c.forced_proton_version.as_ref())
                                .cloned()
                                .unwrap_or_else(|| self.launcher_config.proton_version.clone())
                        } else {
                            self.launcher_config.proton_version.clone()
                        };

                        let library_root = PathBuf::from(&self.launcher_config.steam_library_path);
                        let resolved = crate::utils::resolve_runner(&active_runner_name, &library_root);

                        if let Some(game) = self.selected_game() {
                             self.refresh_runner_components(&resolved, game.app_id);
                        } else {
                             // No game selected, just scan runner root (no prefix)
                             if self.last_scanned_runner != resolved || self.last_scanned_appid.is_some() {
                                 self.last_scanned_runner = resolved.clone();
                                 self.last_scanned_appid = None;
                                 self.runner_components = Some(crate::utils::detect_runner_components(&resolved, None));
                             }
                        }

                        if let Some(components) = &self.runner_components {
                            ui.add_space(8.0);
                            egui::Frame::group(ui.style()).show(ui, |ui| {
                                ui.label(egui::RichText::new("Detected Graphics Components").strong());
                                ui.add_space(4.0);
                                egui::Grid::new("runner_components_grid")
                                    .num_columns(3)
                                    .spacing([16.0, 4.0])
                                    .show(ui, |ui| {
                                        let mut row =
                                            |label: &str, info: &Option<crate::utils::ComponentInfo>| {
                                                ui.label(label);
                                                match info {
                                                    Some(c) => {
                                                        ui.colored_label(egui::Color32::GREEN, &c.version);
                                                        let source_text = if c.source == crate::utils::ComponentSource::BundledWithRunner {
                                                            "bundled".to_string()
                                                        } else {
                                                            format!("{}", c.source)
                                                        };
                                                        let label = ui.colored_label(
                                                            egui::Color32::GRAY,
                                                            format!("({})", source_text),
                                                        );
                                                        if let Some(path) = &c.path {
                                                            label.on_hover_text(path.to_string_lossy());
                                                        }
                                                    }
                                                    None => {
                                                        ui.colored_label(egui::Color32::GRAY, "not found");
                                                        ui.label("wined3d fallback");
                                                    }
                                                }
                                                ui.end_row();
                                            };
                                        let c = components.clone();
                                        row("DXVK:", &c.dxvk);
                                        row("D7VK:", &c.d7vk);
                                        row("VKD3D-Proton:", &c.vkd3d_proton);
                                        row("VKD3D:", &c.vkd3d);
                                        row("DXVK-NVAPI:", &c.dxvk_nvapi);
                                        row("NVAPI:", &c.nvapi);
                                    });
                            });
                        }

                        ui.add_space(8.0);
                        ui.separator();
                        ui.heading("Wine Tools");
                        if ui.button("Open Wine Control Panel").clicked() {
                            let config = self.launcher_config.clone();
                            let tx = self.operation_tx.clone();
                            self.runtime.spawn(async move {
                                match crate::launch::launch_wine_control_panel(&config) {
                                    Ok(()) => {
                                        let _ = tx.send(AsyncOp::WineControlPanelLaunched);
                                    }
                                    Err(e) => {
                                        let _ = tx.send(AsyncOp::Error(format!("Wine Control Panel failed: {e}")));
                                    }
                                }
                            });
                        }
                        ui.label("Launches Wine's control.exe using the default Proton version and SteamFlow's master Wine prefix.");

                        if ui.button("Wine Configuration (winecfg)").clicked() {
                            let config = self.launcher_config.clone();
                            let tx = self.operation_tx.clone();
                            self.runtime.spawn(async move {
                                match crate::launch::launch_winecfg(&config) {
                                    Ok(()) => {
                                        let _ = tx.send(AsyncOp::WineCfgLaunched);
                                    }
                                    Err(e) => {
                                        let _ = tx.send(AsyncOp::Error(format!("Wine Configuration failed: {e}")));
                                    }
                                }
                            });
                        }
                        ui.label("Launches Wine's winecfg.exe — configure Wine DLL overrides, Windows version, and drivers.");

                        if ui.button("Open Wine File Manager").clicked() {
                            let config = self.launcher_config.clone();
                            let tx = self.operation_tx.clone();
                            self.runtime.spawn(async move {
                                match crate::launch::launch_wine_file_manager(&config) {
                                    Ok(()) => {
                                        let _ = tx.send(AsyncOp::WineFileManagerLaunched);
                                    }
                                    Err(e) => {
                                        let _ = tx.send(AsyncOp::Error(format!("Wine File Manager failed: {e}")));
                                    }
                                }
                            });
                        }
                        ui.label("Launches Wine's winefile.exe — browse the Wine prefix filesystem graphically.");

                        if ui.button("Open Wine Registry Editor").clicked() {
                            let config = self.launcher_config.clone();
                            let tx = self.operation_tx.clone();
                            self.runtime.spawn(async move {
                                match crate::launch::launch_wine_regedit(&config) {
                                    Ok(()) => {
                                        let _ = tx.send(AsyncOp::WineRegeditLaunched);
                                    }
                                    Err(e) => {
                                        let _ = tx.send(AsyncOp::Error(format!("Wine Registry Editor failed: {e}")));
                                    }
                                }
                            });
                        }
                        ui.label("Launches Wine's regedit.exe — view and edit the Wine registry.");

                        if ui.button("Open Wine Task Manager").clicked() {
                            let config = self.launcher_config.clone();
                            let tx = self.operation_tx.clone();
                            self.runtime.spawn(async move {
                                match crate::launch::launch_wine_taskmgr(&config) {
                                    Ok(()) => {
                                        let _ = tx.send(AsyncOp::WineTaskManagerLaunched);
                                    }
                                    Err(e) => {
                                        let _ = tx.send(AsyncOp::Error(format!("Wine Task Manager failed: {e}")));
                                    }
                                }
                            });
                        }
                        ui.label("Launches Wine's taskmgr.exe — manage processes running inside the Wine prefix.");

                        ui.add_space(8.0);
                        ui.separator();
                        ui.collapsing("Proton/Wine Manager", |ui| {
                            self.draw_proton_manager(ui);
                        });

                        ui.add_space(16.0);
                        ui.separator();
                        if ui.button("💾  Save Settings").clicked() {
                            let config = self.launcher_config.clone();
                            let tx = self.operation_tx.clone();
                            self.runtime.spawn(async move {
                                let success = crate::config::save_launcher_config(&config).await.is_ok();
                                let _ = tx.send(AsyncOp::SettingsSaved(success));
                            });
                        }
                    });
                });
            self.show_settings = show_settings;
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.needs_reauth {
                ui.heading("Authentication required");
                ui.label("Login from the left panel to restore your Steam session.");
                return;
            }

            if self.main_tab == MainTab::Account {
                self.draw_account_tab(ui);
                return;
            }

            if let Some(game) = self.selected_game().cloned() {
                self.ensure_image_requested(game.app_id);

                ui.vertical(|ui| {
                    egui::TopBottomPanel::bottom("game_status_bar").show_inside(ui, |ui| {
                        egui::ScrollArea::horizontal()
                            .id_salt("game_status_scroll")
                            .show(ui, |ui| {
                                ui.label(&self.status);
                            });
                    });

                    egui::CentralPanel::default().show_inside(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt("game_view_scroll")
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    // === LEFT: poster container — fixed 250x375
                                    // and CLIPPED to its own rect, so the title,
                                    // AppID, and PLAY button can never bleed over
                                    // the cover art / fallback card ===
                                    ui.allocate_ui(egui::vec2(250.0, 375.0), |ui| {
                                        ui.set_clip_rect(ui.max_rect());
                                        if let Some(texture) = self.image_cache.get(&game.app_id) {
                                            ui.add(egui::Image::new(texture).max_width(250.0));
                                        } else {
                                            // Styled fallback card: subtle vertical
                                            // gradient + game title (or spinner while
                                            // a cover download is in flight) — never
                                            // a blank/broken texture.
                                            let (rect, _response) = ui.allocate_exact_size(
                                                egui::vec2(250.0, 375.0),
                                                egui::Sense::hover(),
                                            );
                                            // Spinner is put BEFORE taking the
                                            // painter handle (ui.put needs &mut ui).
                                            if self.pending_images.contains(&game.app_id) {
                                                ui.put(
                                                    egui::Rect::from_center_size(
                                                        rect.center() - egui::vec2(0.0, 14.0),
                                                        egui::vec2(30.0, 30.0),
                                                    ),
                                                    egui::Spinner::new().size(30.0),
                                                );
                                            }
                                            let painter = ui.painter();
                                            let mut mesh = egui::epaint::Mesh::default();
                                            let top_color = egui::Color32::from_rgb(32, 37, 46);
                                            let bottom_color = egui::Color32::from_rgb(14, 16, 20);
                                            mesh.colored_vertex(rect.left_top(), top_color);
                                            mesh.colored_vertex(rect.right_top(), top_color);
                                            mesh.colored_vertex(rect.right_bottom(), bottom_color);
                                            mesh.colored_vertex(rect.left_bottom(), bottom_color);
                                            mesh.add_triangle(0, 1, 2);
                                            mesh.add_triangle(0, 2, 3);
                                            painter.add(egui::epaint::Shape::mesh(mesh));
                                            painter.rect_stroke(
                                                rect,
                                                4.0,
                                                egui::Stroke::new(
                                                    1.0,
                                                    egui::Color32::from_gray(58),
                                                ),
                                                egui::StrokeKind::Inside,
                                            );
                                            if self.pending_images.contains(&game.app_id) {
                                                painter.text(
                                                    egui::pos2(rect.center().x, rect.center().y + 24.0),
                                                    egui::Align2::CENTER_CENTER,
                                                    "Loading cover art…",
                                                    egui::FontId::proportional(14.0),
                                                    egui::Color32::from_gray(140),
                                                );
                                            } else {
                                                // Title card: game name wrapped across
                                                // the card.
                                                let galley = painter.layout(
                                                    game.name.clone(),
                                                    egui::FontId::proportional(20.0),
                                                    egui::Color32::from_gray(180),
                                                    rect.width() - 24.0,
                                                );
                                                painter.galley(
                                                    rect.center() - egui::vec2(
                                                        galley.size().x * 0.5,
                                                        galley.size().y * 0.5,
                                                    ),
                                                    galley,
                                                    egui::Color32::from_gray(180),
                                                );
                                            }
                                        }
                                    });

                                    ui.add_space(12.0);

                                    // === RIGHT: info column — bounded to the
                                    // remaining width so its children (title,
                                    // AppID, buttons) never wrap around or cover
                                    // the poster ===
                                    ui.vertical(|ui| {
                                        ui.set_min_width(ui.available_width());
                                        ui.set_max_width(ui.available_width());
                                        ui.horizontal(|ui| {
                                            // Title: wrap-enabled label constrained
                                            // to the row width MINUS a fixed right
                                            // column, so long titles wrap onto a
                                            // second line instead of being truncated
                                            // or sliding under the folder button.
                                            let button_col = 44.0;
                                            let title_width =
                                                (ui.available_width() - button_col).max(80.0);
                                            ui.vertical(|ui| {
                                                ui.set_max_width(title_width);
                                                ui.add(
                                                    egui::Label::new(
                                                        egui::RichText::new(game.name.clone())
                                                            .size(30.0)
                                                            .strong(),
                                                    )
                                                    .wrap(),
                                                );
                                            });
                                            // Folder button: right-aligned column
                                            // pinned to the top-right with fixed
                                            // padding — never overlaps title lines.
                                            ui.with_layout(
                                                egui::Layout::top_down(egui::Align::Max),
                                                |ui| {
                                                    if let Some(install_path) =
                                                        game.install_path.as_ref()
                                                    {
                                                        let path =
                                                            std::path::PathBuf::from(install_path);
                                                        if ui
                                                            .add(
                                                                egui::Button::new("📁")
                                                                    .corner_radius(6.0)
                                                                    .min_size(egui::vec2(
                                                                        28.0, 28.0,
                                                                    )),
                                                            )
                                                            .on_hover_text(
                                                                "Open game install folder",
                                                            )
                                                            .clicked()
                                                        {
                                                            let _ = std::process::Command::new(
                                                                "xdg-open",
                                                            )
                                                            .arg(&path)
                                                            .status()
                                                            .or_else(|_| {
                                                                std::process::Command::new("open")
                                                                    .arg(&path)
                                                                    .status()
                                                            });
                                                        }
                                                    }
                                                },
                                            );
                                        });
                                        ui.label(format!("AppID: {}", game.app_id));

                                        ui.add_space(20.0);

                                        ui.horizontal(|ui| {
                                            let operation_active =
                                                self.download_tasks.contains_key(&game.app_id);
                                            if operation_active {
                                                let label = if self
                                                    .download_tasks
                                                    .get(&game.app_id)
                                                    .and_then(|task| task.progress.as_ref())
                                                    .map(|progress| {
                                                        progress.state
                                                            == DownloadProgressState::Verifying
                                                    })
                                                    .unwrap_or(false)
                                                {
                                                    "◌  VERIFYING…"
                                                } else {
                                                    "◌  INSTALLING…"
                                                };
                                                ui.add_enabled(
                                                    false,
                                                    egui::Button::new(
                                                        egui::RichText::new(label)
                                                            .color(egui::Color32::WHITE)
                                                            .strong(),
                                                    )
                                                    .fill(egui::Color32::from_rgb(117, 117, 117))
                                                    .min_size(egui::vec2(140.0, 40.0)),
                                                );
                                            } else if game.is_installed {
                                                let process_state = self.game_processes.get(&game.app_id).copied();
                                                let (label, color) = match process_state {
                                                    Some(GameProcessState::Launching) => ("◌  LAUNCHING…", egui::Color32::from_rgb(117, 117, 117)),
                                                    Some(GameProcessState::Running(_)) => ("⏹  STOP", egui::Color32::from_rgb(183, 28, 28)),
                                                    None => ("▶  PLAY", egui::Color32::from_rgb(46, 125, 50)),
                                                };
                                                let play_btn = egui::Button::new(
                                                    egui::RichText::new(label).color(egui::Color32::WHITE).strong(),
                                                )
                                                .fill(color)
                                                .min_size(egui::vec2(140.0, 40.0));

                                                if ui.add_enabled(!matches!(process_state, Some(GameProcessState::Launching)), play_btn).clicked() {
                                                    if matches!(process_state, Some(GameProcessState::Running(_))) {
                                                        self.stop_game(game.app_id);
                                                    } else {
                                                        self.handle_play_click(&game);
                                                    }
                                                }

                                                if game.update_available {
                                                    ui.add_space(50.0);
                                                    let update_btn = egui::Button::new(
                                                        egui::RichText::new("UPDATE AVAILABLE")
                                                            .color(egui::Color32::WHITE)
                                                            .strong(),
                                                    )
                                                    .fill(egui::Color32::from_rgb(33, 150, 243))
                                                    .min_size(egui::vec2(120.0, 40.0));

                                                    if ui
                                                        .add_enabled(!self.client.is_offline(), update_btn)
                                                        .clicked()
                                                    {
                                                        let app_id = game.app_id;
                                                        let client = self.client.clone();
                                                        let tx = self.operation_tx.clone();
                                                        // Per-task DownloadState.
                                                        let download_state = Arc::new(RwLock::new(DownloadState::default()));
                                                        self.runtime.spawn(async move {
                                                            match client.update_game(app_id, download_state.clone()).await {
                                                                Ok(rx) => {
                                                                    let _ = tx.send(AsyncOp::DownloadStarted(
                                                                        app_id, rx, download_state,
                                                                    ));
                                                                }
                                                                Err(err) => {
                                                                    let _ = tx.send(AsyncOp::Error(format!(
                                                                        "Failed to update {app_id}: {err}"
                                                                    )));
                                                                }
                                                            }
                                                        });
                                                    }
                                                }
                                            } else {
                                                let install_btn = egui::Button::new(
                                                    egui::RichText::new("INSTALL")
                                                        .color(egui::Color32::WHITE)
                                                        .strong(),
                                                )
                                                .fill(egui::Color32::from_rgb(46, 125, 50))
                                                .min_size(egui::vec2(120.0, 40.0));

                                                if ui.add_enabled(!self.client.is_offline(), install_btn).clicked()
                                                {
                                                    let app_id = game.app_id;
                                                    let mut client = self.client.clone();
                                                    let tx = self.operation_tx.clone();
                                                    self.runtime.spawn(async move {
                                                        match client.get_available_platforms(app_id).await {
                                                            Ok((platforms, buffer)) => {
                                                                let _ = tx.send(AsyncOp::PlatformsFetched(
                                                                    app_id, platforms, buffer,
                                                                ));
                                                            }
                                                            Err(err) => {
                                                                let _ = tx.send(AsyncOp::Error(format!(
                                                                    "Failed to fetch platforms for {app_id}: {err}"
                                                                )));
                                                            }
                                                        }
                                                    });
                                                }
                                            }
                                        });
                                    });
                                });

                                ui.add_space(10.0);

                                // === Multi-task operation queue ===
                                // One stacked progress bar per active task
                                // (install/update/verify), each strictly bound
                                // to its own AppID + game title, with its own
                                // Pause/Cancel (per-task abort signal).
                                let mut cancelled: Vec<u32> = Vec::new();
                                let task_snapshots: Vec<(
                                    u32,
                                    String,
                                    Option<DownloadProgress>,
                                    VecDeque<(std::time::Instant, u64)>,
                                    Arc<RwLock<DownloadState>>,
                                )> = self
                                    .download_tasks
                                    .values()
                                    .map(|t| {
                                        (
                                            t.app_id,
                                            t.game_name.clone(),
                                            t.progress.clone(),
                                            t.samples.clone(),
                                            t.state.clone(),
                                        )
                                    })
                                    .collect();
                                for (app_id, task_name, progress_opt, samples, state) in task_snapshots {
                                    if let Some(progress) = progress_opt {
                                        let action_word =
                                            if progress.state == DownloadProgressState::Verifying {
                                                "Verifying"
                                            } else {
                                                "Downloading"
                                            };
                                        let denom = if progress.total_bytes == 0 {
                                            1.0
                                        } else {
                                            progress.total_bytes as f32
                                        };
                                        let fraction = (progress.bytes_downloaded as f32 / denom)
                                            .clamp(0.0, 1.0);
                                        // Human-readable sizes + percentage. total == 0
                                        // (e.g. before the manifest resolves) -> 0%, no
                                        // divide-by-zero.
                                        let pct = if progress.total_bytes == 0 {
                                            0.0
                                        } else {
                                            (progress.bytes_downloaded as f64 * 100.0
                                                / progress.total_bytes as f64)
                                                .clamp(0.0, 100.0)
                                        };
                                        let cur_str = Self::format_bytes(progress.bytes_downloaded);
                                        let tot_str = Self::format_bytes(progress.total_bytes);
                                        let eta_suffix = Self::eta_seconds(
                                            &samples,
                                            progress
                                                .total_bytes
                                                .saturating_sub(progress.bytes_downloaded),
                                        )
                                        .map(Self::format_eta)
                                        .map(|e| format!(" · {e}"))
                                        .unwrap_or_default();

                                        ui.horizontal(|ui| {
                                            ui.add(
                                                egui::ProgressBar::new(fraction)
                                                    .show_percentage()
                                                    .text(format!(
                                                        "{action_word} {}: {cur_str} / {tot_str} ({pct:.0}%){eta_suffix}",
                                                        progress.current_file
                                                    )),
                                            );

                                            let (is_downloading, is_paused, controller) = {
                                                let st = state.read().unwrap();
                                                (
                                                    st.is_downloading,
                                                    st.is_paused,
                                                    st.operation_controller.clone(),
                                                )
                                            };
                                            if is_downloading || is_paused {
                                                if ui.button(if is_paused { "▶ Resume" } else { "⏸ Pause" }).clicked() {
                                                    if let Ok(mut st) = state.write() {
                                                        st.is_paused = !is_paused;
                                                        if is_paused {
                                                            st.operation_controller.resume();
                                                        } else {
                                                            st.operation_controller.pause();
                                                        }
                                                    }
                                                }
                                                if ui.button("✖ Cancel").clicked() {
                                                    controller.cancel();
                                                    if let Ok(mut st) = state.write() {
                                                        st.is_downloading = false;
                                                        st.is_paused = false;
                                                        st.abort_signal
                                                            .store(true, std::sync::atomic::Ordering::Release);
                                                    }
                                                    self.status =
                                                        format!("Operation cancelled for {task_name}");
                                                    cancelled.push(app_id);
                                                }
                                            }
                                        });
                                    }
                                }
                                for app_id in cancelled {
                                    self.download_tasks.remove(&app_id);
                                }

                                ui.separator();

                                ui.horizontal(|ui| {
                                    ui.selectable_value(&mut self.current_tab, GameTab::Options, "Options");
                                    ui.selectable_value(&mut self.current_tab, GameTab::Properties, "Properties");
                                    ui.selectable_value(&mut self.current_tab, GameTab::Mods, "Mods");
                                    ui.selectable_value(&mut self.current_tab, GameTab::Info, "Info");
                                    ui.selectable_value(&mut self.current_tab, GameTab::Misc, "Misc");
                                });

                                ui.add_space(8.0);

                                match self.current_tab {
                                    GameTab::Options => self.draw_options_tab(&game, ui),
                                    GameTab::Properties => self.draw_properties_tab(&game, ui),
                                    GameTab::Mods => self.draw_mods_tab(&game, ui),
                                    GameTab::Info => self.draw_info_tab(&game, ui),
                                    GameTab::Misc => self.draw_misc_tab(&game, ui),
                                }
                            });
                    });
                });
            } else {
                ui.heading("SteamFlow");
                ui.label("Select a game from the sidebar.");
            }
        });

        self.draw_uninstall_modal(ctx);
        self.draw_depot_browser_window(ctx);
        self.draw_platform_selection_modal(ctx);
        self.draw_depot_install_selection_modal(ctx);
        self.draw_launch_selector_modal(ctx);
        self.draw_proton_remove_confirm_modal(ctx);

        // Scoped repaint policy — replaces the old unconditional
        // `ctx.request_repaint()` that forced a full frame every vsync
        // (~165 fps on a high-refresh display ≈ one pegged core even when
        // the window sat idle). egui already repaints on input events, so
        // idle frames are only needed when something async changed:
        //
        // 1. A channel was drained this frame (cover art landed, progress
        //    message, play result, async op) → render the new state now.
        // 2. Active downloads → tick progress bars + the Instant-based ETA
        //    countdown (which changes by wall-clock even between messages).
        //    egui::Spinner (cover loading, account/proton/steamguard) is
        //    animated and self-requests repaint while visible, so those
        //    cover themselves and stop when they disappear.
        // 3. A launch/play result is pending → poll its channel at 1 Hz so
        //    a game exit or login-required event is picked up promptly.
        //
        // With nothing pending the UI schedules no repaint and the main
        // thread goes fully idle (~0% CPU) until the next input event.
        if drained_images || drained_progress || drained_play || drained_ops {
            ctx.request_repaint();
        }
        if !self.download_tasks.is_empty() {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }
        if self.play_result_rx.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }
    }
}
