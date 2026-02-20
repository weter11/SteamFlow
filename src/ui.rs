use crate::config::{
    load_launcher_config, opensteam_image_cache_dir, save_launcher_config, LauncherConfig,
};
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
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::mpsc::{self, Receiver, Sender};
use tokio::runtime::Runtime;

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
struct PropertiesModalState {
    app_id: u32,
    game_name: String,
    available_branches: Vec<String>,
    active_branch: String,
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
struct LaunchSelectorState {
    app_id: u32,
    game_name: String,
    options: Vec<crate::steam_client::LaunchInfo>,
    selected_id: String,
    always_use: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GameTab {
    Options,
    Properties,
    Mods,
    Info,
    Misc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MainTab {
    Library,
    Account,
}

pub enum AsyncOp {
    DownloadStarted(u32, tokio::sync::mpsc::Receiver<DownloadProgress>),
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
    DepotOwnershipVerified(HashMap<u64, bool>),
    ManifestFilesFetched(Vec<ManifestFileEntry>),
    LaunchOptionsFetched(u32, Vec<crate::steam_client::LaunchInfo>, Option<String>),
    AuthFailed(String),
    UserProfileFetched(crate::models::UserProfile),
    SettingsSaved(bool),
    ScanCompleted(u32, HashMap<u32, String>),
    MetadataFetched(u32, crate::steam_client::AppMetadata),
    UserConfigsFetched(crate::models::UserConfigStore),
    Error(String),
}

pub struct SteamLauncher {
    runtime: Runtime,
    pub client: SteamClient,
    pub library: Vec<LibraryGame>,
    pub image_cache: HashMap<AppId, TextureHandle>,
    pending_images: HashSet<AppId>,
    pending_metadata: HashSet<AppId>,
    image_tx: Sender<(AppId, String)>,
    image_rx: Receiver<(AppId, String)>,
    selected_app: Option<AppId>,
    show_installed_only: bool,
    search_text: String,
    proton_path_for_windows: String,
    status: String,
    auth_username: String,
    auth_password: String,
    auth_guard_code: String,
    needs_reauth: bool,
    install_log: Vec<String>,
    download_receiver: Option<tokio::sync::mpsc::Receiver<DownloadProgress>>,
    active_download_appid: Option<u32>,
    live_download_progress: Option<DownloadProgress>,
    pub download_state: Arc<RwLock<DownloadState>>,
    play_result_rx: Option<Receiver<String>>,
    show_settings: bool,
    launcher_config: LauncherConfig,
    proton_source: ProtonSource,
    steam_protons: Vec<String>,
    custom_protons: Vec<String>,
    user_profile: Option<UserProfile>,
    refreshing_account_data: bool,
    uninstall_modal: Option<UninstallModalState>,
    properties_modal: Option<PropertiesModalState>,
    depot_browser: Option<DepotBrowserState>,
    platform_selection: Option<PlatformSelectionState>,
    launch_selector: Option<LaunchSelectorState>,
    current_tab: GameTab,
    main_tab: MainTab,
    account_data: Option<crate::steam_client::AccountData>,
    extended_info: HashMap<u32, crate::steam_client::ExtendedAppInfo>,
    depot_list: Vec<crate::steam_client::DepotInfo>,
    depot_selection: HashSet<u64>,
    is_verifying: bool,
    user_configs: crate::models::UserConfigStore,
    operation_tx: Sender<AsyncOp>,
    operation_rx: Receiver<AsyncOp>,
}

impl SteamLauncher {
    pub fn new(runtime: Runtime, client: SteamClient, library: Vec<LibraryGame>) -> Self {
        let (image_tx, image_rx) = mpsc::channel();
        let (operation_tx, operation_rx) = mpsc::channel();
        let authenticated = client.is_authenticated();
        let launcher_config = runtime.block_on(load_launcher_config()).unwrap_or_default();
        let user_configs = runtime.block_on(crate::config::load_user_configs()).unwrap_or_default();
        let (steam_protons, custom_protons) = scan_proton_runtimes();
        let user_profile = runtime
            .block_on(client.get_user_profile(library.len()))
            .ok();
        Self {
            runtime,
            client,
            library,
            image_cache: HashMap::new(),
            pending_images: HashSet::new(),
            pending_metadata: HashSet::new(),
            image_tx,
            image_rx,
            selected_app: None,
            show_installed_only: false,
            search_text: String::new(),
            proton_path_for_windows: String::new(),
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
            download_receiver: None,
            active_download_appid: None,
            live_download_progress: None,
            download_state: Arc::new(RwLock::new(DownloadState::default())),
            play_result_rx: None,
            show_settings: false,
            launcher_config,
            proton_source: ProtonSource::Steam,
            steam_protons,
            custom_protons,
            user_profile,
            refreshing_account_data: false,
            uninstall_modal: None,
            properties_modal: None,
            depot_browser: None,
            platform_selection: None,
            launch_selector: None,
            current_tab: GameTab::Options,
            main_tab: MainTab::Library,
            account_data: None,
            extended_info: HashMap::new(),
            depot_list: Vec::new(),
            depot_selection: HashSet::new(),
            is_verifying: false,
            user_configs,
            operation_tx,
            operation_rx,
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

    fn poll_image_results(&mut self, ctx: &egui::Context) {
        while let Ok((appid, path)) = self.image_rx.try_recv() {
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
                }
            }
            self.pending_images.remove(&appid);
        }
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
        if self.image_cache.contains_key(&appid) || self.pending_images.contains(&appid) {
            return;
        }

        self.pending_images.insert(appid);
        let tx = self.image_tx.clone();

        self.runtime.spawn(async move {
            let Ok(cache_dir) = opensteam_image_cache_dir() else {
                return;
            };

            if tokio::fs::create_dir_all(&cache_dir).await.is_err() {
                return;
            }

            let target_path = cache_dir.join(format!("{appid}_library.jpg"));
            if tokio::fs::metadata(&target_path).await.is_err() {
                let candidates = [
                    format!("https://cdn.akamai.steamstatic.com/steam/apps/{appid}/library_600x900_2x.jpg"),
                    format!("https://cdn.akamai.steamstatic.com/steam/apps/{appid}/header.jpg"),
                    format!("https://steamcdn-a.akamaihd.net/steam/apps/{appid}/library_capsule_2x.jpg"),
                ];

                for url in candidates {
                    if let Ok(response) = reqwest::get(&url).await {
                        if response.status().is_success() {
                            if let Ok(bytes) = response.bytes().await {
                                if tokio::fs::write(&target_path, bytes).await.is_ok() {
                                    let _ = tx.send((appid, target_path.to_string_lossy().to_string()));
                                    return;
                                }
                            }
                        }
                    }
                }
            }

            if tokio::fs::metadata(&target_path).await.is_ok() {
                let _ = tx.send((appid, target_path.to_string_lossy().to_string()));
            }
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

    fn poll_download_progress(&mut self) {
        let mut should_clear_receiver = false;

        if let Some(rx) = &mut self.download_receiver {
            while let Ok(progress) = rx.try_recv() {
                self.live_download_progress = Some(progress.clone());
                match progress.state {
                    DownloadProgressState::Queued => {
                        self.status = "Install queued".to_string();
                    }
                    DownloadProgressState::Downloading => {
                        self.install_log.push(format!(
                            "App {} — downloading {}: {} / {} bytes",
                            self.active_download_appid.unwrap_or(0),
                            progress.current_file,
                            progress.bytes_downloaded,
                            progress.total_bytes
                        ));
                        if self.install_log.len() > 8 {
                            self.install_log.drain(0..self.install_log.len() - 8);
                        }
                        self.status = format!(
                            "Downloading {}: {} / {} bytes",
                            progress.current_file, progress.bytes_downloaded, progress.total_bytes
                        );
                    }
                    DownloadProgressState::Verifying => {
                        self.status = format!(
                            "Verifying {}: {} / {} bytes",
                            progress.current_file, progress.bytes_downloaded, progress.total_bytes
                        );
                    }
                    DownloadProgressState::Completed => {
                        self.status = "Install completed".to_string();
                        if let Ok(mut state) = self.download_state.write() {
                            state.is_downloading = false;
                            state.is_paused = false;
                        }
                        if let Some(appid) = self.active_download_appid {
                            let tx = self.operation_tx.clone();
                            self.runtime.spawn(async move {
                                let installed_paths =
                                    scan_installed_app_paths().await.unwrap_or_default();
                                let _ = tx.send(AsyncOp::ScanCompleted(appid, installed_paths));
                            });
                        }
                        should_clear_receiver = true;
                    }
                    DownloadProgressState::Failed => {
                        self.status = format!("Install failed: {}", progress.current_file);
                        if let Ok(mut state) = self.download_state.write() {
                            state.is_downloading = false;
                            state.is_paused = false;
                        }
                        should_clear_receiver = true;
                    }
                }
            }
        }

        if should_clear_receiver {
            self.download_receiver = None;
            self.active_download_appid = None;
        }
    }


    fn poll_play_result(&mut self) {
        if let Some(rx) = &self.play_result_rx {
            match rx.try_recv() {
                Ok(message) => {
                    self.status = message;
                    self.play_result_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.status = "Play task disconnected".to_string();
                    self.play_result_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
    }

    fn start_install(&mut self, app_id: u32, platform: DepotPlatform, cached_vdf: Option<Vec<u8>>, filter_depots: Option<Vec<u64>>) {
        let client = self.client.clone();
        let tx = self.operation_tx.clone();
        let download_state = self.download_state.clone();
        self.runtime.spawn(async move {
            match client.install_game(app_id, platform, cached_vdf, filter_depots, download_state).await {
                Ok(rx) => {
                    let _ = tx.send(AsyncOp::DownloadStarted(app_id, rx));
                }
                Err(err) => {
                    let _ = tx.send(AsyncOp::Error(format!(
                        "Failed to start install for {app_id}: {err}"
                    )));
                }
            }
        });
    }

    fn poll_async_ops(&mut self) {
        while let Ok(op) = self.operation_rx.try_recv() {
            match op {
                AsyncOp::DownloadStarted(appid, rx) => {
                    self.download_receiver = Some(rx);
                    self.active_download_appid = Some(appid);
                    self.status = format!("Operation started for app {appid}");
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
                        self.start_install(appid, platform, Some(buffer), None);
                    }
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
                AsyncOp::BranchesFetched(appid, branches) => {
                    if let Some(game) = self.library.iter().find(|g| g.app_id == appid) {
                        self.properties_modal = Some(PropertiesModalState {
                            app_id: appid,
                            game_name: game.name.clone(),
                            available_branches: branches,
                            active_branch: game.active_branch.clone(),
                        });
                    }
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
                                return;
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
                    self.status = err;
                }
            }
        }
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

    fn refresh_library(&mut self) {
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

    fn handle_play_click(&mut self, game: &LibraryGame) {
        let proton_path = if self.proton_path_for_windows.trim().is_empty() {
            None
        } else {
            Some(self.proton_path_for_windows.trim().to_string())
        };

        let mut prefer_proton = proton_path.is_some();
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
                    let _ = tx.send(AsyncOp::LaunchOptionsFetched(app_id, options, proton_path));
                }
                Err(err) => {
                    let _ = tx.send(AsyncOp::Error(format!("Failed to get launch options: {err}")));
                }
            }
        });
    }

    fn start_launch_task(&mut self, game: &LibraryGame, launch_info: crate::steam_client::LaunchInfo, proton_path: Option<String>) {
        let game = game.clone();
        let client = self.client.clone();
        let user_config = self.user_configs.get(&game.app_id).cloned();
        let (tx, rx) = mpsc::channel();
        self.play_result_rx = Some(rx);
        self.status = format!("Syncing Cloud... {}", game.name);

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
                match client.spawn_game_process(&game, &launch_info, chosen_proton_path, &launcher_config, user_config.as_ref()) {
                    Ok(child) => child,
                    Err(e) => {
                        let _ = tx.send(format!("Launch failed for {}: {e}", game.name));
                        return;
                    }
                };

            let _ = child.wait();

            if let (Some(c), Some(root)) = (cloud_client.as_ref(), local_root.as_ref()) {
                let _ = c.sync_up(game.app_id, root).await;
                tracing::info!(appid = game.app_id, "Upload Complete");
            }

            let _ = tx.send(format!("Finished playing {}", game.name));
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
            let proton_path = if self.proton_path_for_windows.trim().is_empty() {
                None
            } else {
                Some(self.proton_path_for_windows.trim().to_string())
            };
            let game = self.library.iter().find(|g| g.app_id == app_id).cloned();
            if let Some(game) = game {
                self.start_launch_task(&game, option, proton_path);
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
            self.start_install(app_id, platform, Some(cached_vdf), None);
            self.platform_selection = None;
        } else if close {
            self.platform_selection = None;
        }
    }

    fn draw_properties_modal(&mut self, ctx: &egui::Context) {
        let mut new_branch = None;
        let mut close = false;

        if let Some(state) = &mut self.properties_modal {
            egui::Window::new(format!("Properties - {}", state.game_name))
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.heading("Betas");
                    ui.label("Select the beta you would like to opt into:");

                    egui::ComboBox::from_id_salt("branch_selector")
                        .selected_text(&state.active_branch)
                        .show_ui(ui, |ui| {
                            for branch in &state.available_branches {
                                if ui
                                    .selectable_value(&mut state.active_branch, branch.clone(), branch)
                                    .clicked()
                                {
                                    new_branch = Some((state.app_id, branch.clone()));
                                }
                            }
                        });

                    ui.add_space(8.0);
                    if ui.button("Close").clicked() {
                        close = true;
                    }
                });
        }

        if let Some((app_id, branch)) = new_branch {
            let client = self.client.clone();
            let tx = self.operation_tx.clone();
            self.runtime.spawn(async move {
                match client.update_app_branch(app_id, &branch).await {
                    Ok(()) => {
                        let _ = tx.send(AsyncOp::BranchUpdated(app_id, branch));
                    }
                    Err(err) => {
                        let _ = tx.send(AsyncOp::Error(format!(
                            "Failed to switch branch for {app_id}: {err}"
                        )));
                    }
                }
            });
        }

        if close {
            self.properties_modal = None;
        }
    }


    fn draw_properties_tab(&mut self, game: &LibraryGame, ui: &mut egui::Ui) {
        let mut config = self.user_configs.get(&game.app_id).cloned().unwrap_or_default();
        let mut changed = false;

        ui.vertical(|ui| {
            ui.heading("Launch Options");
            if ui.add(egui::TextEdit::singleline(&mut config.launch_options).desired_width(f32::INFINITY)).changed() {
                changed = true;
            }

            ui.add_space(8.0);
            ui.heading("Environment Variables");
            ui.label("KEY=VALUE (one per line)");

            let mut env_keys: Vec<_> = config.env_variables.keys().collect();
            env_keys.sort();
            let mut env_text = env_keys.iter()
                .map(|k| format!("{}={}", k, config.env_variables.get(*k).unwrap()))
                .collect::<Vec<_>>()
                .join("\n");

            if ui.add(egui::TextEdit::multiline(&mut env_text).desired_width(f32::INFINITY)).changed() {
                let mut new_env = HashMap::new();
                for line in env_text.lines() {
                    if let Some((k, v)) = line.split_once('=') {
                        new_env.insert(k.trim().to_string(), v.trim().to_string());
                    }
                }
                config.env_variables = new_env;
                changed = true;
            }

            ui.add_space(8.0);
            ui.heading("Runtime Settings");
            if ui.checkbox(&mut config.use_steam_runtime, "Use Steam Runtime (Windows)")
                .on_hover_text("Required for DRM-protected games. Runs an official Steam client in the background.")
                .changed() {
                changed = true;
            }
        });

        if changed {
            self.user_configs.insert(game.app_id, config);
            let store = self.user_configs.clone();
            self.runtime.spawn(async move {
                let _ = crate::config::save_user_configs(&store).await;
            });
        }
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
            ui.heading("Maintenance");
            ui.horizontal(|ui| {
                if ui.button("Verify Integrity").clicked() {
                    let app_id = game.app_id;
                    let client = self.client.clone();
                    let tx = self.operation_tx.clone();
                    let download_state = self.download_state.clone();
                    self.runtime.spawn(async move {
                        match client.verify_game(app_id, download_state).await {
                            Ok(rx) => {
                                let _ = tx.send(AsyncOp::DownloadStarted(app_id, rx));
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
    }
}

fn scan_proton_runtimes() -> (Vec<String>, Vec<String>) {
    let home = std::env::var("HOME").unwrap_or_default();
    let steam_tools = PathBuf::from(&home).join(".local/share/Steam/steamapps/common");
    let custom_tools = PathBuf::from(&home).join(".local/share/Steam/compatibilitytools.d");

    let mut steam = vec!["experimental".to_string()];
    if let Ok(entries) = std::fs::read_dir(steam_tools) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.to_ascii_lowercase().contains("proton") {
                    steam.push(name);
                }
            }
        }
    }

    let mut custom = Vec::new();
    if let Ok(entries) = std::fs::read_dir(custom_tools) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                custom.push(entry.file_name().to_string_lossy().to_string());
            }
        }
    }

    steam.sort();
    steam.dedup();
    custom.sort();
    custom.dedup();
    (steam, custom)
}

impl eframe::App for SteamLauncher {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_image_results(ctx);
        self.poll_download_progress();
        self.poll_play_result();
        self.poll_async_ops();

        egui::TopBottomPanel::top("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Refresh Library").clicked() {
                    self.refresh_library();
                }
                ui.separator();
                if ui.button("Settings").clicked() {
                    self.show_settings = !self.show_settings;
                }
                ui.separator();
                ui.label("Proton path (for Windows games):");
                ui.text_edit_singleline(&mut self.proton_path_for_windows);
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

                if self.show_settings {
                    ui.heading("Settings");
                    ui.label("Steam Library Path");
                    ui.text_edit_singleline(&mut self.launcher_config.steam_library_path);

                    ui.add_enabled_ui(!self.client.is_offline(), |ui| {
                        ui.checkbox(
                            &mut self.launcher_config.enable_cloud_sync,
                            "Enable Cloud Sync",
                        );
                    });

                    let shield_color = if self.launcher_config.use_shared_compat_data {
                        egui::Color32::from_rgb(220, 80, 80)
                    } else {
                        egui::Color32::from_rgb(80, 180, 120)
                    };
                    ui.horizontal(|ui| {
                        ui.colored_label(shield_color, "🛡️");
                        let checkbox = ui.checkbox(
                            &mut self.launcher_config.use_shared_compat_data,
                            "Use Shared Steam Compatibility Data",
                        );
                        checkbox.on_hover_text("WARNING: Shares prefix with official Steam. Syncs saves, but may risk corruption if the launcher crashes. Uncheck to use isolated safe mode.");
                    });

                    ui.label("Proton Source");
                    ui.radio_value(
                        &mut self.proton_source,
                        ProtonSource::Steam,
                        "Steam runtimes",
                    );
                    ui.radio_value(
                        &mut self.proton_source,
                        ProtonSource::Custom,
                        "Custom compatibilitytools.d",
                    );

                    let selected_list = if self.proton_source == ProtonSource::Steam {
                        &self.steam_protons
                    } else {
                        &self.custom_protons
                    };

                    egui::ComboBox::from_label("Proton Version")
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

                    ui.add_space(8.0);
                    ui.label("Steam Runtime Runner (Master Prefix)");
                    let runner_name = self.launcher_config.steam_runtime_runner
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "None Selected".to_string());

                    egui::ComboBox::from_id_salt("runtime_runner_selector")
                        .selected_text(runner_name)
                        .show_ui(ui, |ui| {
                            let home = std::env::var("HOME").unwrap_or_default();
                            let custom_tools_paths = [
                                PathBuf::from(&home).join(".local/share/Steam/compatibilitytools.d"),
                                PathBuf::from(&home).join(".steam/steam/compatibilitytools.d"),
                            ];

                            for path in custom_tools_paths {
                                if let Ok(entries) = std::fs::read_dir(path) {
                                    for entry in entries.flatten() {
                                        if entry.path().is_dir() {
                                            let p = entry.path();
                                            let name = p.file_name().unwrap().to_string_lossy().to_string();
                                            if ui.selectable_label(self.launcher_config.steam_runtime_runner == p, name).clicked() {
                                                self.launcher_config.steam_runtime_runner = p;
                                            }
                                        }
                                    }
                                }
                            }
                        });

                    ui.add_space(4.0);
                    if ui.button("Install / Manage Windows Steam Runtime").clicked() {
                        let config = self.launcher_config.clone();
                        let tx = self.operation_tx.clone();
                        self.runtime.spawn(async move {
                            if let Err(e) = crate::launch::install_master_steam(&config).await {
                                let _ = tx.send(AsyncOp::Error(format!("Runtime error: {e}")));
                            }
                        });
                    }

                    ui.add_space(16.0);
                    if ui.button("Save Settings").clicked() {
                        let config = self.launcher_config.clone();
                        let tx = self.operation_tx.clone();
                        self.runtime.spawn(async move {
                            let success = save_launcher_config(&config).await.is_ok();
                            let _ = tx.send(AsyncOp::SettingsSaved(success));
                        });
                    }

                    ui.separator();
                }

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
                            self.selected_app = Some(app_id);
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
                                self.selected_app = Some(game.app_id);
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
                    ui.with_layout(egui::Layout::top_down_justified(egui::Align::LEFT), |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt("game_view_scroll")
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    if let Some(texture) = self.image_cache.get(&game.app_id) {
                                        ui.add(egui::Image::new(texture).max_width(250.0));
                                    } else {
                                        let (rect, _response) = ui.allocate_exact_size(
                                            egui::vec2(250.0, 375.0),
                                            egui::Sense::hover(),
                                        );
                                        ui.painter().rect_filled(rect, 4.0, egui::Color32::from_gray(30));
                                        ui.painter().text(
                                            rect.center(),
                                            egui::Align2::CENTER_CENTER,
                                            "STEAM",
                                            egui::FontId::proportional(20.0),
                                            egui::Color32::from_gray(100),
                                        );
                                    }

                                    ui.vertical(|ui| {
                                        ui.heading(egui::RichText::new(game.name.clone()).size(30.0).strong());
                                        ui.label(format!("AppID: {}", game.app_id));

                                        ui.add_space(20.0);

                                        ui.horizontal(|ui| {
                                            if game.is_installed {
                                                let play_btn = egui::Button::new(
                                                    egui::RichText::new("PLAY")
                                                        .color(egui::Color32::WHITE)
                                                        .strong(),
                                                )
                                                .fill(egui::Color32::from_rgb(46, 125, 50))
                                                .min_size(egui::vec2(120.0, 40.0));

                                                if ui.add(play_btn).clicked() {
                                                    self.handle_play_click(&game);
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
                                        let download_state = self.download_state.clone();
                                        self.runtime.spawn(async move {
                                            match client.update_game(app_id, download_state).await {
                                                Ok(rx) => {
                                                    let _ = tx.send(AsyncOp::DownloadStarted(
                                                        app_id, rx,
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

                if let Some(progress) = self.live_download_progress.clone() {
                    let denom = if progress.total_bytes == 0 {
                        1.0
                    } else {
                        progress.total_bytes as f32
                    };
                    let fraction = (progress.bytes_downloaded as f32 / denom).clamp(0.0, 1.0);

                    ui.horizontal(|ui| {
                        ui.add(
                            egui::ProgressBar::new(fraction)
                                .show_percentage()
                                .text(format!(
                                    "Live operation: {:?} - {} ({} / {} bytes)",
                                    progress.state,
                                    progress.current_file,
                                    progress.bytes_downloaded,
                                    progress.total_bytes
                                )),
                        );

                        let mut download_state = self.download_state.write().unwrap();
                        if download_state.is_downloading || download_state.is_paused {
                            if download_state.is_paused {
                                if ui.button("▶ Resume").clicked() {
                                    download_state.is_paused = false;
                                    download_state.abort_signal.store(false, std::sync::atomic::Ordering::Relaxed);

                                    let app_id = download_state.app_id;
                                    drop(download_state);

                                    // Resume logic: Re-trigger the appropriate operation
                                    if let Some(game) = self.library.iter().find(|g| g.app_id == app_id).cloned() {
                                        if progress.state == DownloadProgressState::Verifying {
                                            let client = self.client.clone();
                                            let tx = self.operation_tx.clone();
                                            let ds = self.download_state.clone();
                                            self.runtime.spawn(async move {
                                                let _ = tx.send(AsyncOp::DownloadStarted(app_id, client.verify_game(app_id, ds).await.unwrap()));
                                            });
                                        } else if game.is_installed {
                                            let client = self.client.clone();
                                            let tx = self.operation_tx.clone();
                                            let ds = self.download_state.clone();
                                            self.runtime.spawn(async move {
                                                let _ = tx.send(AsyncOp::DownloadStarted(app_id, client.update_game(app_id, ds).await.unwrap()));
                                            });
                                        } else {
                                            let platform = self.launcher_config.game_configs.get(&app_id)
                                                .and_then(|c| c.platform_preference.as_ref())
                                                .map(|p| if p == "linux" { DepotPlatform::Linux } else { DepotPlatform::Windows })
                                                .unwrap_or(if cfg!(target_os = "linux") { DepotPlatform::Linux } else { DepotPlatform::Windows });
                                            self.start_install(app_id, platform, None, None);
                                        }
                                    }
                                }
                            } else {
                                if ui.button("⏸ Pause").clicked() {
                                    download_state.is_paused = true;
                                    download_state.abort_signal.store(true, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }
                    });
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
                                    GameTab::Mods => {
                                        ui.label("Coming Soon");
                                    }
                                    GameTab::Info => self.draw_info_tab(&game, ui),
                                    GameTab::Misc => self.draw_misc_tab(&game, ui),
                                }
                            });
                    });

                    ui.separator();
                    egui::ScrollArea::horizontal()
                        .id_salt("game_status_scroll")
                        .show(ui, |ui| {
                            ui.label(&self.status);
                        });
                });
            } else {
                ui.heading("SteamFlow");
                ui.label("Select a game from the sidebar.");
            }
        });

        self.draw_properties_modal(ctx);
        self.draw_uninstall_modal(ctx);
        self.draw_depot_browser_window(ctx);
        self.draw_platform_selection_modal(ctx);
        self.draw_launch_selector_modal(ctx);
        ctx.request_repaint();
    }
}
