use crate::config::{
    load_launcher_config, opensteam_image_cache_dir, save_launcher_config, LauncherConfig,
};
use crate::depot_browser::{DepotInfo, ManifestFileEntry};
use crate::install::{InstallPipeline, InstallStage, ProgressEvent};
use crate::library::{build_game_library, scan_installed_app_paths};
use crate::models::{
    DownloadProgress, DownloadProgressState, LibraryGame, SteamGuardReq, UserProfile,
};
use crate::steam_client::SteamClient;
use eframe::egui;
use egui::{ColorImage, TextureHandle};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
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
struct DepotBrowserState {
    app_id: u32,
    game_name: String,
    depots: Vec<DepotInfo>,
    selected_depot: Option<u32>,
    manifest_input: String,
    files: Vec<ManifestFileEntry>,
}

pub struct SteamLauncher {
    runtime: Runtime,
    pub client: SteamClient,
    pub library: Vec<LibraryGame>,
    pub image_cache: HashMap<AppId, TextureHandle>,
    pending_images: HashSet<AppId>,
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
    install_pipeline: InstallPipeline,
    install_log: Vec<String>,
    current_download_progress: Option<ProgressEvent>,
    download_receiver: Option<tokio::sync::mpsc::Receiver<DownloadProgress>>,
    active_download_appid: Option<u32>,
    live_download_progress: Option<DownloadProgress>,
    play_result_rx: Option<Receiver<String>>,
    show_settings: bool,
    launcher_config: LauncherConfig,
    proton_source: ProtonSource,
    steam_protons: Vec<String>,
    custom_protons: Vec<String>,
    user_profile: Option<UserProfile>,
    uninstall_modal: Option<UninstallModalState>,
    depot_browser: Option<DepotBrowserState>,
}

impl SteamLauncher {
    pub fn new(runtime: Runtime, client: SteamClient, library: Vec<LibraryGame>) -> Self {
        let (image_tx, image_rx) = mpsc::channel();
        let authenticated = client.is_authenticated();
        let launcher_config = runtime.block_on(load_launcher_config()).unwrap_or_default();
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
            install_pipeline: InstallPipeline::default(),
            install_log: Vec::new(),
            current_download_progress: None,
            download_receiver: None,
            active_download_appid: None,
            live_download_progress: None,
            play_result_rx: None,
            show_settings: false,
            launcher_config,
            proton_source: ProtonSource::Steam,
            steam_protons,
            custom_protons,
            user_profile,
            uninstall_modal: None,
            depot_browser: None,
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

            let path = cache_dir.join(format!("{appid}_library_600x900.jpg"));
            if tokio::fs::metadata(&path).await.is_err() {
                let candidates = [
                    (
                        format!(
                            "https://steamcdn-a.akamaihd.net/steam/apps/{appid}/library_600x900.jpg"
                        ),
                        path.clone(),
                    ),
                    (
                        format!("https://steamcdn-a.akamaihd.net/steam/apps/{appid}/header.jpg"),
                        cache_dir.join(format!("{appid}_header.jpg")),
                    ),
                    (
                        format!("https://steamcdn-a.akamaihd.net/steam/apps/{appid}/portrait.png"),
                        cache_dir.join(format!("{appid}_portrait.png")),
                    ),
                ];

                for (url, target_path) in candidates {
                    if let Ok(response) = reqwest::get(url).await {
                        if response.status().is_success() {
                            if let Ok(bytes) = response.bytes().await {
                                if tokio::fs::write(&target_path, bytes).await.is_ok() {
                                    let _ =
                                        tx.send((appid, target_path.to_string_lossy().to_string()));
                                    return;
                                }
                            }
                        }
                    }
                }
            }

            if tokio::fs::metadata(&path).await.is_ok() {
                let _ = tx.send((appid, path.to_string_lossy().to_string()));
            }
        });
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
                        self.status = format!(
                            "Downloading {}: {} / {} bytes",
                            progress.current_file, progress.bytes_downloaded, progress.total_bytes
                        );
                    }
                    DownloadProgressState::Completed => {
                        self.status = "Install completed".to_string();
                        if let Some(appid) = self.active_download_appid {
                            let installed_paths = self
                                .runtime
                                .block_on(scan_installed_app_paths())
                                .unwrap_or_default();

                            for g in &mut self.library {
                                if g.app_id == appid {
                                    g.install_path = installed_paths.get(&appid).cloned();
                                    g.is_installed = g.install_path.is_some();
                                }
                            }
                        }
                        should_clear_receiver = true;
                    }
                    DownloadProgressState::Failed => {
                        self.status = format!("Install failed: {}", progress.current_file);
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

    fn process_install_pipeline(&mut self) {
        for event in self.install_pipeline.tick() {
            self.install_log.push(format!(
                "App {} -> {:?}: {}",
                event.app_id, event.stage, event.message
            ));
            self.status = format!("Install pipeline: App {} {:?}", event.app_id, event.stage);
        }

        for progress in self.install_pipeline.take_progress_events() {
            self.current_download_progress = Some(progress.clone());
            self.status = format!(
                "Downloading {}: {} / {} bytes",
                progress.file_name, progress.bytes_downloaded, progress.total_bytes
            );
        }

        if self.install_log.len() > 8 {
            let drop_count = self.install_log.len() - 8;
            self.install_log.drain(0..drop_count);
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
        self.user_profile = self
            .runtime
            .block_on(self.client.get_user_profile(self.library.len()))
            .ok();
    }

    fn refresh_library(&mut self) {
        let owned = match self.runtime.block_on(self.client.fetch_owned_games()) {
            Ok(games) => games,
            Err(err) => {
                if self.client.is_offline() {
                    let cached = self
                        .runtime
                        .block_on(self.client.load_cached_owned_games())
                        .unwrap_or_default();
                    let installed = self
                        .runtime
                        .block_on(scan_installed_app_paths())
                        .unwrap_or_default();
                    self.library = build_game_library(cached, installed).games;
                    let _ = self
                        .runtime
                        .block_on(self.client.check_for_updates(&mut self.library));
                    self.status =
                        format!("OFFLINE MODE: loaded {} cached games", self.library.len());
                    self.refresh_user_profile();
                    return;
                }

                self.status = format!("Failed to refresh library: {err}");
                if SteamClient::is_auth_error_text(&err.to_string()) {
                    self.needs_reauth = true;
                    self.client.invalidate_session();
                }
                return;
            }
        };

        let installed = self
            .runtime
            .block_on(scan_installed_app_paths())
            .unwrap_or_default();
        self.library = build_game_library(owned, installed).games;
        let _ = self
            .runtime
            .block_on(self.client.check_for_updates(&mut self.library));
        self.status = format!("Library refreshed ({})", self.library.len());
        self.refresh_user_profile();
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

        let result = self.runtime.block_on(self.client.login(
            self.auth_username.trim().to_string(),
            self.auth_password.clone(),
            if self.auth_guard_code.trim().is_empty() {
                None
            } else {
                Some(self.auth_guard_code.trim().to_string())
            },
        ));

        match result {
            Ok(_) => {
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
            Err(err) => {
                if self.client.is_offline() {
                    self.needs_reauth = false;
                    self.status = "OFFLINE MODE".to_string();
                    self.refresh_library();
                } else {
                    self.status = format!("Login failed: {err}");
                    self.needs_reauth = true;
                }
            }
        }
    }

    fn handle_play_click(&mut self, game: &LibraryGame) {
        let proton_path = if self.proton_path_for_windows.trim().is_empty() {
            None
        } else {
            Some(self.proton_path_for_windows.trim().to_string())
        };

        let game = game.clone();
        let mut client = self.client.clone();
        let (tx, rx) = mpsc::channel();
        self.play_result_rx = Some(rx);
        self.status = format!("Syncing Cloud... {}", game.name);

        self.runtime.spawn(async move {
            let result = client
                .play_game(&game, proton_path.as_deref())
                .await
                .map(|info| format!("Upload Complete - {} ({})", game.name, info.app_id))
                .unwrap_or_else(|err| format!("Launch failed for {}: {err}", game.name));
            let _ = tx.send(result);
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
        let depots = self.runtime.block_on(self.client.fetch_depots(game.app_id));
        match depots {
            Ok(depots) => {
                let selected_depot = depots.first().map(|d| d.depot_id);
                let manifest_input = depots
                    .first()
                    .and_then(|d| d.public_manifest_id)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "public".to_string());
                self.depot_browser = Some(DepotBrowserState {
                    app_id: game.app_id,
                    game_name: game.name.clone(),
                    depots,
                    selected_depot,
                    manifest_input,
                    files: Vec::new(),
                });
            }
            Err(err) => {
                self.status = format!("Failed to load depots for {}: {err}", game.name);
            }
        }
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
            match self.client.uninstall_game(app_id, delete_prefix) {
                Ok(()) => {
                    if let Some(game) = self.library.iter_mut().find(|g| g.app_id == app_id) {
                        game.is_installed = false;
                        game.install_path = None;
                        game.update_available = false;
                        game.local_manifest_ids.clear();
                    }
                    self.status = format!("Uninstalled {game_name}");
                }
                Err(err) => {
                    self.status = format!("Failed to uninstall {game_name}: {err}");
                }
            }
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
            match self
                .runtime
                .block_on(self.client.fetch_manifest_files(appid, depot_id, &manifest))
            {
                Ok(files) => {
                    if let Some(state) = &mut self.depot_browser {
                        state.files = files;
                    }
                    self.status = format!("Loaded manifest {} for depot {}", manifest, depot_id);
                }
                Err(err) => {
                    self.status = format!("Failed to fetch manifest files: {err}");
                }
            }
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
        self.process_install_pipeline();
        self.poll_play_result();

        egui::TopBottomPanel::top("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status);
                ui.separator();
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

                    if ui.button("Save Settings").clicked() {
                        if self
                            .runtime
                            .block_on(save_launcher_config(&self.launcher_config))
                            .is_ok()
                        {
                            self.status = "Settings saved".to_string();
                        } else {
                            self.status = "Failed to save settings".to_string();
                        }
                    }

                    ui.separator();
                }

                ui.heading("Games");
                ui.checkbox(&mut self.show_installed_only, "Show Installed Only");
                ui.separator();

                let visible_games: Vec<(u32, String)> = self
                    .visible_games()
                    .into_iter()
                    .map(|g| (g.app_id, g.name.clone()))
                    .collect();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (app_id, name) in &visible_games {
                        let selected = self.selected_app == Some(*app_id);
                        let response = ui.selectable_label(selected, name);
                        if response.clicked() {
                            self.selected_app = Some(*app_id);
                        }

                        response.context_menu(|ui| {
                            if ui.button("Verify Integrity").clicked() {
                                match self.client.verify_game(*app_id) {
                                    Ok(rx) => {
                                        self.download_receiver = Some(rx);
                                        self.active_download_appid = Some(*app_id);
                                        self.status = format!("Started verify for app {}", app_id);
                                    }
                                    Err(err) => {
                                        self.status = format!("Failed to verify {}: {err}", app_id);
                                    }
                                }
                                ui.close();
                            }

                            ui.menu_button("Manage", |ui| {
                                if ui.button("Uninstall").clicked() {
                                    if let Some(game) = self.library.iter().find(|g| g.app_id == *app_id).cloned() {
                                        self.open_uninstall_modal(&game);
                                    }
                                    ui.close();
                                }
                            });

                            ui.menu_button("Advanced", |ui| {
                                if ui.button("Depot Browser").clicked() {
                                    if let Some(game) = self.library.iter().find(|g| g.app_id == *app_id).cloned() {
                                        self.open_depot_browser(&game);
                                    }
                                    ui.close();
                                }
                            });
                        });

                        if self
                            .library
                            .iter()
                            .find(|g| g.app_id == *app_id)
                            .map(|g| g.update_available)
                            .unwrap_or(false)
                        {
                            ui.colored_label(egui::Color32::from_rgb(66, 133, 244), "Update Available");
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

            if let Some(game) = self.selected_game().cloned() {
                self.ensure_image_requested(game.app_id);

                if let Some(texture) = self.image_cache.get(&game.app_id) {
                    ui.image(texture);
                } else {
                    ui.label("Loading cover...");
                    ui.add_space(8.0);
                }

                ui.heading(egui::RichText::new(game.name.clone()).size(30.0));
                ui.label(format!("AppID: {}", game.app_id));
                if let Some(job) =
                    self.install_pipeline.jobs().iter().find(|job| {
                        job.app_id == game.app_id && job.stage != InstallStage::Complete
                    })
                {
                    ui.label(format!(
                        "Install pipeline stage: {:?} ({}%)",
                        job.stage, job.progress_percent
                    ));
                }

                if let Some(progress) = &self.live_download_progress {
                    let denom = if progress.total_bytes == 0 {
                        1.0
                    } else {
                        progress.total_bytes as f32
                    };
                    let fraction = (progress.bytes_downloaded as f32 / denom).clamp(0.0, 1.0);
                    ui.add(
                        egui::ProgressBar::new(fraction)
                            .show_percentage()
                            .text(format!(
                                "Live install: {:?} - {} ({} / {} bytes)",
                                progress.state,
                                progress.current_file,
                                progress.bytes_downloaded,
                                progress.total_bytes
                            )),
                    );
                } else if let Some(progress) = &self.current_download_progress {
                    if progress.total_bytes > 0 {
                        let fraction =
                            progress.bytes_downloaded as f32 / progress.total_bytes as f32;
                        ui.add(
                            egui::ProgressBar::new(fraction.clamp(0.0, 1.0))
                                .show_percentage()
                                .text(format!(
                                    "{} ({} / {} bytes)",
                                    progress.file_name,
                                    progress.bytes_downloaded,
                                    progress.total_bytes
                                )),
                        );
                    }
                }

                ui.add_space(12.0);
                if game.is_installed {
                    ui.horizontal(|ui| {
                        let button = egui::Button::new(
                            egui::RichText::new("PLAY")
                                .color(egui::Color32::WHITE)
                                .strong(),
                        )
                        .fill(egui::Color32::from_rgb(46, 125, 50))
                        .min_size(egui::vec2(160.0, 42.0));

                        if ui.add(button).clicked() {
                            self.handle_play_click(&game);
                        }

                        if game.update_available {
                            let update_button = egui::Button::new(
                                egui::RichText::new("⬇ Update")
                                    .color(egui::Color32::WHITE)
                                    .strong(),
                            )
                            .fill(egui::Color32::from_rgb(33, 150, 243))
                            .min_size(egui::vec2(100.0, 42.0));

                            if ui
                                .add_enabled(!self.client.is_offline(), update_button)
                                .clicked()
                            {
                                match self.client.update_game(game.app_id) {
                                    Ok(rx) => {
                                        self.download_receiver = Some(rx);
                                        self.active_download_appid = Some(game.app_id);
                                        self.status =
                                            format!("Started update for app {}", game.app_id);
                                    }
                                    Err(err) => {
                                        self.status = format!(
                                            "Failed to start update for {}: {err}",
                                            game.app_id
                                        );
                                    }
                                }
                            }
                        }
                    });
                } else {
                    let button = egui::Button::new(
                        egui::RichText::new("INSTALL")
                            .color(egui::Color32::WHITE)
                            .strong(),
                    )
                    .fill(egui::Color32::from_rgb(33, 150, 243))
                    .min_size(egui::vec2(160.0, 42.0));

                    if self.client.is_offline() {
                        ui.label("Downloads disabled in offline mode.");
                    }
                    if ui.add_enabled(!self.client.is_offline(), button).clicked() {
                        self.install_pipeline.enqueue(game.app_id);
                        match self.client.install_game(game.app_id) {
                            Ok(rx) => {
                                self.download_receiver = Some(rx);
                                self.active_download_appid = Some(game.app_id);
                                self.status = format!("Started install for app {}", game.app_id);
                            }
                            Err(err) => {
                                self.status =
                                    format!("Failed to start install for {}: {err}", game.app_id);
                            }
                        }
                    }
                }
            } else {
                ui.heading("SteamFlow");
                ui.label("Select a game from the sidebar.");
            }
        });

        self.draw_uninstall_modal(ctx);
        self.draw_depot_browser_window(ctx);
        ctx.request_repaint();
    }
}
