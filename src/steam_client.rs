use crate::cloud_sync::{default_cloud_root, CloudClient};
use crate::cm_list::get_cm_endpoints;
use crate::config::{
    library_cache_path, load_launcher_config, load_library_cache, load_session, save_library_cache,
    save_session,
};
use crate::depot_browser::{self, DepotInfo, ManifestFileEntry};
use crate::download_pipeline::{
    self, should_keep_depot, AppInfoRoot, DepotPlatform, ManifestSelection,
};
use crate::models::{
    DownloadProgress, DownloadProgressState, LibraryGame, OwnedGame, SessionState, SteamGuardReq,
    UserProfile,
};
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::time::Instant;

use steam_vent::auth::{
    AuthConfirmationHandler, ConfirmationMethod, DeviceConfirmationHandler, FileGuardDataStore,
    UserProvidedAuthConfirmationHandler,
};
use steam_vent::connection::Connection;
use steam_vent::proto::steammessages_clientserver_appinfo::{
    cmsg_client_picsproduct_info_request, CMsgClientPICSProductInfoRequest,
    CMsgClientPICSProductInfoResponse,
};
use steam_vent::proto::steammessages_player_steamclient::{
    CPlayer_GetOwnedGames_Request, CPlayer_GetOwnedGames_Response,
};
use steam_vent::{ConnectionError, ConnectionTrait, ServerList};
use tokio::io::{duplex, sink, AsyncWriteExt};
use tokio::sync::mpsc::Receiver;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoginState {
    Connected,
    AwaitingCredentialSession,
    AwaitingGuardConfirmation,
    AwaitingPollResult,
    AwaitingAccessTokenLogon,
    Complete,
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchTarget {
    NativeLinux,
    WindowsProton,
}

#[derive(Debug, Clone)]
pub struct LaunchInfo {
    pub app_id: u32,
    pub executable: String,
    pub arguments: String,
    pub target: LaunchTarget,
}

#[derive(Debug, Clone)]
pub struct ConfirmationPrompt {
    pub requirement: SteamGuardReq,
    pub details: String,
}

#[derive(Clone)]
pub struct SteamClient {
    connection: Option<Connection>,
    state: LoginState,
    connected_at: Option<Instant>,
    active_cm: Option<SocketAddr>,
    server_list: Option<ServerList>,
    pending_confirmations: Vec<ConfirmationPrompt>,
}

impl SteamClient {
    pub fn new() -> Result<Self> {
        Ok(Self {
            connection: None,
            state: LoginState::Connected,
            connected_at: None,
            active_cm: None,
            server_list: None,
            pending_confirmations: Vec::new(),
        })
    }

    pub fn is_authenticated(&self) -> bool {
        self.connection.is_some()
    }

    pub fn is_offline(&self) -> bool {
        self.state == LoginState::Offline
    }

    pub fn pending_confirmations(&self) -> &[ConfirmationPrompt] {
        &self.pending_confirmations
    }

    pub fn clear_pending_confirmations(&mut self) {
        self.pending_confirmations.clear();
    }

    pub fn is_auth_error_text(message: &str) -> bool {
        let msg = message.to_ascii_lowercase();
        msg.contains("invalid access token")
            || msg.contains("not logged on")
            || msg.contains("apierror(notloggedon)")
            || msg.contains("expired")
            || msg.contains("session")
    }

    pub async fn connect(&mut self) -> Result<()> {
        match self.resolve_server_list().await {
            Ok(server_list) => {
                self.active_cm = Some(server_list.pick());
                self.connected_at = Some(Instant::now());
                self.state = LoginState::Connected;
                Ok(())
            }
            Err(err) => {
                if self.try_enter_offline_mode().await? {
                    tracing::warn!("Steam unavailable; entering offline mode");
                    return Ok(());
                }
                Err(err)
            }
        }
    }

    async fn resolve_server_list(&mut self) -> Result<ServerList> {
        if let Some(existing) = &self.server_list {
            return Ok(existing.clone());
        }

        match ServerList::discover().await {
            Ok(list) => {
                self.server_list = Some(list.clone());
                Ok(list)
            }
            Err(_) => {
                let tcp_servers = get_cm_endpoints().await;
                if tcp_servers.is_empty() {
                    bail!("failed to discover Steam CM servers and no fallback endpoints were available")
                }

                let ws_servers = tcp_servers
                    .iter()
                    .map(|entry| format!("{}:{}", entry.ip(), entry.port()))
                    .collect();

                let list = ServerList::new(tcp_servers, ws_servers)
                    .context("failed constructing fallback server list")?;
                self.server_list = Some(list.clone());
                Ok(list)
            }
        }
    }

    async fn try_enter_offline_mode(&mut self) -> Result<bool> {
        let cache_path = library_cache_path()?;
        if cache_path.exists() {
            self.state = LoginState::Offline;
            self.connection = None;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn invalidate_session(&mut self) {
        self.connection = None;
        self.state = LoginState::Connected;
    }

    pub fn connected_seconds(&self) -> Option<u64> {
        self.connected_at.map(|v| v.elapsed().as_secs())
    }

    pub fn active_cm(&self) -> Option<SocketAddr> {
        self.active_cm
    }

    pub async fn restore_session(&mut self) -> Result<SessionState> {
        let persisted = load_session().await?;
        let account_name = persisted
            .account_name
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow!("no persisted account_name found"))?;
        let refresh_token = persisted
            .refresh_token
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow!("no persisted refresh_token found"))?;

        self.connect().await?;
        if self.is_offline() {
            bail!("offline mode: using cached library");
        }
        self.state = LoginState::AwaitingAccessTokenLogon;

        let server_list = self.resolve_server_list().await?;
        let connection = Connection::access(&server_list, &account_name, &refresh_token)
            .await
            .context("refresh token login failed")?;

        self.connection = Some(connection);
        let session = self
            .session_from_connection(account_name)
            .context("refresh token login succeeded but no token was available for persistence")?;
        save_session(&session).await?;
        self.state = LoginState::Complete;
        self.pending_confirmations.clear();
        Ok(session)
    }

    pub async fn login(
        &mut self,
        account_name: String,
        password: String,
        guard_code: Option<String>,
    ) -> Result<SessionState> {
        self.connect().await?;
        if self.is_offline() {
            bail!("offline mode: using cached library");
        }

        self.state = LoginState::AwaitingCredentialSession;
        let server_list = self.resolve_server_list().await?;

        self.state = LoginState::AwaitingGuardConfirmation;
        self.state = LoginState::AwaitingPollResult;
        self.state = LoginState::AwaitingAccessTokenLogon;

        let login_result = if let Some(code) = guard_code.filter(|v| !v.trim().is_empty()) {
            let (mut writer, reader) = duplex(64);
            writer
                .write_all(format!("{}\n", code.trim()).as_bytes())
                .await
                .context("failed to prepare guard code input")?;
            drop(writer);

            let handler = UserProvidedAuthConfirmationHandler::new(reader, sink())
                .or(DeviceConfirmationHandler);

            Connection::login(
                &server_list,
                &account_name,
                &password,
                FileGuardDataStore::user_cache(),
                handler,
            )
            .await
        } else {
            Connection::login(
                &server_list,
                &account_name,
                &password,
                FileGuardDataStore::user_cache(),
                DeviceConfirmationHandler,
            )
            .await
        };

        let connection = match login_result {
            Ok(connection) => connection,
            Err(ConnectionError::UnsupportedConfirmationAction(methods)) => {
                self.pending_confirmations =
                    methods.iter().map(map_confirmation).collect::<Vec<_>>();
                bail!("Steam Guard confirmation required")
            }
            Err(other) => return Err(anyhow!(other)).context("steam-vent login flow failed"),
        };

        self.connection = Some(connection);
        let session = self
            .session_from_connection(account_name)
            .context("login succeeded but no token was available for persistence")?;
        save_session(&session).await?;
        self.state = LoginState::Complete;
        self.pending_confirmations.clear();
        Ok(session)
    }

    fn session_from_connection(&self, account_name: String) -> Option<SessionState> {
        let connection = self.connection.as_ref()?;
        let steam_id = u64::from(connection.steam_id());
        Some(SessionState {
            account_name: Some(account_name),
            steam_id: Some(steam_id),
            refresh_token: connection.access_token().map(ToString::to_string),
            client_instance_id: None,
        })
    }

    pub async fn get_available_platforms(&mut self, appid: u32) -> Result<Vec<DepotPlatform>> {
        let connection = self
            .connection
            .as_ref()
            .context("steam connection not initialized")?;

        let mut request = CMsgClientPICSProductInfoRequest::new();
        request
            .apps
            .push(cmsg_client_picsproduct_info_request::AppInfo {
                appid: Some(appid),
                ..Default::default()
            });

        let response: CMsgClientPICSProductInfoResponse = connection
            .job(request)
            .await
            .context("failed requesting appinfo product info")?;

        let app = response
            .apps
            .iter()
            .find(|entry| entry.appid() == appid)
            .ok_or_else(|| anyhow!("missing app info payload for app {appid}"))?;

        let appinfo_vdf = String::from_utf8_lossy(app.buffer()).to_string();
        let parsed: AppInfoRoot =
            keyvalues_serde::from_str(&appinfo_vdf).context("failed parsing appinfo VDF")?;
        let depots = parsed
            .appinfo
            .map(|node| node.depots)
            .unwrap_or(parsed.depots);

        let mut has_linux = false;
        let mut has_windows = false;

        for node in depots.values() {
            if let Some(config) = &node.config {
                if let Some(oslist) = &config.oslist {
                    let oslist = oslist.to_lowercase();
                    if oslist.contains("linux") {
                        has_linux = true;
                    }
                    if oslist.contains("windows") {
                        has_windows = true;
                    }
                }
            }
        }

        let mut platforms = Vec::new();
        if has_windows {
            platforms.push(DepotPlatform::Windows);
        }
        if has_linux {
            platforms.push(DepotPlatform::Linux);
        }

        if platforms.is_empty() {
            platforms.push(DepotPlatform::Windows);
        }

        Ok(platforms)
    }

    pub fn install_game(
        &self,
        appid: u32,
        platform: DepotPlatform,
    ) -> Result<Receiver<DownloadProgress>> {
        let connection = self
            .connection
            .as_ref()
            .cloned()
            .context("steam connection not initialized")?;

        let cfg = tokio::runtime::Handle::current().block_on(load_launcher_config())?;
        let library_root = cfg.steam_library_path.clone();
        let game_name = self.resolve_install_game_name(appid);
        let install_dir = Path::new(&library_root)
            .join("steamapps")
            .join("common")
            .join(&game_name);
        std::fs::create_dir_all(&install_dir)
            .with_context(|| format!("failed creating {}", install_dir.display()))?;
        let manifest_path = Path::new(&library_root)
            .join("steamapps")
            .join(format!("appmanifest_{appid}.acf"));

        let (tx, rx) = tokio::sync::mpsc::channel(128);

        tokio::task::spawn(async move {
            let _ = tx
                .send(DownloadProgress {
                    state: DownloadProgressState::Queued,
                    bytes_downloaded: 0,
                    total_bytes: 0,
                    current_file: String::new(),
                })
                .await;

            let mut request = CMsgClientPICSProductInfoRequest::new();
            request
                .apps
                .push(cmsg_client_picsproduct_info_request::AppInfo {
                    appid: Some(appid),
                    ..Default::default()
                });

            let response: CMsgClientPICSProductInfoResponse = match connection.job(request).await {
                Ok(res) => res,
                Err(e) => {
                    let _ = tx
                        .send(DownloadProgress {
                            state: DownloadProgressState::Failed,
                            bytes_downloaded: 0,
                            total_bytes: 0,
                            current_file: format!("failed requesting appinfo: {e}"),
                        })
                        .await;
                    return;
                }
            };

            let app = response.apps.iter().find(|entry| entry.appid() == appid);
            let Some(app) = app else {
                let _ = tx
                    .send(DownloadProgress {
                        state: DownloadProgressState::Failed,
                        bytes_downloaded: 0,
                        total_bytes: 0,
                        current_file: "missing appinfo payload".to_string(),
                    })
                    .await;
                return;
            };

            let appinfo_vdf = String::from_utf8_lossy(app.buffer()).to_string();
            let parsed: AppInfoRoot = match keyvalues_serde::from_str(&appinfo_vdf) {
                Ok(p) => p,
                Err(e) => {
                    let _ = tx
                        .send(DownloadProgress {
                            state: DownloadProgressState::Failed,
                            bytes_downloaded: 0,
                            total_bytes: 0,
                            current_file: format!("failed parsing appinfo: {e}"),
                        })
                        .await;
                    return;
                }
            };

            let depots = parsed
                .appinfo
                .map(|node| node.depots)
                .unwrap_or(parsed.depots);

            let mut selections = Vec::new();
            for (depot_id_str, node) in depots {
                if !depot_id_str.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }

                let oslist = node.config.as_ref().and_then(|c| c.oslist.as_deref());
                if !should_keep_depot(oslist, platform) {
                    continue;
                }

                if let Some(manifests) = node.manifests {
                    if let Some(gid_text) = manifests.public {
                        if let (Ok(d_id), Ok(m_id)) = (depot_id_str.parse::<u32>(), gid_text.parse::<u64>()) {
                            selections.push(ManifestSelection {
                                app_id: appid,
                                depot_id: d_id,
                                manifest_id: m_id,
                                appinfo_vdf: appinfo_vdf.clone(),
                            });
                        }
                    }
                }
            }

            if selections.is_empty() {
                let _ = tx
                    .send(DownloadProgress {
                        state: DownloadProgressState::Failed,
                        bytes_downloaded: 0,
                        total_bytes: 0,
                        current_file: "no matching depots found for platform".to_string(),
                    })
                    .await;
                return;
            }

            let _ = tx
                .send(DownloadProgress {
                    state: DownloadProgressState::Downloading,
                    bytes_downloaded: 0,
                    total_bytes: 0,
                    current_file: format!("starting download of {} depots", selections.len()),
                })
                .await;

            let result = download_pipeline::execute_multi_depot_download_async(
                &connection,
                appid,
                selections,
                install_dir,
                None,
            )
            .await;

            match result {
                Ok(()) => {
                    if let Err(err) =
                        SteamClient::write_basic_appmanifest(&manifest_path, appid, &game_name)
                    {
                        tracing::warn!("failed writing appmanifest for {}: {}", appid, err);
                    }
                    let _ = tx
                        .send(DownloadProgress {
                            state: DownloadProgressState::Completed,
                            bytes_downloaded: 1,
                            total_bytes: 1,
                            current_file: "completed".to_string(),
                        })
                        .await;
                }
                Err(err) => {
                    let _ = tx
                        .send(DownloadProgress {
                            state: DownloadProgressState::Failed,
                            bytes_downloaded: 0,
                            total_bytes: 0,
                            current_file: err.to_string(),
                        })
                        .await;
                }
            }
        });

        Ok(rx)
    }

    pub fn uninstall_game(&self, appid: u32, delete_prefix: bool) -> Result<()> {
        let cfg = tokio::runtime::Handle::current().block_on(load_launcher_config())?;
        let steamapps = PathBuf::from(cfg.steam_library_path).join("steamapps");
        let appmanifest = steamapps.join(format!("appmanifest_{appid}.acf"));

        let install_dir = if appmanifest.exists() {
            let raw = std::fs::read_to_string(&appmanifest)
                .with_context(|| format!("failed reading {}", appmanifest.display()))?;
            parse_installdir_from_acf(&raw)
                .map(|dir| steamapps.join("common").join(dir))
                .unwrap_or_else(|| steamapps.join("common").join(appid.to_string()))
        } else {
            steamapps.join("common").join(appid.to_string())
        };

        if install_dir.exists() {
            std::fs::remove_dir_all(&install_dir)
                .with_context(|| format!("failed deleting {}", install_dir.display()))?;
        }

        if appmanifest.exists() {
            std::fs::remove_file(&appmanifest)
                .with_context(|| format!("failed deleting {}", appmanifest.display()))?;
        }

        if delete_prefix {
            let compat = steamapps.join("compatdata").join(appid.to_string());
            if compat.exists() {
                std::fs::remove_dir_all(&compat)
                    .with_context(|| format!("failed deleting {}", compat.display()))?;
            }
        }

        Ok(())
    }

    pub async fn fetch_depots(&self, appid: u32) -> Result<Vec<DepotInfo>> {
        let connection = self
            .connection
            .as_ref()
            .context("steam connection not initialized")?;
        depot_browser::fetch_depots(connection, appid).await
    }

    pub async fn fetch_manifest_files(
        &self,
        appid: u32,
        depot_id: u32,
        manifest_ref: &str,
    ) -> Result<Vec<ManifestFileEntry>> {
        let connection = self
            .connection
            .as_ref()
            .context("steam connection not initialized")?;
        depot_browser::fetch_manifest_files(connection, appid, depot_id, manifest_ref).await
    }

    pub fn download_single_file(
        &self,
        appid: u32,
        depot_id: u32,
        manifest_ref: &str,
        file_path: &str,
        output_dir: &Path,
    ) -> Result<()> {
        let connection = self
            .connection
            .as_ref()
            .context("steam connection not initialized")?;
        depot_browser::download_single_file(
            connection,
            appid,
            depot_id,
            manifest_ref,
            file_path,
            output_dir,
        )
    }

    pub async fn fetch_owned_games(&mut self) -> Result<Vec<OwnedGame>> {
        let connection = self
            .connection
            .as_ref()
            .context("steam connection not initialized")?;

        let request = CPlayer_GetOwnedGames_Request {
            steamid: Some(u64::from(connection.steam_id())),
            include_appinfo: Some(true),
            include_played_free_games: Some(true),
            ..Default::default()
        };

        let response: CPlayer_GetOwnedGames_Response = connection
            .service_method(request)
            .await
            .context("failed calling Player.GetOwnedGames")?;

        let mut owned = Vec::new();
        for game in response.games {
            owned.push(OwnedGame {
                app_id: game.appid() as u32,
                name: if game.name().is_empty() {
                    format!("App {}", game.appid())
                } else {
                    game.name().to_string()
                },
                playtime_forever_minutes: game.playtime_forever() as u32,
                local_manifest_ids: HashMap::new(),
                update_available: false,
            });
        }

        save_library_cache(&owned).await.ok();
        Ok(owned)
    }

    pub async fn refresh_owned_games(&mut self, _session: &SessionState) -> Result<Vec<OwnedGame>> {
        self.fetch_owned_games().await
    }

    pub async fn load_cached_owned_games(&self) -> Result<Vec<OwnedGame>> {
        load_library_cache().await
    }

    pub async fn check_for_updates(&self, games: &mut [LibraryGame]) -> Result<()> {
        for game in games.iter_mut() {
            game.update_available = false;
            game.local_manifest_ids.clear();

            if !game.is_installed {
                continue;
            }

            let local = self.local_manifest_ids(game)?;
            game.local_manifest_ids = local.clone();

            if self.is_offline() || self.connection.is_none() {
                continue;
            }

            let remote = self
                .remote_manifest_ids(game.app_id)
                .await
                .unwrap_or_default();
            if remote.is_empty() {
                continue;
            }

            game.update_available = remote.iter().any(|(depot, remote_manifest)| {
                local.get(depot).copied().unwrap_or_default() != *remote_manifest
            });
        }

        Ok(())
    }

    fn local_manifest_ids(&self, game: &LibraryGame) -> Result<HashMap<u64, u64>> {
        let install_path = match &game.install_path {
            Some(path) => PathBuf::from(path),
            None => return Ok(HashMap::new()),
        };

        let steamapps = match install_path.parent().and_then(|p| p.parent()) {
            Some(path) => path.to_path_buf(),
            None => return Ok(HashMap::new()),
        };

        let manifest_path = steamapps.join(format!("appmanifest_{}.acf", game.app_id));
        if !manifest_path.exists() {
            return Ok(HashMap::new());
        }

        let raw = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("failed reading {}", manifest_path.display()))?;
        Ok(parse_installed_depots_from_acf(&raw))
    }

    async fn remote_manifest_ids(&self, appid: u32) -> Result<HashMap<u64, u64>> {
        let connection = self
            .connection
            .as_ref()
            .context("steam connection not initialized")?;

        let mut request = CMsgClientPICSProductInfoRequest::new();
        request
            .apps
            .push(cmsg_client_picsproduct_info_request::AppInfo {
                appid: Some(appid),
                ..Default::default()
            });

        let response: CMsgClientPICSProductInfoResponse = connection
            .job(request)
            .await
            .context("failed requesting appinfo product info for update metadata")?;

        let app = response
            .apps
            .iter()
            .find(|entry| entry.appid() == appid)
            .ok_or_else(|| anyhow!("missing appinfo payload for app {appid}"))?;

        let raw_vdf = String::from_utf8_lossy(app.buffer()).to_string();
        Ok(parse_remote_depot_manifests_from_vdf(&raw_vdf))
    }

    pub async fn get_user_profile(&self, current_library_len: usize) -> Result<UserProfile> {
        let persisted = load_session().await.unwrap_or_default();
        let account_name = persisted
            .account_name
            .unwrap_or_else(|| "Unknown User".to_string());

        if self.is_offline() {
            let cached_games = load_library_cache().await.unwrap_or_default();
            return Ok(UserProfile {
                steam_id: persisted.steam_id.unwrap_or_default(),
                account_name,
                game_count: cached_games.len(),
                is_online: false,
            });
        }

        let steam_id = self
            .connection
            .as_ref()
            .map(|connection| u64::from(connection.steam_id()))
            .or(persisted.steam_id)
            .unwrap_or_default();

        Ok(UserProfile {
            steam_id,
            account_name,
            game_count: current_library_len,
            is_online: true,
        })
    }

    pub async fn get_product_info(&mut self, appid: u32) -> Result<LaunchInfo> {
        let connection = self
            .connection
            .as_ref()
            .context("steam connection not initialized")?;

        let mut request = CMsgClientPICSProductInfoRequest::new();
        request
            .apps
            .push(cmsg_client_picsproduct_info_request::AppInfo {
                appid: Some(appid),
                ..Default::default()
            });

        let response: CMsgClientPICSProductInfoResponse = connection
            .job(request)
            .await
            .context("failed requesting appinfo product info for launch metadata")?;

        let app = response
            .apps
            .iter()
            .find(|entry| entry.appid() == appid)
            .ok_or_else(|| anyhow!("missing appinfo payload for app {appid}"))?;

        let raw_vdf = String::from_utf8_lossy(app.buffer()).to_string();
        if raw_vdf.trim().is_empty() {
            bail!("empty appinfo payload returned for app {appid}")
        }

        let launch_info = parse_launch_info_from_vdf(appid, &raw_vdf)
            .context("failed to parse launch metadata from PICS appinfo")?;

        println!("DEBUG PICS: {:#?}", launch_info);
        Ok(launch_info)
    }

    pub async fn play_game(
        &mut self,
        app: &LibraryGame,
        proton_path: Option<&str>,
    ) -> Result<LaunchInfo> {
        let launch_info = self.get_product_info(app.app_id).await?;

        let launcher_config = load_launcher_config().await.unwrap_or_default();
        let chosen_proton_path = match launch_info.target {
            LaunchTarget::NativeLinux => None,
            LaunchTarget::WindowsProton => {
                proton_path.or(Some(launcher_config.proton_version.as_str()))
            }
        };

        let cloud_enabled = launcher_config.enable_cloud_sync && !self.is_offline();
        let mut cloud_client = None;
        let mut local_root = None;

        if cloud_enabled {
            let client = CloudClient::new(
                self.connection
                    .as_ref()
                    .cloned()
                    .context("steam connection not initialized")?,
            );
            let root = default_cloud_root(client.steam_id(), app.app_id)?;
            tracing::info!(appid = app.app_id, path = %root.display(), "Syncing Cloud...");
            client.sync_down(app.app_id, &root).await?;
            cloud_client = Some(client);
            local_root = Some(root);
        }

        let mut child = self.spawn_game_process(app, &launch_info, chosen_proton_path)?;
        child
            .wait()
            .context("failed waiting for game process exit")?;

        if let (Some(client), Some(root)) = (cloud_client.as_ref(), local_root.as_ref()) {
            client.sync_up(app.app_id, root).await?;
            tracing::info!(appid = app.app_id, "Upload Complete");
        }

        Ok(launch_info)
    }

    pub fn launch_game(
        &self,
        app: &LibraryGame,
        launch_info: &LaunchInfo,
        proton_path: Option<&str>,
    ) -> Result<()> {
        self.spawn_game_process(app, launch_info, proton_path)?;
        Ok(())
    }

    pub fn update_game(&self, appid: u32) -> Result<Receiver<DownloadProgress>> {
        self.start_manifest_download(appid, false)
    }

    pub fn verify_game(&self, appid: u32) -> Result<Receiver<DownloadProgress>> {
        self.start_manifest_download(appid, true)
    }

    fn start_manifest_download(
        &self,
        appid: u32,
        smart_verify_existing: bool,
    ) -> Result<Receiver<DownloadProgress>> {
        let connection = self
            .connection
            .as_ref()
            .cloned()
            .context("steam connection not initialized")?;

        let install_root = self.install_root_for_app(appid)?;
        let manifest_path = self.appmanifest_path(appid)?;
        let (tx, rx) = tokio::sync::mpsc::channel(128);

        let local_manifests = self.local_manifest_ids_for_appid(appid).unwrap_or_default();

        tokio::task::spawn(async move {
            let _ = tx
                .send(DownloadProgress {
                    state: DownloadProgressState::Queued,
                    bytes_downloaded: 0,
                    total_bytes: 0,
                    current_file: if smart_verify_existing {
                        "verifying installed chunks".to_string()
                    } else {
                        "resolving latest manifest".to_string()
                    },
                })
                .await;

            let remote_manifests = if smart_verify_existing {
                local_manifests.clone()
            } else {
                SteamClient::remote_manifest_ids_static(&connection, appid)
                    .await
                    .unwrap_or_default()
            };

            let selected = if smart_verify_existing {
                local_manifests.iter().next().map(|(d, m)| (*d as u32, *m))
            } else {
                remote_manifests.iter().next().map(|(d, m)| (*d as u32, *m))
            };

            let Some((depot_id, manifest_id)) = selected else {
                let _ = tx
                    .send(DownloadProgress {
                        state: DownloadProgressState::Failed,
                        bytes_downloaded: 0,
                        total_bytes: 0,
                        current_file: "no manifest/depot available for download".to_string(),
                    })
                    .await;
                return;
            };

            let result = tokio::task::spawn_blocking(move || {
                download_pipeline::execute_download_with_manifest_id(
                    &connection,
                    appid,
                    depot_id,
                    manifest_id,
                    &install_root,
                    smart_verify_existing,
                )
            })
            .await;

            match result {
                Ok(Ok(())) => {
                    if !smart_verify_existing {
                        let _ = SteamClient::write_manifest_ids_at_path(
                            &manifest_path,
                            &remote_manifests,
                        );
                    }
                    let _ = tx
                        .send(DownloadProgress {
                            state: DownloadProgressState::Completed,
                            bytes_downloaded: 1,
                            total_bytes: 1,
                            current_file: if smart_verify_existing {
                                "verify completed".to_string()
                            } else {
                                "update completed".to_string()
                            },
                        })
                        .await;
                }
                Ok(Err(err)) => {
                    let _ = tx
                        .send(DownloadProgress {
                            state: DownloadProgressState::Failed,
                            bytes_downloaded: 0,
                            total_bytes: 0,
                            current_file: err.to_string(),
                        })
                        .await;
                }
                Err(err) => {
                    let _ = tx
                        .send(DownloadProgress {
                            state: DownloadProgressState::Failed,
                            bytes_downloaded: 0,
                            total_bytes: 0,
                            current_file: format!("download task join failure: {err}"),
                        })
                        .await;
                }
            }
        });

        Ok(rx)
    }

    fn appmanifest_path(&self, appid: u32) -> Result<PathBuf> {
        let cfg = tokio::runtime::Handle::current().block_on(load_launcher_config())?;
        Ok(PathBuf::from(cfg.steam_library_path)
            .join("steamapps")
            .join(format!("appmanifest_{appid}.acf")))
    }

    fn local_manifest_ids_for_appid(&self, appid: u32) -> Result<HashMap<u64, u64>> {
        let manifest_path = self.appmanifest_path(appid)?;
        if !manifest_path.exists() {
            return Ok(HashMap::new());
        }
        let raw = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("failed reading {}", manifest_path.display()))?;
        Ok(parse_installed_depots_from_acf(&raw))
    }

    fn install_root_for_app(&self, appid: u32) -> Result<PathBuf> {
        let manifest_path = self.appmanifest_path(appid)?;
        let steamapps = manifest_path
            .parent()
            .ok_or_else(|| anyhow!("invalid steamapps path for app {appid}"))?
            .to_path_buf();

        if manifest_path.exists() {
            let raw = std::fs::read_to_string(&manifest_path)
                .with_context(|| format!("failed reading {}", manifest_path.display()))?;
            if let Some(installdir) = parse_installdir_from_acf(&raw) {
                return Ok(steamapps.join("common").join(installdir));
            }
        }

        Ok(PathBuf::from(
            tokio::runtime::Handle::current()
                .block_on(load_launcher_config())?
                .steam_library_path,
        )
        .join("steamapps")
        .join("common")
        .join(appid.to_string()))
    }

    async fn remote_manifest_ids_static(
        connection: &Connection,
        appid: u32,
    ) -> Result<HashMap<u64, u64>> {
        let mut request = CMsgClientPICSProductInfoRequest::new();
        request
            .apps
            .push(cmsg_client_picsproduct_info_request::AppInfo {
                appid: Some(appid),
                ..Default::default()
            });

        let response: CMsgClientPICSProductInfoResponse = connection
            .job(request)
            .await
            .context("failed requesting appinfo product info for update metadata")?;

        let app = response
            .apps
            .iter()
            .find(|entry| entry.appid() == appid)
            .ok_or_else(|| anyhow!("missing appinfo payload for app {appid}"))?;

        let raw_vdf = String::from_utf8_lossy(app.buffer()).to_string();
        Ok(parse_remote_depot_manifests_from_vdf(&raw_vdf))
    }

    fn write_manifest_ids_at_path(path: &Path, new_manifest_ids: &HashMap<u64, u64>) -> Result<()> {
        if !path.exists() || new_manifest_ids.is_empty() {
            return Ok(());
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed reading {}", path.display()))?;
        let rewritten = rewrite_installed_manifest_ids(&raw, new_manifest_ids);
        std::fs::write(path, rewritten)
            .with_context(|| format!("failed writing {}", path.display()))?;
        Ok(())
    }

    fn resolve_install_game_name(&self, appid: u32) -> String {
        tokio::runtime::Handle::current()
            .block_on(load_library_cache())
            .ok()
            .and_then(|games| {
                games
                    .into_iter()
                    .find(|g| g.app_id == appid)
                    .map(|g| g.name)
            })
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| format!("App {appid}"))
    }

    fn write_basic_appmanifest(path: &Path, appid: u32, game_name: &str) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }

        let installdir = sanitize_install_dir(game_name);
        let game_name = game_name.replace('"', "");
        let content = format!(
            "\"AppState\"\n{{\n\t\"appid\"\t\"{appid}\"\n\t\"name\"\t\"{game_name}\"\n\t\"StateFlags\"\t\"4\"\n\t\"installdir\"\t\"{installdir}\"\n}}\n"
        );

        std::fs::write(path, content)
            .with_context(|| format!("failed writing {}", path.display()))?;
        Ok(())
    }

    fn spawn_game_process(
        &self,
        app: &LibraryGame,
        launch_info: &LaunchInfo,
        proton_path: Option<&str>,
    ) -> Result<std::process::Child> {
        let install_dir = PathBuf::from(
            app.install_path
                .clone()
                .ok_or_else(|| anyhow!("game {} is not installed", app.app_id))?,
        );

        let executable = install_dir.join(&launch_info.executable);
        let args = split_args(&launch_info.arguments);

        match launch_info.target {
            LaunchTarget::NativeLinux => {
                let mut cmd = Command::new(&executable);
                cmd.args(args);

                let bin_dir = executable.parent().unwrap_or_else(|| Path::new("."));
                let existing_ld = std::env::var("LD_LIBRARY_PATH").unwrap_or_default();
                let new_ld = if existing_ld.is_empty() {
                    bin_dir.to_string_lossy().to_string()
                } else {
                    format!("{}:{}", bin_dir.to_string_lossy(), existing_ld)
                };
                cmd.env("LD_LIBRARY_PATH", new_ld);

                cmd.spawn().context("failed to spawn native linux game")
            }
            LaunchTarget::WindowsProton => {
                let proton = proton_path
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| anyhow!("proton path is required for Windows launch"))?;

                let launcher_config = match tokio::runtime::Handle::try_current() {
                    Ok(handle) => handle.block_on(load_launcher_config()).unwrap_or_default(),
                    Err(_) => crate::config::LauncherConfig::default(),
                };

                let compat_data_path = if launcher_config.use_shared_compat_data {
                    PathBuf::from(launcher_config.steam_library_path)
                        .join("steamapps/compatdata")
                        .join(app.app_id.to_string())
                } else {
                    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                    PathBuf::from(home)
                        .join(".local/share/SteamFlow/compatdata")
                        .join(app.app_id.to_string())
                };
                std::fs::create_dir_all(&compat_data_path)
                    .with_context(|| format!("failed creating {}", compat_data_path.display()))?;

                let mut cmd = Command::new(proton);
                cmd.arg("run").arg(&executable).args(args);
                cmd.env("SteamAppId", app.app_id.to_string());
                cmd.env("STEAM_COMPAT_DATA_PATH", compat_data_path);
                cmd.spawn().context("failed to spawn proton game")
            }
        }
    }
}

fn sanitize_install_dir(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        })
        .collect();
    sanitized.trim().to_string()
}

fn map_confirmation(method: &ConfirmationMethod) -> ConfirmationPrompt {
    let details = method.confirmation_details().to_string();
    let requirement = match method.confirmation_type() {
        "email" => SteamGuardReq::EmailCode {
            domain_hint: details.clone(),
        },
        "device code" => SteamGuardReq::DeviceCode,
        "device confirmation" => SteamGuardReq::DeviceConfirmation,
        _ => SteamGuardReq::DeviceConfirmation,
    };

    ConfirmationPrompt {
        requirement,
        details,
    }
}

fn parse_launch_info_from_vdf(appid: u32, raw_vdf: &str) -> Result<LaunchInfo> {
    let parsed: ProductInfoEnvelope =
        keyvalues_serde::from_str(raw_vdf).context("failed to parse product info VDF")?;

    let config = parsed
        .appinfo
        .and_then(|appinfo| appinfo.config)
        .or(parsed.config)
        .ok_or_else(|| anyhow!("missing config section in product info for app {appid}"))?;

    println!("AppInfo Config: {:?}", config);

    if config.launch.is_empty() {
        bail!("no launch entries found for app {appid}")
    }

    let mut chosen = None;
    for section in config.launch.values() {
        let oslist = section.oslist.as_deref().unwrap_or_default();
        if oslist.to_ascii_lowercase().contains("linux") {
            chosen = Some((section, LaunchTarget::NativeLinux));
            break;
        }
    }

    if chosen.is_none() {
        for section in config.launch.values() {
            let oslist = section.oslist.as_deref().unwrap_or_default();
            if oslist.to_ascii_lowercase().contains("windows") {
                chosen = Some((section, LaunchTarget::WindowsProton));
                break;
            }
        }
    }

    let (section, target) =
        chosen.ok_or_else(|| anyhow!("no linux/windows launch option found"))?;

    Ok(LaunchInfo {
        app_id: appid,
        executable: section.executable.clone().unwrap_or_default(),
        arguments: section.arguments.clone().unwrap_or_default(),
        target,
    })
}

#[derive(Debug, Deserialize)]
struct ProductInfoEnvelope {
    #[serde(default)]
    appinfo: Option<ProductInfoAppInfo>,
    #[serde(default)]
    config: Option<ProductInfoConfig>,
}

#[derive(Debug, Deserialize)]
struct ProductInfoAppInfo {
    #[serde(default)]
    config: Option<ProductInfoConfig>,
}

#[derive(Debug, Deserialize)]
struct ProductInfoConfig {
    #[serde(default)]
    launch: HashMap<String, ProductLaunchEntry>,
}

#[derive(Debug, Deserialize)]
struct ProductLaunchEntry {
    #[serde(default)]
    executable: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
    #[serde(default)]
    oslist: Option<String>,
}

fn parse_installdir_from_acf(raw: &str) -> Option<String> {
    for line in raw.lines() {
        let quoted = extract_quoted_values(line.trim());
        if quoted.len() >= 2 && quoted[0] == "installdir" {
            return Some(quoted[1].clone());
        }
    }
    None
}

fn rewrite_installed_manifest_ids(raw: &str, updated: &HashMap<u64, u64>) -> String {
    let mut out = Vec::new();
    let mut in_installed_depots = false;
    let mut current_depot: Option<u64> = None;

    for line in raw.lines() {
        let trimmed = line.trim();

        if trimmed.contains("\"InstalledDepots\"") {
            in_installed_depots = true;
            out.push(line.to_string());
            continue;
        }

        if in_installed_depots && trimmed == "}" {
            if current_depot.is_some() {
                current_depot = None;
                out.push(line.to_string());
                continue;
            }
            in_installed_depots = false;
            out.push(line.to_string());
            continue;
        }

        if in_installed_depots {
            let quoted = extract_quoted_values(trimmed);
            if quoted.len() == 1 {
                current_depot = quoted[0].parse::<u64>().ok();
                out.push(line.to_string());
                continue;
            }

            if quoted.len() >= 2 && quoted[0] == "manifest" {
                if let Some(depot_id) = current_depot {
                    if let Some(new_manifest) = updated.get(&depot_id) {
                        let indent = line
                            .chars()
                            .take_while(|ch| ch.is_whitespace())
                            .collect::<String>();
                        out.push(format!(r#"{indent}"manifest"	"{new_manifest}""#));
                        continue;
                    }
                }
            }
        }

        out.push(line.to_string());
    }

    format!("{}\n", out.join("\n"))
}

fn parse_installed_depots_from_acf(raw: &str) -> HashMap<u64, u64> {
    let mut manifests = HashMap::new();
    let mut in_installed_depots = false;
    let mut current_depot: Option<u64> = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.contains("\"InstalledDepots\"") {
            in_installed_depots = true;
            continue;
        }

        if !in_installed_depots {
            continue;
        }

        if trimmed == "}" {
            if current_depot.is_some() {
                current_depot = None;
                continue;
            }
            break;
        }

        let quoted = extract_quoted_values(trimmed);
        if quoted.len() == 1 {
            if let Ok(depot_id) = u64::from_str(&quoted[0]) {
                current_depot = Some(depot_id);
            }
        } else if quoted.len() >= 2 && quoted[0] == "manifest" && current_depot.is_some() {
            if let Ok(manifest) = u64::from_str(&quoted[1]) {
                manifests.insert(current_depot.unwrap_or_default(), manifest);
            }
        }
    }

    manifests
}

fn parse_remote_depot_manifests_from_vdf(raw: &str) -> HashMap<u64, u64> {
    let mut manifests = HashMap::new();
    let mut in_depots = false;
    let mut current_depot: Option<u64> = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.contains("\"depots\"") {
            in_depots = true;
            continue;
        }

        if !in_depots {
            continue;
        }

        if trimmed == "}" {
            current_depot = None;
            continue;
        }

        let quoted = extract_quoted_values(trimmed);
        if quoted.is_empty() {
            continue;
        }

        if quoted.len() == 1 {
            if let Ok(depot_id) = u64::from_str(&quoted[0]) {
                current_depot = Some(depot_id);
            }
        } else if quoted.len() >= 2
            && (quoted[0] == "public" || quoted[0] == "manifest")
            && current_depot.is_some()
        {
            if let Ok(manifest) = u64::from_str(&quoted[1]) {
                manifests.insert(current_depot.unwrap_or_default(), manifest);
            }
        }
    }

    manifests
}

fn extract_quoted_values(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_quote = false;
    let mut current = String::new();
    for ch in line.chars() {
        if ch == '"' {
            if in_quote {
                out.push(current.clone());
                current.clear();
            }
            in_quote = !in_quote;
            continue;
        }
        if in_quote {
            current.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_launch_section_from_vdf() {
        let raw = r#""appinfo"
{
  "appid" "10"
  "config"
  {
    "launch"
    {
      "0"
      {
        "executable" "linux/game.sh"
        "arguments" "-foo -bar"
        "oslist" "linux"
      }
    }
  }
}"#;

        let launch = parse_launch_info_from_vdf(10, raw).expect("parse launch info");
        assert_eq!(launch.target, LaunchTarget::NativeLinux);
        assert_eq!(launch.executable, "linux/game.sh");
        assert_eq!(launch.arguments, "-foo -bar");
    }
}

fn split_args(args: &str) -> Vec<String> {
    args.split_whitespace().map(ToString::to_string).collect()
}
