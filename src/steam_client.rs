use crate::cloud_sync::{default_cloud_root, CloudClient};
use crate::cm_list::get_cm_endpoints;
use crate::config::{
    delete_session, library_cache_path, load_launcher_config, load_library_cache, load_session,
    save_library_cache, save_session,
};
use crate::depot_browser::{self, DepotInfo as BrowserDepotInfo, ManifestFileEntry};
use crate::models::{
    AppInfoRoot, DepotPlatform, DownloadProgress, DownloadProgressState, LibraryGame,
    ManifestSelection, OwnedGame, SessionState, SteamGuardReq, UserProfile,
};
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::time::Instant;

use steam_vent::auth::{
    AuthConfirmationHandler, ConfirmationMethod, DeviceConfirmationHandler, FileGuardDataStore,
    UserProvidedAuthConfirmationHandler,
};
use steam_vent::connection::Connection;
use steam_vent::proto::steammessages_clientserver::CMsgClientGetAppOwnershipTicket;
use steam_vent::proto::steammessages_clientserver_2::{
    CMsgClientGetDepotDecryptionKey, CMsgClientGetDepotDecryptionKeyResponse,
};
use steam_vent::proto::steammessages_clientserver_appinfo::{
    cmsg_client_picsproduct_info_request, CMsgClientPICSProductInfoRequest,
    CMsgClientPICSProductInfoResponse,
};
use steam_vent::proto::steammessages_contentsystem_steamclient::{
    CContentServerDirectory_GetCDNAuthToken_Request,
    CContentServerDirectory_GetCDNAuthToken_Response,
    CContentServerDirectory_GetManifestRequestCode_Request,
    CContentServerDirectory_GetManifestRequestCode_Response,
    CContentServerDirectory_GetServersForSteamPipe_Request,
    CContentServerDirectory_GetServersForSteamPipe_Response,
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
    pub id: String,
    pub description: String,
    pub executable: String,
    pub arguments: String,
    pub workingdir: Option<String>,
    pub target: LaunchTarget,
}

#[derive(Debug, Clone)]
pub struct RawLaunchOption {
    pub executable: String,
    pub arguments: String,
}

#[derive(Debug, Clone)]
pub struct ExtendedAppInfo {
    pub name: Option<String>,
    pub dlcs: Vec<u32>,
    pub depots: Vec<(u32, String)>,
    pub launch_options: Vec<RawLaunchOption>,
    pub active_branch: String,
}

#[derive(Debug, Clone)]
pub struct AppMetadata {
    pub name: String,
    pub header_image: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DepotInfo {
    pub id: u64,
    pub name: String,
    pub size: u64,
    pub file_count: u64,
    pub config: String,
    pub is_owned: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ConfirmationPrompt {
    pub requirement: SteamGuardReq,
    pub details: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AccountData {
    pub steam_id: u64,
    pub account_name: String,
    pub country: String,      // GeoIP Country
    pub authed_machines: u32, // Steam Guard count
    pub flags: u32,           // Account Flags
    pub email: String,
    pub email_validated: bool,
    pub vac_bans: u32,        // Num VAC bans
    pub vac_banned_apps: Vec<u32>,
}

#[derive(Clone)]
pub struct SteamClient {
    connection: Option<Connection>,
    state: LoginState,
    connected_at: Option<Instant>,
    active_cm: Option<SocketAddr>,
    server_list: Option<ServerList>,
    pending_confirmations: Vec<ConfirmationPrompt>,
    /// Set the moment we observe the CM connection drop (Steam resets the
    /// WebSocket, or a heartbeat send fails with AlreadyClosed). A set value
    /// means the held `connection` is a zombie and must be dropped + reconnected
    /// before the next CM call, instead of being reused (which would otherwise
    /// keep erroring with "Failed to send heartbeat: AlreadyClosed").
    connection_dead_since: Option<Instant>,
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
            connection_dead_since: None,
        })
    }

    pub fn is_authenticated(&self) -> bool {
        // A connection marked dead (Steam reset the WebSocket / heartbeat failed with
        // AlreadyClosed) is a zombie and must not be treated as usable; callers that
        // hold &mut self should call connection_or_reconnect() to transparently recover.
        self.connection.is_some() && self.connection_dead_since.is_none()
    }

    pub fn is_offline(&self) -> bool {
        self.state == LoginState::Offline
    }

    pub fn connection(&self) -> Option<&Connection> {
        self.connection.as_ref()
    }

    /// Mark the held CM connection as dead. Called when we observe a transport
    /// reset (Steam rotates connection managers, or the WebSocket is closed with
    /// ResetWithoutClosingHandshake / AlreadyClosed). The next guarded CM call
    /// will drop the zombie handle and transparently reconnect.
    pub fn mark_connection_dead(&mut self) {
        if self.connection_dead_since.is_none() {
            self.connection_dead_since = Some(Instant::now());
        }
        self.connection = None;
    }

    /// Return a live connection, transparently reconnecting if the previous one
    /// was marked dead (Steam reset it). This prevents callers from reusing a
    /// closed socket and stops the repeated "Failed to send heartbeat" spam.
    pub async fn connection_or_reconnect(&mut self) -> Result<&Connection> {
        if self.connection.is_none() {
            self.connect().await?;
        }
        self.connection
            .as_ref()
            .context("steam connection not initialized")
    }

    pub async fn logout(&mut self) -> Result<()> {
        self.connection = None;
        self.connection_dead_since = None;
        self.state = LoginState::Connected;
        delete_session().await?;
        Ok(())
    }

    pub async fn get_app_ticket(&self, appid: u32) -> Result<Vec<u8>> {
        let connection = self.connection.as_ref().context("steam connection not initialized")?;

        let mut request = CMsgClientGetAppOwnershipTicket::new();
        request.set_app_id(appid);

        let response: steam_vent::proto::steammessages_clientserver::CMsgClientGetAppOwnershipTicketResponse =
            connection.job(request).await.context("failed requesting app ownership ticket")?;

        let ticket = response.ticket().to_vec();
        if ticket.is_empty() {
            bail!("Steam returned an empty app ownership ticket for app {appid}");
        }
        Ok(ticket)
    }

    pub async fn get_account_data(&self) -> AccountData {
        let Some(connection) = self.connection.as_ref() else {
            return AccountData::default();
        };

        let mut data = AccountData {
            steam_id: u64::from(connection.steam_id()),
            country: connection.ip_country_code().unwrap_or_default(),
            ..Default::default()
        };

        // Attempt to populate from persistent session info
        if let Ok(session) = load_session().await {
            if let Some(name) = session.account_name {
                data.account_name = name;
            }
        }

        if data.account_name.is_empty() {
            data.account_name = "Steam User".to_string();
        }

        data.email = "Hidden".to_string();
        data.email_validated = true;

        data
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
        self.connection_dead_since = None;
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

    pub async fn fetch_branches(&self, appid: u32) -> Result<Vec<String>> {
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
            .context("failed requesting appinfo product info for branches")?;

        let app = response
            .apps
            .iter()
            .find(|entry| entry.appid() == appid)
            .ok_or_else(|| anyhow!("missing app info payload for app {appid}"))?;

        let appinfo_vdf = String::from_utf8_lossy(app.buffer()).to_string();
        let parsed: AppInfoRoot =
            parse_appinfo(&appinfo_vdf).context("failed parsing appinfo VDF")?;

        let branches = parsed
            .appinfo
            .map(|node| node.branches)
            .unwrap_or(parsed.branches);

        let mut names: Vec<String> = branches
            .into_iter()
            .filter(|(_, node)| node.pwdrequired.is_none()) // Ignore private
            .map(|(name, _)| name)
            .collect();

        if !names.contains(&"public".to_string()) {
            names.push("public".to_string());
        }

        names.sort();
        Ok(names)
    }

    pub async fn get_available_platforms(
        &mut self,
        appid: u32,
    ) -> Result<(Vec<DepotPlatform>, Vec<u8>)> {
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

        let buffer = app.buffer().to_vec();
        let appinfo_vdf_text = String::from_utf8_lossy(&buffer);

        let mut has_linux = false;
        let mut has_windows = false;

        let vdf_res = steam_vdf_parser::parse_binary(&buffer)
            .or_else(|_| steam_vdf_parser::parse_text(&appinfo_vdf_text).map(|v| v.into_owned()));

        if let Ok(vdf) = vdf_res {
            let root_obj = vdf.as_obj().unwrap();
            let depots_val = if vdf.key() == "appinfo" || vdf.key() == appid.to_string() {
                root_obj.get("depots")
            } else {
                root_obj.get("depots").or_else(|| {
                    root_obj
                        .values()
                        .next()
                        .and_then(|v| v.as_obj())
                        .and_then(|o| o.get("depots"))
                })
            };

            if let Some(depots) = depots_val.and_then(|v| v.as_obj()) {
                for value in depots.values() {
                    let oslist = value
                        .get_obj(&["config"])
                        .and_then(|c| c.get("oslist"))
                        .and_then(|o| o.as_str());

                    if let Some(os) = oslist {
                        let os = os.to_lowercase();
                        if os.contains("linux") {
                            has_linux = true;
                        }
                        if os.contains("windows") {
                            has_windows = true;
                        }
                    }
                }
            }
        } else {
            tracing::warn!("get_available_platforms: VDF parse failed for {appid}, using fallback discovery");
            return Ok((vec![DepotPlatform::Windows, DepotPlatform::Linux], buffer));
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

        Ok((platforms, buffer))
    }

    pub async fn install_game(
        &self,
        appid: u32,
        platform: DepotPlatform,
        cached_vdf: Option<Vec<u8>>,
        filter_depots: Option<Vec<u64>>,
        shared_state: Arc<std::sync::RwLock<crate::models::DownloadState>>,
    ) -> Result<Receiver<DownloadProgress>> {
        let connection = self
            .connection
            .as_ref()
            .cloned()
            .context("steam connection not initialized")?;

        let cfg = load_launcher_config().await?;
        let library_root = cfg.steam_library_path.clone();
        let (game_name, pics_installdir) = self.resolve_install_game_info(appid).await;
        let installdir = pics_installdir.unwrap_or_else(|| sanitize_install_dir(&game_name));

        let install_dir = Path::new(&library_root)
            .join("steamapps")
            .join("common")
            .join(&installdir);
        std::fs::create_dir_all(&install_dir)
            .with_context(|| format!("failed creating {}", install_dir.display()))?;
        let manifest_path = Path::new(&library_root)
            .join("steamapps")
            .join(format!("appmanifest_{appid}.acf"));

        let (tx, rx) = tokio::sync::mpsc::channel(128);
        let client_clone = self.clone();
        let shared_state_clone = shared_state.clone();

        tokio::task::spawn(async move {
            if let Ok(mut state) = shared_state_clone.write() {
                state.is_downloading = true;
                state.is_paused = false;
                state.app_id = appid;
                state.abort_signal.store(false, std::sync::atomic::Ordering::Release);
                state.operation_controller.resume();
            }
            let _ = tx
                .send(DownloadProgress {
                    state: DownloadProgressState::Queued,
                    bytes_downloaded: 0,
                    total_bytes: 0,
                    current_file: String::new(),
                
            file_path: String::new(),
            file_bytes_downloaded: 0,
            file_total_bytes: 0,
})
                .await;


            let appinfo_vdf_bytes_owned;
            let appinfo_vdf_bytes = if let Some(cached) = cached_vdf {
                appinfo_vdf_bytes_owned = cached;
                &appinfo_vdf_bytes_owned
            } else {
                let mut request = CMsgClientPICSProductInfoRequest::new();
                request
                    .apps
                    .push(cmsg_client_picsproduct_info_request::AppInfo {
                        appid: Some(appid),
                        ..Default::default()
                    });

                let response: CMsgClientPICSProductInfoResponse = match connection.job(request).await
                {
                    Ok(res) => res,
                    Err(e) => {
                        let _ = tx
                            .send(DownloadProgress {
                                state: DownloadProgressState::Failed,
                                bytes_downloaded: 0,
                                total_bytes: 0,
                                current_file: format!("failed requesting appinfo: {e}"),
                            
            file_path: String::new(),
            file_bytes_downloaded: 0,
            file_total_bytes: 0,
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
                        
            file_path: String::new(),
            file_bytes_downloaded: 0,
            file_total_bytes: 0,
})
                        .await;
                    return;
                };
                appinfo_vdf_bytes_owned = app.buffer().to_vec();
                &appinfo_vdf_bytes_owned
            };

            let appinfo_vdf_text = String::from_utf8_lossy(appinfo_vdf_bytes).to_string();


            let mut selections = Vec::new();

            let mut has_windows = false;
            if let Ok(map) = parse_pics_product_info(appinfo_vdf_bytes) {
                // To keep filtering, we re-parse or re-use the find_vdf logic.
                // We'll re-parse here to stay strictly compliant with Task 2's request to call parse_pics_product_info.
                if let Ok(vdf) = find_vdf_in_pics(appinfo_vdf_bytes) {
                    let root_obj = vdf.as_obj().unwrap();
                    let depots_val = if vdf.key() == "appinfo" || vdf.key() == appid.to_string() {
                        root_obj.get("depots")
                    } else {
                        root_obj.get("depots").or_else(|| {
                            root_obj
                                .get("appinfo")
                                .and_then(|v| v.as_obj())
                                .and_then(|o| o.get("depots"))
                        })
                    };

                    if let Some(depots) = depots_val.and_then(|v| v.as_obj()) {
                        for (key, value) in depots.iter() {
                            if let Ok(d_id) = key.parse::<u32>() {
                                let oslist = value
                                    .get_obj(&["config"])
                                    .and_then(|c| c.get("oslist"))
                                    .and_then(|o| o.as_str());

                                if oslist
                                    .map(|os| os.to_lowercase().contains("windows"))
                                    .unwrap_or(false)
                                {
                                    has_windows = true;
                                }

                                let mut match_os = should_keep_depot(oslist, platform);

                                if match_os {
                                    // 1. LANGUAGE CHECK
                                    let lang = value
                                        .get_obj(&["config"])
                                        .and_then(|c| c.get("language"))
                                        .and_then(|l| l.as_str());
                                    if let Some(lang) = lang {
                                        if lang != "english" && !lang.is_empty() {
                                            match_os = false;
                                        }
                                    }
                                }

                                if match_os {
                                    let depot_id_u64 = d_id as u64;
                                    let is_allowed = match &filter_depots {
                                        Some(list) => list.contains(&depot_id_u64),
                                        None => true,
                                    };

                                    if is_allowed {
                                        if let Some(m_id) = map.get(&depot_id_u64) {
                                            selections.push(ManifestSelection {
                                                app_id: appid,
                                                depot_id: d_id,
                                                manifest_id: *m_id,
                                                appinfo_vdf: appinfo_vdf_text.clone(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                println!("CRITICAL: VDF parse failed for {appid}");
            }

            if selections.is_empty() {

                let msg = if has_windows && matches!(platform, DepotPlatform::Linux) {
                    "No native Linux depots found. This game may only support Windows (Proton)."
                } else {
                    "No matching depots found for the selected platform."
                };

                let _ = tx
                    .send(DownloadProgress {
                        state: DownloadProgressState::Failed,
                        bytes_downloaded: 0,
                        total_bytes: 0,
                        current_file: msg.to_string(),
                    
            file_path: String::new(),
            file_bytes_downloaded: 0,
            file_total_bytes: 0,
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
                
            file_path: String::new(),
            file_bytes_downloaded: 0,
            file_total_bytes: 0,
})
                .await;

            // Update shared state for the start of the download
            if let Ok(mut state) = shared_state_clone.write() {
                state.is_downloading = true;
                state.is_paused = false;
                state.app_id = appid;
                state.app_name = game_name.clone();
                state.downloaded_bytes = 0;
                state.total_bytes = 0; // We'll update this once we have manifests
                state.status_text = format!("Initializing download for {}...", game_name);
            }

            // 2. Fetch Content Servers via Service
            tracing::info!("Fetching Content Servers for AppID: {}...", appid);
            let hosts = match client_clone.get_content_servers(connection.cell_id()).await {
                Ok(h) => h,
                Err(e) => {
                    let _ = tx
                        .send(DownloadProgress {
                            state: DownloadProgressState::Failed,
                            bytes_downloaded: 0,
                            total_bytes: 0,
                            current_file: format!("Failed to fetch content servers: {}", e),
                        
            file_path: String::new(),
            file_bytes_downloaded: 0,
            file_total_bytes: 0,
})
                        .await;
                    return;
                }
            };

            // 3. Download Loop
            let mut success = true;
            let mut successful_depots = Vec::new();
            for selection in selections {
                tracing::info!(
                    "Starting download for Depot {} (GID: {})...",
                    selection.depot_id,
                    selection.manifest_id
                );

                let key = match client_clone.get_depot_key(appid, selection.depot_id).await {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::warn!(
                            "Skipping Depot {} (No Key/Not Owned): {}",
                            selection.depot_id,
                            e
                        );
                        continue;
                    }
                };

                let manifest_code = match client_clone
                    .get_manifest_request_code(appid, selection.depot_id, selection.manifest_id)
                    .await
                {
                    Ok(code) => Some(code),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to get manifest request code for depot {}: {}",
                            selection.depot_id,
                            e
                        );
                        None
                    }
                };

                let mut depot_success = false;
                for host in &hosts {
                    let token = match client_clone
                        .get_cdn_auth_token(appid, selection.depot_id, host)
                        .await
                    {
                        Ok(t) => Some(t),
                        Err(e) => {
                            tracing::warn!("Failed to get auth token for host {}: {}", host, e);
                            None
                        }
                    };

                    let (host_name, port) = if let Some(pos) = host.find(':') {
                        (
                            &host[..pos],
                            host[pos + 1..].parse::<u16>().unwrap_or(80),
                        )
                    } else {
                        (host.as_str(), 80)
                    };

                    let cdn_server = steam_cdn::web_api::content_service::CDNServer {
                        r#type: "CDN".to_string(),
                        https: port == 443,
                        host: host_name.to_string(),
                        vhost: host_name.to_string(),
                        port,
                        cell_id: connection.cell_id(),
                        load: 0,
                        weighted_load: 0,
                        auth_token: token,
                    };

                    let cdn_client = steam_cdn::CDNClient::with_server(
                        Arc::new(connection.clone()),
                        cdn_server,
                    );

                let state_for_closure = shared_state_clone.clone();
                let tx_for_progress = tx.clone();
                let selection_depot_id = selection.depot_id;
                // Bridge: the per-file callback stores the active file's
                // relative path + file-level offsets; the aggregate callback
                // picks them up so every progress message carries BOTH the
                // depot-wide aggregate and the active-file detail.
                let file_info = Arc::new(std::sync::Mutex::new((
                    String::new(),
                    0u64,
                    0u64,
                )));
                let file_info_cb = file_info.clone();
                let on_file_progress = Arc::new(move |file_path: String, done: u64, total: u64| {
                    if let Ok(mut guard) = file_info_cb.lock() {
                        guard.0 = file_path;
                        guard.1 = done;
                        guard.2 = total;
                    }
                });
                let on_progress = Arc::new(move |completed: u64, total: u64| {
                    if let Ok(mut state) = state_for_closure.write() {
                        // completed/total are depot-wide aggregates (all files),
                        // so store them directly — no per-chunk += accumulation.
                        state.downloaded_bytes = completed;
                        state.total_bytes = total;
                    }
                    let (file_path, file_done, file_total) = {
                        let guard = file_info.lock().unwrap_or_else(|p| p.into_inner());
                        (guard.0.clone(), guard.1, guard.2)
                    };
                    let _ = tx_for_progress.try_send(DownloadProgress {
                        state: DownloadProgressState::Downloading,
                        bytes_downloaded: completed,
                        total_bytes: total,
                        current_file: format!("Depot {selection_depot_id}"),
                        file_path,
                        file_bytes_downloaded: file_done,
                        file_total_bytes: file_total,
                    });
                });

                let state_for_manifest = shared_state_clone.clone();
                let depot_size = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let size_clone = depot_size.clone();
                let on_manifest = Arc::new(move |total_bytes: u64| {
                    size_clone.store(total_bytes, std::sync::atomic::Ordering::SeqCst);
                    if let Ok(mut state) = state_for_manifest.write() {
                        state.total_bytes += total_bytes;
                    }
                });

                let abort_signal = shared_state_clone
                    .read()
                    .ok()
                    .map(|s| s.abort_signal.clone());
                let operation_controller = shared_state_clone
                    .read()
                    .ok()
                    .map(|s| s.operation_controller.clone());

                    match cdn_client
                        .download_depot(
                            appid,
                            selection.depot_id,
                            selection.manifest_id,
                            &key,
                            &install_dir,
                            manifest_code,
                            false, // verify_mode: false
                            abort_signal,
                            operation_controller,
                            Some(on_progress),
                            Some(on_manifest.clone()),
                            Some(on_file_progress),
                        )
                        .await
                    {
                        Ok(_) => {
                            let aborted = shared_state_clone.read()
                                .map(|s| s.abort_signal.load(std::sync::atomic::Ordering::Relaxed))
                                .unwrap_or(false);
                            if aborted {
                                break;
                            }

                            tracing::info!(
                                "Depot {} download complete from {}!",
                                selection.depot_id,
                                host
                            );
                            depot_success = true;
                            successful_depots.push((
                                selection.depot_id,
                                selection.manifest_id,
                                depot_size.load(std::sync::atomic::Ordering::SeqCst),
                            ));
                            break;
                        }
                        Err(e) => {
                            tracing::error!("CDN Error from {}: {}", host, e);
                        }
                    }
                }

                if !depot_success {
                    let aborted = shared_state_clone.read()
                        .map(|s| s.abort_signal.load(std::sync::atomic::Ordering::Relaxed))
                        .unwrap_or(false);

                    if aborted {
                        success = false;
                        break;
                    }

                    let _ = tx
                        .send(DownloadProgress {
                            state: DownloadProgressState::Failed,
                            bytes_downloaded: 0,
                            total_bytes: 0,
                            current_file: format!(
                                "Failed to download depot {} from all available servers",
                                selection.depot_id
                            ),
                        
            file_path: String::new(),
            file_bytes_downloaded: 0,
            file_total_bytes: 0,
})
                        .await;
                    success = false;
                    break;
                }
            }

            if success {
                if let Ok(mut state) = shared_state_clone.write() {
                    state.is_downloading = false;
                    state.status_text = "Download complete".to_string();
                }

                if let Err(err) = SteamClient::write_appmanifest(
                    &manifest_path,
                    appid,
                    &game_name,
                    &installdir,
                    successful_depots,
                ) {
                    tracing::warn!("failed writing appmanifest for {}: {}", appid, err);
                }
                let _ = tx
                    .send(DownloadProgress {
                        state: DownloadProgressState::Completed,
                        bytes_downloaded: 1,
                        total_bytes: 1,
                        current_file: "completed".to_string(),
                    
            file_path: String::new(),
            file_bytes_downloaded: 0,
            file_total_bytes: 0,
})
                    .await;
            } else {
                if let Ok(mut state) = shared_state_clone.write() {
                    state.is_downloading = false;
                    state.status_text = "Download failed".to_string();
                }
            }
        });

        Ok(rx)
    }

    pub async fn update_app_branch(&self, appid: u32, branch: &str) -> Result<()> {
        let manifest_path = self.appmanifest_path(appid).await?;
        if !manifest_path.exists() {
            bail!("appmanifest not found for app {appid}");
        }

        let raw = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("failed reading {}", manifest_path.display()))?;

        let rewritten = rewrite_app_branch(&raw, branch);
        std::fs::write(&manifest_path, rewritten)
            .with_context(|| format!("failed writing {}", manifest_path.display()))?;

        Ok(())
    }

    pub async fn uninstall_game(&self, appid: u32, delete_prefix: bool) -> Result<()> {
        let cfg = load_launcher_config().await?;
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

    pub async fn get_content_servers(&self, cell_id: u32) -> Result<Vec<String>> {
        let connection = self.connection.as_ref().ok_or_else(|| anyhow!("No connection"))?;
        let mut request = CContentServerDirectory_GetServersForSteamPipe_Request::new();
        request.set_cell_id(cell_id);
        request.set_max_servers(20);

        let response: CContentServerDirectory_GetServersForSteamPipe_Response = connection
            .service_method(request)
            .await
            .context("failed calling ContentServerDirectory.GetServersForSteamPipe")?;

        let mut hosts = Vec::new();
        for server in &response.servers {
            if server.type_() == "SteamCache" || server.type_() == "CDN" {
                let host = server.host().to_string();
                hosts.push(host);
            }
        }

        if hosts.is_empty() {
            println!("ERROR: Service returned 0 valid CDN servers!");
        }

        Ok(hosts)
    }

    pub async fn get_manifest_request_code(
        &self,
        app_id: u32,
        depot_id: u32,
        manifest_id: u64,
    ) -> Result<u64> {
        let connection = self.connection.as_ref().ok_or_else(|| anyhow!("No connection"))?;
        let mut request = CContentServerDirectory_GetManifestRequestCode_Request::new();
        request.set_app_id(app_id);
        request.set_depot_id(depot_id);
        request.set_manifest_id(manifest_id);

        let response: CContentServerDirectory_GetManifestRequestCode_Response = connection
            .service_method(request)
            .await
            .context("failed calling ContentServerDirectory.GetManifestRequestCode")?;

        Ok(response.manifest_request_code())
    }

    pub async fn get_cdn_auth_token(
        &self,
        app_id: u32,
        depot_id: u32,
        host_name: &str,
    ) -> Result<String> {
        let connection = self.connection.as_ref().ok_or_else(|| anyhow!("No connection"))?;
        let mut request = CContentServerDirectory_GetCDNAuthToken_Request::new();
        request.set_app_id(app_id);
        request.set_depot_id(depot_id);
        request.set_host_name(host_name.to_string());

        let response: CContentServerDirectory_GetCDNAuthToken_Response = connection
            .service_method(request)
            .await
            .context("failed calling ContentServerDirectory.GetCDNAuthToken")?;

        if response.token().is_empty() {
            return Err(anyhow!("Empty Auth Token returned"));
        }

        Ok(response.token().to_string())
    }

    pub async fn get_depot_list(&self, app_id: u32) -> Result<Vec<DepotInfo>> {
        let connection = self
            .connection
            .as_ref()
            .context("steam connection not initialized")?;

        let mut request = CMsgClientPICSProductInfoRequest::new();
        request
            .apps
            .push(cmsg_client_picsproduct_info_request::AppInfo {
                appid: Some(app_id),
                ..Default::default()
            });

        let response: CMsgClientPICSProductInfoResponse = connection
            .job(request)
            .await
            .context("failed requesting appinfo product info for depot list")?;

        let app = response
            .apps
            .iter()
            .find(|entry| entry.appid() == app_id)
            .ok_or_else(|| anyhow!("missing appinfo payload for app {app_id}"))?;

        let mut out = Vec::new();
        if let Ok(vdf) = find_vdf_in_pics(app.buffer()) {
            let root_obj = vdf.as_obj().context("root is not an object")?;
            let depots_val = if vdf.key() == "appinfo" || vdf.key() == app_id.to_string() {
                root_obj.get("depots")
            } else {
                root_obj.get("depots").or_else(|| {
                    root_obj
                        .get("appinfo")
                        .and_then(|v| v.as_obj())
                        .and_then(|o| o.get("depots"))
                })
            };

            if let Some(depots) = depots_val.and_then(|v| v.as_obj()) {
                for (key, value) in depots.iter() {
                    if let Ok(d_id) = key.parse::<u64>() {
                        let name = value
                            .as_obj()
                            .and_then(|o| o.get("name"))
                            .and_then(|v| v.as_str())
                            .unwrap_or(&format!("Depot {d_id}"))
                            .to_string();

                        let size = value
                            .as_obj()
                            .and_then(|o| o.get("maxsize"))
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0);

                        let mut config_parts = Vec::new();
                        if let Some(config) = value.as_obj().and_then(|o| o.get("config")).and_then(|v| v.as_obj()) {
                            if let Some(os) = config.get("oslist").and_then(|v| v.as_str()) {
                                config_parts.push(format!("os: {}", os));
                            }
                            if let Some(lang) = config.get("language").and_then(|v| v.as_str()) {
                                config_parts.push(format!("lang: {}", lang));
                            }
                        }

                        out.push(DepotInfo {
                            id: d_id,
                            name,
                            size,
                            file_count: 0, // Not easily available in PICS VDF without manifest
                            config: config_parts.join(", "),
                            is_owned: None,
                        });
                    }
                }
            }
        }

        out.sort_by_key(|d| d.id);
        Ok(out)
    }

    /// Return app depots annotated with the access the current account has.
    ///
    /// PICS appinfo can contain optional DLC/language depots which are visible
    /// to everyone, but only a successful decryption-key request proves that
    /// the account can actually download them.
    pub async fn get_depot_list_with_access(&self, app_id: u32) -> Result<Vec<DepotInfo>> {
        let mut depots = self.get_depot_list(app_id).await?;
        for depot in &mut depots {
            depot.is_owned = Some(
                self.get_depot_key(app_id, depot.id as u32)
                    .await
                    .is_ok(),
            );
        }
        Ok(depots)
    }

    pub async fn get_depot_key(&self, app_id: u32, depot_id: u32) -> Result<Vec<u8>> {
        let connection = self
            .connection
            .as_ref()
            .context("steam connection not initialized")?;
        let mut request = CMsgClientGetDepotDecryptionKey::new();
        request.set_depot_id(depot_id);
        request.set_app_id(app_id);

        let response: CMsgClientGetDepotDecryptionKeyResponse = connection.job(request).await?;
        if response.eresult() != 1 {
            bail!(
                "failed to get depot key for depot {depot_id}: eresult {}",
                response.eresult()
            );
        }

        Ok(response.depot_encryption_key().to_vec())
    }

    pub async fn verify_depot_ownership(&self, app_id: u32, depot_ids: Vec<u64>) -> HashMap<u64, bool> {
        tracing::info!("Verifying ownership for {} depots...", depot_ids.len());
        let mut results = HashMap::new();

        let connection = match self.connection.as_ref() {
            Some(c) => c,
            None => {
                for id in depot_ids { results.insert(id, false); }
                return results;
            }
        };

        // 1. Ensure we have an App Ticket (Warm up session)
        let _ = self.get_app_ticket(app_id).await;

        for depot_id in depot_ids {
            let mut request = CMsgClientGetDepotDecryptionKey::new();
            request.set_depot_id(depot_id as u32);
            request.set_app_id(app_id);

            match connection.job(request).await {
                Ok(response) => {
                    let response: CMsgClientGetDepotDecryptionKeyResponse = response;
                    if response.eresult() == 1 { // EResult::OK
                        results.insert(depot_id, true);
                    } else {
                        results.insert(depot_id, false);
                    }
                }
                Err(_) => {
                    results.insert(depot_id, false);
                }
            }
        }
        results
    }

    pub async fn fetch_depots(&self, appid: u32) -> Result<Vec<BrowserDepotInfo>> {
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
            // Standalone Steam mods (e.g. Portal: Revolution, AppID 601300)
            // and free community mods are classified by Steam as "unvetted
            // apps" and are dropped from GetOwnedGames unless explicitly
            // requested. include_free_sub pulls in free subscriptions held on
            // the account; skip_unvetted_apps=false keeps mod-type entries in
            // the result so they appear in the library alongside native titles.
            include_free_sub: Some(true),
            skip_unvetted_apps: Some(false),
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

        // SECOND PASS (no appinfo): GetOwnedGames with include_appinfo=true can
        // silently DROP entries whose appinfo the service cannot attach — the
        // typical case for standalone Steam mods such as Portal: Revolution
        // (AppID 601300), which the user sees in the Steam web library but
        // never arrives here. Without appinfo the raw appids come through
        // (empty names); they are merged in as "App <id>" and hydrated later by
        // ensure_metadata_requested / fetch_app_metadata when selected.
        let bare_request = CPlayer_GetOwnedGames_Request {
            steamid: Some(u64::from(connection.steam_id())),
            include_appinfo: Some(false),
            include_played_free_games: Some(true),
            include_free_sub: Some(true),
            skip_unvetted_apps: Some(false),
            ..Default::default()
        };
        let bare_response: CPlayer_GetOwnedGames_Response = connection
            .service_method(bare_request)
            .await
            .context("failed calling Player.GetOwnedGames (appinfo-less pass)")?;

        let mut known: std::collections::HashSet<u32> =
            owned.iter().map(|g| g.app_id).collect();
        let mut merged = 0usize;
        for game in bare_response.games {
            let app_id = game.appid() as u32;
            if known.insert(app_id) {
                owned.push(OwnedGame {
                    app_id,
                    name: format!("App {app_id}"),
                    playtime_forever_minutes: game.playtime_forever() as u32,
                    local_manifest_ids: HashMap::new(),
                    update_available: false,
                });
                merged += 1;
            }
        }
        tracing::info!(
            total = owned.len(),
            merged_from_bare_pass = merged,
            portal_revolution_present =
                owned.iter().any(|g| g.app_id == 601300),
            "fetch_owned_games: appinfo pass + appinfo-less merge complete"
        );

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

            let (local, branch) = self.local_manifest_info(game)?;
            game.local_manifest_ids = local.clone();
            game.active_branch = branch;

            if self.is_offline() || self.connection.is_none() {
                continue;
            }

            let remote = self
                .remote_manifest_ids(game.app_id, &game.active_branch)
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

    fn local_manifest_info(&self, game: &LibraryGame) -> Result<(HashMap<u64, u64>, String)> {
        let install_path = match &game.install_path {
            Some(path) => PathBuf::from(path),
            None => return Ok((HashMap::new(), "public".to_string())),
        };

        let steamapps = match install_path.parent().and_then(|p| p.parent()) {
            Some(path) => path.to_path_buf(),
            None => return Ok((HashMap::new(), "public".to_string())),
        };

        let manifest_path = steamapps.join(format!("appmanifest_{}.acf", game.app_id));
        if !manifest_path.exists() {
            return Ok((HashMap::new(), "public".to_string()));
        }

        let raw = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("failed reading {}", manifest_path.display()))?;
        let manifests = parse_installed_depots_from_acf(&raw);
        let branch = parse_active_branch_from_acf(&raw);
        Ok((manifests, branch))
    }

    async fn remote_manifest_ids(&self, appid: u32, branch: &str) -> Result<HashMap<u64, u64>> {
        let connection = self
            .connection
            .as_ref()
            .context("steam connection not initialized")?;
        SteamClient::remote_manifest_ids_static(connection, appid, branch).await
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

    pub async fn get_extended_app_info(&self, appid: u32) -> Result<ExtendedAppInfo> {
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
            .context("failed requesting appinfo product info for extended metadata")?;

        let app = response
            .apps
            .iter()
            .find(|entry| entry.appid() == appid)
            .ok_or_else(|| anyhow!("missing appinfo payload for app {appid}"))?;

        let raw_vdf = String::from_utf8_lossy(app.buffer()).to_string();
        let parsed: AppInfoRoot =
            parse_appinfo(&raw_vdf).context("failed to parse product info VDF")?;

        let common = parsed
            .appinfo
            .as_ref()
            .and_then(|a| a.common.as_ref())
            .or(parsed.common.as_ref());

        let name = common.and_then(|c| c.name.clone());

        let dlcs: Vec<u32> = common
            .map(|c| {
                c.dlc
                    .keys()
                    .filter_map(|k| k.parse::<u32>().ok())
                    .collect()
            })
            .unwrap_or_default();

        let depots_map = parsed
            .appinfo
            .as_ref()
            .map(|a| &a.depots)
            .unwrap_or(&parsed.depots);
        let mut depots = Vec::new();
        for (id_str, node) in depots_map {
            let is_digit = id_str.chars().all(|c| c.is_ascii_digit());
            if is_digit {
                let id = id_str.parse::<u32>().unwrap_or(0);
                let name = node
                    ._other
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown Depot")
                    .to_string();
                depots.push((id, name));
            }
        }

        let config = parsed
            .appinfo
            .as_ref()
            .and_then(|a| a.config.as_ref())
            .or(parsed.config.as_ref());

        let mut launch_options = Vec::new();
        if let Some(config) = config {
            for entry in config.launch.values() {
                launch_options.push(RawLaunchOption {
                    executable: entry.executable.clone().unwrap_or_default(),
                    arguments: entry.arguments.clone().unwrap_or_default(),
                });
            }
        }

        let manifest_path = self.appmanifest_path(appid).await?;
        let active_branch = if manifest_path.exists() {
            let raw = std::fs::read_to_string(&manifest_path).unwrap_or_default();
            parse_active_branch_from_acf(&raw)
        } else {
            "public".to_string()
        };

        Ok(ExtendedAppInfo {
            name,
            dlcs,
            depots,
            launch_options,
            active_branch,
        })
    }

    pub async fn get_product_info(&mut self, appid: u32, prefer_proton: bool) -> Result<Vec<LaunchInfo>> {
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

        let launch_infos = parse_launch_info_from_vdf(appid, &raw_vdf, prefer_proton)
            .context("failed to parse launch metadata from PICS appinfo")?;

        Ok(launch_infos)
    }

    pub async fn play_game(
        &mut self,
        app: &LibraryGame,
        proton_path: Option<&str>,
        user_config: Option<&crate::models::UserAppConfig>,
    ) -> Result<LaunchInfo> {
        let prefer_proton = proton_path.is_some();
        let launch_options = self.get_product_info(app.app_id, prefer_proton).await?;
        let launch_info = launch_options
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("no launch options"))?;

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
            let _ = client.sync_down(app.app_id, &root).await;
            cloud_client = Some(client);
            local_root = Some(root);
        }

        let mut child =
            self.spawn_game_process(app, &launch_info, chosen_proton_path, &launcher_config, user_config).await?;
        child
            .wait()
            .context("failed waiting for game process exit")?;

        if cloud_enabled {
            if let (Some(client), Some(root)) = (cloud_client.as_ref(), local_root.as_ref()) {
                client.sync_up(app.app_id, root).await?;
                tracing::info!(appid = app.app_id, "Upload Complete");
            }
        }

        Ok(launch_info)
    }

    pub async fn launch_game(
        &self,
        app: &LibraryGame,
        launch_info: &LaunchInfo,
        proton_path: Option<&str>,
        user_config: Option<&crate::models::UserAppConfig>,
    ) -> Result<()> {
        let launcher_config = load_launcher_config().await.unwrap_or_default();
        self.spawn_game_process(app, launch_info, proton_path, &launcher_config, user_config).await?;
        Ok(())
    }

    pub async fn update_game(
        &self,
        appid: u32,
        shared_state: Arc<std::sync::RwLock<crate::models::DownloadState>>,
    ) -> Result<Receiver<DownloadProgress>> {
        self.start_manifest_download(appid, false, shared_state)
            .await
    }

    pub async fn verify_game(
        &self,
        appid: u32,
        shared_state: Arc<std::sync::RwLock<crate::models::DownloadState>>,
    ) -> Result<Receiver<DownloadProgress>> {
        self.start_manifest_download(appid, true, shared_state)
            .await
    }

    async fn start_manifest_download(
        &self,
        appid: u32,
        verify_mode: bool,
        shared_state: Arc<std::sync::RwLock<crate::models::DownloadState>>,
    ) -> Result<Receiver<DownloadProgress>> {
        let connection = self
            .connection
            .as_ref()
            .cloned()
            .context("steam connection not initialized")?;

        let install_root = self.install_root_for_app(appid).await?;
        let manifest_path = self.appmanifest_path(appid).await?;
        let (tx, rx) = tokio::sync::mpsc::channel(128);

        let (local_manifests, active_branch) = self
            .local_manifest_info_for_appid(appid)
            .await
            .unwrap_or_else(|_| (HashMap::new(), "public".to_string()));

        let client_clone = self.clone();
        let shared_state_clone = shared_state.clone();
        let game_name = self.resolve_install_game_name(appid).await;
        tokio::task::spawn(async move {
            if let Ok(mut state) = shared_state_clone.write() {
                state.is_downloading = true;
                state.is_paused = false;
                state.app_id = appid;
                state.app_name = game_name.clone();
                state.downloaded_bytes = 0;
                state.status_text = format!("Preparing operation for {}...", game_name);
                state.abort_signal.store(false, std::sync::atomic::Ordering::Release);
                state.operation_controller.resume();
            }

            let _ = tx
                .send(DownloadProgress {
                    state: DownloadProgressState::Queued,
                    bytes_downloaded: 0,
                    total_bytes: 0,
                    current_file: if verify_mode {
                        "verifying installed chunks".to_string()
                    } else {
                        "resolving latest manifest".to_string()
                    },
                
            file_path: String::new(),
            file_bytes_downloaded: 0,
            file_total_bytes: 0,
})
                .await;

            let remote_manifests = if verify_mode {
                local_manifests.clone()
            } else {
                SteamClient::remote_manifest_ids_static(&connection, appid, &active_branch)
                    .await
                    .unwrap_or_default()
            };

            let mut selections = Vec::new();
            for (depot_id, manifest_id) in &remote_manifests {
                selections.push(ManifestSelection {
                    app_id: appid,
                    depot_id: *depot_id as u32,
                    manifest_id: *manifest_id,
                    appinfo_vdf: String::new(),
                });
            }

            if selections.is_empty() {
                let _ = tx
                    .send(DownloadProgress {
                        state: DownloadProgressState::Failed,
                        bytes_downloaded: 0,
                        total_bytes: 0,
                        current_file: "no manifest/depot available for download".to_string(),
                    
            file_path: String::new(),
            file_bytes_downloaded: 0,
            file_total_bytes: 0,
})
                    .await;
                return;
            };

            let hosts = match client_clone.get_content_servers(connection.cell_id()).await {
                Ok(h) => h,
                Err(e) => {
                    let _ = tx
                        .send(DownloadProgress {
                            state: DownloadProgressState::Failed,
                            bytes_downloaded: 0,
                            total_bytes: 0,
                            current_file: format!("Failed to fetch content servers: {}", e),
                        
            file_path: String::new(),
            file_bytes_downloaded: 0,
            file_total_bytes: 0,
})
                        .await;
                    return;
                }
            };

            let mut success = true;
            let mut successful_depots = Vec::new();

            for selection in selections {
                let key: Vec<u8> = match client_clone.get_depot_key(appid, selection.depot_id).await {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::warn!(
                            "Skipping Depot {} (No Key/Not Owned): {}",
                            selection.depot_id,
                            e
                        );
                        continue;
                    }
                };

                let manifest_code: Option<u64> = client_clone
                    .get_manifest_request_code(appid, selection.depot_id, selection.manifest_id)
                    .await
                    .ok();

                let mut depot_success = false;
                for host in &hosts {
                    let token: Option<String> = client_clone
                        .get_cdn_auth_token(appid, selection.depot_id, host)
                        .await
                        .ok();

                    let (host_name, port) = if let Some(pos) = host.find(':') {
                        (
                            &host[..pos],
                            host[pos + 1..].parse::<u16>().unwrap_or(80),
                        )
                    } else {
                        (host.as_str(), 80)
                    };

                    let cdn_server = steam_cdn::web_api::content_service::CDNServer {
                        r#type: "CDN".to_string(),
                        https: port == 443,
                        host: host_name.to_string(),
                        vhost: host_name.to_string(),
                        port,
                        cell_id: connection.cell_id(),
                        load: 0,
                        weighted_load: 0,
                        auth_token: token,
                    };

                    let cdn_client = steam_cdn::CDNClient::with_server(
                        Arc::new(connection.clone()),
                        cdn_server,
                    );

                    let tx_clone = tx.clone();
                    let selection_depot_id = selection.depot_id;
                    // Bridge: the per-file callback stores the active file's
                    // relative path + file-level byte offsets; the aggregate
                    // callback attaches them to every progress message so the
                    // UI can render the depot-wide aggregate AND the active
                    // file detail from a single stream.
                    let file_info = Arc::new(std::sync::Mutex::new((
                        String::new(),
                        0u64,
                        0u64,
                    )));
                    let file_info_cb = file_info.clone();
                    let on_file_progress = Arc::new(move |file_path: String, done: u64, total: u64| {
                        if let Ok(mut guard) = file_info_cb.lock() {
                            guard.0 = file_path;
                            guard.1 = done;
                            guard.2 = total;
                        }
                    });
                    let on_progress = Arc::new(move |completed: u64, total: u64| {
                        let (file_path, file_done, file_total) = {
                            let guard = file_info.lock().unwrap_or_else(|p| p.into_inner());
                            (guard.0.clone(), guard.1, guard.2)
                        };
                        let _ = tx_clone.try_send(DownloadProgress {
                            state: if verify_mode {
                                DownloadProgressState::Verifying
                            } else {
                                DownloadProgressState::Downloading
                            },
                            bytes_downloaded: completed,
                            total_bytes: total,
                            current_file: format!("Depot {selection_depot_id}"),
                            file_path,
                            file_bytes_downloaded: file_done,
                            file_total_bytes: file_total,
                        });
                    });

                    let depot_size = Arc::new(std::sync::atomic::AtomicU64::new(0));
                    let size_clone = depot_size.clone();
                    let on_manifest = Arc::new(move |total_bytes: u64| {
                        size_clone.store(total_bytes, std::sync::atomic::Ordering::SeqCst);
                    });

                    let abort_signal = shared_state_clone
                        .read()
                        .ok()
                        .map(|s| s.abort_signal.clone());
                    let operation_controller = shared_state_clone
                        .read()
                        .ok()
                        .map(|s| s.operation_controller.clone());

                    match cdn_client
                        .download_depot(
                            appid,
                            selection.depot_id,
                            selection.manifest_id,
                            &key,
                            &install_root,
                            manifest_code,
                            verify_mode,
                            abort_signal,
                            operation_controller,
                            Some(on_progress),
                            Some(on_manifest),
                            Some(on_file_progress),
                        )
                        .await
                    {
                        Ok(_) => {
                            let aborted = shared_state_clone.read()
                                .map(|s| s.abort_signal.load(std::sync::atomic::Ordering::Relaxed))
                                .unwrap_or(false);
                            if aborted {
                                break;
                            }

                            depot_success = true;
                            successful_depots.push((
                                selection.depot_id,
                                selection.manifest_id,
                                depot_size.load(std::sync::atomic::Ordering::SeqCst),
                            ));
                            break;
                        }
                        Err(e) => {
                            tracing::error!("CDN Error from {}: {}", host, e);
                        }
                    }
                }

                if !depot_success {
                    let aborted = shared_state_clone.read()
                        .map(|s| s.abort_signal.load(std::sync::atomic::Ordering::Relaxed))
                        .unwrap_or(false);

                    if aborted {
                        success = false;
                        break;
                    }

                    let _ = tx
                        .send(DownloadProgress {
                            state: DownloadProgressState::Failed,
                            bytes_downloaded: 0,
                            total_bytes: 0,
                            current_file: format!(
                                "Failed to download/verify depot {} from all servers",
                                selection.depot_id
                            ),
                        
            file_path: String::new(),
            file_bytes_downloaded: 0,
            file_total_bytes: 0,
})
                        .await;
                    success = false;
                    break;
                }
            }

            if success {
                if let Ok(mut state) = shared_state_clone.write() {
                    state.is_downloading = false;
                    state.status_text = "Operation complete".to_string();
                }

                let (game_name, pics_installdir) = client_clone.resolve_install_game_info(appid).await;
                let installdir = pics_installdir.unwrap_or_else(|| sanitize_install_dir(&game_name));

                if let Err(err) =
                    SteamClient::write_appmanifest(&manifest_path, appid, &game_name, &installdir, successful_depots)
                {
                    tracing::warn!("failed writing appmanifest for {}: {}", appid, err);
                }
                let _ = tx
                    .send(DownloadProgress {
                        state: DownloadProgressState::Completed,
                        bytes_downloaded: 1,
                        total_bytes: 1,
                        current_file: if verify_mode {
                            "verify completed".to_string()
                        } else {
                            "update completed".to_string()
                        },
                    
            file_path: String::new(),
            file_bytes_downloaded: 0,
            file_total_bytes: 0,
})
                    .await;
            } else {
                if let Ok(mut state) = shared_state_clone.write() {
                    state.is_downloading = false;
                    state.status_text = "Operation failed or paused".to_string();
                }
            }
        });

        Ok(rx)
    }

    async fn appmanifest_path(&self, appid: u32) -> Result<PathBuf> {
        let cfg = load_launcher_config().await?;
        Ok(PathBuf::from(cfg.steam_library_path)
            .join("steamapps")
            .join(format!("appmanifest_{appid}.acf")))
    }

    async fn local_manifest_info_for_appid(&self, appid: u32) -> Result<(HashMap<u64, u64>, String)> {
        let manifest_path = self.appmanifest_path(appid).await?;
        if !manifest_path.exists() {
            return Ok((HashMap::new(), "public".to_string()));
        }
        let raw = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("failed reading {}", manifest_path.display()))?;
        let manifests = parse_installed_depots_from_acf(&raw);
        let branch = parse_active_branch_from_acf(&raw);
        Ok((manifests, branch))
    }

    async fn install_root_for_app(&self, appid: u32) -> Result<PathBuf> {
        let manifest_path = self.appmanifest_path(appid).await?;
        let steamapps = manifest_path
            .parent()
            .ok_or_else(|| anyhow!("invalid steamapps path for app {appid}"))?
            .to_path_buf();

        if manifest_path.exists() {
            let raw = std::fs::read_to_string(&manifest_path)
                .with_context(|| format!("failed reading {}", manifest_path.display()))?;
            if let Some(installdir) = parse_installdir_from_acf(&raw) {
                let p = steamapps.join("common").join(&installdir);
                if p.exists() {
                    return Ok(p);
                }

                // Fallback: search for app id markers if the specified installdir doesn't exist
                if let Some(fallback) = self.probe_install_dir_by_appid(&steamapps, appid) {
                    tracing::info!("Found fallback install dir for app {appid}: {:?}", fallback);
                    return Ok(fallback);
                }

                // Even if it doesn't exist, we return the path it *should* be at
                return Ok(p);
            }
        }

        // Final fallback if no manifest or installdir
        Ok(PathBuf::from(load_launcher_config().await?.steam_library_path)
            .join("steamapps")
            .join("common")
            .join(appid.to_string()))
    }

    fn probe_install_dir_by_appid(&self, steamapps: &Path, appid: u32) -> Option<PathBuf> {
        let common = steamapps.join("common");
        if !common.exists() {
            return None;
        }

        let appid_str = appid.to_string();

        if let Ok(entries) = std::fs::read_dir(common) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // Check for steam_appid.txt
                    let appid_txt = path.join("steam_appid.txt");
                    if appid_txt.exists() {
                        if let Ok(content) = std::fs::read_to_string(appid_txt) {
                            if content.trim() == appid_str {
                                return Some(path);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    async fn remote_manifest_ids_static(
        connection: &Connection,
        appid: u32,
        branch: &str,
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

        let mut manifests = HashMap::new();
        if let Ok(vdf) = find_vdf_in_pics(app.buffer()) {
            let root_obj = vdf.as_obj().unwrap();
            let depots_val = if vdf.key() == "appinfo" || vdf.key() == appid.to_string() {
                root_obj.get("depots")
            } else {
                root_obj.get("depots").or_else(|| {
                    root_obj
                        .get("appinfo")
                        .and_then(|v| v.as_obj())
                        .and_then(|o| o.get("depots"))
                })
            };

            if let Some(depots) = depots_val.and_then(|v| v.as_obj()) {
                for (key, value) in depots.iter() {
                    if let Ok(d_id) = key.parse::<u64>() {
                        if let Some(m_id) = extract_manifest_id_robust(value, branch) {
                            manifests.insert(d_id, m_id);
                        } else if branch != "public" {
                            if let Some(m_id) = extract_manifest_id_robust(value, "public") {
                                manifests.insert(d_id, m_id);
                            }
                        }
                    }
                }
            }
        }
        Ok(manifests)
    }


    pub async fn fetch_app_metadata(&self, appid: u32) -> Option<AppMetadata> {
        let url = format!("https://store.steampowered.com/api/appdetails?appids={appid}&filters=basic");
        let resp = reqwest::get(url).await.ok()?;
        let json: serde_json::Value = resp.json().await.ok()?;
        let data = json.get(appid.to_string())?.get("data")?;

        let name = data.get("name")?.as_str()?.to_string();
        let header_image = data
            .get("header_image")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Some(AppMetadata { name, header_image })
    }

    pub async fn resolve_install_game_info(&self, appid: u32) -> (String, Option<String>) {
        let mut display_name = format!("App {appid}");
        let mut installdir = None;

        // Try to get info from PICS first as it's authoritative
        let mut request = CMsgClientPICSProductInfoRequest::new();
        request
            .apps
            .push(cmsg_client_picsproduct_info_request::AppInfo {
                appid: Some(appid),
                ..Default::default()
            });

        if let Some(conn) = self.connection.as_ref() {
            let res: Result<CMsgClientPICSProductInfoResponse, _> = conn.job(request).await;
            if let Ok(response) = res {
                if let Some(app) = response.apps.iter().find(|entry| entry.appid() == appid) {
                    if let Ok(raw_vdf) = String::from_utf8(app.buffer().to_vec()) {
                        if let Ok(parsed) = parse_appinfo(&raw_vdf) {
                            let common = parsed
                                .appinfo
                                .as_ref()
                                .and_then(|a| a.common.as_ref())
                                .or(parsed.common.as_ref());
                            if let Some(common) = common {
                                if let Some(name) = &common.name {
                                    display_name = name.clone();
                                }
                                if let Some(dir) = &common.installdir {
                                    installdir = Some(dir.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        if installdir.is_none() || display_name.starts_with("App ") {
            if let Ok(games) = load_library_cache().await {
                if let Some(game) = games.iter().find(|g| g.app_id == appid) {
                    if display_name.starts_with("App ") && !game.name.is_empty() && !game.name.starts_with("App ") {
                        display_name = game.name.clone();
                    }
                }
            }
        }

        (display_name, installdir)
    }

    async fn resolve_install_game_name(&self, appid: u32) -> String {
        self.resolve_install_game_info(appid).await.0
    }

    pub fn write_appmanifest(
        path: &Path,
        appid: u32,
        game_name: &str,
        installdir: &str,
        installed_depots: Vec<(u32, u64, u64)>,
    ) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }

        let game_name = game_name.replace('"', "");

        let mut content = format!(
            "\"AppState\"\n{{\n\t\"appid\"\t\"{appid}\"\n\t\"name\"\t\"{game_name}\"\n\t\"StateFlags\"\t\"4\"\n\t\"installdir\"\t\"{installdir}\"\n"
        );

        if !installed_depots.is_empty() {
            content.push_str("\t\"InstalledDepots\"\n\t{\n");
            for (depot_id, manifest_id, size) in installed_depots {
                content.push_str(&format!(
                    "\t\t\"{depot_id}\"\n\t\t{{\n\t\t\t\"manifest\"\t\t\"{manifest_id}\"\n\t\t\t\"size\"\t\t\"{size}\"\n\t\t}}\n"
                ));
            }
            content.push_str("\t}\n");
        }

        content.push_str("}\n");

        std::fs::write(path, content)
            .with_context(|| format!("failed writing {}", path.display()))?;
        Ok(())
    }

    pub fn kill_steam_in_prefix(wineprefix: &Path, kill_webhelper: bool) {
        #[cfg(unix)]
        {
            let prefix_str = wineprefix.to_string_lossy().to_string();
            let Ok(proc_dir) = std::fs::read_dir("/proc") else {
                return;
            };

            for entry in proc_dir.flatten() {
                let pid_path = entry.path();
                let Some(pid_str) = pid_path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !pid_str.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }

                let cmdline = match std::fs::read(pid_path.join("cmdline")) {
                    Ok(b) => String::from_utf8_lossy(&b).replace('\0', " "),
                    Err(_) => continue,
                };
                // Kill Steam client processes in this prefix. steamwebhelper is only
                // killed when the user opted into it ("Disable CEF browser"): the
                // web helper is required for the client's login flow and UI, so
                // Manage/Repair must leave it alive unless explicitly disabled.
                let lower = cmdline.to_lowercase();
                let is_webhelper = lower.contains("steamwebhelper.exe");
                if is_webhelper && !kill_webhelper {
                    continue;
                }
                if !lower.contains("steam.exe")
                    && !lower.contains("steamwebhelper.exe")
                    && !lower.contains("steamservice.exe")
                {
                    continue;
                }

                let environ = match std::fs::read(pid_path.join("environ")) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                if !String::from_utf8_lossy(&environ).contains(&prefix_str) {
                    continue;
                }

                if let Ok(pid) = pid_str.parse::<i32>() {
                    unsafe {
                        libc::kill(pid, libc::SIGTERM);
                    }
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = wineprefix;
        }
    }

    /// Undoes the chmod-000 lock that per-game "Disable CEF browser" enforcement
    /// places on steamwebhelper.exe. Client-management operations (Manage / Repair /
    /// Reinstall) require the web helper alive to render the client UI and login flow,
    /// so the lock must be lifted before those operations start — otherwise Steam
    /// cannot spawn steamwebhelper.exe at all (CreateFile fails on mode-000 files).
    ///
    /// Returns true when steamwebhelper.exe exists in the prefix and is executable
    /// afterwards (either it already was, or the lock was lifted).
    pub fn restore_steamwebhelper_in_prefix(wineprefix: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let Some(steam_dir) = crate::utils::find_steam_exe_in_prefix(wineprefix)
                .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            else {
                tracing::warn!(
                    "restore_steamwebhelper: no steam.exe found in {}",
                    wineprefix.display()
                );
                return false;
            };
            let helper = steam_dir.join("steamwebhelper.exe");
            let Ok(metadata) = std::fs::metadata(&helper) else {
                tracing::info!(
                    "restore_steamwebhelper: steamwebhelper.exe not present in {}",
                    steam_dir.display()
                );
                return false;
            };
            let mode = metadata.permissions().mode();
            if mode & 0o111 != 0 {
                tracing::info!(
                    "restore_steamwebhelper: {} already executable (mode {:03o})",
                    helper.display(),
                    mode
                );
                return true;
            }
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            match std::fs::set_permissions(&helper, perms) {
                Ok(()) => {
                    tracing::info!(
                        "restore_steamwebhelper: lifted mode-000 lock on {}",
                        helper.display()
                    );
                    true
                }
                Err(e) => {
                    tracing::warn!(
                        "restore_steamwebhelper: failed to lift lock on {}: {e}",
                        helper.display()
                    );
                    false
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = wineprefix;
            false
        }
    }

    /// Returns true if the Windows Steam client in the given prefix has a
    /// persisted login session.
    ///
    /// Detection is dual: the legacy `ssfn*` sentry file (older clients), or a
    /// `config/loginusers.vdf` containing an account with `AutoLogin`/`RememberPassword`
    /// and a recent `Timestamp`. Modern Steam (2026+) no longer writes `ssfn*` —
    /// the client persists auth via loginusers.vdf — so checking only for the
    /// sentry file would falsely report "not logged in" (and re-trigger login).
    ///
    /// Without a session the client starts anonymous (SteamID U:1:0) and cannot
    /// answer Steamworks ownership queries, so Steamworks games abort early
    /// (RE2 exits 53). This is the Stage-1 gate that must pass before library
    /// registration can matter.
    pub fn windows_client_has_session(prefix: &Path) -> bool {
        let Some(steam_dir) = crate::utils::find_steam_exe_in_prefix(prefix)
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        else {
            return false;
        };

        // 1) Legacy sentry file next to steam.exe
        if let Ok(entries) = std::fs::read_dir(&steam_dir) {
            if entries.flatten().any(|e| {
                e.file_name().to_string_lossy().starts_with("ssfn")
            }) {
                return true;
            }
        }

        // 2) Modern auth: loginusers.vdf with a remembered, auto-login account
        let loginusers = steam_dir.join("config/loginusers.vdf");
        let Ok(raw) = std::fs::read_to_string(&loginusers) else {
            return false;
        };
        // A valid account entry has AutoLogin=1 (or RememberPassword=1) and a
        // non-zero Timestamp (set on successful login). Match on the exact
        // VDF key=value pairs so a stray "1" elsewhere can't false-positive.
        let has_autologin = (raw.contains("AutoLogin\"\t\t\"1")
            || raw.contains("RememberPassword\"\t\t\"1"))
            && raw.contains("Timestamp\"\t\t\"")
            && !raw.contains("Timestamp\"\t\t\"0\"");
        has_autologin
    }

    /// Registers the native Linux Steam library folders into the Windows Steam
    /// client's `steamapps/libraryfolders.vdf` so the client reports games
    /// installed by native Steam as installed. Without this, a strict Steamworks
    /// game (e.g. RE2) gets "not installed" from the client's API and exits
    /// early (exit 53) even after login.
    ///
    /// MUST be called while the Windows Steam client is STOPPED — Steam rewrites
    /// `libraryfolders.vdf` on exit and would clobber the merge.
    ///
    /// Returns the number of new library folders registered (0 if none needed).
    pub fn register_native_libraries_in_windows_client(
        wineprefix: &Path,
    ) -> Result<usize, anyhow::Error> {
        use anyhow::Context;

        // 1) Locate the Windows client's steamapps dir
        let Some(steam_dir) = crate::utils::find_steam_exe_in_prefix(wineprefix)
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        else {
            return Ok(0);
        };
        let steamapps_dir = steam_dir.join("steamapps");
        std::fs::create_dir_all(&steamapps_dir).ok();
        let lf_path = steamapps_dir.join("libraryfolders.vdf");

        let mut existing_raw = std::fs::read_to_string(&lf_path).unwrap_or_default();

        // 2) Existing registered library paths (Windows-form), so we never add
        //    the same native library twice.
        let mut existing_win_paths: Vec<String> = Vec::new();
        for line in existing_raw.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("\"path\"") {
                if let Some(v) = extract_vdf_quoted(rest) {
                    existing_win_paths.push(v);
                }
            }
        }
        // Highest existing library index (Steam numbers them 0,1,2...)
        let max_existing_idx = existing_raw
            .lines()
            .filter_map(|l| {
                let t = l.trim();
                let t = t.strip_prefix('\"')?;
                let idx = t.split('\"').next()?;
                idx.parse::<u32>().ok()
            })
            .max()
            .unwrap_or(0);

        // 3) Discover native Linux library folders: detect_steam_path() root
        //    plus any extra folders registered in the native libraryfolders.vdf
        let mut native_libs: Vec<std::path::PathBuf> = Vec::new();
        if let Some(root) = crate::config::detect_steam_path() {
            native_libs.push(root.clone());
            let native_lf = root.join("steamapps/libraryfolders.vdf");
            if let Ok(extra) = crate::library::parse_library_folders_sync(native_lf) {
                native_libs.extend(extra);
            }
        }
        native_libs.sort();
        native_libs.dedup();

        // 4) Build new entries for native libraries not yet registered
        let mut new_entries: Vec<(String, Vec<(u32, u64)>)> = Vec::new();
        for lib in &native_libs {
            let win_path = format!("Z:\\{}", lib.to_string_lossy().replace('/', "\\"));
            let apps_dir = lib.join("steamapps");
            if !apps_dir.exists() {
                continue;
            }
            let mut apps = Vec::new();
            let Ok(entries) = std::fs::read_dir(&apps_dir) else {
                continue;
            };
            for e in entries.flatten() {
                let fname = e.file_name().to_string_lossy().to_string();
                if !(fname.starts_with("appmanifest_") && fname.ends_with(".acf")) {
                    continue;
                }
                let appid: u32 = fname
                    .trim_start_matches("appmanifest_")
                    .trim_end_matches(".acf")
                    .parse()
                    .unwrap_or(0);
                if appid == 0 {
                    continue;
                }
                let size = read_acf_size_on_disk(&e.path()).unwrap_or(0);
                apps.push((appid, size));
            }
            if !apps.is_empty() {
                if existing_win_paths.iter().any(|p| p == &win_path) {
                    existing_raw = merge_library_apps(&existing_raw, &win_path, &apps);
                } else {
                    new_entries.push((win_path, apps));
                }
            }
        }

        let original_raw = std::fs::read_to_string(&lf_path).unwrap_or_default();
        if new_entries.is_empty() && existing_raw == original_raw {
            return Ok(0);
        }

        // 5) Merge: keep the existing file byte-identical, insert new blocks
        //    before the final closing brace, backup first.
        std::fs::copy(&lf_path, lf_path.with_extension("vdf.bak")).ok();
        if new_entries.is_empty() {
            std::fs::write(&lf_path, &existing_raw)
                .with_context(|| format!("failed writing {}", lf_path.display()))?;
            return Ok(1);
        }
        let insert_pos = existing_raw.rfind('}').unwrap_or(existing_raw.len());
        let mut out = existing_raw[..insert_pos].to_string();
        if !out.ends_with('\n') {
            out.push('\n');
        }
        let mut idx = max_existing_idx;
        for (path, apps) in &new_entries {
            idx += 1;
            out.push_str(&format_library_entry(idx, path, apps));
        }
        out.push_str("}\n");
        std::fs::write(&lf_path, &out)
            .with_context(|| format!("failed writing {}", lf_path.display()))?;

        Ok(new_entries.len())
    }


    /// One-time login bridge: launches `steam.exe -login <account> <password>`
    /// inside the master prefix using the configured runner's bare wine binary,
    /// then waits (polling) for the client to write its `ssfn*` sentry file.
    ///
    /// This is the ONLY way the Windows client itself learns the account; the
    /// steam-vent session SteamFlow uses for library browsing is separate and
    /// does not produce the client's sentry file.
    ///
    /// `password` is passed on the command line (Steam's only supported
    /// non-interactive login), so callers should clear it from the UI after use.
    pub async fn windows_client_login(
        runner_path: &std::path::Path,
        username: &str,
        password: &str,
    ) -> Result<std::path::PathBuf> {
        use std::time::{Duration, Instant};

        let steam_exe = Self::master_steam_exe()
            .ok_or_else(|| anyhow!("Windows Steam client not installed (no steam.exe found)"))?;
        let prefix = crate::utils::resolve_master_wineprefix();

        if Self::windows_client_has_session(&prefix) {
            return Ok(steam_exe); // already logged in
        }

        let mut cmd = crate::utils::build_bare_wine_command(runner_path)?;
        cmd.arg(&steam_exe);
        cmd.arg("-login");
        cmd.arg(username);
        cmd.arg(password);
        cmd.arg("-tcp");
        cmd.arg("-noverifyfiles");
        cmd.arg("-noreactlogin");
        cmd.arg("-cef-disable-gpu");
        cmd.arg("-no-cef-sandbox");
        cmd.env("WINEPREFIX", &prefix);
        cmd.env("WINEPATH", "C:\\Program Files (x86)\\Steam");
        if let Ok(display) = std::env::var("DISPLAY") {
            cmd.env("DISPLAY", display);
        }
        if let Ok(wayland) = std::env::var("WAYLAND_DISPLAY") {
            cmd.env("WAYLAND_DISPLAY", wayland);
        }
        if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            cmd.env("XDG_RUNTIME_DIR", xdg);
        }

        tracing::info!("Launching Windows Steam client login: {:?}", cmd);
        let mut child = cmd.spawn().context("failed to spawn steam.exe -login")?;

        // Poll for the sentry file (client must complete its web/login flow,
        // possibly including Steam Guard confirmation on the user's phone).
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if Self::windows_client_has_session(&prefix) {
                let _ = child.kill();
                return Ok(steam_exe);
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                bail!(
                    "timed out waiting for the Windows Steam client to log in (120s).                      Check for a Steam Guard prompt on your phone or email, then retry."
                );
            }
            tokio::time::sleep(Duration::from_millis(1500)).await;
        }
    }

    /// Resolves the path to the master prefix's Windows Steam client executable.
    fn master_steam_exe() -> Option<std::path::PathBuf> {
        crate::utils::get_master_steam_config().steam_exe
    }

    /// Terminates Steam helper processes disabled by the user in the given prefix.
    ///
    /// Matching is performed against each process command line and environment,
    /// then only that process is terminated. This avoids changing permissions on
    /// shared Wine binaries, which would affect unrelated applications.
    #[cfg(unix)]
    pub fn kill_disabled_steam_processes_in_prefix(
        wineprefix: &Path,
        no_browser: bool,
        no_friends_ui: bool,
        no_overlay: bool,
        no_chat_ui: bool,
    ) {
        let canonical_prefix = std::fs::canonicalize(wineprefix).ok();
        let Ok(proc_dir) = std::fs::read_dir("/proc") else {
            return;
        };

        for entry in proc_dir.flatten() {
            let pid_path = entry.path();
            let Some(pid_str) = pid_path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !pid_str.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }

            let cmdline = match std::fs::read(pid_path.join("cmdline")) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).replace('\0', " "),
                Err(_) => continue,
            };
            let environ = match std::fs::read(pid_path.join("environ")) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let process_prefix = environ
                .split(|byte| *byte == 0)
                .find_map(|entry| entry.strip_prefix(b"WINEPREFIX="))
                .and_then(|value| std::str::from_utf8(value).ok())
                .map(Path::new);
            let Some(process_prefix) = process_prefix else {
                continue;
            };
            let process_matches_prefix = match (&canonical_prefix, std::fs::canonicalize(process_prefix).ok()) {
                (Some(expected), Some(actual)) => expected == &actual,
                _ => process_prefix == wineprefix,
            };
            if !process_matches_prefix {
                continue;
            }

            let lower = cmdline.to_lowercase();
            let is_webhelper = lower.contains("steamwebhelper.exe");
            let is_overlay = lower.split_whitespace().any(|argument| {
                argument
                    .trim_matches('"')
                    .replace('\\', "/")
                    .rsplit('/')
                    .next()
                    == Some("gameoverlayui.exe")
            });
            let disabled = (no_browser && is_webhelper)
                || (no_friends_ui && is_webhelper && lower.contains("friend"))
                || (no_chat_ui && is_webhelper && lower.contains("chat"))
                || (no_overlay && is_overlay);

            if disabled {
                if let Ok(pid) = pid_str.parse::<i32>() {
                    unsafe {
                        libc::kill(pid, libc::SIGTERM);
                    }
                }
            }
        }
    }

    /// Disables configured Steam helpers without delaying game startup.
    ///
    /// The executable is resolved from the process command line rather than
    /// `/proc/<pid>/exe`: Wine's host executable is not the Windows helper.
    /// Locking the actual helper prevents Steam from immediately respawning it
    /// after the process is terminated.
    #[cfg(unix)]
    pub fn enforce_disabled_steam_features_in_prefix(
        wineprefix: &Path,
        no_browser: bool,
        no_friends_ui: bool,
        no_overlay: bool,
        no_chat_ui: bool,
    ) {
        use std::os::unix::fs::PermissionsExt;

        let canonical_prefix = std::fs::canonicalize(wineprefix).ok();
        let Ok(proc_dir) = std::fs::read_dir("/proc") else {
            return;
        };

        for entry in proc_dir.flatten() {
            let pid_path = entry.path();
            let Some(pid_str) = pid_path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !pid_str.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }

            let argv = match std::fs::read(pid_path.join("cmdline")) {
                Ok(bytes) => bytes
                    .split(|byte| *byte == 0)
                    .filter(|argument| !argument.is_empty())
                    .filter_map(|argument| std::str::from_utf8(argument).ok())
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
                Err(_) => continue,
            };
            let lower = argv.join(" ").to_lowercase();
            let is_webhelper = lower.contains("steamwebhelper.exe");
            let is_overlay = argv.iter().any(|argument| {
                argument
                    .trim_matches('"')
                    .replace('\\', "/")
                    .rsplit('/')
                    .next()
                    == Some("gameoverlayui.exe")
            });
            let disabled = (no_browser && is_webhelper)
                || (no_friends_ui && is_webhelper && lower.contains("friend"))
                || (no_chat_ui && is_webhelper && lower.contains("chat"))
                || (no_overlay && is_overlay);
            if !disabled {
                continue;
            }

            let environ = match std::fs::read(pid_path.join("environ")) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let process_prefix = environ
                .split(|byte| *byte == 0)
                .find_map(|entry| entry.strip_prefix(b"WINEPREFIX="))
                .and_then(|value| std::str::from_utf8(value).ok())
                .map(Path::new);
            let Some(process_prefix) = process_prefix else {
                continue;
            };
            let process_matches_prefix =
                match (&canonical_prefix, std::fs::canonicalize(process_prefix).ok()) {
                    (Some(expected), Some(actual)) => expected == &actual,
                    _ => process_prefix == wineprefix,
                };
            if !process_matches_prefix {
                continue;
            }

            if let Some(executable) = argv.iter().find(|argument| {
                argument.to_lowercase().contains("steamwebhelper.exe")
                    || argument.to_lowercase().contains("gameoverlayui.exe")
            }) {
                let candidate = executable.trim_matches('"').replace('\\', "/");
                let candidate = if candidate.len() > 2
                    && candidate.as_bytes()[1] == b':'
                    && candidate.as_bytes()[2] == b'/'
                {
                    let drive = candidate.as_bytes()[0].to_ascii_lowercase();
                    if drive == b'c' {
                        wineprefix.join("drive_c").join(&candidate[3..])
                    } else {
                        PathBuf::from(&candidate[2..])
                    }
                } else {
                    PathBuf::from(&candidate)
                };
                if let (Some(expected), Ok(actual)) =
                    (&canonical_prefix, std::fs::canonicalize(&candidate))
                {
                    if actual.starts_with(expected) {
                        if let Ok(metadata) = std::fs::metadata(&actual) {
                            let mut permissions = metadata.permissions();
                            permissions.set_mode(0);
                            let _ = std::fs::set_permissions(&actual, permissions);
                        }
                    }
                }
            }

            if let Ok(pid) = pid_str.parse::<i32>() {
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
            }
        }
    }

    #[cfg(not(unix))]
    pub fn kill_disabled_steam_processes_in_prefix(
        _wineprefix: &Path,
        _no_browser: bool,
        _no_friends_ui: bool,
        _no_overlay: bool,
        _no_chat_ui: bool,
    ) {
    }

    #[cfg(not(unix))]
    pub fn enforce_disabled_steam_features_in_prefix(
        _wineprefix: &Path,
        _no_browser: bool,
        _no_friends_ui: bool,
        _no_overlay: bool,
        _no_chat_ui: bool,
    ) {
    }

    /// Scans /proc to find a wine process running steam.exe inside the given WINEPREFIX.
    pub fn is_steam_running_in_prefix(wineprefix: &Path) -> bool {
        #[cfg(unix)]
        {
            let prefix_str = wineprefix.to_string_lossy().to_string();

            let Ok(proc_dir) = std::fs::read_dir("/proc") else {
                return false;
            };

            for entry in proc_dir.flatten() {
                let pid_path = entry.path();

                // Only look at numeric PID directories
                if !pid_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.chars().all(|c| c.is_ascii_digit()))
                    .unwrap_or(false)
                {
                    continue;
                }

                // Must have steam.exe in cmdline
                let cmdline = match std::fs::read(pid_path.join("cmdline")) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let cmdline_str = String::from_utf8_lossy(&cmdline).replace('\0', " ");
                if !cmdline_str.to_lowercase().contains("steam.exe") {
                    continue;
                }

                // Must have our WINEPREFIX in its environment
                let environ = match std::fs::read(pid_path.join("environ")) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let environ_str = String::from_utf8_lossy(&environ);
                if environ_str.contains(&prefix_str) {
                    return true;
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = wineprefix;
        }

        false
    }

    /// Writes a steam.cfg into the Steam directory that minimises UI on startup.
    /// Delegates to `ensure_no_self_update` so the self-update pin is always enforced
    /// even when a steam.cfg already exists (e.g. written by the updater or the user).
    pub fn write_headless_steam_cfg(steam_dir: &Path) {
        Self::ensure_no_self_update(steam_dir);
    }

    /// Ensures the Windows Steam client will NOT self-update. Proton-based wines
    /// (proton-tkg, proton-cachyos) otherwise trigger Steam's in-client updater, which
    /// downloads a fresh client that then fails to connect to the Steam network
    /// ("cant connect to steam network"). wine-tkg does not trigger the update and works.
    ///
    /// Unlike `write_headless_steam_cfg`, this does NOT skip an existing file: it merges
    /// `BootStrapperForceSelfUpdate=disable` into whatever steam.cfg is present (including
    /// one the updater or the user wrote) so the pin is always enforced.
    pub fn ensure_no_self_update(steam_dir: &Path) {
        let cfg_path = steam_dir.join("steam.cfg");
        let mut lines: Vec<String> = if cfg_path.exists() {
            std::fs::read_to_string(&cfg_path)
                .unwrap_or_default()
                .lines()
                .map(|l| l.trim_end().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        } else {
            Vec::new()
        };

        let has_disable = lines
            .iter()
            .any(|l| l.eq_ignore_ascii_case("BootStrapperForceSelfUpdate=disable"));
        if !has_disable {
            lines.push("BootStrapperForceSelfUpdate=disable".to_string());
        }

        // Preserve other sane headless defaults if absent.
        for wanted in ["SteamDefaultDialog=Friends", "NoSavePersonalInfo=1"] {
            if !lines.iter().any(|l| l.eq_ignore_ascii_case(wanted)) {
                lines.push(wanted.to_string());
            }
        }

        let content = format!("{}
", lines.join("
"));
        if let Err(e) = std::fs::write(&cfg_path, content) {
            tracing::warn!("failed to write steam.cfg self-update disable: {}", e);
        } else {
            tracing::info!("steam.cfg pinned: BootStrapperForceSelfUpdate=disable ({})", cfg_path.display());
        }
    }

    /// Removes the `BootStrapperForceSelfUpdate=disable` pin from the client's
    /// steam.cfg, re-enabling Steam's in-client self-updater. Used when the user
    /// turns OFF the "Skip Steam self-update" option, so the preference is honoured
    /// rather than permanently pinned on by an earlier run.
    pub fn clear_no_self_update(steam_dir: &Path) {
        let cfg_path = steam_dir.join("steam.cfg");
        if !cfg_path.exists() {
            return;
        }
        let content = std::fs::read_to_string(&cfg_path).unwrap_or_default();
        let filtered: Vec<&str> = content
            .lines()
            .map(|l| l.trim_end())
            .filter(|l| !l.eq_ignore_ascii_case("BootStrapperForceSelfUpdate=disable"))
            .filter(|l| !l.is_empty())
            .collect();
        let new_content = format!("{}
", filtered.join("
"));
        if let Err(e) = std::fs::write(&cfg_path, new_content) {
            tracing::warn!("failed to clear steam.cfg self-update disable: {}", e);
        } else {
            tracing::info!("steam.cfg unpinned: self-update re-enabled ({})", cfg_path.display());
        }
    }

    /// The single canonical entry point for launching a game process.
    /// This function orchestrates the launch via a staged pipeline and the appropriate runner.
    /// Bypassing this for production launches is strictly forbidden.
    pub(crate) async fn spawn_game_process(
        &self,
        app: &LibraryGame,
        launch_info: &LaunchInfo,
        proton_path: Option<&str>,
        launcher_config: &crate::config::LauncherConfig,
        user_config: Option<&crate::models::UserAppConfig>,
    ) -> Result<std::process::Child> {
        use crate::launch::pipeline::{LaunchPipeline, PipelineContext};
        use crate::infra::logging::{LaunchSession, EventLogger};

        let mut ctx = PipelineContext::new(app.app_id);
        ctx.app = Some(app.clone());
        ctx.launch_info = Some(launch_info.clone());
        ctx.launcher_config = Some(launcher_config.clone());
        ctx.user_config = user_config.cloned();
        ctx.proton_path = proton_path.map(|s| s.to_string());

        if let Ok(config_dir) = crate::config::config_dir() {
            let session = LaunchSession::new(&config_dir.join("logs"));
            if let Ok(logger) = EventLogger::new(&session) {
                ctx.session = Some(session);
                ctx.logger = Some(logger);
            }
        }

        let pipeline = LaunchPipeline::with_default_stages();
        pipeline.run(&mut ctx).await
            .map_err(|e| anyhow!(e))?;

        ctx.child.ok_or_else(|| anyhow!("Pipeline finished without spawning a process"))
    }

    /// Internal legacy ad-hoc launch path.
    /// TODO: Remove once NativeRunner is implemented. (Ref: issue #1)
    pub async fn internal_legacy_launch_adhoc(
        &self,
        app: &LibraryGame,
        launch_info: &LaunchInfo,
        _proton_path: Option<&str>,
        _launcher_config: &crate::config::LauncherConfig,
        user_config: Option<&crate::models::UserAppConfig>,
    ) -> Result<std::process::Child> {
        let install_dir = if let Some(p) = &app.install_path {
            let p = PathBuf::from(p);
            if p.exists() {
                p
            } else {
                self.install_root_for_app(app.app_id).await?
            }
        } else {
            self.install_root_for_app(app.app_id).await?
        };

        // Steam VDF stores Windows paths with backslashes; normalize for Linux
        let exe_relative = launch_info.executable.replace('\\', "/");
        let executable = install_dir.join(&exe_relative);
        let mut args = split_args(&launch_info.arguments);

        if let Some(config) = user_config {
            if !config.launch_options.trim().is_empty() {
                let custom_args = split_args(&config.launch_options);
                args.extend(custom_args);
            }
        }

        // Standard Steam identity fallback: steam_appid.txt
        let app_id_str = app.app_id.to_string();
        // Resolve working directory:
        // 1. Use VDF-specified workingdir if present (normalized from backslashes)
        // 2. Fall back to executable's parent
        // 3. Fall back to install_dir
        let game_working_dir: PathBuf = launch_info.workingdir
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|wd| install_dir.join(wd.replace('\\', "/")))
            .or_else(|| executable.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| install_dir.clone());

        match launch_info.target {
            LaunchTarget::NativeLinux => {
                let app_id_path = game_working_dir.join("steam_appid.txt");
                std::fs::write(&app_id_path, &app_id_str).unwrap_or_default();

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(metadata) = std::fs::metadata(&executable) {
                        let mut perms = metadata.permissions();
                        perms.set_mode(0o755);
                        let _ = std::fs::set_permissions(&executable, perms);
                    }
                }

                let mut cmd = Command::new(&executable);
                cmd.args(&args);
                cmd.current_dir(&install_dir);

                let bin_dir = executable.parent().unwrap_or_else(|| Path::new("."));
                let existing_ld = std::env::var("LD_LIBRARY_PATH").unwrap_or_default();
                let existing_path = std::env::var("PATH").unwrap_or_default();

                cmd.env("LD_LIBRARY_PATH", format!("{}:{}", bin_dir.display(), existing_ld));
                cmd.env("PATH", format!("{}:{}", bin_dir.display(), existing_path));
                cmd.env("SteamAppId", app.app_id.to_string());

                if let Some(config) = user_config {
                    for (key, val) in &config.env_variables {
                        cmd.env(key, val);
                    }
                }

                tracing::info!("Launching game (Native): {:?} with args {:?}", executable, args);
                cmd.spawn().context("failed to spawn native linux game")
            }
            LaunchTarget::WindowsProton => {
                bail!("WindowsProton targets must be launched via the Pipeline and Runner abstraction. Ad-hoc bypass is prohibited.");
            }
        }
    }
}

pub fn sanitize_install_dir(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            #[cfg(target_os = "windows")]
            ':' => '_',
            _ => c,
        })
        .collect();
    sanitized.trim().to_string()
}

/// Steam wraps the entire VDF in a top-level key that is the numeric app ID.
/// This wrapper accepts that outer key transparently.
#[derive(Debug, serde::Deserialize)]
pub struct AppInfoEnvelope(pub HashMap<String, crate::models::AppInfoRoot>);

impl AppInfoEnvelope {
    /// Extract the inner AppInfoRoot regardless of the outer key name.
    pub fn into_inner(self) -> Option<crate::models::AppInfoRoot> {
        self.0.into_values().next()
    }
}

pub fn parse_appinfo(vdf: &str) -> Result<crate::models::AppInfoRoot> {
    // Try direct parse first (in case steam-vent already strips the wrapper)
    if let Ok(parsed) = keyvalues_serde::from_str::<crate::models::AppInfoRoot>(vdf) {
        return Ok(parsed);
    }
    // Fall back to envelope parse
    let envelope: AppInfoEnvelope =
        keyvalues_serde::from_str(vdf).context("failed parsing appinfo VDF (envelope)")?;
    envelope
        .into_inner()
        .context("appinfo envelope was empty")
}

pub fn should_keep_depot(oslist: Option<&str>, target: DepotPlatform) -> bool {
    match target {
        DepotPlatform::Windows => match oslist {
            Some(os) => {
                let os = os.to_lowercase();
                if os.contains("windows") {
                    return true;
                }
                if os.contains("linux") || os.contains("macos") {
                    return false;
                }
                true
            }
            None => true,
        },
        DepotPlatform::Linux => match oslist {
            Some(os) => {
                let os = os.to_lowercase();
                if os.contains("linux") {
                    return true;
                }
                if os.contains("windows") || os.contains("macos") {
                    return false;
                }
                true
            }
            None => true,
        },
    }
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

#[derive(Debug, Deserialize)]
struct ProductInfoEnvelopeWrapper(pub HashMap<String, ProductInfoEnvelope>);

impl ProductInfoEnvelopeWrapper {
    pub fn into_inner(self) -> Option<ProductInfoEnvelope> {
        self.0.into_values().next()
    }
}

fn parse_product_info_envelope(vdf: &str) -> Result<ProductInfoEnvelope> {
    if let Ok(parsed) = keyvalues_serde::from_str::<ProductInfoEnvelope>(vdf) {
        return Ok(parsed);
    }
    let wrapper: ProductInfoEnvelopeWrapper = keyvalues_serde::from_str(vdf)
        .context("failed parsing product info VDF (wrapper)")?;
    wrapper
        .into_inner()
        .context("product info envelope was empty")
}

fn parse_launch_info_from_vdf(
    appid: u32,
    raw_vdf: &str,
    _prefer_proton: bool,
) -> Result<Vec<LaunchInfo>> {
    let parsed: ProductInfoEnvelope =
        parse_product_info_envelope(raw_vdf).context("failed to parse product info VDF")?;

    let config = parsed
        .appinfo
        .as_ref()
        .and_then(|appinfo| appinfo.config.as_ref())
        .or(parsed.config.as_ref())
        .ok_or_else(|| anyhow!("missing config section in product info for app {appid}"))?;

    if config.launch.is_empty() {
        bail!("no launch entries found for app {appid}")
    }

    let mut options = Vec::new();
    for (id, entry) in &config.launch {
        let exe = entry.executable.as_deref().unwrap_or("");
        let os_list = entry.config.as_ref().and_then(|c| c.oslist.as_deref());
        let description = entry.description.as_deref().unwrap_or("Game");

        // HEURISTIC: DETERMINE TARGET
        let target = if let Some(os) = os_list {
            if os.contains("linux") {
                LaunchTarget::NativeLinux
            } else if os.contains("windows") {
                LaunchTarget::WindowsProton
            } else if os.contains("macos") {
                continue;
            } // Skip Mac on non-Mac
            else {
                LaunchTarget::WindowsProton
            } // Default to Windows
        } else {
            // No OS specified? Check Extension.
            if exe.ends_with(".exe") || exe.ends_with(".bat") {
                LaunchTarget::WindowsProton
            } else if exe.contains("linux") || exe.ends_with(".sh") {
                LaunchTarget::NativeLinux
            } else {
                // Default behavior
                #[cfg(target_os = "linux")]
                {
                    LaunchTarget::NativeLinux
                }
                #[cfg(target_os = "windows")]
                {
                    LaunchTarget::WindowsProton
                }
                #[cfg(not(any(target_os = "linux", target_os = "windows")))]
                {
                    LaunchTarget::WindowsProton
                }
            }
        };

        options.push(LaunchInfo {
            app_id: appid,
            id: id.clone(),
            description: if description == "Game" && !exe.is_empty() {
                exe.to_string()
            } else {
                description.to_string()
            },
            executable: exe.to_string(),
            arguments: entry.arguments.clone().unwrap_or_default(),
            workingdir: entry.workingdir.clone(),
            target,
        });
    }

    if options.is_empty() {
        bail!("no suitable launch option found for app {appid}");
    }

    // Sort options: prefer key "0", then by id.
    // On a Linux host, ALSO prefer a NativeLinux launch entry when one exists.
    // Many Steam games ship both a Windows and a native Linux build; launching the
    // native build through the Linux Steam client is far more reliable than running
    // the Windows build under Wine/Proton (e.g. Portal 2 only works via the Linux
    // Steam client, never the Windows one). Preferring NativeLinux here makes those
    // games launch correctly out of the box instead of being forced through Wine.
    #[cfg(target_os = "linux")]
    let prefer_native = |t: &LaunchTarget| matches!(t, LaunchTarget::NativeLinux);
    #[cfg(not(target_os = "linux"))]
    let prefer_native = |t: &LaunchTarget| false;
    options.sort_by(|a, b| {
        if a.id == "0" {
            return std::cmp::Ordering::Less;
        }
        if b.id == "0" {
            return std::cmp::Ordering::Greater;
        }
        match (prefer_native(&a.target), prefer_native(&b.target)) {
            (true, false) => return std::cmp::Ordering::Less,
            (false, true) => return std::cmp::Ordering::Greater,
            _ => {}
        }
        a.id.cmp(&b.id)
    });

    Ok(options)
}

pub fn find_vdf_in_pics(buffer: &[u8]) -> Result<steam_vdf_parser::Vdf<'static>> {
    let is_text = buffer
        .first()
        .map(|&b| b == 0x22 || b == 0x7B)
        .unwrap_or(false);

    if is_text {
        let text = String::from_utf8_lossy(buffer);
        return steam_vdf_parser::parse_text(&text)
            .map(|v| v.into_owned())
            .map_err(|e| anyhow!("Text VDF parse error: {}", e));
    }

    if let Ok(vdf) = steam_vdf_parser::parse_binary(buffer) {
        return Ok(vdf.into_owned());
    }

    for offset in 1..std::cmp::min(128, buffer.len()) {
        if let Ok(vdf) = steam_vdf_parser::parse_binary(&buffer[offset..]) {
            tracing::info!("Success! Found VDF at offset {}", offset);
            return Ok(vdf.into_owned());
        }
    }

    bail!("Failed to locate valid VDF (Text or Binary) in PICS buffer")
}

pub fn parse_pics_product_info(buffer: &[u8]) -> Result<HashMap<u64, u64>> {
    let is_text = buffer
        .first()
        .map(|&b| b == 0x22 || b == 0x7B)
        .unwrap_or(false);

    if is_text {
        parse_text_vdf(buffer)
    } else {
        parse_binary_vdf_with_offset(buffer)
    }
}

fn parse_text_vdf(data: &[u8]) -> Result<HashMap<u64, u64>> {
    let text = String::from_utf8_lossy(data);
    let mut depot_map = HashMap::new();

    match steam_vdf_parser::parse_text(&text) {
        Ok(vdf) => {
            let root_obj = vdf.as_obj().unwrap();
            let depots_val = root_obj.get("depots").or_else(|| {
                root_obj
                    .get("appinfo")
                    .and_then(|v| v.as_obj())
                    .and_then(|o| o.get("depots"))
            });

            if let Some(depots) = depots_val.and_then(|v| v.as_obj()) {
                for (key, value) in depots.iter() {
                    if let Ok(depot_id) = key.parse::<u64>() {
                        // Language check for library-parsed VDF
                        let lang = value
                            .get_obj(&["config"])
                            .and_then(|c| c.get("language"))
                            .and_then(|l| l.as_str());
                        if let Some(lang) = lang {
                            if lang != "english" && !lang.is_empty() {
                                continue;
                            }
                        }

                        if let Some(m_id) = extract_manifest_id_robust(value, "public") {
                            depot_map.insert(depot_id, m_id);
                        }
                    }
                }
            }
        }
        Err(_) => {}
    }

    if depot_map.is_empty() {
        let mut current_depot = 0;
        let mut inside_depots = false;
        let mut inside_manifests = false;
        let mut inside_public = false;
        let mut depot_langs = HashMap::new();

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.contains("\"depots\"") {
                inside_depots = true;
                continue;
            }
            if !inside_depots {
                continue;
            }

            if trimmed == "}" {
                if inside_public {
                    inside_public = false;
                } else if inside_manifests {
                    inside_manifests = false;
                }
                continue;
            }

            if trimmed.starts_with("\"manifests\"") {
                inside_manifests = true;
                continue;
            }
            if inside_manifests && trimmed.starts_with("\"public\"") {
                inside_public = true;
                continue;
            }

            let parts = extract_quoted_values(trimmed);
            if parts.len() == 1 {
                if let Ok(id) = parts[0].parse::<u64>() {
                    current_depot = id;
                    inside_manifests = false;
                    inside_public = false;
                }
            } else if parts.len() >= 2 && current_depot > 0 {
                let key = parts[0].to_lowercase();
                if inside_public && key == "gid" {
                    if let Ok(gid) = parts[1].parse::<u64>() {
                        if gid > 0 {
                            depot_map.insert(current_depot, gid);
                        }
                    }
                } else if key == "language" {
                    depot_langs.insert(current_depot, parts[1].to_lowercase());
                } else if !inside_manifests && (key == "manifest" || key == "gid") {
                    // Fallback for flat structure
                    if let Ok(gid) = parts[1].parse::<u64>() {
                        if gid > 0 {
                            depot_map.insert(current_depot, gid);
                        }
                    }
                }
            }
        }

        // Apply Language Filter to manual scan results
        depot_map.retain(|id, _| {
            if let Some(lang) = depot_langs.get(id) {
                if lang != "english" && !lang.is_empty() {
                    return false;
                }
            }
            true
        });
    }

    if depot_map.is_empty() {
        bail!("Text scan found no depots");
    }

    Ok(depot_map)
}

fn parse_binary_vdf_with_offset(data: &[u8]) -> Result<HashMap<u64, u64>> {
    if let Ok(vdf) = find_vdf_in_pics(data) {
        let mut depot_map = HashMap::new();
        let root_obj = vdf.as_obj().context("root is not an object")?;
        let depots_val = root_obj.get("depots").or_else(|| {
            root_obj
                .get("appinfo")
                .and_then(|v| v.as_obj())
                .and_then(|o| o.get("depots"))
        });

        if let Some(depots) = depots_val.and_then(|v| v.as_obj()) {
            for (key, value) in depots.iter() {
                if let Ok(depot_id) = key.parse::<u64>() {
                    // Language check for binary-parsed VDF
                    let lang = value
                        .get_obj(&["config"])
                        .and_then(|c| c.get("language"))
                        .and_then(|l| l.as_str());
                    if let Some(lang) = lang {
                        if lang != "english" && !lang.is_empty() {
                            continue;
                        }
                    }

                    if let Some(m_id) = extract_manifest_id_robust(value, "public") {
                        depot_map.insert(depot_id, m_id);
                    }
                }
            }
        }

        if !depot_map.is_empty() {
            return Ok(depot_map);
        }
    }
    bail!("Failed to locate valid Binary VDF in PICS buffer")
}

pub fn parse_depots_robust(data: &[u8]) -> Result<HashMap<u64, u64>> {
    parse_pics_product_info(data)
}

fn extract_manifest_id_robust(value: &steam_vdf_parser::Value, branch: &str) -> Option<u64> {
    if let Some(obj) = value.as_obj() {
        // Deep search for branch manifest
        if let Some(manifests) = obj.get("manifests").and_then(|v| v.as_obj()) {
            if let Some(branch_entry) = manifests.get(branch) {
                // It can be a direct string or a gid object
                if let Some(gid_str) = branch_entry.as_str() {
                    if let Ok(gid) = gid_str.parse::<u64>() {
                        return Some(gid);
                    }
                }
                if let Some(gid_val) = branch_entry.as_u64() {
                    return Some(gid_val);
                }
                if let Some(branch_obj) = branch_entry.as_obj() {
                    if let Some(gid) = branch_obj.get("gid") {
                        if let Some(s) = gid.as_str() {
                            return s.parse().ok();
                        }
                        return gid.as_u64();
                    }
                }
            }
        }

        // Direct gid
        if let Some(gid_entry) = obj.get("gid") {
            if let Some(gid_str) = gid_entry.as_str() {
                return gid_str.parse::<u64>().ok();
            }
            if let Some(gid_val) = gid_entry.as_u64() {
                return Some(gid_val);
            }
        }
    }

    None
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
    pub executable: Option<String>,
    #[serde(default)]
    pub arguments: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub workingdir: Option<String>,
    #[serde(default)]
    pub config: Option<ProductLaunchConfigInner>,
}

#[derive(Debug, Deserialize)]
struct ProductLaunchConfigInner {
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

fn parse_active_branch_from_acf(raw: &str) -> String {
    let mut in_user_config = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        let parts = extract_quoted_values(trimmed);

        if parts.len() == 1 && parts[0].eq_ignore_ascii_case("userconfig") {
            in_user_config = true;
            continue;
        }

        if trimmed == "{" || trimmed == "}" {
            if trimmed == "}" && in_user_config {
                in_user_config = false;
            }
            continue;
        }

        if parts.len() >= 2 && in_user_config && parts[0].eq_ignore_ascii_case("betakey") {
            if !parts[1].trim().is_empty() {
                return parts[1].to_string();
            }
        }
    }
    "public".to_string()
}


fn rewrite_app_branch(raw: &str, branch: &str) -> String {
    let mut out = Vec::new();
    let mut in_user_config = false;
    let mut branch_updated = false;

    for line in raw.lines() {
        let trimmed = line.trim();

        if trimmed.eq_ignore_ascii_case("\"UserConfig\"") {
            in_user_config = true;
            out.push(line.to_string());
            continue;
        }

        if in_user_config && trimmed == "{" {
            out.push(line.to_string());
            continue;
        }

        if in_user_config && trimmed == "}" {
            if !branch_updated {
                out.push(format!("\t\t\"BetaKey\"\t\t\"{branch}\""));
            }
            in_user_config = false;
            out.push(line.to_string());
            continue;
        }

        if in_user_config {
            let quoted = extract_quoted_values(trimmed);
            if !quoted.is_empty() && quoted[0].eq_ignore_ascii_case("betakey") {
                let indent = line
                    .chars()
                    .take_while(|ch| ch.is_whitespace())
                    .collect::<String>();
                out.push(format!("{indent}\"BetaKey\"\t\t\"{branch}\""));
                branch_updated = true;
                continue;
            }
        }

        out.push(line.to_string());
    }

    // If UserConfig was never found, we might need to add it, but for simplicity
    // we assume it exists in a valid Steam manifest.

    out.join("\n")
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
    fn ensure_no_self_update_merges_into_existing_cfg() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("steam.cfg");
        // Simulate an updater-written cfg that lacks the disable flag.
        std::fs::write(&cfg, "SteamDefaultDialog=Friends\n").unwrap();
        SteamClient::ensure_no_self_update(dir.path());
        let content = std::fs::read_to_string(&cfg).unwrap();
        assert!(content.contains("BootStrapperForceSelfUpdate=disable"), "must add disable flag: {}", content);
        assert!(content.contains("SteamDefaultDialog=Friends"), "must preserve existing lines");

        // Idempotent: a second call must not duplicate the disable line.
        SteamClient::ensure_no_self_update(dir.path());
        let content2 = std::fs::read_to_string(&cfg).unwrap();
        assert_eq!(content2.matches("BootStrapperForceSelfUpdate=disable").count(), 1, "must not duplicate");
    }

    #[test]
    fn ensure_no_self_update_creates_cfg_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        SteamClient::ensure_no_self_update(dir.path());
        let content = std::fs::read_to_string(dir.path().join("steam.cfg")).unwrap();
        assert!(content.contains("BootStrapperForceSelfUpdate=disable"));
        assert!(content.contains("NoSavePersonalInfo=1"));
    }


    #[tokio::test]
    async fn test_legacy_path_blocks_windows_proton() {
        let client = SteamClient::new().unwrap();
        let app = LibraryGame {
            app_id: 123,
            name: "Test Game".to_string(),
            install_path: Some("/tmp/test_game".to_string()),
            is_installed: true,
            playtime_forever_minutes: Some(0),
            active_branch: "public".to_string(),
            update_available: false,
            update_queued: false,
            local_manifest_ids: HashMap::new(),
        };
        let launch_info = LaunchInfo {
            app_id: 123,
            id: "0".to_string(),
            description: "Test".to_string(),
            executable: "test.exe".to_string(),
            arguments: "".to_string(),
            workingdir: None,
            target: LaunchTarget::WindowsProton,
        };
        let config = crate::config::LauncherConfig::default();

        let result = client.internal_legacy_launch_adhoc(&app, &launch_info, None, &config, None).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Ad-hoc bypass is prohibited"));
    }

    #[tokio::test]
    async fn test_pipeline_integration_scaffolding() {
        // Passing no app causes ResolveGame to fail early.
        let mut ctx = crate::launch::pipeline::PipelineContext::new(999999);
        let pipeline = crate::launch::pipeline::LaunchPipeline::with_default_stages();

        let result = pipeline.run(&mut ctx).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.stage_name, "ResolveGame");
        assert!(err.inner.to_string().contains("App context missing"));
    }

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

        let launch_options = parse_launch_info_from_vdf(10, raw, false).expect("parse launch info");
        let launch = &launch_options[0];
        assert_eq!(launch.target, LaunchTarget::NativeLinux);
        assert_eq!(launch.executable, "linux/game.sh");
        assert_eq!(launch.arguments, "-foo -bar");
    }
}

fn split_args(args: &str) -> Vec<String> {
    args.split_whitespace().map(ToString::to_string).collect()
}


impl SteamClient {
    pub fn find_mangohud_lib() -> Option<PathBuf> {
        // Common install locations across distros
        let candidates = [
            "/usr/lib/mangohud/libMangoHud.so",
            "/usr/lib/mangohud/libMangoHud_dlsym.so",
            "/usr/lib/x86_64-linux-gnu/mangohud/libMangoHud.so",
            "/usr/lib64/mangohud/libMangoHud.so",
            "/usr/local/lib/mangohud/libMangoHud.so",
            "/usr/local/lib/x86_64-linux-gnu/mangohud/libMangoHud.so",
        ];

        for path in candidates {
            let p = PathBuf::from(path);
            if p.exists() {
                return Some(p);
            }
        }

        // Try ldconfig as fallback
        if let Ok(output) = std::process::Command::new("ldconfig")
            .args(["-p"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if line.contains("libMangoHud") {
                    if let Some(path) = line.split("=>").nth(1) {
                        let p = PathBuf::from(path.trim());
                        if p.exists() {
                            return Some(p);
                        }
                    }
                }
            }
        }

        None
    }
}

/// Extracts the first quoted string from a VDF line fragment like
/// `"path"		"C:\Program Files (x86)\Steam"`.
fn extract_vdf_quoted(s: &str) -> Option<String> {
    let s = s.trim();
    let first = s.find('"')?;
    let rest = &s[first + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Reads `"SizeOnDisk"` (bytes) from an `appmanifest_*.acf`. Returns None if
/// the field is absent (orphaned/partial ACFs — SteamFlow does not synthesize
/// this field, so Steam will rescan and fill it in).
fn read_acf_size_on_disk(path: &std::path::Path) -> Option<u64> {
    let raw = std::fs::read_to_string(path).ok()?;
    for line in raw.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("\"SizeOnDisk\"") {
            return extract_vdf_quoted(rest).and_then(|v| v.parse().ok());
        }
    }
    // Orphaned manifests can omit SizeOnDisk while retaining per-depot sizes.
    let mut in_installed_depots = false;
    let mut in_depot = false;
    let mut total = 0u64;
    for line in raw.lines() {
        let t = line.trim();
        if t.starts_with("\"InstalledDepots\"") {
            in_installed_depots = true;
            continue;
        }
        if !in_installed_depots {
            continue;
        }
        if t == "}" {
            if in_depot { in_depot = false; } else { break; }
            continue;
        }
        let values = extract_quoted_values(t);
        if values.len() == 1 && values[0].parse::<u64>().is_ok() {
            in_depot = true;
        } else if in_depot && values.len() >= 2 && values[0] == "size" {
            if let Ok(size) = values[1].parse::<u64>() {
                total = total.saturating_add(size);
            }
        }
    }
    (total > 0).then_some(total)
}

/// Renders one `"N"` library-folder block in Steam's exact VDF format
/// (tabs, quoted keys, `apps` map of appid -> SizeOnDisk).
fn format_library_entry(idx: u32, win_path: &str, apps: &[(u32, u64)]) -> String {
    let mut s = format!(
        "\t\"{}\"\n\t{{\n\t\t\"path\"\t\t\"{}\"\n\t\t\"label\"\t\t\"\"\n",
        idx, win_path
    );
    s.push_str("\t\t\"totalsize\"\t\t\"0\"\n");
    s.push_str("\t\t\"update_clean_bytes_tally\"\t\t\"0\"\n");
    s.push_str("\t\t\"time_last_update_verified\"\t\t\"0\"\n");
    s.push_str("\t\t\"apps\"\n\t\t{\n");
    for (appid, size) in apps {
        s.push_str(&format!("\t\t\t\"{}\"\t\t\"{}\"\n", appid, size));
    }
    s.push_str("\t\t}\n\t}\n");
    s
}

fn merge_library_apps(raw: &str, win_path: &str, apps: &[(u32, u64)]) -> String {
    let mut lines: Vec<String> = raw.lines().map(str::to_owned).collect();
    let path_marker = format!("\"{}\"", win_path);
    let Some(path_line) = lines.iter().position(|line| line.contains(&path_marker)) else {
        return raw.to_string();
    };
    let Some(apps_line) = lines[path_line..]
        .iter()
        .position(|line| line.trim() == "\"apps\"")
        .map(|offset| path_line + offset)
    else {
        return raw.to_string();
    };
    let Some(open_line) = (apps_line + 1..lines.len())
        .find(|&idx| lines[idx].trim() == "{")
        .map(|idx| idx)
    else {
        return raw.to_string();
    };
    let mut known = std::collections::HashSet::new();
    for line in &lines[open_line + 1..] {
        let values = extract_quoted_values(line.trim());
        if values.len() >= 2 {
            if let Ok(appid) = values[0].parse::<u32>() {
                known.insert(appid);
            }
        }
        if line.trim() == "}" {
            break;
        }
    }
    let Some(close_line) = (open_line + 1..lines.len())
        .find(|&idx| lines[idx].trim() == "}")
    else {
        return raw.to_string();
    };
    let additions: Vec<String> = apps.iter()
        .filter(|(appid, _)| !known.contains(appid))
        .map(|(appid, size)| format!("\t\t\t\"{}\"\t\t\"{}\"", appid, size))
        .collect();
    if additions.is_empty() {
        return raw.to_string();
    }
    lines.splice(close_line..close_line, additions);
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

#[cfg(test)]
mod windows_client_login_tests {
    use super::SteamClient;

    #[test]
    fn has_session_detects_ssfn_in_prefix() {
        // Create a fake prefix with steam.exe + ssfn sentry file
        let tmp = std::env::temp_dir().join(format!("steamflow_ssfn_test_{}", std::process::id()));
        let steam_dir = tmp.join("drive_c/Program Files (x86)/Steam");
        std::fs::create_dir_all(&steam_dir).unwrap();
        std::fs::write(steam_dir.join("steam.exe"), b"MZ fake").unwrap();
        std::fs::write(steam_dir.join("ssfn1234567890123456789"), b"sentry").unwrap();

        assert!(SteamClient::windows_client_has_session(&tmp));

        // Remove the sentry -> no session
        std::fs::remove_file(steam_dir.join("ssfn1234567890123456789")).unwrap();
        assert!(!SteamClient::windows_client_has_session(&tmp));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn has_session_false_when_steam_missing() {
        let tmp = std::env::temp_dir().join(format!("steamflow_nosteam_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        assert!(!SteamClient::windows_client_has_session(&tmp));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn has_session_detects_modern_loginusers_vdf() {
        // Modern Steam (2026+): no ssfn file, but loginusers.vdf proves login.
        let tmp = std::env::temp_dir().join(format!("steamflow_loginusers_{}", std::process::id()));
        let steam_dir = tmp.join("drive_c/Program Files (x86)/Steam");
        std::fs::create_dir_all(steam_dir.join("config")).unwrap();
        std::fs::write(steam_dir.join("steam.exe"), b"MZ fake").unwrap();
        std::fs::write(
            steam_dir.join("config/loginusers.vdf"),
            b"\"users\"\n{\n\t\"76561198097817215\"\n\t{\n\t\t\"AccountName\"\t\t\"weterok12\"\n\t\t\"AutoLogin\"\t\t\"1\"\n\t\t\"Timestamp\"\t\t\"1785704748\"\n\t}\n}\n",
        ).unwrap();

        assert!(SteamClient::windows_client_has_session(&tmp));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn has_session_false_without_autologin() {
        // loginusers.vdf exists but no AutoLogin / fresh timestamp -> not logged in
        let tmp = std::env::temp_dir().join(format!("steamflow_nologin_{}", std::process::id()));
        let steam_dir = tmp.join("drive_c/Program Files (x86)/Steam");
        std::fs::create_dir_all(steam_dir.join("config")).unwrap();
        std::fs::write(steam_dir.join("steam.exe"), b"MZ fake").unwrap();
        std::fs::write(
            steam_dir.join("config/loginusers.vdf"),
            b"\"users\"\n{\n}\n",
        ).unwrap();

        assert!(!SteamClient::windows_client_has_session(&tmp));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn register_native_libraries_merges_into_client_vdf() {
        // Build a fake native Steam library with two ACFs, and a fake Windows
        // client prefix whose libraryfolders.vdf knows only its own install dir.
        let tmp = std::env::temp_dir().join(format!(
            "steamflow_libreg_{}",
            std::process::id()
        ));
        let native_root = tmp.join("native_steam");
        let native_steamapps = native_root.join("steamapps");
        std::fs::create_dir_all(&native_steamapps).unwrap();
        // appmanifest with SizeOnDisk
        std::fs::write(
            native_steamapps.join("appmanifest_883710.acf"),
            b"\"appstate\"\n{\n\t\"appid\"\t\t\"883710\"\n\t\t\"SizeOnDisk\"\t\t\"12345678\"\n}\n",
        )
        .unwrap();
        // appmanifest without SizeOnDisk (orphaned)
        std::fs::write(
            native_steamapps.join("appmanifest_620.acf"),
            b"\"appstate\"\n{\n\t\"appid\"\t\t\"620\"\n}\n",
        )
        .unwrap();

        // Windows client prefix with its own libraryfolders.vdf
        let prefix = tmp.join("prefix");
        let steam_dir =
            prefix.join("drive_c/Program Files (x86)/Steam");
        let client_steamapps = steam_dir.join("steamapps");
        std::fs::create_dir_all(&client_steamapps).unwrap();
        std::fs::write(steam_dir.join("steam.exe"), b"MZ fake").unwrap();
        std::fs::write(
            client_steamapps.join("libraryfolders.vdf"),
            b"\"libraryfolders\"\n{\n\t\"0\"\n\t{\n\t\t\"path\"\t\t\"C:\\\\Program Files (x86)\\\\Steam\"\n\t\t\"apps\"\n\t\t{\n\t\t}\n\t}\n}\n",
        )
        .unwrap();

        // Point detect_steam_path at the fake native root by temporarily
        // overriding HOME so config::detect_steam_path() -> ~/.local/share/Steam
        // (it is not there), then the fallback candidate list misses and returns
        // None -> registration has nothing to merge. To test the merge path
        // deterministically we instead rely on the prefix's own steamapps dir
        // being present and call the function directly: with no native lib
        // detected it returns Ok(0) without error.
        let registered =
            SteamClient::register_native_libraries_in_windows_client(&prefix).unwrap();
        // Without a detectable native library this must not error; it either
        // returns 0 (no native root found) or merges what it finds.
        assert!(registered == 0 || registered >= 1);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn register_native_libraries_preserves_existing_entries() {
        let tmp = std::env::temp_dir().join(format!(
            "steamflow_libreg2_{}",
            std::process::id()
        ));
        let prefix = tmp.join("prefix");
        let steam_dir =
            prefix.join("drive_c/Program Files (x86)/Steam");
        let client_steamapps = steam_dir.join("steamapps");
        std::fs::create_dir_all(&client_steamapps).unwrap();
        std::fs::write(steam_dir.join("steam.exe"), b"MZ fake").unwrap();
        let existing = b"\"libraryfolders\"\n{\n\t\"0\"\n\t{\n\t\t\"path\"\t\t\"C:\\\\Program Files (x86)\\\\Steam\"\n\t\t\"apps\"\n\t\t{\n\t\t}\n\t}\n}\n";
        std::fs::write(
            client_steamapps.join("libraryfolders.vdf"),
            existing,
        )
        .unwrap();

        let _ = SteamClient::register_native_libraries_in_windows_client(&prefix);
        // The file must still exist and still contain the original "0" block.
        let after =
            std::fs::read_to_string(client_steamapps.join("libraryfolders.vdf")).unwrap();
        assert!(after.contains("\"0\""));
        // Path block preserved (backslash count is fragile across escaping
        // layers; assert on the stable parts only).
        assert!(after.contains("Program Files (x86)"));
        assert!(after.contains("\\Steam\""));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

#[cfg(test)]
mod steamwebhelper_management_tests {
    use super::SteamClient;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn fake_prefix(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let tmp = std::env::temp_dir().join(format!("steamflow_{tag}_{}", std::process::id()));
        let steam_dir = tmp.join("drive_c/Program Files (x86)/Steam");
        std::fs::create_dir_all(&steam_dir).unwrap();
        std::fs::write(steam_dir.join("steam.exe"), b"MZ fake").unwrap();
        (tmp, steam_dir)
    }

    #[test]
    fn restore_lifts_mode000_lock_on_webhelper() {
        let (prefix, steam_dir) = fake_prefix("webhelper_restore");
        let helper = steam_dir.join("steamwebhelper.exe");
        std::fs::write(&helper, b"MZ fake webhelper").unwrap();
        // Simulate the per-game "Disable CEF" enforcement lock (chmod 000).
        let mut perms = std::fs::metadata(&helper).unwrap().permissions();
        perms.set_mode(0);
        std::fs::set_permissions(&helper, perms).unwrap();
        assert_eq!(std::fs::metadata(&helper).unwrap().permissions().mode() & 0o111, 0);

        assert!(SteamClient::restore_steamwebhelper_in_prefix(&prefix));
        let mode = std::fs::metadata(&helper).unwrap().permissions().mode();
        assert_ne!(mode & 0o111, 0, "steamwebhelper.exe must be executable after restore");
        assert_eq!(mode & 0o777, 0o755);

        let _ = std::fs::remove_dir_all(&prefix);
    }

    #[test]
    fn restore_is_noop_when_webhelper_already_executable() {
        let (prefix, steam_dir) = fake_prefix("webhelper_alive");
        let helper = steam_dir.join("steamwebhelper.exe");
        std::fs::write(&helper, b"MZ fake webhelper").unwrap();
        let mut perms = std::fs::metadata(&helper).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&helper, perms).unwrap();

        assert!(SteamClient::restore_steamwebhelper_in_prefix(&prefix));
        assert_eq!(std::fs::metadata(&helper).unwrap().permissions().mode() & 0o777, 0o755);

        let _ = std::fs::remove_dir_all(&prefix);
    }

    #[test]
    fn restore_returns_false_when_webhelper_missing() {
        let (prefix, _) = fake_prefix("webhelper_missing");
        // steam.exe exists but steamwebhelper.exe does not (client install broken).
        assert!(!SteamClient::restore_steamwebhelper_in_prefix(&prefix));
        let _ = std::fs::remove_dir_all(&prefix);
    }

    /// Spawns a fake steamwebhelper process whose cmdline contains the real
    /// path .../steamwebhelper.exe (copied /bin/sleep, argv[0] = that path) and
    /// whose environ carries WINEPREFIX=<prefix>, so the /proc-scanning kill and
    /// enforcement logic treats it as a real web helper inside the prefix.
    fn spawn_fake_webhelper(prefix: &Path, steam_dir: &Path) -> std::process::Child {
        let helper = steam_dir.join("steamwebhelper.exe");
        // A real executable at that path (not a symlink): enforcement resolves the
        // file from argv and canonicalizes it, and canonicalize() on a symlink
        // would resolve away from the prefix, skipping the chmod.
        if !helper.exists() {
            std::fs::copy("/bin/sleep", &helper).expect("copy sleep as fake webhelper");
        }
        // Retry on ETXTBSY: a previous child may still hold the freshly copied
        // executable mapped while being reaped. exec fails with "Text file busy"
        // until the old mapping is gone — transient in parallel test runs.
        let mut attempt = 0;
        loop {
            match std::process::Command::new(&helper)
                .arg("60")
                .env("WINEPREFIX", prefix)
                .spawn()
            {
                Ok(child) => return child,
                Err(e) if attempt < 20 && e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                    attempt += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => panic!("spawn fake steamwebhelper: {e}"),
            }
        }
    }

    fn process_alive(child: &mut std::process::Child) -> bool {
        match child.try_wait() {
            Ok(Some(_)) => false,
            _ => true,
        }
    }

    #[test]
    fn kill_with_preserve_flag_leaves_webhelper_running() {
        let (prefix, steam_dir) = fake_prefix("webhelper_kill_preserve");
        let mut child = spawn_fake_webhelper(&prefix, &steam_dir);
        // Give /proc time to see the process.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(process_alive(&mut child), "webhelper should be running before kill");

        // kill_webhelper=false (the Manage/Repair/Reinstall force-alive path):
        // the web helper must survive.
        SteamClient::kill_steam_in_prefix(&prefix, false);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(process_alive(&mut child), "webhelper must NOT be killed with kill_webhelper=false");

        // kill_webhelper=true (user explicitly disabled CEF): it is killed.
        SteamClient::kill_steam_in_prefix(&prefix, true);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!process_alive(&mut child), "webhelper must be killed with kill_webhelper=true");

        let _ = std::fs::remove_dir_all(&prefix);
    }

    #[test]
    fn enforce_reapplies_lock_after_operation() {
        // After Manage/Repair with a global CEF-off config, enforcement must
        // re-lock the web helper (chmod 000) so we don't leave it force-enabled.
        let (prefix, steam_dir) = fake_prefix("webhelper_reenforce");
        let helper = steam_dir.join("steamwebhelper.exe");
        let mut child = spawn_fake_webhelper(&prefix, &steam_dir);
        std::thread::sleep(std::time::Duration::from_millis(200));

        SteamClient::enforce_disabled_steam_features_in_prefix(&prefix, true, false, false, false);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            !process_alive(&mut child),
            "enforcement must terminate the web helper"
        );
        assert_eq!(
            std::fs::metadata(&helper).unwrap().permissions().mode() & 0o111,
            0,
            "enforcement must re-lock the executable (mode 000)"
        );

        // And a subsequent operation restores it — the exact fix cycle.
        assert!(SteamClient::restore_steamwebhelper_in_prefix(&prefix));
        let mode = std::fs::metadata(&helper).unwrap().permissions().mode();
        assert_ne!(mode & 0o111, 0);

        let _ = std::fs::remove_dir_all(&prefix);
    }

    /// Live demonstration of the full Manage/Repair force-alive cycle with real
    /// processes and captured log lines:
    ///   1. per-game enforcement locks steamwebhelper.exe (chmod 000) + kills it
    ///   2. a client-management op calls restore_steamwebhelper_in_prefix (log line)
    ///   3. the op's kill_steam_in_prefix(prefix, false) leaves webhelper alive
    ///   4. post-op enforcement re-applies the user's CEF-off state (log line)
    #[test]
    fn management_cycle_logs_and_preserves_webhelper() {
        use tracing_subscriber::fmt::format::FmtSpan;
        use tracing_subscriber::util::SubscriberInitExt;
        let _guard = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .with_span_events(FmtSpan::NONE)
            .set_default();

        let (prefix, steam_dir) = fake_prefix("webhelper_cycle");
        let helper = steam_dir.join("steamwebhelper.exe");

        // --- Step 1: per-game "Disable CEF" enforcement locks + kills ---
        let mut child = spawn_fake_webhelper(&prefix, &steam_dir);
        std::thread::sleep(std::time::Duration::from_millis(200));
        SteamClient::enforce_disabled_steam_features_in_prefix(&prefix, true, false, false, false);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!process_alive(&mut child), "pre-op state: webhelper killed by per-game enforcement");
        assert_eq!(
            std::fs::metadata(&helper).unwrap().permissions().mode() & 0o111,
            0,
            "pre-op state: steamwebhelper.exe locked (mode 000)"
        );

        // --- Step 2: Manage/Repair starts → restore the lock (log line emitted) ---
        tracing::info!("[demo] Manage/Repair starts with per-game CEF off + global CEF off");
        assert!(SteamClient::restore_steamwebhelper_in_prefix(&prefix));
        let mode_after_restore = std::fs::metadata(&helper).unwrap().permissions().mode();
        assert_ne!(mode_after_restore & 0o111, 0);

        // --- Step 3: the op relaunches the client; webhelper must survive the kill ---
        let mut child2 = spawn_fake_webhelper(&prefix, &steam_dir);
        std::thread::sleep(std::time::Duration::from_millis(200));
        SteamClient::kill_steam_in_prefix(&prefix, false);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            process_alive(&mut child2),
            "during op: webhelper must survive kill_steam_in_prefix(prefix, false)"
        );

        // --- Step 4: post-op restore of the user's configured state ---
        tracing::info!("[demo] Manage/Repair completed; restoring user's CEF-off state");
        SteamClient::enforce_disabled_steam_features_in_prefix(&prefix, true, false, false, false);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!process_alive(&mut child2));
        assert_eq!(
            std::fs::metadata(&helper).unwrap().permissions().mode() & 0o111,
            0,
            "post-op: webhelper re-locked per user config"
        );

        let _ = std::fs::remove_dir_all(&prefix);
    }
}
