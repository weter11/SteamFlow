use crate::cloud_sync::{default_cloud_root, CloudClient};
use crate::cm_list::get_cm_endpoints;
use crate::config::{
    library_cache_path, load_launcher_config, load_library_cache, load_session, save_library_cache,
    save_session,
};
use crate::depot_browser::{self, DepotInfo, ManifestFileEntry};
use crate::download_pipeline::{
    self, parse_appinfo, should_keep_depot, AppInfoRoot, DepotPlatform, ManifestSelection,
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
use steam_vent::proto::steammessages_clientserver_2::{
    CMsgClientRequestFreeLicense, CMsgClientRequestFreeLicenseResponse,
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
    pub target: LaunchTarget,
}

#[derive(Debug, Clone)]
pub struct RawLaunchOption {
    pub executable: String,
    pub arguments: String,
}

#[derive(Debug, Clone)]
pub struct ExtendedAppInfo {
    pub dlcs: Vec<u32>,
    pub depots: Vec<(u32, String)>,
    pub launch_options: Vec<RawLaunchOption>,
    pub active_branch: String,
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

    pub fn connection(&self) -> Option<&Connection> {
        self.connection.as_ref()
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

    pub async fn get_available_platforms(&mut self, appid: u32) -> Result<(Vec<DepotPlatform>, Vec<u8>)> {
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

        let raw_buffer = app.buffer().to_vec();
        let appinfo_vdf = String::from_utf8_lossy(&raw_buffer).to_string();
        let parsed: Result<AppInfoRoot> = parse_appinfo(&appinfo_vdf);

        let parsed = match parsed {
            Ok(p) => p,
            Err(e) => {
                println!("CRITICAL VDF ERROR for {}: {:?}", appid, e);
                // Print the raw AppInfo buffer as string to see what's wrong if possible
                println!("RAW DATA: {}", appinfo_vdf);

                // Fallback: assume both for now if we can't parse it
                return Ok((vec![DepotPlatform::Windows, DepotPlatform::Linux], raw_buffer));
            }
        };

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

        Ok((platforms, raw_buffer))
    }

    pub async fn install_game(
        &self,
        appid: u32,
        platform: DepotPlatform,
        cached_vdf: Option<Vec<u8>>,
    ) -> Result<Receiver<DownloadProgress>> {
        let connection = self
            .connection
            .as_ref()
            .cloned()
            .context("steam connection not initialized")?;

        let cfg = load_launcher_config().await?;
        let library_root = cfg.steam_library_path.clone();
        let game_name = self.resolve_install_game_name(appid).await;
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

            let appinfo_vdf = if let Some(buffer) = cached_vdf {
                String::from_utf8_lossy(&buffer).to_string()
            } else {
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
                match app {
                    Some(app) => String::from_utf8_lossy(app.buffer()).to_string(),
                    None => {
                        let _ = tx
                            .send(DownloadProgress {
                                state: DownloadProgressState::Failed,
                                bytes_downloaded: 0,
                                total_bytes: 0,
                                current_file: "missing appinfo payload".to_string(),
                            })
                            .await;
                        return;
                    }
                }
            };
            let parsed: Result<AppInfoRoot> = parse_appinfo(&appinfo_vdf);

            let mut selections = Vec::new();
            match &parsed {
                Ok(p) => {
                    let depots = p
                        .appinfo
                        .as_ref()
                        .map(|node| &node.depots)
                        .unwrap_or(&p.depots);

                    for (depot_id_str, node) in depots {
                        if !depot_id_str.chars().all(|c| c.is_ascii_digit()) {
                            continue;
                        }

                        let oslist = node.config.as_ref().and_then(|c| c.oslist.as_deref());
                        if !should_keep_depot(oslist, platform) {
                            continue;
                        }

                        if let Some(manifests) = &node.manifests {
                            if let Some(gid_text) = &manifests.public {
                                if let (Ok(d_id), Ok(m_id)) =
                                    (depot_id_str.parse::<u32>(), gid_text.parse::<u64>())
                                {
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
                }
                Err(e) => {
                    println!("VDF Parse failed, using greedy fallback: {}", e);
                    let fallback_map = fuzzy_extract_depots(&appinfo_vdf, appid);

                    if fallback_map.is_empty() {
                        let _ = tx
                            .send(DownloadProgress {
                                state: DownloadProgressState::Failed,
                                bytes_downloaded: 0,
                                total_bytes: 0,
                                current_file: "No depots found in greedy fallback".to_string(),
                            })
                            .await;
                        return;
                    }

                    for (d_id, m_id) in fallback_map {
                        selections.push(ManifestSelection {
                            app_id: appid,
                            depot_id: d_id as u32,
                            manifest_id: m_id,
                            appinfo_vdf: appinfo_vdf.clone(),
                        });
                    }
                }
            }

            if selections.is_empty() {
                println!("Hard VDF failure for {}. Attempting Blind Depot Guessing...", appid);
                // Attempt blind guessing as a last resort before failing
                // Most games use AppID+1 for Windows, etc.
                // However, without a ManifestID from the VDF, we technically cannot proceed.
                // We'll report the specific error requested by the user.

                let msg = format!("Cannot install {appid}: VDF required for Manifest IDs.");
                let _ = tx
                    .send(DownloadProgress {
                        state: DownloadProgressState::Failed,
                        bytes_downloaded: 0,
                        total_bytes: 0,
                        current_file: msg,
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

            let (progress_tx, mut progress_rx) =
                tokio::sync::mpsc::unbounded_channel::<crate::install::ProgressEvent>();
            let tx_clone = tx.clone();
            tokio::task::spawn(async move {
                while let Some(event) = progress_rx.recv().await {
                    let state = DownloadProgressState::Downloading;
                    let _ = tx_clone
                        .send(DownloadProgress {
                            state,
                            bytes_downloaded: event.bytes_downloaded,
                            total_bytes: event.total_bytes,
                            current_file: event.file_name,
                        })
                        .await;
                }
            });

            println!("Attempting to request free license for AppID: {}", appid);
            let mut license_req = CMsgClientRequestFreeLicense::new();
            license_req.appids.push(appid);

            match connection.job::<CMsgClientRequestFreeLicense, CMsgClientRequestFreeLicenseResponse>(license_req).await {
                Ok(res) => {
                    println!("License Request Result: {:?}", res);
                    println!("License granted! If download fails, please RESTART the application to refresh permissions.");
                }
                Err(e) => {
                    println!("Warning: Failed to request free license (might already own it): {}", e);
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            let result = download_pipeline::execute_multi_depot_download_async(
                &connection,
                appid,
                selections,
                install_dir,
                false,
                Some(progress_tx),
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
                    let mut msg = err.to_string();
                    if msg.contains("CDN auth token") {
                        msg = format!("{}. TIP: Try RESTARTING the application to refresh your authentication ticket.", msg);
                    }
                    let _ = tx
                        .send(DownloadProgress {
                            state: DownloadProgressState::Failed,
                            bytes_downloaded: 0,
                            total_bytes: 0,
                            current_file: msg,
                        })
                        .await;
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
        // Still uses manual scanner for remote_manifest_ids, which should be okay as it scans lines
        Ok(parse_remote_depot_manifests_from_vdf(&raw_vdf, branch))
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
        let dlcs = common
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
            if id_str.chars().all(|c| c.is_ascii_digit()) {
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

        println!("DEBUG PICS: {:#?}", launch_infos);
        Ok(launch_infos)
    }

    pub async fn play_game(
        &mut self,
        app: &LibraryGame,
        proton_path: Option<&str>,
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
            self.spawn_game_process(app, &launch_info, chosen_proton_path, &launcher_config)?;
        child
            .wait()
            .context("failed waiting for game process exit")?;

        if let (Some(client), Some(root)) = (cloud_client.as_ref(), local_root.as_ref()) {
            client.sync_up(app.app_id, root).await?;
            tracing::info!(appid = app.app_id, "Upload Complete");
        }

        Ok(launch_info)
    }

    pub async fn launch_game(
        &self,
        app: &LibraryGame,
        launch_info: &LaunchInfo,
        proton_path: Option<&str>,
    ) -> Result<()> {
        let launcher_config = load_launcher_config().await.unwrap_or_default();
        self.spawn_game_process(app, launch_info, proton_path, &launcher_config)?;
        Ok(())
    }

    pub async fn update_game(&self, appid: u32) -> Result<Receiver<DownloadProgress>> {
        self.start_manifest_download(appid, false).await
    }

    pub async fn verify_game(&self, appid: u32) -> Result<Receiver<DownloadProgress>> {
        self.start_manifest_download(appid, true).await
    }

    async fn start_manifest_download(
        &self,
        appid: u32,
        smart_verify_existing: bool,
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
                    })
                    .await;
                return;
            };

            let (progress_tx, mut progress_rx) =
                tokio::sync::mpsc::unbounded_channel::<crate::install::ProgressEvent>();
            let tx_clone = tx.clone();
            tokio::task::spawn(async move {
                while let Some(event) = progress_rx.recv().await {
                    let state = if smart_verify_existing {
                        DownloadProgressState::Verifying
                    } else {
                        DownloadProgressState::Downloading
                    };
                    let _ = tx_clone
                        .send(DownloadProgress {
                            state,
                            bytes_downloaded: event.bytes_downloaded,
                            total_bytes: event.total_bytes,
                            current_file: event.file_name,
                        })
                        .await;
                }
            });

            let result = download_pipeline::execute_multi_depot_download_async(
                &connection,
                appid,
                selections,
                install_root,
                smart_verify_existing,
                Some(progress_tx),
            )
            .await;

            match result {
                Ok(()) => {
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
                return Ok(steamapps.join("common").join(installdir));
            }
        }

        Ok(PathBuf::from(
            load_launcher_config().await?
                .steam_library_path,
        )
        .join("steamapps")
        .join("common")
        .join(appid.to_string()))
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

        let raw_vdf = String::from_utf8_lossy(app.buffer()).to_string();
        Ok(parse_remote_depot_manifests_from_vdf(&raw_vdf, branch))
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

    async fn resolve_install_game_name(&self, appid: u32) -> String {
        load_library_cache().await
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

    fn resolve_proton_path(&self, proton_name: &str, library_root: &Path) -> PathBuf {
        if proton_name.contains('/') || proton_name.contains('\\') {
            return PathBuf::from(proton_name);
        }

        let standard_path = library_root
            .join("steamapps/common")
            .join(proton_name)
            .join("proton");

        if standard_path.exists() {
            return standard_path;
        }

        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let custom_path = PathBuf::from(home)
            .join(".local/share/Steam/compatibilitytools.d")
            .join(proton_name)
            .join("proton");

        if custom_path.exists() {
            return custom_path;
        }

        PathBuf::from(proton_name)
    }

    pub(crate) fn spawn_game_process(
        &self,
        app: &LibraryGame,
        launch_info: &LaunchInfo,
        proton_path: Option<&str>,
        launcher_config: &crate::config::LauncherConfig,
    ) -> Result<std::process::Child> {
        let install_dir = PathBuf::from(
            app.install_path
                .clone()
                .ok_or_else(|| anyhow!("game {} is not installed", app.app_id))?,
        );

        let executable = install_dir.join(&launch_info.executable);
        let args = split_args(&launch_info.arguments);

        // Standard Steam identity fallback: steam_appid.txt
        let _ = std::fs::write(install_dir.join("steam_appid.txt"), app.app_id.to_string());

        match launch_info.target {
            LaunchTarget::NativeLinux => {
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
                cmd.args(args);
                cmd.current_dir(&install_dir);

                let bin_dir = executable.parent().unwrap_or_else(|| Path::new("."));
                let existing_ld = std::env::var("LD_LIBRARY_PATH").unwrap_or_default();
                let existing_path = std::env::var("PATH").unwrap_or_default();

                cmd.env("LD_LIBRARY_PATH", format!("{}:{}", bin_dir.display(), existing_ld));
                cmd.env("PATH", format!("{}:{}", bin_dir.display(), existing_path));
                cmd.env("SteamAppId", app.app_id.to_string());

                println!("EXECUTING COMMAND: {:?}", cmd);
                println!("Working Dir: {:?}", install_dir);
                println!("Environment: {:?}", cmd.get_envs());

                cmd.spawn().context("failed to spawn native linux game")
            }
            LaunchTarget::WindowsProton => {
                let proton = if let Some(forced) = launcher_config
                    .game_configs
                    .get(&app.app_id)
                    .and_then(|c| c.forced_proton_version.as_ref())
                {
                    forced
                } else {
                    proton_path
                        .filter(|p| !p.is_empty())
                        .ok_or_else(|| anyhow!("proton path is required for Windows launch"))?
                };

                let library_root = PathBuf::from(&launcher_config.steam_library_path);
                let resolved_proton = self.resolve_proton_path(proton, &library_root);

                let compat_data_path = library_root
                    .join("steamapps")
                    .join("compatdata")
                    .join(app.app_id.to_string());

                std::fs::create_dir_all(&compat_data_path)
                    .with_context(|| format!("failed creating {}", compat_data_path.display()))?;

                let mut cmd = Command::new(resolved_proton);
                cmd.arg("run").arg(&executable).args(args);
                cmd.current_dir(&install_dir);
                cmd.env("SteamAppId", app.app_id.to_string());
                cmd.env("STEAM_COMPAT_DATA_PATH", &compat_data_path);
                cmd.env("STEAM_COMPAT_CLIENT_INSTALL_PATH", &library_root);

                println!("EXECUTING COMMAND: {:?}", cmd);
                println!("Working Dir: {:?}", install_dir);
                println!("Environment: {:?}", cmd.get_envs());

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

    println!("AppInfo Config: {:?}", config);

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
            target,
        });
    }

    if options.is_empty() {
        bail!("no suitable launch option found for app {appid}");
    }

    // Sort options: prefer key "0", then by id
    options.sort_by(|a, b| {
        if a.id == "0" {
            return std::cmp::Ordering::Less;
        }
        if b.id == "0" {
            return std::cmp::Ordering::Greater;
        }
        a.id.cmp(&b.id)
    });

    Ok(options)
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
    description: Option<String>,
    #[serde(default)]
    config: Option<ProductLaunchConfigInner>,
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

        if parts.len() >= 2 && in_user_config && parts[0].eq_ignore_ascii_case("betakey") && !parts[1].trim().is_empty() {
            return parts[1].to_string();
        }
    }
    "public".to_string()
}

fn fuzzy_extract_depots(vdf_text: &str, app_id: u32) -> HashMap<u64, u64> {
    let mut depots = HashMap::new();
    println!("Starting Super-Greedy Fuzzy Scan for AppID: {}", app_id);

    // Stage 1: Structured scan (look for depot ID keys and then manifest IDs in their block)
    let depot_re = regex::Regex::new(r#""(\d+)"\s*\{"#).unwrap();
    let gid_re = regex::Regex::new(r#""gid"\s*"(\d+)""#).unwrap();
    let fallback_re = regex::Regex::new(r#""(?:public|manifest)"\s+"(\d+)""#).unwrap();

    let matches: Vec<_> = depot_re.find_iter(vdf_text).collect();
    for i in 0..matches.len() {
        let m = matches[i];
        let caps = depot_re.captures(m.as_str()).unwrap();
        if let Ok(id) = caps[1].parse::<u64>() {
            if id > 1000 && id != app_id as u64 {
                let start = m.end();
                let end = if i + 1 < matches.len() {
                    matches[i + 1].start()
                } else {
                    vdf_text.len()
                };
                // Search within a 2000 char window from the depot ID start
                let search_range = &vdf_text[start..std::cmp::min(end, start + 2000)];

                let manifest_id = if let Some(g_caps) = gid_re.captures(search_range) {
                    g_caps[1].parse::<u64>().ok()
                } else if let Some(f_caps) = fallback_re.captures(search_range) {
                    f_caps[1].parse::<u64>().ok()
                } else {
                    None
                };

                if let Some(m_id) = manifest_id.filter(|&id| id != 0) {
                    depots.insert(id, m_id);
                    println!("Found Depot (Stage 1): {} -> Manifest: {}", id, m_id);
                }
            }
        }
    }

    // Stage 2: Flat scan (for malformed VDFs or extreme cases)
    if depots.is_empty() {
        println!("Stage 1 found nothing. Trying Stage 2 (flat scan)...");
        let all_manifest_re = regex::Regex::new(r#""(?:gid|public|manifest)"\s+"?(\d+)"?"#).unwrap();
        let digit_key_re = regex::Regex::new(r#""(\d+)""#).unwrap();
        for mat in all_manifest_re.find_iter(vdf_text) {
             if let Some(m_caps) = all_manifest_re.captures(mat.as_str()) {
                 if let Ok(manifest_id) = m_caps[1].parse::<u64>() {
                     if manifest_id == 0 { continue; }

                     let search_start = mat.start().saturating_sub(500);
                     let search_area = &vdf_text[search_start..mat.start()];

                     if let Some(depot_match) = digit_key_re.find_iter(search_area).last() {
                         if let Some(d_caps) = digit_key_re.captures(depot_match.as_str()) {
                             if let Ok(depot_id) = d_caps[1].parse::<u64>() {
                                 if depot_id > 1000 && depot_id != app_id as u64 {
                                     if let std::collections::hash_map::Entry::Vacant(e) = depots.entry(depot_id) {
                                         e.insert(manifest_id);
                                         println!("Found Depot (Stage 2): {} -> Manifest: {}", depot_id, manifest_id);
                                     }
                                 }
                             }
                         }
                     }
                 }
             }
        }
    }

    println!("Super-Greedy Scan associations: {:?}", depots);
    depots
}

fn parse_remote_depot_manifests_from_vdf(raw: &str, branch: &str) -> HashMap<u64, u64> {
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
        } else if quoted.len() >= 2 && current_depot.is_some() && (quoted[0] == branch || (branch != "public" && quoted[0] == "public") || quoted[0] == "manifest") {
            if let Ok(manifest) = u64::from_str(&quoted[1]) {
                // If we already have a manifest for this depot, only overwrite if this is the requested branch
                // (prevents 'public' fallback from overwriting a previously found 'beta' manifest if it appeared first,
                // though usually branch manifests are inside a 'manifests' sub-section which we are not fully parsing yet)
                if !manifests.contains_key(&current_depot.unwrap()) || quoted[0] == branch {
                     manifests.insert(current_depot.unwrap_or_default(), manifest);
                }
            }
        }
    }

    manifests
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
    fn test_fuzzy_extract_depots_greedy() {
        let vdf = r#"
"appinfo"
{
    "appid" "2368470"
    "depots"
    {
        "2368471"
        {
            "manifests"
            {
                "public" "1111111111111111111"
            }
        }
        "2368472"
        {
            "manifests"
            {
                "public" "2222222222222222222"
            }
        }
    }
}
"#;
        let app_id = 2368470;
        let depots = fuzzy_extract_depots(vdf, app_id);
        assert_eq!(depots.len(), 2);
        assert_eq!(depots.get(&2368471), Some(&1111111111111111111));
        assert_eq!(depots.get(&2368472), Some(&2222222222222222222));
    }

    #[test]
    fn test_fuzzy_extract_depots_nested_braces() {
        // Simulating the "nested braces" issue where a simple regex would fail
        let vdf = r#"
"appinfo"
{
    "appid" "2000"
    "depots"
    {
        "2001"
        {
            "config" { "foo" { "bar" "baz" } }
            "manifests" { "public" "200101" }
        }
        "2002"
        {
            "manifests" { "public" "200202" }
        }
    }
}
"#;
        let depots = fuzzy_extract_depots(vdf, 2000);
        assert_eq!(depots.len(), 2);
        assert_eq!(depots.get(&2001), Some(&200101));
        assert_eq!(depots.get(&2002), Some(&200202));
    }

    #[test]
    fn test_fuzzy_extract_depots_gid_format() {
        let vdf = r#"
"depots"
{
    "3001"
    {
        "manifests"
        {
            "public"
            {
                "gid" "300101"
            }
        }
    }
}
"#;
        let depots = fuzzy_extract_depots(vdf, 3000);
        assert_eq!(depots.len(), 1);
        assert_eq!(depots.get(&3001), Some(&300101));
    }

    #[test]
    fn test_fuzzy_extract_depots_extreme_fallback() {
        // Malformed VDF where keys don't have braces nearby as expected
        let vdf = r#"
"depots" "something"
"4001" "config" "manifests" "public" "400101"
"4002" "manifests" "public" "400202"
"#;
        let depots = fuzzy_extract_depots(vdf, 4000);
        assert_eq!(depots.len(), 2);
        assert_eq!(depots.get(&4001), Some(&400101));
        assert_eq!(depots.get(&4002), Some(&400202));
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
