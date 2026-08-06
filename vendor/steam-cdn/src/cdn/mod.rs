use depot::AppDepots;
use inner::InnerClient;
use manifest::DepotManifest;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use steam_vent::{
    proto::{
        steammessages_clientserver_2::{
            CMsgClientGetDepotDecryptionKey, CMsgClientGetDepotDecryptionKeyResponse,
        },
        steammessages_contentsystem_steamclient::CContentServerDirectory_GetManifestRequestCode_Request,
    },
    Connection, ConnectionTrait,
};

use crate::{error::Error, web_api, web_api::content_service::CDNServer};

pub mod depot;
pub mod depot_chunk;
pub mod inner;
pub mod manifest;

#[derive(Clone, Debug)]
pub struct OperationController {
    state: Arc<AtomicU8>,
}

impl OperationController {
    pub fn new() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(0)),
        }
    }

    pub fn pause(&self) {
        self.state.store(1, Ordering::Release);
    }

    pub fn resume(&self) {
        self.state.store(0, Ordering::Release);
    }

    pub fn cancel(&self) {
        self.state.store(2, Ordering::Release);
    }

    pub fn is_paused(&self) -> bool {
        self.state.load(Ordering::Acquire) == 1
    }

    pub fn is_cancelled(&self) -> bool {
        self.state.load(Ordering::Acquire) == 2
    }
}

pub const MANIFEST_VERSION: usize = 5;

#[derive(Debug)]
pub struct CDNClient {
    inner: Arc<InnerClient>,
}

impl CDNClient {
    pub fn new(connection: Arc<Connection>) -> Self {
        Self {
            inner: Arc::new(InnerClient::new(connection)),
        }
    }

    pub fn with_servers(connection: Arc<Connection>, servers: Vec<CDNServer>) -> Self {
        let mut inner = InnerClient::new(connection);
        inner.servers = servers;
        Self {
            inner: Arc::new(inner),
        }
    }

    pub fn with_server(connection: Arc<Connection>, server: CDNServer) -> Self {
        Self::with_servers(connection, vec![server])
    }

    pub async fn discover(connection: Arc<Connection>) -> Result<Self, Error> {
        let mut inner = InnerClient::new(connection);
        inner.servers =
            web_api::content_service::get_servers_for_steam_pipe(inner.cell_id()).await?;
        inner
            .servers
            .sort_by(|a, b| a.weighted_load.cmp(&b.weighted_load));
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    // tbd: should be renamed
    pub async fn get_depots(&self, app_ids: Vec<u32>) -> Result<Vec<AppDepots>, Error> {
        let product_info = self.inner.get_product_info(app_ids).await?;
        let mut apps_depots: Vec<AppDepots> = Vec::new();

        for app in product_info.apps {
            let mut app_depots = AppDepots::new(app.appid());
            app_depots.vdf_parse(app.buffer())?;
            apps_depots.push(app_depots);
        }

        Ok(apps_depots)
    }

    pub async fn get_depot_decryption_key(
        &self,
        app_id: u32,
        depot_id: u32,
    ) -> Result<Option<[u8; 32]>, Error> {
        let response: CMsgClientGetDepotDecryptionKeyResponse = self
            .inner
            .connection
            .job(CMsgClientGetDepotDecryptionKey {
                depot_id: Some(depot_id),
                app_id: Some(app_id),
                ..Default::default()
            })
            .await?;
        match response.depot_encryption_key {
            Some(bytes) if bytes.len() == 32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes[..]);
                Ok(Some(key))
            }
            Some(_) => Err(Error::Unexpected(
                "depot key has unexpected size".to_string(),
            )),
            None => Ok(None),
        }
    }

    pub async fn get_manifest_request_code(
        &self,
        app_id: u32,
        depot_id: u32,
        manifest_id: u64,
    ) -> Result<u64, Error> {
        self.inner
            .connection
            .service_method(CContentServerDirectory_GetManifestRequestCode_Request {
                app_id: Some(app_id),
                depot_id: Some(depot_id),
                manifest_id: Some(manifest_id),
                ..Default::default()
            })
            .await?
            .manifest_request_code
            .ok_or(Error::Unexpected(
                "failed to get manifest request code".to_string(),
            ))
    }

    pub async fn download_depot(
        &self,
        app_id: u32,
        depot_id: u32,
        manifest_id: u64,
        depot_key: &[u8],
        target_dir: impl AsRef<std::path::Path>,
        manifest_request_code: Option<u64>,
        verify_mode: bool,
        abort_signal: Option<Arc<AtomicBool>>,
        operation_controller: Option<OperationController>,
        on_progress: Option<Arc<dyn Fn(u64, u64) + Send + Sync + 'static>>,
        on_manifest: Option<Arc<dyn Fn(u64) + Send + Sync + 'static>>,
        on_file_progress: Option<Arc<dyn Fn(String, u64, u64) + Send + Sync + 'static>>,
    ) -> Result<(), Error> {
        let request_code = if manifest_request_code.is_some() {
            manifest_request_code
        } else {
            self.get_manifest_request_code(app_id, depot_id, manifest_id)
                .await
                .ok()
        };

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&depot_key[..32]);

        let manifest = self
            .get_manifest(app_id, depot_id, manifest_id, request_code, Some(key_arr))
            .await?;

        // Pre-calculate the total depot size across ALL manifest files before
        // downloading anything, so the progress denominator is stable for the
        // whole depot instead of being per-file (or 0). Files with size 0
        // (directories/links) contribute 0 to both total and completed.
        let total_depot_bytes: u64 = manifest
            .files()
            .iter()
            .map(|f| f.size())
            .sum::<u64>();

        if let Some(ref cb) = on_manifest {
            cb(total_depot_bytes);
        }

        // Shared aggregate counter across every file in this depot. Verified
        // (hash-skipped) chunks and downloaded chunks both increment it via the
        // per-file callback, and each increment emits (completed, total) so the
        // caller can render a smooth 0%..100% progress bar across multi-file
        // depots instead of resetting per file.
        let completed = Arc::new(std::sync::atomic::AtomicU64::new(0));

        for file in manifest.files() {
            if let Some(signal) = &abort_signal {
                if signal.load(Ordering::Relaxed) {
                    break;
                }
            }
            if let Some(controller) = &operation_controller {
                if controller.is_cancelled() {
                    break;
                }
                while controller.is_paused() {
                    if controller.is_cancelled() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            }
            let full_path = target_dir.as_ref().join(file.full_path());
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| Error::Unexpected(e.to_string()))?;
            }

            if file.size() > 0 {
                // Per-file progress adapter: the download callback reports
                // chunk deltas; accumulate them into both a per-file counter
                // (for the file-level callback) and the shared depot counter
                // (for the aggregate callback). Each chunk therefore emits the
                // active file's relative path + file-level byte offsets AND
                // the depot-wide (completed, total).
                let file_completed = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let file_path = file.full_path();
                let file_size = file.size();
                let completed = completed.clone();
                let on_progress = on_progress.clone();
                let on_file_progress = on_file_progress.clone();
                let on_progress_inner = Arc::new(move |bytes: u64| {
                    let file_done =
                        file_completed.fetch_add(bytes, std::sync::atomic::Ordering::SeqCst) + bytes;
                    if let Some(cb) = &on_file_progress {
                        cb(file_path.clone(), file_done, file_size);
                    }
                    if let Some(cb) = &on_progress {
                        let done =
                            completed.fetch_add(bytes, std::sync::atomic::Ordering::SeqCst) + bytes;
                        cb(done, total_depot_bytes);
                    }
                }) as Arc<dyn Fn(u64) + Send + Sync + 'static>;

                // Announce the active file immediately (0 bytes) so callers can
                // show the file name before its first chunk completes.
                on_progress_inner(0);

                file.download(
                    key_arr,
                    &full_path,
                    verify_mode,
                    abort_signal.clone(),
                    operation_controller.clone(),
                    None,
                    Some(on_progress_inner),
                )
                .await?;
            }
        }
        Ok(())
    }

    pub async fn get_manifest(
        &self,
        app_id: u32,
        depot_id: u32,
        manifest_id: u64,
        request_code: Option<u64>,
        depot_key: Option<[u8; 32]>,
    ) -> Result<DepotManifest, Error> {
        let bytes = self
            .inner
            .remote_cmd_with_auth(
                "depot",
                format!("{depot_id}/manifest/{manifest_id}/{MANIFEST_VERSION}"),
                request_code,
                Some(app_id),
                Some(depot_id),
            )
            .await?
            .bytes()
            .await?;

        let mut manifest =
            DepotManifest::deserialize(self.inner.clone(), app_id, depot_id, manifest_id, &bytes[..])?;
        if manifest.filenames_encrypted() {
            if let Some(key) = depot_key {
                manifest.decrypt_filenames(key)?;
            }
        }

        Ok(manifest)
    }
}
