use aes::Aes256;
use anyhow::{anyhow, bail, Context, Result};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use flate2::read::GzDecoder;
use sha1::Digest;
use std::collections::HashMap;
use std::io::{Cursor, Read, SeekFrom};
use std::path::{Path, PathBuf};

use steam_vent::connection::Connection;
use steam_vent::proto::content_manifest::ContentManifestPayload;
use steam_vent::proto::protobuf::Message;
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
    CContentServerDirectory_GetServersForSteamPipe_Request,
    CContentServerDirectory_GetServersForSteamPipe_Response,
};
use steam_vent::ConnectionTrait;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::install::ProgressEvent;
use xz2::read::XzDecoder;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub struct ManifestSelection {
    pub app_id: u32,
    pub depot_id: u32,
    pub manifest_id: u64,
    pub appinfo_vdf: String,
}

#[derive(Debug, Clone)]
pub struct SecurityInfo {
    pub depot_id: u32,
    pub depot_key: Vec<u8>,
    pub cdn_host: String,
    pub cdn_auth_token: String,
}


#[derive(Debug, Clone, Copy)]
pub enum DepotPlatform {
    Linux,
    Windows,
}

#[derive(Debug, Clone)]
pub struct DepotDownloadPlan {
    pub app_id: u32,
    pub depot_id: u32,
    pub manifest_id: u64,
    pub platform: DepotPlatform,
    pub language: String,
}

/// Steam wraps the entire VDF in a top-level key that is the numeric app ID.
/// This wrapper accepts that outer key transparently.
#[derive(Debug, serde::Deserialize)]
pub struct AppInfoEnvelope(pub HashMap<String, AppInfoRoot>);

impl AppInfoEnvelope {
    /// Extract the inner AppInfoRoot regardless of the outer key name.
    pub fn into_inner(self) -> Option<AppInfoRoot> {
        self.0.into_values().next()
    }
}

pub fn parse_appinfo(vdf: &str) -> Result<AppInfoRoot> {
    // Try direct parse first (in case steam-vent already strips the wrapper)
    if let Ok(parsed) = keyvalues_serde::from_str::<AppInfoRoot>(vdf) {
        return Ok(parsed);
    }
    // Fall back to envelope parse
    let envelope: AppInfoEnvelope = keyvalues_serde::from_str(vdf)
        .context("failed parsing appinfo VDF (envelope)")?;
    envelope
        .into_inner()
        .context("appinfo envelope was empty")
}

#[derive(Debug, serde::Deserialize)]
pub struct AppInfoRoot {
    #[serde(default)]
    pub appinfo: Option<AppInfoNode>,
    #[serde(default)]
    pub common: Option<CommonNode>,
    #[serde(default)]
    pub depots: HashMap<String, DepotNode>,
    #[serde(default)]
    pub branches: HashMap<String, BranchNode>,
    #[serde(default)]
    pub config: Option<ConfigNode>,
}

#[derive(Debug, serde::Deserialize)]
pub struct AppInfoNode {
    #[serde(default)]
    pub common: Option<CommonNode>,
    #[serde(default)]
    pub depots: HashMap<String, DepotNode>,
    #[serde(default)]
    pub branches: HashMap<String, BranchNode>,
    #[serde(default)]
    pub config: Option<ConfigNode>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ConfigNode {
    #[serde(default)]
    pub launch: HashMap<String, ProductLaunchEntry>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ProductLaunchEntry {
    #[serde(default)]
    pub executable: Option<String>,
    #[serde(default)]
    pub arguments: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub oslist: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct CommonNode {
    #[serde(default)]
    pub dlc: HashMap<String, String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct DepotNode {
    #[serde(default)]
    pub config: Option<DepotConfig>,
    #[serde(default)]
    pub manifests: Option<DepotManifests>,
    #[serde(flatten)]
    pub _other: HashMap<String, serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
pub struct BranchNode {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub pwdrequired: Option<String>,
    #[serde(default)]
    pub buildid: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct DepotConfig {
    #[serde(default)]
    pub oslist: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct DepotManifests {
    #[serde(default)]
    pub public: Option<String>,
}

pub fn should_keep_depot(oslist: Option<&str>, target: DepotPlatform) -> bool {
    match target {
        DepotPlatform::Windows => {
            match oslist {
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
            }
        }
        DepotPlatform::Linux => {
            match oslist {
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
            }
        }
    }
}

pub async fn phase1_get_manifest_id(
    connection: &Connection,
    app_id: u32,
    platform: DepotPlatform,
    language: &str,
) -> Result<ManifestSelection> {
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
        .context("failed requesting appinfo product info")?;

    let app = response
        .apps
        .iter()
        .find(|entry| entry.appid() == app_id)
        .ok_or_else(|| anyhow!("missing app info payload for app {app_id}"))?;

    let appinfo_vdf = String::from_utf8_lossy(app.buffer()).to_string();
    if appinfo_vdf.trim().is_empty() {
        bail!("appinfo buffer was empty for app {app_id}")
    }

    let parsed: AppInfoRoot = parse_appinfo(&appinfo_vdf).context("failed parsing appinfo VDF")?;
    let depots = parsed
        .appinfo
        .map(|node| node.depots)
        .unwrap_or(parsed.depots);
    if depots.is_empty() {
        bail!("missing appinfo/depots root for app {app_id}")
    }

    let platform_str = match platform {
        DepotPlatform::Linux => "linux",
        DepotPlatform::Windows => "windows",
    };

    for (depot_id, depot) in depots {
        if !depot_id.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let Some(manifests) = depot.manifests else {
            continue;
        };
        let Some(gid_text) = manifests.public else {
            continue;
        };

        let platform_ok = depot
            .config
            .as_ref()
            .and_then(|cfg| cfg.oslist.as_deref())
            .map(|os| os.to_ascii_lowercase().contains(platform_str))
            .unwrap_or(true);

        let language_ok = depot
            .config
            .as_ref()
            .and_then(|cfg| cfg.language.as_deref())
            .map(|lang| lang.eq_ignore_ascii_case(language))
            .unwrap_or(true);

        if platform_ok && language_ok {
            return Ok(ManifestSelection {
                app_id,
                depot_id: depot_id.parse::<u32>()?,
                manifest_id: gid_text.parse::<u64>()?,
                appinfo_vdf,
            });
        }
    }

    bail!("failed to locate matching depot/manifest for app {app_id}")
}

pub async fn phase2_get_security_info(
    connection: &Connection,
    app_id: u32,
    depot_id: u32,
    preferred_host: Option<String>,
) -> Result<SecurityInfo> {
    let depot_request = CMsgClientGetDepotDecryptionKey {
        app_id: Some(app_id),
        depot_id: Some(depot_id),
        ..Default::default()
    };

    let depot_response: CMsgClientGetDepotDecryptionKeyResponse = connection
        .job(depot_request)
        .await
        .context("failed requesting depot decryption key")?;

    let depot_key = depot_response.depot_encryption_key().to_vec();
    if depot_key.is_empty() {
        bail!("Steam returned empty depot decryption key")
    }

    let cdn_host = if let Some(host) = preferred_host {
        host
    } else {
        let servers_response: CContentServerDirectory_GetServersForSteamPipe_Response = connection
            .service_method(CContentServerDirectory_GetServersForSteamPipe_Request {
                cell_id: Some(connection.cell_id()),
                max_servers: Some(20),
                ..Default::default()
            })
            .await
            .context("failed requesting SteamPipe CDN server list")?;

        let server = servers_response
            .servers
            .first()
            .ok_or_else(|| anyhow!("Steam did not return any CDN server"))?;
        server.host().to_string()
    };

    let token_response: CContentServerDirectory_GetCDNAuthToken_Response = connection
        .service_method(CContentServerDirectory_GetCDNAuthToken_Request {
            app_id: Some(app_id),
            depot_id: Some(depot_id),
            host_name: Some(cdn_host.clone()),
            ..Default::default()
        })
        .await
        .context("failed requesting CDN auth token")?;

    Ok(SecurityInfo {
        depot_id,
        depot_key,
        cdn_host,
        cdn_auth_token: token_response.token().to_string(),
    })
}

pub async fn phase3_download_manifest(
    selection: &ManifestSelection,
    security: &SecurityInfo,
) -> Result<ContentManifestPayload> {
    let url = format!(
        "https://{}/depot/{}/manifest/{}/5",
        security.cdn_host, selection.depot_id, selection.manifest_id
    );

    let mut request = reqwest::Client::new().get(&url);
    if !security.cdn_auth_token.is_empty() {
        request = request
            .header("x-steam-auth", &security.cdn_auth_token)
            .header("x-cdn-auth-token", &security.cdn_auth_token);
    }

    let response = request
        .send()
        .await
        .with_context(|| format!("failed to download manifest from {url}"))?;
    if !response.status().is_success() {
        bail!("manifest download failed with status {}", response.status())
    }

    let body = response.bytes().await?.to_vec();
    decode_manifest_payload(&body)
}

pub struct DownloadState {
    pub manifest: ContentManifestPayload,
    pub install_dir: PathBuf,
    pub client: reqwest::Client,
    pub security: SecurityInfo,
    pub progress_tx: Option<tokio::sync::mpsc::UnboundedSender<ProgressEvent>>,
    pub smart_verify_existing: bool,
}

impl DownloadState {
    pub fn new(
        manifest: ContentManifestPayload,
        install_dir: PathBuf,
        security: SecurityInfo,
        progress_tx: Option<tokio::sync::mpsc::UnboundedSender<ProgressEvent>>,
        smart_verify_existing: bool,
    ) -> Self {
        Self {
            manifest,
            install_dir,
            client: reqwest::Client::new(),
            security,
            progress_tx,
            smart_verify_existing,
        }
    }

    pub async fn download_all_files(&self) -> Result<()> {
        for file_entry in self.manifest.mappings.iter().cloned() {
            self.download_file(file_entry).await?;
        }
        Ok(())
    }

    pub async fn download_file(
        &self,
        file_entry: steam_vent::proto::content_manifest::content_manifest_payload::FileMapping,
    ) -> Result<()> {
        let filename = file_entry.filename().to_string();
        if filename.is_empty() {
            return Ok(());
        }

        let file_path = self.install_dir.join(&filename);
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }

        let file_exists = file_path.exists();
        let existing_len = if file_exists {
            std::fs::metadata(&file_path)
                .map(|meta| meta.len())
                .unwrap_or_default()
        } else {
            0
        };

        let mut output = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&file_path)
            .await
            .with_context(|| format!("failed opening {}", file_path.display()))?;

        let total_bytes = file_entry.size();
        output
            .set_len(total_bytes)
            .await
            .with_context(|| format!("failed pre-allocating {}", file_path.display()))?;

        let mut bytes_downloaded = 0_u64;

        for (index, chunk) in file_entry.chunks.iter().enumerate() {
            let chunk_offset = chunk.offset();
            let next_offset = file_entry
                .chunks
                .get(index + 1)
                .map(|next| next.offset())
                .unwrap_or(total_bytes);
            let expected_chunk_len = next_offset.saturating_sub(chunk_offset) as usize;

            if file_exists
                && expected_chunk_len > 0
                && chunk_offset + expected_chunk_len as u64 <= existing_len
            {
                let mut existing_chunk = vec![0_u8; expected_chunk_len];
                output
                    .seek(SeekFrom::Start(chunk_offset))
                    .await
                    .with_context(|| format!("failed seeking {}", file_path.display()))?;
                if output.read_exact(&mut existing_chunk).await.is_ok() {
                    let digest = sha1::Sha1::digest(&existing_chunk);
                    if digest.as_slice() == chunk.sha() {
                        bytes_downloaded =
                            (bytes_downloaded + expected_chunk_len as u64).min(total_bytes);
                        if let Some(tx) = &self.progress_tx {
                            let _ = tx.send(ProgressEvent {
                                file_name: filename.clone(),
                                bytes_downloaded,
                                total_bytes,
                            });
                        }
                        continue;
                    }
                }
            }

            let chunk_id = hex::encode(chunk.sha());
            let url = format!(
                "https://{}/depot/{}/chunk/{}",
                self.security.cdn_host, self.security.depot_id, chunk_id
            );

            let mut request = self.client.get(&url);
            if !self.security.cdn_auth_token.is_empty() {
                request = request
                    .header("x-steam-auth", &self.security.cdn_auth_token)
                    .header("x-cdn-auth-token", &self.security.cdn_auth_token);
            }

            let response = request
                .send()
                .await
                .with_context(|| format!("failed downloading chunk {}", chunk_id))?;
            if !response.status().is_success() {
                bail!("chunk {} download failed ({})", chunk_id, response.status())
            }

            let chunk_data = response
                .bytes()
                .await
                .with_context(|| format!("failed reading chunk body {}", chunk_id))?
                .to_vec();

            let processed = process_chunk(chunk_data, &self.security.depot_key);

            output
                .seek(SeekFrom::Start(chunk_offset))
                .await
                .with_context(|| format!("failed seeking {}", file_path.display()))?;
            output
                .write_all(&processed)
                .await
                .with_context(|| format!("failed writing {}", file_path.display()))?;

            bytes_downloaded = (bytes_downloaded + processed.len() as u64).min(total_bytes);
            if let Some(tx) = &self.progress_tx {
                let _ = tx.send(ProgressEvent {
                    file_name: filename.clone(),
                    bytes_downloaded,
                    total_bytes,
                });
            }
        }

        output
            .flush()
            .await
            .with_context(|| format!("failed flushing {}", file_path.display()))?;

        Ok(())
    }
}

pub fn process_chunk(chunk_data: Vec<u8>, depot_key: &[u8]) -> Vec<u8> {
    let decrypted = decrypt_chunk_best_effort(&chunk_data, depot_key);
    decompress_chunk_best_effort(&decrypted).unwrap_or(decrypted)
}

pub async fn phase4_download_chunks_async(
    manifest: ContentManifestPayload,
    security: SecurityInfo,
    install_root: PathBuf,
    smart_verify_existing: bool,
    progress_tx: Option<tokio::sync::mpsc::UnboundedSender<ProgressEvent>>,
) -> Result<()> {
    if !install_root.exists() {
        std::fs::create_dir_all(&install_root)
            .with_context(|| format!("failed creating install root {}", install_root.display()))?;
    }

    let state = DownloadState::new(
        manifest,
        install_root,
        security,
        progress_tx,
        smart_verify_existing,
    );
    state.download_all_files().await
}

pub fn phase4_download_chunks(
    manifest: &ContentManifestPayload,
    security: &SecurityInfo,
    install_root: &Path,
    smart_verify_existing: bool,
) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(phase4_download_chunks_async(
        manifest.clone(),
        security.clone(),
        install_root.to_path_buf(),
        smart_verify_existing,
        None,
    ))
}

pub async fn execute_multi_depot_download_async(
    connection: &Connection,
    app_id: u32,
    selections: Vec<ManifestSelection>,
    install_root: PathBuf,
    smart_verify_existing: bool,
    progress_tx: Option<tokio::sync::mpsc::UnboundedSender<ProgressEvent>>,
) -> Result<()> {
    for selection in selections {
        let security = match phase2_get_security_info(connection, app_id, selection.depot_id, None).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Could not get key for Depot {} (User might not own this DLC/Language). Skipping. Error: {}", selection.depot_id, e);
                continue;
            }
        };
        let manifest = phase3_download_manifest(&selection, &security).await?;
        phase4_download_chunks_async(
            manifest,
            security,
            install_root.clone(),
            smart_verify_existing,
            progress_tx.clone(),
        )
        .await?;
    }
    Ok(())
}

pub fn execute_four_step_download(
    connection: &Connection,
    plan: &DepotDownloadPlan,
    install_root: &Path,
) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let selection = phase1_get_manifest_id(
            connection,
            plan.app_id,
            plan.platform,
            &plan.language,
        )
        .await?;

        execute_multi_depot_download_async(
            connection,
            plan.app_id,
            vec![selection],
            install_root.to_path_buf(),
            false,
            None,
        )
        .await
    })
}

pub fn execute_download_with_manifest_id(
    connection: &Connection,
    app_id: u32,
    depot_id: u32,
    manifest_id: u64,
    install_root: &Path,
    smart_verify_existing: bool,
) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;

    let security = runtime.block_on(phase2_get_security_info(connection, app_id, depot_id, None))?;
    let selection = ManifestSelection {
        app_id,
        depot_id,
        manifest_id,
        appinfo_vdf: String::new(),
    };
    let manifest = runtime.block_on(phase3_download_manifest(&selection, &security))?;
    phase4_download_chunks(&manifest, &security, install_root, smart_verify_existing)?;
    Ok(())
}

fn decode_manifest_payload(bytes: &[u8]) -> Result<ContentManifestPayload> {
    // 1. Check for standard PKZip Header (0x50 0x4B)
    if bytes.len() > 2 && bytes[0] == 0x50 && bytes[1] == 0x4B {
        if let Ok(mut archive) = zip::read::ZipArchive::new(std::io::Cursor::new(bytes)) {
            if archive.len() > 0 {
                if let Ok(mut file) = archive.by_index(0) {
                    let mut unzipped_data = Vec::with_capacity(file.size() as usize);
                    if std::io::copy(&mut file, &mut unzipped_data).is_ok() {
                        let (offset, len) = if unzipped_data.len() > 8
                            && unzipped_data[0] == 0xD0
                            && unzipped_data[1] == 0x17
                        {
                            let payload_len = u32::from_le_bytes([
                                unzipped_data[4],
                                unzipped_data[5],
                                unzipped_data[6],
                                unzipped_data[7],
                            ]) as usize;
                            (8, payload_len)
                        } else if unzipped_data.len() > 8 && unzipped_data[8] == 0x0A {
                            (8, unzipped_data.len() - 8)
                        } else if unzipped_data.len() > 4 && unzipped_data[4] == 0x0A {
                            (4, unzipped_data.len() - 4)
                        } else {
                            (0, unzipped_data.len())
                        };

                        let end = (offset + len).min(unzipped_data.len());
                        if let Ok(payload) =
                            ContentManifestPayload::parse_from_bytes(&unzipped_data[offset..end])
                        {
                            return Ok(payload);
                        }
                    }
                }
            }
        }
    }

    if let Ok(payload) = ContentManifestPayload::parse_from_bytes(bytes) {
        return Ok(payload);
    }

    let mut gzip = Vec::new();
    if GzDecoder::new(Cursor::new(bytes))
        .read_to_end(&mut gzip)
        .is_ok()
    {
        if let Ok(payload) = ContentManifestPayload::parse_from_bytes(&gzip) {
            return Ok(payload);
        }
    }

    let mut xz = Vec::new();
    if XzDecoder::new(Cursor::new(bytes))
        .read_to_end(&mut xz)
        .is_ok()
    {
        if let Ok(payload) = ContentManifestPayload::parse_from_bytes(&xz) {
            return Ok(payload);
        }
    }

    bail!("failed decoding manifest payload (raw/gzip/xz)")
}

fn decrypt_chunk_best_effort(encrypted: &[u8], depot_key: &[u8]) -> Vec<u8> {
    if depot_key.len() >= 32 && encrypted.len() >= 16 {
        let mut buf = encrypted.to_vec();
        let iv = [0_u8; 16];
        if let Ok(dec) = Aes256CbcDec::new_from_slices(&depot_key[..32], &iv) {
            if let Ok(plain) = dec.decrypt_padded_mut::<Pkcs7>(&mut buf) {
                return plain.to_vec();
            }
        }
    }

    encrypted.to_vec()
}

fn decompress_chunk_best_effort(data: &[u8]) -> Result<Vec<u8>> {
    let mut gzip = Vec::new();
    if GzDecoder::new(Cursor::new(data))
        .read_to_end(&mut gzip)
        .is_ok()
    {
        return Ok(gzip);
    }

    let mut zlib = Vec::new();
    if flate2::read::ZlibDecoder::new(Cursor::new(data))
        .read_to_end(&mut zlib)
        .is_ok()
    {
        return Ok(zlib);
    }

    let mut xz = Vec::new();
    if XzDecoder::new(Cursor::new(data))
        .read_to_end(&mut xz)
        .is_ok()
    {
        return Ok(xz);
    }

    Ok(data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_manifest_gid_from_vdf() {
        let vdf = r#""appinfo"
{
  "appid" "10"
  "depots"
  {
    "12345"
    {
      "config"
      {
        "oslist" "linux"
        "language" "english"
      }
      "manifests"
      {
        "public" "892913123"
      }
    }
  }
}"#;

        let parsed: AppInfoRoot = keyvalues_serde::from_str(vdf).expect("parse appinfo");
        let depots = parsed
            .appinfo
            .map(|node| node.depots)
            .unwrap_or(parsed.depots);
        let depot = depots.get("12345").expect("depot");
        let gid = depot
            .manifests
            .as_ref()
            .and_then(|m| m.public.as_ref())
            .expect("gid");
        assert_eq!(gid, "892913123");
    }

    #[test]
    fn process_chunk_handles_plain_bytes() {
        let data = b"hello-chunk".to_vec();
        let out = process_chunk(data.clone(), &[]);
        assert_eq!(out, data);
    }

    #[test]
    fn should_keep_common_depots() {
        // None means common/all
        assert!(should_keep_depot(None, DepotPlatform::Windows));
        assert!(should_keep_depot(None, DepotPlatform::Linux));

        // Explicitly including target OS
        assert!(should_keep_depot(Some("windows"), DepotPlatform::Windows));
        assert!(should_keep_depot(Some("linux"), DepotPlatform::Linux));

        // Excluding other OS
        assert!(!should_keep_depot(Some("windows"), DepotPlatform::Linux));
        assert!(!should_keep_depot(Some("linux"), DepotPlatform::Windows));
    }
}
