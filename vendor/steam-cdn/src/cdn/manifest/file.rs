use futures::{stream::FuturesOrdered, StreamExt};
use itertools::Itertools;
use sha1::Digest;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing;
use std::{fmt::Write, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::Semaphore,
};

use crate::{cdn::{inner::InnerClient, OperationController}, Error};

#[derive(Debug)]
pub struct ChunkData {
    pub(super) sha: Vec<u8>,
    pub(super) crc: u32,
    pub(super) offset: u64,
    pub(super) original_size: u32,
    pub(super) compressed_size: u32,
}

impl ChunkData {
    pub fn sha(&self) -> Vec<u8> {
        self.sha.clone()
    }

    pub fn id(&self) -> String {
        self.sha.iter().fold(String::new(), |mut output, b| {
            let _ = write!(output, "{b:02x}");
            output
        })
    }

    pub fn crc(&self) -> u32 {
        self.crc
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn original_size(&self) -> u32 {
        self.original_size
    }

    pub fn compressed_size(&self) -> u32 {
        self.compressed_size
    }
}

#[derive(Debug)]
pub struct ManifestFile {
    pub(super) inner: Arc<InnerClient>,
    pub(super) app_id: u32,
    pub(super) depot_id: u32,
    pub(super) filename: String,
    pub(super) size: u64,
    pub(super) flags: u32,
    pub(super) sha_filename: Vec<u8>,
    pub(super) sha_content: Vec<u8>,
    pub(super) chunks: Vec<ChunkData>,
    pub(super) linktarget: String,
}

impl ManifestFile {
    pub fn full_path(&self) -> String {
        self.filename
            .trim_matches(|c: char| c.is_whitespace() || c == '\0')
            .replace("\\", "/")
    }

    pub fn path(&self) -> String {
        let full_path = self.full_path();
        if let Some(pos) = full_path.rfind('/') {
            full_path[..pos].to_string()
        } else {
            full_path
        }
    }

    pub fn filename(&self) -> String {
        self.full_path()
            .rsplit("/")
            .next()
            .unwrap_or("")
            .to_string()
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub fn sha_filename(&self) -> Vec<u8> {
        self.sha_filename.clone()
    }

    pub fn sha_content(&self) -> Vec<u8> {
        self.sha_content.clone()
    }

    pub fn chunks(&self) -> &Vec<ChunkData> {
        self.chunks.as_ref()
    }

    pub fn linktarget(&self) -> String {
        self.linktarget.clone()
    }

    pub async fn download(
        &self,
        depot_key: [u8; 32],
        target_path: &std::path::Path,
        verify_mode: bool,
        abort_signal: Option<Arc<AtomicBool>>,
        operation_controller: Option<OperationController>,
        max_tasks: Option<usize>,
        on_progress: Option<Arc<dyn Fn(u64) + Send + Sync + 'static>>,
    ) -> Result<(), Error> {
        let max_tasks = max_tasks.unwrap_or(4);
        let semaphore = Arc::new(Semaphore::new(max_tasks));

        let metadata_before = tokio::fs::metadata(target_path).await;
        let file_exists_before = metadata_before.is_ok();
        let current_len_before = metadata_before.as_ref().map(|m| m.len()).unwrap_or(0);

        // Steam replaces files regardless of their on-disk permissions. A
        // read-only target (e.g. chmod 0555 by the game, REFramework, or a
        // previous tool) makes `write(true)` fail with EACCES. Mirror the
        // official client: ensure the owner write bit before opening.
        if file_exists_before {
            if let Ok(meta) = &metadata_before {
                let mut perms = meta.permissions();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = perms.mode();
                    if mode & 0o200 == 0 {
                        perms.set_mode(mode | 0o200);
                        let _ = tokio::fs::set_permissions(target_path, perms).await;
                    }
                }
            }
        }

        let mut out = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(target_path)
            .await
            .map_err(|e| Error::Unexpected(e.to_string()))?;

        if current_len_before != self.size {
            out.set_len(self.size)
                .await
                .map_err(|e| Error::Unexpected(e.to_string()))?;
        }

        let mut tasks = self
            .chunks()
            .iter()
            .sorted_by(|&a, &b| a.offset.cmp(&b.offset))
            .map(|chunk_data| {
                let semaphore_owned = semaphore.clone();
                let verify_mode = verify_mode;
                let abort_signal = abort_signal.clone();
                let operation_controller = operation_controller.clone();
                let target_path = target_path.to_path_buf();
                let on_progress = on_progress.clone();
                async move {
                    // Cancellation check
                    if let Some(signal) = &abort_signal {
                        if signal.load(Ordering::Relaxed) {
                            return Ok((chunk_data.offset, None));
                        }
                        if let Some(controller) = &operation_controller {
                            if controller.is_cancelled() {
                                return Ok((chunk_data.offset, None));
                            }
                            while controller.is_paused() {
                                if controller.is_cancelled() {
                                    return Ok((chunk_data.offset, None));
                                }
                                tokio::task::yield_now().await;
                            }
                        }
                    }

                    let permit = semaphore_owned.acquire_owned().await?;

                    let metadata = tokio::fs::metadata(&target_path).await;
                    let file_exists = metadata.is_ok();
                    let current_len = metadata.map(|m| m.len()).unwrap_or(0);

                    // Deep Check (runs in BOTH verify and install/resume mode):
                    // a chunk whose byte range is already present on disk is
                    // accepted ONLY if its content hashes to the manifest SHA.
                    // Length alone is never trusted — a same-size corrupt file
                    // (e.g. a zeroed region from a failed write) would otherwise
                    // be silently skipped during install/update/repair and never
                    // repaired. Verified chunks are skipped (no HTTP fetch);
                    // corrupt or missing chunks fall through to the CDN fetch.
                    if file_exists && current_len >= chunk_data.offset + chunk_data.original_size as u64 {
                        let mut file = tokio::fs::File::open(&target_path)
                            .await
                            .map_err(|e| Error::Unexpected(e.to_string()))?;
                        file.seek(tokio::io::SeekFrom::Start(chunk_data.offset))
                            .await
                            .map_err(|e| Error::Unexpected(e.to_string()))?;

                        let mut buffer = vec![0u8; chunk_data.original_size as usize];
                        if file.read_exact(&mut buffer).await.is_ok() {
                            let mut hasher = sha1::Sha1::new();
                            hasher.update(&buffer);
                            let hash = hasher.finalize().to_vec();

                            if hash == chunk_data.sha {
                                tracing::info!("Verified chunk {}", chunk_data.id());
                                if let Some(ref cb) = on_progress {
                                    cb(chunk_data.original_size as u64);
                                }
                                drop(permit);
                                return Ok((chunk_data.offset, None));
                            } else {
                                tracing::warn!(
                                    "Corruption detected in chunk {} (verify_mode={})",
                                    chunk_data.id(),
                                    verify_mode
                                );
                            }
                        }
                    }

                    let result = self
                        .inner
                        .get_chunk(self.app_id, self.depot_id, depot_key, chunk_data.id())
                        .await;
                    drop(permit);
                    result.map(|data| (chunk_data.offset, Some(data)))
                }
            })
            .collect::<FuturesOrdered<_>>();

        while let Some(result) = tasks.next().await {
            if let Some(signal) = &abort_signal {
                if signal.load(Ordering::Relaxed) {
                    break;
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
                    if controller.is_cancelled() {
                        break;
                    }
                }
            }
            let (offset, data) = result?;
            if let Some(data) = data {
                let len = data.len() as u64;
                out.seek(tokio::io::SeekFrom::Start(offset))
                    .await
                    .map_err(|e| Error::Unexpected(e.to_string()))?;
                out.write_all(&data)
                    .await
                    .map_err(|e| Error::Unexpected(e.to_string()))?;
                if let Some(ref cb) = on_progress {
                    cb(len);
                }
            }
        }
        out.flush().await.map_err(|e| Error::Unexpected(e.to_string()))?;
        Ok(())
    }
}
