use futures::{stream::FuturesOrdered, StreamExt};
use itertools::Itertools;
use std::{fmt::Write, sync::Arc};
use tokio::{io::AsyncWriteExt, sync::Semaphore};

use crate::{cdn::inner::InnerClient, Error};

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

    pub async fn download<S: AsyncWriteExt + Unpin>(
        &self,
        depot_key: [u8; 32],
        stream: &mut S,
        max_tasks: Option<usize>,
    ) -> Result<(), Error> {
        let max_tasks = max_tasks.unwrap_or(4);
        let semaphore = Arc::new(Semaphore::new(max_tasks));

        let mut tasks = self
            .chunks()
            .iter()
            .sorted_by(|&a, &b| a.offset.cmp(&b.offset))
            .map(|chunk_data| {
                let semaphore_owned = semaphore.clone();
                async move {
                    let permit = semaphore_owned.acquire_owned().await?;
                    let result = self
                        .inner
                        .get_chunk(self.app_id, self.depot_id, depot_key, chunk_data.id())
                        .await;
                    drop(permit);
                    result
                }
            })
            .collect::<FuturesOrdered<_>>();
        while let Some(result) = tasks.next().await {
            let data = result?;
            stream.write_all(&data).await?;
        }
        stream.flush().await?;
        Ok(())
    }
}
