use buf::TryBuf;
use bytes::Bytes;
use error::ManifestError;
use file::{ChunkData, ManifestFile};
use std::sync::Arc;
use std::{
    io::{Cursor, Read},
    str,
};
use steam_vent::proto::{
    content_manifest::{ContentManifestMetadata, ContentManifestPayload, ContentManifestSignature},
    protobuf::Message,
};
use zip::ZipArchive;

use super::inner::InnerClient;
use crate::{crypto::aes256, utils::base64::base64_decode};

mod buf;
pub mod error;
pub mod file;

const PROTOBUF_PAYLOAD_MAGIC: u32 = 0x71F617D0;
const PROTOBUF_METADATA_MAGIC: u32 = 0x1F4812BE;
const PROTOBUF_SIGNATURE_MAGIC: u32 = 0x1B81B817;
const PROTOBUF_ENDOFMANIFEST_MAGIC: u32 = 0x32C415AB;

#[derive(Debug)]
pub struct DepotManifest {
    app_id: u32,
    depot_id: u32,
    manifest_gid: u64,
    creatime_time: u32,
    filenames_encrypted: bool,
    original_size: u64,
    compressed_size: u64,
    files: Vec<ManifestFile>,
}

impl DepotManifest {
    pub fn depot_id(&self) -> u32 {
        self.depot_id
    }

    pub fn manifest_gid(&self) -> u64 {
        self.manifest_gid
    }

    pub fn creatime_time(&self) -> u32 {
        self.creatime_time
    }

    pub fn filenames_encrypted(&self) -> bool {
        self.filenames_encrypted
    }

    pub fn original_size(&self) -> u64 {
        self.original_size
    }

    pub fn compressed_size(&self) -> u64 {
        self.compressed_size
    }

    pub fn files(&self) -> &Vec<ManifestFile> {
        &self.files
    }

    pub fn decrypt_filenames(&mut self, key: [u8; 32]) -> Result<(), ManifestError> {
        if self.filenames_encrypted {
            for file in &mut self.files {
                let mut encrypted = base64_decode(file.filename.as_bytes())?;
                file.filename = str::from_utf8(&aes256::decrypt_cbc_with_iv_extraction(
                    &mut encrypted[..],
                    key,
                )?)?
                .to_string();
            }
            self.filenames_encrypted = false;
        }
        Ok(())
    }

    pub(crate) fn deserialize(
        client: Arc<InnerClient>,
        app_id: u32,
        data: &[u8],
    ) -> Result<Self, ManifestError> {
        let mut buffer = Vec::new();
        let is_zip = data.len() > 2 && data[0] == 0x50 && data[1] == 0x4B;

        let raw_data = if is_zip {
            println!("DEBUG: Detected PKZip format in Manifest. Extracting...");
            let cursor = Cursor::new(data);
            match ZipArchive::new(cursor) {
                Ok(mut archive) if archive.len() > 0 => {
                    if let Ok(mut file) = archive.by_index(0) {
                        println!("DEBUG: Zip Entry Name: {}", file.name());
                        if file.read_to_end(&mut buffer).is_ok() {
                            println!("DEBUG: Successfully unzipped {} bytes.", buffer.len());

                            if buffer.len() >= 16 {
                                println!("DEBUG: Unzipped Header (Hex): {:02X?}", &buffer[..16]);
                            }

                            if buffer.starts_with(b"VBKV") {
                                println!(
                                    "DEBUG: Warning: Found VBKV header! This is not raw Protobuf."
                                );
                            }

                            if !buffer.is_empty() && buffer[0] == 0x0A {
                                println!("DEBUG: Looks like valid ContentManifestPayload (starts with 0x0A).");
                            }

                            &buffer[..]
                        } else {
                            data
                        }
                    } else {
                        data
                    }
                }
                _ => data,
            }
        } else {
            data
        };

        let mut bytes = Bytes::from(raw_data.to_vec());
        if bytes.try_get_u32()? != PROTOBUF_PAYLOAD_MAGIC {
            return Err(ManifestError::MagicMismatch(
                "expecting protobuf payload".to_string(),
            ));
        }

        let payload = ContentManifestPayload::parse_from_bytes(&bytes.try_get_bytes()?)?;

        if bytes.try_get_u32()? != PROTOBUF_METADATA_MAGIC {
            return Err(ManifestError::MagicMismatch(
                "expecting protobuf metadata".to_string(),
            ));
        }

        let metadata = ContentManifestMetadata::parse_from_bytes(&bytes.try_get_bytes()?)?;

        if bytes.try_get_u32()? != PROTOBUF_SIGNATURE_MAGIC {
            return Err(ManifestError::MagicMismatch(
                "expecting protobuf signature".to_string(),
            ));
        }

        let _signature = ContentManifestSignature::parse_from_bytes(&bytes.try_get_bytes()?)?;

        if bytes.try_get_u32()? != PROTOBUF_ENDOFMANIFEST_MAGIC {
            return Err(ManifestError::MagicMismatch(
                "expecting end of manifest".to_string(),
            ));
        }

        Ok(Self {
            app_id,
            depot_id: metadata.depot_id(),
            manifest_gid: metadata.gid_manifest(),
            creatime_time: metadata.creation_time(),
            filenames_encrypted: metadata.filenames_encrypted(),
            original_size: metadata.cb_disk_original(),
            compressed_size: metadata.cb_disk_compressed(),
            files: payload
                .mappings
                .into_iter()
                .map(|map| ManifestFile {
                    inner: client.clone(),
                    app_id,
                    depot_id: metadata.depot_id(),
                    filename: map.filename().to_string(),
                    size: map.size(),
                    flags: map.flags(),
                    sha_filename: map.sha_filename().to_vec(),
                    sha_content: map.sha_content().to_vec(),
                    chunks: map
                        .chunks
                        .iter()
                        .map(|chunk| ChunkData {
                            sha: chunk.sha().to_vec(),
                            crc: chunk.crc(),
                            offset: chunk.offset(),
                            original_size: chunk.cb_original(),
                            compressed_size: chunk.cb_compressed(),
                        })
                        .collect::<Vec<ChunkData>>(),
                    linktarget: map.linktarget().to_string(),
                })
                .collect::<Vec<ManifestFile>>(),
        })
    }
}
