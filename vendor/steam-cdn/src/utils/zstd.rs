use crate::Error;

/// Steam VZstd chunk format (mirrors SteamKit2 `VZstdUtil`):
///
/// ```text
/// [ 4 ] "VSZa" (0x615A5356 LE)   header magic
/// [ 4 ] crc32                    (written twice — header AND footer)
/// [ .. ] zstd frame              decompressed by zstd
/// [ 4 ] crc32                    footer copy
/// [ 4 ] size_decompressed (LE u32)
/// [ 3 ] "zsv"                    footer magic
/// ```
///
/// Modern Valve depots (Proton 11.x era) ship Zstd-compressed chunks; older
/// ones use the LZMA "VZa" format (see `lzma.rs`) or zip.
const VZSTD_HEADER: u32 = 0x615A5356; // "VSZa"
const VZSTD_FOOTER_LEN: usize = 15;

pub fn is_vzstd(data: &[u8]) -> bool {
    data.len() >= 4 && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == VZSTD_HEADER
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>, Error> {
    if !is_vzstd(data) {
        return Err(Error::Eof("expecting VZstd header".to_string()));
    }
    if data.len() < 8 + VZSTD_FOOTER_LEN {
        return Err(Error::Eof("VZstd data too small".to_string()));
    }

    let crc32 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    let footer = &data[data.len() - VZSTD_FOOTER_LEN..];
    let crc32_footer = u32::from_le_bytes([footer[0], footer[1], footer[2], footer[3]]);
    let size_decompressed = u32::from_le_bytes([footer[4], footer[5], footer[6], footer[7]]);
    // "zsv" sits in the LAST three bytes of the stream (SteamKit2: buffer[^3..]).
    if data[data.len() - 3] != b'z' || data[data.len() - 2] != b's' || data[data.len() - 1] != b'v' {
        return Err(Error::Eof("expecting VZstd footer".to_string()));
    }

    // SteamKit2 asserts the CRC is written twice (header + footer); treat a
    // mismatch as corruption rather than silently trusting the header copy.
    if crc32 != crc32_footer {
        return Err(Error::Decompress("VZstd crc32 header/footer mismatch".to_string()));
    }

    let frame = &data[8..data.len() - VZSTD_FOOTER_LEN];
    let decoded = zstd::stream::decode_all(std::io::Cursor::new(frame))
        .map_err(|e| Error::Decompress(format!("zstd decode failed: {e}")))?;

    if decoded.len() as u32 != size_decompressed {
        return Err(Error::Decompress(format!(
            "VZstd size mismatch: expected {size_decompressed}, got {}",
            decoded.len()
        )));
    }
    if crc32fast::hash(&decoded) != crc32_footer {
        return Err(Error::Decompress("VZstd crc32 mismatch".to_string()));
    }

    Ok(decoded)
}
