use crate::eresult::EResult;
use crate::message::MalformedBody;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt::Debug;
use std::io::Error as IoError;
use std::io::{Cursor, Seek, SeekFrom};
use steam_vent_core::{
    EncodableMessage, JobId, NetMessageHeader, RawSteamId, ReceivableMessage, SendableMessage,
};
use steam_vent_crypto::CryptError;
use steam_vent_proto_common::protobuf::Message;
use steam_vent_proto_common::{MsgKind, MsgKindEnum};
use steam_vent_proto_steam::enums_clientserver::EMsg;
use steam_vent_proto_steam::steammessages_base::CMsgProtoBufHeader;
use thiserror::Error;
use tracing::{debug, trace};

pub const PROTO_MASK: u32 = 0x80000000;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NetworkError {
    #[error("{0}")]
    IO(#[from] IoError),
    #[error("{0}")]
    Ws(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("Invalid message header")]
    InvalidHeader,
    #[error("Invalid message kind {0}")]
    InvalidMessageKind(i32),
    #[error("Failed to perform crypto handshake")]
    CryptoHandshakeFailed,
    #[error("Different message expected, expected {0:?}, got {1:?}")]
    DifferentMessage(MsgKind, MsgKind),
    #[error("Different service method expected, expected {0:?}, got {1:?}")]
    DifferentServiceMethod(&'static str, String),
    #[error("{0}")]
    MalformedBody(#[from] MalformedBody),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptError),
    #[error("Unexpected end of stream")]
    EOF,
    #[error("Response timed out")]
    Timeout,
    #[error("Remote returned an error code: {0:?}")]
    ApiError(EResult),
}

impl From<EResult> for NetworkError {
    fn from(value: EResult) -> Self {
        NetworkError::ApiError(value)
    }
}

pub type Result<T, E = NetworkError> = std::result::Result<T, E>;

fn parse_proto_header(header: CMsgProtoBufHeader) -> NetMessageHeader {
    NetMessageHeader {
        source_job_id: JobId::new(header.jobid_source()),
        target_job_id: JobId::new(header.jobid_target()),
        steam_id: RawSteamId::new(header.steamid()),
        session_id: header.client_sessionid(),
        target_job_name: header
            .has_target_job_name()
            .then(|| header.target_job_name().to_string().into()),
        result: header.eresult,
        source_app_id: header.routing_appid,
    }
}

fn proto_header(header: &NetMessageHeader, kind: MsgKind) -> CMsgProtoBufHeader {
    let mut proto_header = CMsgProtoBufHeader::new();
    if header.source_job_id != JobId::NONE {
        proto_header.set_jobid_source(header.source_job_id.id());
    }
    if header.target_job_id != JobId::NONE {
        proto_header.set_jobid_target(header.target_job_id.id());
    }
    if header.steam_id != RawSteamId::NONE {
        proto_header.set_steamid(
            if kind == EMsg::k_EMsgServiceMethodCallFromClientNonAuthed {
                0
            } else {
                header.steam_id.id()
            },
        );
    }
    if header.session_id != 0 {
        proto_header.set_client_sessionid(header.session_id);
    }
    if kind == EMsg::k_EMsgServiceMethodCallFromClientNonAuthed
        || kind == EMsg::k_EMsgServiceMethodCallFromClient
    {
        proto_header.set_realm(1);
    }
    if let Some(target_job_name) = header.target_job_name.as_deref() {
        proto_header.set_target_job_name(target_job_name.into());
    }
    proto_header.routing_appid = header.source_app_id;
    proto_header
}

pub(crate) fn read_header<R: ReadBytesExt + Seek>(
    mut reader: R,
    kind: MsgKind,
    is_protobuf: bool,
) -> Result<(NetMessageHeader, usize)> {
    if is_protobuf {
        let header_length = reader.read_u32::<LittleEndian>()?;
        trace!("reading protobuf header of {} bytes", header_length);
        let header = if header_length > 0 {
            let mut bytes = vec![0; header_length as usize];
            let num = reader.read(&mut bytes)?;
            parse_proto_header(
                CMsgProtoBufHeader::parse_from_bytes(&bytes[0..num])
                    .map_err(|_| NetworkError::InvalidHeader)?,
            )
        } else {
            NetMessageHeader::default()
        };
        Ok((header, 8 + header_length as usize))
    } else if kind == EMsg::k_EMsgChannelEncryptRequest || kind == EMsg::k_EMsgChannelEncryptResult
    {
        let target_job_id = reader.read_u64::<LittleEndian>()?;
        let source_job_id = reader.read_u64::<LittleEndian>()?;
        Ok((
            NetMessageHeader {
                target_job_id: JobId::new(target_job_id),
                source_job_id: JobId::new(source_job_id),
                session_id: 0,
                steam_id: RawSteamId::NONE,
                ..NetMessageHeader::default()
            },
            4 + 8 + 8,
        ))
    } else {
        reader.seek(SeekFrom::Current(3))?; // 1 byte (fixed) header size, 2 bytes (fixed) header version
        let target_job_id = reader.read_u64::<LittleEndian>()?;
        let source_job_id = reader.read_u64::<LittleEndian>()?;
        reader.seek(SeekFrom::Current(1))?; // header canary (fixed)
        let steam_id = RawSteamId::new(reader.read_u64::<LittleEndian>()?);
        let session_id = reader.read_i32::<LittleEndian>()?;
        Ok((
            NetMessageHeader {
                source_job_id: JobId::new(source_job_id),
                target_job_id: JobId::new(target_job_id),
                steam_id,
                session_id,
                target_job_name: None,
                result: None,
                source_app_id: None,
            },
            4 + 3 + 8 + 8 + 1 + 8 + 4,
        ))
    }
}

pub(crate) fn write_header<W: WriteBytesExt, K: MsgKindEnum>(
    header: &NetMessageHeader,
    writer: &mut W,
    kind: K,
    proto: bool,
) -> std::io::Result<()> {
    if MsgKind::from(kind) == EMsg::k_EMsgChannelEncryptResponse {
        writer.write_u32::<LittleEndian>(kind.value() as u32)?;
    } else if proto {
        trace!(
            "writing header for {:?} protobuf message: {:?}",
            kind,
            header
        );
        let proto_header = proto_header(header, kind.into());
        writer.write_u32::<LittleEndian>(kind.encode_kind(true))?;
        writer.write_u32::<LittleEndian>(proto_header.compute_size() as u32)?;
        proto_header.write_to_writer(writer)?;
    } else {
        trace!("writing header for {:?} message: {:?}", kind, header);
        writer.write_u32::<LittleEndian>(kind.value() as u32)?;
        writer.write_u8(32)?;
        writer.write_u16::<LittleEndian>(2)?;
        writer.write_u64::<LittleEndian>(header.target_job_id.id())?;
        writer.write_u64::<LittleEndian>(header.source_job_id.id())?;
        writer.write_u8(239)?;
        writer.write_u64::<LittleEndian>(header.steam_id.id())?;
        writer.write_i32::<LittleEndian>(header.session_id)?;
    }
    Ok(())
}

pub(crate) fn header_encode_size(header: &NetMessageHeader, kind: MsgKind, proto: bool) -> usize {
    if kind == EMsg::k_EMsgChannelEncryptResponse {
        4
    } else if proto {
        let proto_header = proto_header(header, kind);
        4 + 4 + proto_header.compute_size() as usize
    } else {
        4 + 1 + 2 + 8 + 8 + 1 + 8 + 4 + 4
    }
}

#[derive(Debug, Clone)]
pub struct RawNetMessage {
    pub kind: MsgKind,
    pub is_protobuf: bool,
    pub header: NetMessageHeader,
    pub data: BytesMut,
    pub(crate) frame_header_buffer: Option<BytesMut>,
    pub(crate) iv_buffer: Option<BytesMut>,
    pub(crate) header_buffer: BytesMut,
}

pub(crate) fn decode_kind(kind: u32) -> (MsgKind, bool) {
    let is_protobuf = kind & PROTO_MASK == PROTO_MASK;
    let kind = MsgKind((kind & !PROTO_MASK) as i32);
    (kind, is_protobuf)
}

impl RawNetMessage {
    pub fn read<Body: Into<Bytes>>(body: Body) -> Result<Self> {
        let mut value = BytesMut::from(body.into());
        let mut reader = Cursor::new(&value);
        let kind = reader
            .read_u32::<LittleEndian>()
            .map_err(|_| NetworkError::InvalidHeader)?;

        let is_protobuf = kind & PROTO_MASK == PROTO_MASK;
        let kind = MsgKind((kind & !PROTO_MASK) as i32);

        trace!(
            "reading header for {:?} {}message",
            kind,
            if is_protobuf { "protobuf " } else { "" }
        );

        let header_start = reader.position() as usize;
        let (header, body_start) = read_header(&mut reader, kind, is_protobuf)?;

        value.advance(header_start);
        let header_buffer = value.split_to(body_start - header_start);

        Ok(RawNetMessage {
            kind,
            is_protobuf,
            header,
            data: value,
            frame_header_buffer: None,
            iv_buffer: None,
            header_buffer,
        })
    }

    pub fn from_message<T: SendableMessage>(header: NetMessageHeader, message: T) -> Result<Self> {
        let kind = message.kind();
        let is_protobuf = message.is_protobuf();
        Self::from_message_with_kind(header, message, kind, is_protobuf)
    }

    pub fn from_message_with_kind<T: EncodableMessage, K: MsgKindEnum>(
        mut header: NetMessageHeader,
        message: T,
        kind: K,
        is_protobuf: bool,
    ) -> Result<Self> {
        debug!("writing raw {:?} message", kind);

        message.process_header(&mut header);

        let body_size = message.encode_size();

        // allocate the buffer with extra bytes and split those off
        // this allows later re-joining the bytes and use the space for the frame header and iv
        // without having to copy the message again
        //
        // 8 byte frame header, 16 byte iv, header, body, 16 byte encryption padding
        let mut buff = BytesMut::with_capacity(
            8 + 16 + header_encode_size(&header, kind.into(), is_protobuf) + body_size + 16,
        );
        buff.extend([0; 8 + 16]);
        let frame_header_buffer = buff.split_to(8);
        let iv_buffer = buff.split_to(16);

        {
            let mut writer = (&mut buff).writer();
            write_header(&header, &mut writer, kind, is_protobuf)?;
        }

        let header_buffer = buff.split();
        let mut writer = (&mut buff).writer();
        message.write_body(&mut writer)?;
        trace!("encoded body({} bytes): {:x?}", buff.len(), buff.as_ref());

        Ok(RawNetMessage {
            kind: kind.into(),
            is_protobuf,
            header,
            data: buff,
            frame_header_buffer: Some(frame_header_buffer),
            iv_buffer: Some(iv_buffer),
            header_buffer,
        })
    }

    /// Return a buffer containing the raw message bytes
    pub fn into_bytes(self) -> BytesMut {
        let mut body = self.header_buffer;
        body.unsplit(self.data);
        body
    }
}

impl RawNetMessage {
    pub fn into_header_and_message<T: ReceivableMessage>(self) -> Result<(NetMessageHeader, T)> {
        if let Some(result) = self.header.result {
            EResult::from_result(result)?;
        }
        if self.kind == T::KIND {
            trace!(
                "reading body of {:?} message({} bytes)",
                self.kind,
                self.data.len()
            );
            let body = T::read_body(self.data, &self.header)
                .map_err(|err| MalformedBody::new(T::KIND, err))?;
            Ok((self.header, body))
        } else {
            Err(NetworkError::DifferentMessage(T::KIND.into(), self.kind))
        }
    }

    pub fn into_message<T: ReceivableMessage>(self) -> Result<T> {
        self.into_header_and_message().map(|(_, msg)| msg)
    }
}
