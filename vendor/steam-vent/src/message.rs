use crate::net::{NetworkError, RawNetMessage};
use binrw::BinRead;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use bytes::{Buf, BytesMut};
use crc::{Crc, CRC_32_ISO_HDLC};
use flate2::read::GzDecoder;
use futures_util::{
    future::ready,
    stream::{iter, once},
    StreamExt,
};
use std::io::Error as IoError;
use std::io::{Cursor, Read, Write};
use std::{fmt::Debug, io::ErrorKind};
use steam_vent_core::{
    DecodableMessage, EncodableMessage, NetMessageHeader, ReceivableMessage, SendableMessage,
    ServiceMethodRequest, ServiceNotification,
};
use steam_vent_proto_common::protobuf::Message;
use steam_vent_proto_common::{MsgKind, RpcMessage};
use steam_vent_proto_steam::enums_clientserver::EMsg;
use steam_vent_proto_steam::steammessages_base::CMsgMulti;
use thiserror::Error;
use tokio_stream::Stream;
use tracing::{debug, trace};

/// Malformed message body
#[derive(Error, Debug)]
#[error("Malformed message body for {0:?}: {1}")]
pub struct MalformedBody(MsgKind, MessageParseError);

impl MalformedBody {
    pub fn new<K: Into<MsgKind>>(kind: K, err: impl Into<MessageParseError>) -> Self {
        MalformedBody(kind.into(), err.into())
    }
}

/// Error while parsing the message body
#[derive(Error, Debug)]
#[non_exhaustive]
#[error("{error:#}")]
pub struct MessageParseError {
    #[from]
    error: IoError,
}

#[derive(Debug, BinRead)]
#[brw(little)]
pub(crate) struct ChannelEncryptRequest {
    pub protocol: u32,
    #[allow(dead_code)]
    pub universe: u32,
    pub nonce: [u8; 16],
}

fn extract_io_error(error: binrw::Error) -> IoError {
    match error {
        binrw::Error::Io(error) => error,
        error => IoError::other(error),
    }
}

impl DecodableMessage for ChannelEncryptRequest {
    fn read_body(data: BytesMut, _header: &NetMessageHeader) -> Result<Self, IoError> {
        trace!("reading body of {:?} message", Self::KIND);
        let mut reader = Cursor::new(data);
        ChannelEncryptRequest::read(&mut reader).map_err(extract_io_error)
    }
}

impl ReceivableMessage for ChannelEncryptRequest {
    type KindEnum = EMsg;
    const KIND: Self::KindEnum = EMsg::k_EMsgChannelEncryptRequest;
    const IS_PROTOBUF: bool = false;
}

#[derive(Debug, BinRead)]
#[brw(little)]
pub(crate) struct ChannelEncryptResult {
    pub result: u32,
}

impl DecodableMessage for ChannelEncryptResult {
    fn read_body(data: BytesMut, _header: &NetMessageHeader) -> Result<Self, IoError> {
        trace!("reading body of {:?} message", Self::KIND);
        let mut reader = Cursor::new(data);
        ChannelEncryptResult::read(&mut reader).map_err(extract_io_error)
    }
}

impl ReceivableMessage for ChannelEncryptResult {
    type KindEnum = EMsg;
    const KIND: Self::KindEnum = EMsg::k_EMsgChannelEncryptResult;
    const IS_PROTOBUF: bool = false;
}

#[derive(Debug)]
pub(crate) struct ClientEncryptResponse {
    pub protocol: u32,
    pub encrypted_key: Vec<u8>,
}

const CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

impl EncodableMessage for ClientEncryptResponse {
    fn write_body<W: Write>(&self, mut writer: W) -> Result<(), IoError> {
        trace!("writing body of {:?} message", self.kind());
        writer.write_u64::<LittleEndian>(u64::MAX)?;
        writer.write_u64::<LittleEndian>(u64::MAX)?;
        writer.write_u32::<LittleEndian>(self.protocol)?;
        writer.write_u32::<LittleEndian>(self.encrypted_key.len() as u32)?;
        writer.write_all(&self.encrypted_key)?;

        let mut digest = CRC.digest();
        digest.update(&self.encrypted_key);
        writer.write_u32::<LittleEndian>(digest.finalize())?;
        writer.write_u32::<LittleEndian>(0)?;
        Ok(())
    }

    fn encode_size(&self) -> usize {
        8 + 8 + 4 + 4 + self.encrypted_key.len() + 4 + 4
    }
}

impl SendableMessage for ClientEncryptResponse {
    type KindEnum = EMsg;
    fn kind(&self) -> Self::KindEnum {
        EMsg::k_EMsgChannelEncryptResponse
    }

    fn is_protobuf(&self) -> bool {
        false
    }
}

enum MaybeZipReader {
    Raw(Cursor<Vec<u8>>),
    Zipped(Box<GzDecoder<Cursor<Vec<u8>>>>),
}

impl Read for MaybeZipReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            MaybeZipReader::Raw(raw) => raw.read(buf),
            MaybeZipReader::Zipped(zipped) => zipped.read(buf),
        }
    }
}

/// Flatten any "multi" messages in a stream of raw messages
pub(crate) fn flatten_multi<S: Stream<Item = Result<RawNetMessage, NetworkError>>>(
    source: S,
) -> impl Stream<Item = Result<RawNetMessage, NetworkError>> {
    source.flat_map(|res| match res {
        Ok(next) if next.kind == EMsg::k_EMsgMulti => {
            let reader = Cursor::new(next.data);
            let multi = match MultiBodyIter::new(reader) {
                Err(e) => return once(ready(Err(e.into()))).right_stream(),
                Ok(iter) => iter,
            };
            iter(multi).left_stream()
        }
        res => once(ready(res)).right_stream(),
    })
}

struct MultiBodyIter<R> {
    reader: R,
}

impl MultiBodyIter<MaybeZipReader> {
    pub fn new<R: Read>(mut reader: R) -> Result<Self, MalformedBody> {
        let mut multi = CMsgMulti::parse_from_reader(&mut reader)
            .map_err(|e| MalformedBody::new(EMsg::k_EMsgMulti, IoError::from(e)))?;

        let data = match multi.size_unzipped() {
            0 => MaybeZipReader::Raw(Cursor::new(multi.take_message_body())),
            _ => MaybeZipReader::Zipped(Box::new(GzDecoder::new(Cursor::new(
                multi.take_message_body(),
            )))),
        };

        Ok(MultiBodyIter { reader: data })
    }
}

impl<R: Read> Iterator for MultiBodyIter<R> {
    type Item = Result<RawNetMessage, NetworkError>;

    fn next(&mut self) -> Option<Self::Item> {
        let size = match self.reader.read_u32::<LittleEndian>() {
            Ok(size) => size,
            Err(_) => return None,
        };

        let mut msg_data = BytesMut::with_capacity(size as usize);
        msg_data.resize(size as usize, 0);
        if let Err(e) = self.reader.read_exact(&mut msg_data) {
            return Some(Err(NetworkError::IO(e)));
        }
        let raw = match RawNetMessage::read(msg_data) {
            Ok(raw) => raw,
            Err(e) => return Some(Err(e)),
        };

        debug!("Reading child message {:?}", raw.kind);

        Some(Ok(raw))
    }
}

#[derive(Debug)]
pub(crate) struct ServiceMethodMessage<Request: Debug>(pub Request);

impl<Request: ServiceMethodRequest + Debug> EncodableMessage for ServiceMethodMessage<Request> {
    fn write_body<W: Write>(&self, mut writer: W) -> Result<(), IoError> {
        trace!("writing body of protobuf message {:?}", self.kind());
        self.0
            .write(&mut writer)
            .map_err(|_| IoError::from(ErrorKind::InvalidData))
    }

    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }

    fn process_header(&self, header: &mut NetMessageHeader) {
        header.target_job_name = Some(Request::REQ_NAME.into())
    }
}

impl<Request: ServiceMethodRequest + Debug> SendableMessage for ServiceMethodMessage<Request> {
    type KindEnum = EMsg;

    fn kind(&self) -> Self::KindEnum {
        EMsg::k_EMsgServiceMethodCallFromClient
    }

    fn is_protobuf(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub(crate) struct ServiceMethodResponseMessage {
    job_name: String,
    body: BytesMut,
}

impl ServiceMethodResponseMessage {
    pub fn into_response<Request: ServiceMethodRequest>(
        self,
    ) -> Result<Request::Response, NetworkError> {
        if self.job_name == Request::REQ_NAME {
            Ok(Request::Response::parse(&mut self.body.reader())
                .map_err(|e| MalformedBody::new(Self::KIND, IoError::from(e)))?)
        } else {
            Err(NetworkError::DifferentServiceMethod(
                Request::REQ_NAME,
                self.job_name,
            ))
        }
    }
}

impl DecodableMessage for ServiceMethodResponseMessage {
    fn read_body(data: BytesMut, header: &NetMessageHeader) -> Result<Self, IoError> {
        trace!("reading body of protobuf message {:?}", Self::KIND);
        Ok(ServiceMethodResponseMessage {
            job_name: header
                .target_job_name
                .as_deref()
                .unwrap_or_default()
                .to_string(),
            body: data,
        })
    }
}

impl ReceivableMessage for ServiceMethodResponseMessage {
    type KindEnum = EMsg;
    const KIND: Self::KindEnum = EMsg::k_EMsgServiceMethodResponse;
    const IS_PROTOBUF: bool = true;
}

#[derive(Debug, Clone)]
pub(crate) struct ServiceMethodNotification {
    pub(crate) job_name: String,
    body: BytesMut,
}

impl ServiceMethodNotification {
    pub fn into_notification<Request: ServiceNotification>(self) -> Result<Request, NetworkError> {
        if self.job_name == Request::NOTIFICATION_NAME {
            Ok(Request::parse(&mut self.body.reader())
                .map_err(|e| MalformedBody::new(Self::KIND, e))?)
        } else {
            Err(NetworkError::DifferentServiceMethod(
                Request::NOTIFICATION_NAME,
                self.job_name,
            ))
        }
    }
}

impl DecodableMessage for ServiceMethodNotification {
    fn read_body(data: BytesMut, header: &NetMessageHeader) -> Result<Self, IoError> {
        trace!("reading body of protobuf message {:?}", Self::KIND);
        Ok(ServiceMethodNotification {
            job_name: header
                .target_job_name
                .as_deref()
                .unwrap_or_default()
                .to_string(),
            body: data,
        })
    }
}

impl ReceivableMessage for ServiceMethodNotification {
    type KindEnum = EMsg;
    const KIND: Self::KindEnum = EMsg::k_EMsgServiceMethod;
    const IS_PROTOBUF: bool = true;
}
