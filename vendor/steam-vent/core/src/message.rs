use crate::net::NetMessageHeader;
use bytes::{Buf, BytesMut};
use std::fmt::Debug;
use std::io::Error as IoError;
use std::io::Write;
use steam_vent_proto_common::{MsgKindEnum, RpcMessage, RpcMessageWithKind};
use tracing::trace;

/// A message which can be encoded
///
/// To send messasages that implement this trait but not [`SendableMessage`], use [`EncodableMessage::with_kind`] to specify the kind of the message at runtime.
pub trait EncodableMessage: Sized + Debug + Send {
    /// Encode the message
    fn write_body<W: Write>(&self, writer: W) -> Result<(), IoError>;

    /// How many bytes are required to encode the message
    fn encode_size(&self) -> usize;

    /// Perform pre-processing on a header before sending
    ///
    /// This allows messages to customize the header that is being send with it.
    /// The primary usecase for this is setting the job name for [`ServiceMethodRequest`s][crate::ServiceMethodRequest].
    fn process_header(&self, _header: &mut NetMessageHeader) {}

    /// Override the kind of the message at runtime
    fn with_kind<Kind: MsgKindEnum>(self, kind: Kind, is_protobuf: bool) -> impl SendableMessage {
        DynamicKind {
            msg: self,
            kind,
            is_protobuf,
        }
    }
}

/// A message which can be decoded
pub trait DecodableMessage: Sized + Debug + Send {
    /// Read and decode the message
    fn read_body(data: BytesMut, header: &NetMessageHeader) -> Result<Self, IoError>;
}

/// A message that can be send over a connection.
///
/// Unlike [`ReceivableMessage`], this doesn't have a static associated kind, and thus can't be received.
pub trait SendableMessage: EncodableMessage {
    type KindEnum: MsgKindEnum;

    ///  The message kind
    fn kind(&self) -> Self::KindEnum;

    /// Is this message encoded using protobuf
    fn is_protobuf(&self) -> bool;
}

#[derive(Debug)]
struct DynamicKind<Msg: EncodableMessage, Kind: MsgKindEnum> {
    msg: Msg,
    kind: Kind,
    is_protobuf: bool,
}

impl<Msg: EncodableMessage, Kind: MsgKindEnum> EncodableMessage for DynamicKind<Msg, Kind> {
    fn write_body<W: Write>(&self, writer: W) -> Result<(), IoError> {
        self.msg.write_body(writer)
    }

    fn encode_size(&self) -> usize {
        self.msg.encode_size()
    }

    fn process_header(&self, header: &mut NetMessageHeader) {
        self.msg.process_header(header);
    }

    fn with_kind<NewKind: MsgKindEnum>(
        self,
        kind: NewKind,
        is_protobuf: bool,
    ) -> impl SendableMessage {
        DynamicKind {
            msg: self,
            kind,
            is_protobuf,
        }
    }
}

impl<Msg: EncodableMessage, Kind: MsgKindEnum> SendableMessage for DynamicKind<Msg, Kind> {
    type KindEnum = Kind;

    fn kind(&self) -> Self::KindEnum {
        self.kind
    }

    fn is_protobuf(&self) -> bool {
        self.is_protobuf
    }
}

/// A message that can be received from a connection.
///
/// Unlike [`SendableMessage`] this requires the assotiacted kind to be constant
pub trait ReceivableMessage: DecodableMessage {
    type KindEnum: MsgKindEnum;
    ///  The message kind
    const KIND: Self::KindEnum;
    /// Is this message encoded using protobuf
    const IS_PROTOBUF: bool;
}

impl<ProtoMsg: RpcMessageWithKind + Send> EncodableMessage for ProtoMsg {
    fn write_body<W: Write>(&self, mut writer: W) -> Result<(), IoError> {
        trace!("writing body of protobuf message {:?}", Self::KIND);
        self.write(&mut writer)
            .map_err(|_| IoError::from(std::io::ErrorKind::InvalidData))
    }

    fn encode_size(&self) -> usize {
        <Self as RpcMessage>::encode_size(self)
    }
}

impl<ProtoMsg: RpcMessageWithKind + Send> SendableMessage for ProtoMsg {
    type KindEnum = ProtoMsg::KindEnum;

    fn kind(&self) -> Self::KindEnum {
        Self::KIND
    }

    fn is_protobuf(&self) -> bool {
        true
    }
}

impl<ProtoMsg: RpcMessageWithKind + Send> DecodableMessage for ProtoMsg {
    fn read_body(data: BytesMut, _header: &NetMessageHeader) -> Result<Self, IoError> {
        trace!("reading body of protobuf message {:?}", Self::KIND);
        Self::parse(&mut data.reader()).map_err(IoError::from)
    }
}

impl<ProtoMsg: RpcMessageWithKind + Send> ReceivableMessage for ProtoMsg {
    type KindEnum = ProtoMsg::KindEnum;
    const KIND: Self::KindEnum = <ProtoMsg as RpcMessageWithKind>::KIND;
    const IS_PROTOBUF: bool = true;
}
