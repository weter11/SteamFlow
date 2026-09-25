use std::fmt::Debug;
use std::io::{Error, Read, Result, Write};
use steam_vent_proto_common::{RpcMessage, RpcMethod};

/// A service method message which returns a typed response
///
/// Service methods have an associated response type,
/// sending a service method with [`service_method`] will
/// automatically wait for the matching response from the connection and return it.
///
/// [`service_method`]: `crate::ConnectionTrait::service_method`
pub trait ServiceMethodRequest: Debug + Send {
    const REQ_NAME: &'static str;
    type Response: RpcMessage;

    fn write(&self, writer: &mut dyn Write) -> Result<()>;
    fn encode_size(&self) -> usize;
}

impl<T: RpcMethod> ServiceMethodRequest for T {
    const REQ_NAME: &'static str = T::METHOD_NAME;
    type Response = T::Response;

    fn write(&self, writer: &mut dyn Write) -> Result<()> {
        <Self as RpcMessage>::write(self, writer).map_err(Error::from)
    }

    fn encode_size(&self) -> usize {
        <Self as RpcMessage>::encode_size(self)
    }
}

/// A notification message which can be received
pub trait ServiceNotification: Debug + Sized + Send {
    const NOTIFICATION_NAME: &'static str;

    fn parse(reader: &mut dyn Read) -> Result<Self>;
}

impl<T: RpcMethod> ServiceNotification for T {
    const NOTIFICATION_NAME: &'static str = T::METHOD_NAME;

    fn parse(reader: &mut dyn Read) -> Result<Self> {
        <Self as RpcMessage>::parse(reader).map_err(Error::from)
    }
}
