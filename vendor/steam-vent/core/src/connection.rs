use crate::{
    NetMessageHeader, ReceivableMessage, SendableMessage, ServiceMethodRequest, ServiceNotification,
};
use steam_vent_proto_common::JobMultiple;
use tokio_stream::Stream;

/// A trait for connections that only allow listening for messages coming from steam
pub trait ReadonlyConnection {
    type Error;

    fn on_notification<T: ServiceNotification>(
        &self,
    ) -> impl Stream<Item = Result<T, Self::Error>> + 'static;

    /// Wait for one message of a specific kind, also returning the header
    fn one_with_header<T: ReceivableMessage + 'static>(
        &self,
    ) -> impl Future<Output = Result<(NetMessageHeader, T), Self::Error>> + 'static;

    /// Wait for one message of a specific kind
    fn one<T: ReceivableMessage + 'static>(
        &self,
    ) -> impl Future<Output = Result<T, Self::Error>> + 'static;

    /// Listen to messages of a specific kind, also returning the header
    fn on_with_header<T: ReceivableMessage + 'static>(
        &self,
    ) -> impl Stream<Item = Result<(NetMessageHeader, T), Self::Error>> + 'static;

    /// Listen to messages of a specific kind
    fn on<T: ReceivableMessage + 'static>(
        &self,
    ) -> impl Stream<Item = Result<T, Self::Error>> + 'static;
}

/// A trait for sending messages to steam
pub trait ConnectionTrait {
    type Error;

    /// Listen for notification messages from steam
    fn on_notification<T: ServiceNotification>(
        &self,
    ) -> impl Stream<Item = Result<T, Self::Error>> + 'static;

    /// Wait for one message of a specific kind
    fn one<T: ReceivableMessage + 'static>(
        &self,
    ) -> impl Future<Output = Result<T, Self::Error>> + 'static;

    /// Listen to messages of a specific kind
    fn on<T: ReceivableMessage + 'static>(
        &self,
    ) -> impl Stream<Item = Result<T, Self::Error>> + 'static;

    /// Send a rpc-request to steam, waiting for the matching rpc-response
    fn service_method<Msg: ServiceMethodRequest>(
        &self,
        msg: Msg,
    ) -> impl Future<Output = Result<Msg::Response, Self::Error>> + Send;

    /// Send a message to steam, waiting for a response with the same job id
    fn job<Req: SendableMessage, Rsp: ReceivableMessage>(
        &self,
        msg: Req,
    ) -> impl Future<Output = Result<Rsp, Self::Error>> + Send;

    /// Send a message to steam, receiving responses until the response marks that the response is complete
    fn job_multi<Req: SendableMessage, Rsp: ReceivableMessage + JobMultiple>(
        &self,
        msg: Req,
    ) -> impl Stream<Item = Result<Rsp, Self::Error>> + Send;

    /// Send a message to steam without waiting for a response
    fn send<Msg: SendableMessage>(
        &self,
        msg: Msg,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
