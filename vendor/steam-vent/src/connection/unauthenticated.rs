use super::Result;
use super::raw::RawConnection;
use crate::auth::{
    AuthConfirmationHandler, ClientInfo, GuardDataStore, RefreshToken, RefreshTokenError,
    begin_password_auth, perform_confirmation,
};
use crate::connection::ConnectionImpl;
use crate::message::{ServiceMethodMessage, ServiceMethodResponseMessage};
use crate::net::RawNetMessage;
use crate::session::{anonymous, login};
use crate::{Connection, ConnectionError, EResult, LoginError, NetworkError, ServerList};
use bytes::BytesMut;
use futures_util::Stream;
use futures_util::{FutureExt, Sink};
use std::future::Future;
use steam_vent_core::{
    NetMessageHeader, ReadonlyConnection, ReceivableMessage, ServiceMethodRequest,
    ServiceNotification,
};
use steam_vent_proto_steam::enums_clientserver::EMsg;
use steamid_ng::{AccountType, SteamID};
use tokio::time::timeout;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tracing::{debug, error};

/// A Connection that hasn't been authentication yet
pub struct UnAuthenticatedConnection(RawConnection);

impl UnAuthenticatedConnection {
    /// Create a connection from a sender, receiver pair.
    ///
    /// This allows customizing the transport used by the connection. For example to customize the
    /// TLS configuration, use an existing websocket client or use a proxy.
    pub async fn from_sender_receiver<
        Sender: Sink<BytesMut, Error = NetworkError> + Send + 'static,
        Receiver: Stream<Item = Result<BytesMut>> + Send + 'static,
    >(
        sender: Sender,
        receiver: Receiver,
    ) -> Result<Self, ConnectionError> {
        Ok(UnAuthenticatedConnection(
            RawConnection::from_sender_receiver(sender, receiver).await?,
        ))
    }

    /// Connect to a server from the server list using the default websocket transport
    pub async fn connect(server_list: &ServerList) -> Result<Self, ConnectionError> {
        Ok(UnAuthenticatedConnection(
            RawConnection::connect(server_list).await?,
        ))
    }

    /// Start an anonymous client session with this connection
    pub async fn anonymous(self) -> Result<Connection, ConnectionError> {
        let mut raw = self.0;
        let session = anonymous(&raw, AccountType::AnonUser).await?;
        raw.session = session.session;
        raw.setup_heartbeat(session.auth.steam_id);
        let connection = Connection::new(raw, session.auth);

        Ok(connection)
    }

    /// Start an anonymous server session with this connection
    pub async fn anonymous_server(self) -> Result<Connection, ConnectionError> {
        let mut raw = self.0;
        let session = anonymous(&raw, AccountType::AnonGameServer).await?;
        raw.session = session.session;
        raw.setup_heartbeat(session.auth.steam_id);
        let connection = Connection::new(raw, session.auth);

        Ok(connection)
    }

    /// Start a client session with this connection
    pub async fn login<H: AuthConfirmationHandler, G: GuardDataStore>(
        self,
        account: &str,
        password: &str,
        mut guard_data_store: G,
        mut confirmation_handler: H,
        client_info: &ClientInfo,
    ) -> Result<Connection, ConnectionError> {
        let mut raw = self.0;
        let guard_data = guard_data_store.load(account).await.unwrap_or_else(|e| {
            error!(error = ?e, "failed to retrieve guard data");
            None
        });
        if guard_data.is_some() {
            debug!(account, "found stored guard data");
        }
        let begin = begin_password_auth(
            &mut raw,
            account,
            password,
            guard_data.as_deref(),
            client_info,
        )
        .await?;
        let steam_id = SteamID::from_steam64(begin.steam_id()).map_err(LoginError::from)?;

        let allowed_confirmations = begin.allowed_confirmations();

        let tokens = loop {
            match perform_confirmation(
                &raw,
                &mut confirmation_handler,
                &begin,
                &allowed_confirmations,
            )
            .await
            {
                None
                | Some(Err(ConnectionError::Network(NetworkError::ApiError(
                    EResult::TwoFactorCodeMismatch,
                )))) => continue,
                Some(result) => break result?,
            }
        };

        if let Some(guard_data) = tokens.new_guard_data
            && let Err(e) = guard_data_store.store(account, guard_data).await
        {
            error!(error = ?e, "failed to store guard data");
        } else {
            debug!("no guard data received");
        }

        let session = login(
            &mut raw,
            Some(account),
            steam_id,
            tokens.refresh_token.as_ref(),
        )
        .await?;
        raw.session = session.session;
        raw.setup_heartbeat(session.auth.steam_id);
        let connection = Connection::new(raw, session.auth);

        Ok(connection)
    }

    /// Start a client session with this connection using access token.
    pub async fn login_with_refresh_token(
        self,
        token: &RefreshToken,
    ) -> Result<Connection, ConnectionError> {
        let mut raw = self.0;

        if token.expired() {
            return Err(RefreshTokenError::Expired.into());
        }

        let session = login(&mut raw, None, token.subject, token.token()).await?;
        raw.session = session.session;
        raw.setup_heartbeat(session.auth.steam_id);
        Ok(Connection::new(raw, session.auth))
    }
}

/// Listen for messages before starting authentication
impl ReadonlyConnection for UnAuthenticatedConnection {
    type Error = NetworkError;

    fn on_notification<T: ServiceNotification>(&self) -> impl Stream<Item = Result<T>> + 'static {
        BroadcastStream::new(self.0.filter.on_notification(T::NOTIFICATION_NAME))
            .filter_map(|res| res.ok())
            .map(|raw| raw.into_notification())
    }

    fn one_with_header<T: ReceivableMessage + 'static>(
        &self,
    ) -> impl Future<Output = Result<(NetMessageHeader, T)>> + 'static {
        // async block instead of async fn, so we don't have to tie the lifetime of the returned future
        // to the lifetime of &self
        let fut = self.0.filter.one_kind(T::KIND);
        async move {
            let raw = fut.await.map_err(|_| NetworkError::EOF)?;
            raw.into_header_and_message()
        }
    }

    fn one<T: ReceivableMessage + 'static>(&self) -> impl Future<Output = Result<T>> + 'static {
        self.one_with_header::<T>()
            .map(|res| res.map(|(_, msg)| msg))
    }

    fn on_with_header<T: ReceivableMessage + 'static>(
        &self,
    ) -> impl Stream<Item = Result<(NetMessageHeader, T)>> + 'static {
        BroadcastStream::new(self.0.filter.on_kind(T::KIND)).map(|raw| {
            let raw = raw.map_err(|_| NetworkError::EOF)?;
            raw.into_header_and_message()
        })
    }

    fn on<T: ReceivableMessage + 'static>(&self) -> impl Stream<Item = Result<T>> + 'static {
        self.on_with_header::<T>()
            .map(|res| res.map(|(_, msg)| msg))
    }
}

pub(crate) async fn service_method_un_authenticated<Msg: ServiceMethodRequest>(
    connection: &RawConnection,
    msg: Msg,
) -> Result<Msg::Response> {
    let header = connection.generate_header(true);
    let recv = connection.filter.on_job_id(header.source_job_id);
    let msg = RawNetMessage::from_message_with_kind(
        header,
        ServiceMethodMessage(msg),
        EMsg::k_EMsgServiceMethodCallFromClientNonAuthed,
        true,
    )?;
    connection.sender.send_raw(msg).await?;
    let message = timeout(connection.timeout, recv)
        .await
        .map_err(|_| NetworkError::Timeout)?
        .map_err(|_| NetworkError::Timeout)?
        .into_message::<ServiceMethodResponseMessage>()?;
    message.into_response::<Msg>()
}
