mod client;
mod confirmation;
mod guard_data;

use crate::connection::raw::RawConnection;
use crate::connection::unauthenticated::service_method_un_authenticated;
use crate::message::MalformedBody;
use crate::net::NetworkError;
use crate::session::{ConnectionError, LoginError};
use base64::Engine;
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
pub use client::*;
pub use confirmation::*;
use futures_util::future::{Either, select};
pub use guard_data::*;
use num_bigint_dig::BigUint;
use num_traits::Num;
use rsa::RsaPublicKey;
use serde::Deserialize;
use std::io::{Error as IoError, ErrorKind};
use std::pin::pin;
use std::time::{Duration, SystemTime};
use steam_vent_crypto::encrypt_with_key_pkcs1;
use steam_vent_proto_common::protobuf::{EnumOrUnknown, MessageField};
use steam_vent_proto_steam::enums::ESessionPersistence;
use steam_vent_proto_steam::enums_clientserver::EMsg;
use steam_vent_proto_steam::steammessages_auth_steamclient::CAuthentication_GetPasswordRSAPublicKey_Request;
use steam_vent_proto_steam::steammessages_auth_steamclient::{
    CAuthentication_AllowedConfirmation, CAuthentication_BeginAuthSessionViaCredentials_Request,
    CAuthentication_BeginAuthSessionViaCredentials_Response, CAuthentication_DeviceDetails,
    CAuthentication_PollAuthSessionStatus_Request, CAuthentication_PollAuthSessionStatus_Response,
    CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request, EAuthSessionGuardType,
};
use steamid_ng::SteamID;
use thiserror::Error;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, instrument};

pub(crate) async fn begin_password_auth(
    connection: &mut RawConnection,
    account: &str,
    password: &str,
    guard_data: Option<&str>,
    client_info: &ClientInfo,
) -> Result<StartedAuth, ConnectionError> {
    let (pub_key, timestamp) = get_password_rsa(connection, account.into()).await?;
    let encrypted_password =
        encrypt_with_key_pkcs1(&pub_key, password.as_bytes()).map_err(LoginError::InvalidPubKey)?;
    let encoded_password = BASE64_STANDARD.encode(encrypted_password);
    info!(account, "starting credentials login");
    let req = CAuthentication_BeginAuthSessionViaCredentials_Request {
        account_name: Some(account.into()),
        encrypted_password: Some(encoded_password),
        encryption_timestamp: Some(timestamp),
        persistence: Some(EnumOrUnknown::new(
            ESessionPersistence::k_ESessionPersistence_Persistent,
        )),

        // todo: platform types
        website_id: Some("Client".into()),
        device_details: MessageField::some(CAuthentication_DeviceDetails {
            device_friendly_name: Some(client_info.name.clone()),
            platform_type: Some(EnumOrUnknown::new(client_info.platform_type)),
            os_type: Some(client_info.os.into()),
            machine_id: Some(client_info.machine_id.encode()),
            ..CAuthentication_DeviceDetails::default()
        }),
        guard_data: guard_data.map(String::from),
        ..CAuthentication_BeginAuthSessionViaCredentials_Request::default()
    };
    let res = service_method_un_authenticated(connection, req).await?;
    Ok(StartedAuth::Credentials(res))
}

pub(crate) enum StartedAuth {
    Credentials(CAuthentication_BeginAuthSessionViaCredentials_Response),
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfirmationError {
    #[error(transparent)]
    Network(#[from] NetworkError),
    #[error("Aborted")]
    Aborted,
}

impl StartedAuth {
    fn raw_confirmations(&self) -> &[CAuthentication_AllowedConfirmation] {
        match self {
            StartedAuth::Credentials(res) => res.allowed_confirmations.as_slice(),
        }
    }

    pub fn allowed_confirmations(&self) -> Vec<ConfirmationMethod> {
        self.raw_confirmations()
            .iter()
            .cloned()
            .map(ConfirmationMethod::from)
            .collect()
    }

    #[allow(dead_code)]
    pub fn action_required(&self) -> bool {
        self.raw_confirmations().iter().any(|method| {
            method.confirmation_type() != EAuthSessionGuardType::k_EAuthSessionGuardType_None
        })
    }

    fn client_id(&self) -> u64 {
        match self {
            StartedAuth::Credentials(res) => res.client_id(),
        }
    }

    pub fn steam_id(&self) -> u64 {
        match self {
            StartedAuth::Credentials(res) => res.steamid(),
        }
    }

    fn request_id(&self) -> Vec<u8> {
        match self {
            StartedAuth::Credentials(res) => res.request_id().into(),
        }
    }

    fn interval(&self) -> f32 {
        match self {
            StartedAuth::Credentials(res) => res.interval(),
        }
    }

    pub fn poll(&self) -> PendingAuth {
        PendingAuth {
            interval: self.interval(),
            client_id: self.client_id(),
            request_id: self.request_id(),
        }
    }

    pub async fn submit_confirmation(
        &self,
        connection: &RawConnection,
        confirmation: ConfirmationAction,
    ) -> Result<(), ConfirmationError> {
        match confirmation {
            ConfirmationAction::GuardToken(token, ty) => {
                let req = CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request {
                    client_id: Some(self.client_id()),
                    steamid: Some(self.steam_id()),
                    code: Some(token.0),
                    code_type: Some(EnumOrUnknown::new(ty.into())),
                    ..CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request::default()
                };
                let _ = service_method_un_authenticated(connection, req).await?;
            }
            ConfirmationAction::None => {}
            ConfirmationAction::Abort => return Err(ConfirmationError::Aborted),
        };
        Ok(())
    }
}

/// The token to send to steam to confirm the login
#[derive(Debug)]
pub struct SteamGuardToken(pub String);

impl SteamGuardToken {
    /// Construct a guard token from a raw one-time code (an email or device
    /// code).
    ///
    /// This lets a custom confirmation handler construct tokens without access
    /// to the tuple field.
    pub fn new(code: impl Into<String>) -> Self {
        Self(code.into())
    }
}

pub(crate) struct PendingAuth {
    client_id: u64,
    request_id: Vec<u8>,
    interval: f32,
}

impl PendingAuth {
    pub(crate) async fn wait_for_tokens(
        self,
        connection: &RawConnection,
    ) -> Result<Tokens, NetworkError> {
        loop {
            let mut response = poll_until_info(
                connection,
                self.client_id,
                &self.request_id,
                Duration::from_secs_f32(self.interval),
            )
            .await?;
            if response.has_access_token() {
                return Ok(Tokens {
                    access_token: Token(response.take_access_token()),
                    refresh_token: Token(response.take_refresh_token()),
                    new_guard_data: response.new_guard_data,
                });
            }
            // Pace this loop at the poll interval. `poll_until_info` returns as
            // soon as *any* status field is populated — including
            // `had_remote_interaction`, which is sticky once the user has acted
            // (e.g. submitted a Steam Guard code). When the session is not yet
            // approved (a pending confirmation, or a rejected guard code), the
            // access token never arrives, so without this sleep the loop would
            // re-issue `PollAuthSessionStatus` at the network round-trip rate
            // rather than the interval Steam asks for, risking auth
            // rate-limiting. A successful login returns the token on the first
            // poll and never reaches here.
            sleep(Duration::from_secs_f32(self.interval)).await;
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Token(String);

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Tokens {
    #[allow(dead_code)]
    pub access_token: Token,
    pub refresh_token: Token,
    pub new_guard_data: Option<String>,
}

async fn poll_until_info(
    connection: &RawConnection,
    client_id: u64,
    request_id: &[u8],
    interval: Duration,
) -> Result<CAuthentication_PollAuthSessionStatus_Response, NetworkError> {
    loop {
        let req = CAuthentication_PollAuthSessionStatus_Request {
            client_id: Some(client_id),
            request_id: Some(request_id.into()),
            ..CAuthentication_PollAuthSessionStatus_Request::default()
        };

        let resp = service_method_un_authenticated(connection, req).await?;
        let has_data = resp.has_access_token()
            || resp.has_account_name()
            || resp.has_agreement_session_url()
            || resp.has_had_remote_interaction()
            || resp.has_new_challenge_url()
            || resp.has_new_client_id()
            || resp.has_new_guard_data()
            || resp.has_refresh_token();

        if has_data {
            return Ok(resp);
        }

        sleep(interval).await;
    }
}

#[instrument(skip(connection))]
async fn get_password_rsa(
    connection: &mut RawConnection,
    account: String,
) -> Result<(RsaPublicKey, u64), NetworkError> {
    debug!("getting password rsa");
    let req = CAuthentication_GetPasswordRSAPublicKey_Request {
        account_name: Some(account),
        ..CAuthentication_GetPasswordRSAPublicKey_Request::default()
    };
    let response = service_method_un_authenticated(connection, req).await?;

    let key_mod =
        BigUint::from_str_radix(response.publickey_mod.as_deref().unwrap_or_default(), 16)
            .map_err(|e| {
                MalformedBody::new(
                    EMsg::k_EMsgServiceMethodCallFromClient,
                    IoError::new(ErrorKind::InvalidData, e),
                )
            })?;
    let key_exp =
        BigUint::from_str_radix(response.publickey_exp.as_deref().unwrap_or_default(), 16)
            .map_err(|e| {
                MalformedBody::new(
                    EMsg::k_EMsgServiceMethodCallFromClient,
                    IoError::new(ErrorKind::InvalidData, e),
                )
            })?;
    let key = RsaPublicKey::new(key_mod, key_exp).map_err(|e| {
        MalformedBody::new(
            EMsg::k_EMsgServiceMethodCallFromClient,
            IoError::new(ErrorKind::InvalidData, e),
        )
    })?;
    Ok((key, response.timestamp.unwrap_or_default()))
}

/// How long to wait for tokens after submitting a guard code before treating
/// the attempt as rejected and re-prompting.
///
/// A correct code makes the next poll return tokens (well within one poll
/// interval); a wrong code is accepted by the submit RPC but never yields
/// tokens, so it manifests only as the absence of a response. Bounding the wait
/// turns that silence into a retry signal, while staying generous enough that a
/// correct code on a slow link is never misread as a rejection.
const RETRY_POLL_TIMEOUT_SECS: u64 = 30;

pub(crate) async fn perform_confirmation<C: AuthConfirmationHandler>(
    raw: &RawConnection,
    confirmation_handler: &mut C,
    begin: &StartedAuth,
    allowed_confirmations: &[ConfirmationMethod],
) -> Option<Result<Tokens, ConnectionError>> {
    let pending = begin.poll();

    let action = Box::into_pin(confirmation_handler.handle_confirmation(allowed_confirmations));
    let tokens = pin!(pending.wait_for_tokens(raw));

    match select(action, tokens).await {
        Either::Left((confirmation_action, tokens_fut)) => {
            let Some(confirmation_action) = confirmation_action else {
                if begin.action_required() {
                    return Some(Err(ConnectionError::UnsupportedConfirmationAction(
                        allowed_confirmations.into(),
                    )));
                }
                return Some(tokens_fut.await.map_err(ConnectionError::from));
            };
            let retry_on_timeout =
                matches!(confirmation_action, ConfirmationAction::GuardToken(..));
            if let Err(e) = begin.submit_confirmation(raw, confirmation_action).await {
                return Some(Err(e.into()));
            };
            if retry_on_timeout {
                match timeout(Duration::from_secs(RETRY_POLL_TIMEOUT_SECS), tokens_fut).await {
                    Ok(tokens) => Some(tokens.map_err(ConnectionError::from)),
                    Err(_) => None,
                }
            } else {
                Some(tokens_fut.await.map_err(ConnectionError::from))
            }
        }
        Either::Right((tokens, _)) => Some(tokens.map_err(ConnectionError::from)),
    }
}

/// A token created on login that can be used to re-authenticate
///
/// After login it can be retrieved from [`Connection::refresh_token`] and used for authentication with [`Connection::login_with_refresh_token`].
///
/// [`Connection::refresh_token`]: `crate::Connection::refresh_token`
/// [`Connection::login_with_refresh_token`]: `crate::Connection::login_with_refresh_token`
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct RefreshToken {
    raw: String,
    pub subject: SteamID,
    pub expiration: SystemTime,
}

impl RefreshToken {
    /// Validate the access token and extract the subject and expiration date
    pub fn new(raw: String) -> Result<RefreshToken, RefreshTokenError> {
        /// JWT access token payload descriptor.
        #[derive(Deserialize)]
        pub struct RawAccessToken<'a> {
            sub: &'a str,
            iss: &'a str,
            exp: u64,
        }

        let base64 = raw
            .split('.')
            .nth(1)
            .ok_or(RefreshTokenError::Malformed("token not formatted as JWT"))?;
        let json = BASE64_URL_SAFE_NO_PAD
            .decode(base64)
            .map_err(|_| RefreshTokenError::Malformed("token contains invalid base64 payload"))?;

        let token = serde_json::from_slice::<RawAccessToken>(&json)
            .map_err(|_| RefreshTokenError::Malformed("token contains invalid json payload"))?;

        if token.iss != "steam" {
            return Err(RefreshTokenError::InvalidIssuer);
        }

        // TODO: Consider adding `AccessToken.exp` check (expiration UNIX timestamp in seconds).

        let subject = SteamID::from_steam64(
            token
                .sub
                .parse()
                .map_err(|_| RefreshTokenError::InvalidSubject)?,
        )
        .map_err(|_| RefreshTokenError::InvalidSubject)?;

        Ok(RefreshToken {
            raw,
            subject,
            expiration: SystemTime::UNIX_EPOCH + Duration::from_secs(token.exp),
        })
    }

    /// Get the raw token to use for authentiaction or storage
    pub fn token(&self) -> &str {
        &self.raw
    }

    /// How much longer is this token valid for or `None` is the token is already expired
    pub fn remaining_lifetime(&self) -> Option<Duration> {
        self.expiration.duration_since(SystemTime::now()).ok()
    }

    /// Check if the token is expired
    pub fn expired(&self) -> bool {
        self.remaining_lifetime().is_none()
    }
}

impl PartialEq for RefreshToken {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

#[derive(Debug, Error)]
pub enum RefreshTokenError {
    #[error("malformed token supplied: {0}")]
    Malformed(&'static str),
    #[error("invalid issuer")]
    InvalidIssuer,
    #[error("invalid subject steam id")]
    InvalidSubject,
    #[error("refresh token is expired")]
    Expired,
}
