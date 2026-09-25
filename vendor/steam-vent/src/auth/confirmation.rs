use crate::auth::SteamGuardToken;
use another_steam_totp::generate_auth_code;
use futures_util::FutureExt;
use futures_util::future::{Either, select};
use futures_util::stream::{FuturesUnordered, StreamExt};
use std::future::ready;
use steam_vent_proto_steam::steammessages_auth_steamclient::{
    CAuthentication_AllowedConfirmation, EAuthSessionGuardType,
};
use tokio::io::AsyncBufReadExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, Stdin, Stdout, stdin, stdout};
use tokio_stream::Stream;

/// A method that can be used to confirm a login
#[derive(Debug, Clone)]
pub struct ConfirmationMethod(CAuthentication_AllowedConfirmation);

impl From<CAuthentication_AllowedConfirmation> for ConfirmationMethod {
    fn from(value: CAuthentication_AllowedConfirmation) -> Self {
        Self(value)
    }
}

impl ConfirmationMethod {
    /// Get the human-readable confirmation type
    pub fn confirmation_type(&self) -> &'static str {
        match self.0.confirmation_type() {
            EAuthSessionGuardType::k_EAuthSessionGuardType_Unknown => "unknown",
            EAuthSessionGuardType::k_EAuthSessionGuardType_None => "none",
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode => "email",
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => "device code",
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => {
                "device confirmation"
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation => {
                "email confirmation"
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_MachineToken => "machine token",
            EAuthSessionGuardType::k_EAuthSessionGuardType_LegacyMachineAuth => "machine auth",
        }
    }

    /// Get the server-provided message for the confirmation
    pub fn confirmation_details(&self) -> &str {
        self.0.associated_message()
    }

    /// Is any action required to confirm the login
    pub fn action_required(&self) -> bool {
        self.0.confirmation_type() != EAuthSessionGuardType::k_EAuthSessionGuardType_None
    }

    /// Get the class of the confirmation
    pub fn class(&self) -> ConfirmationMethodClass {
        match self.0.confirmation_type() {
            EAuthSessionGuardType::k_EAuthSessionGuardType_Unknown => ConfirmationMethodClass::None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_None => ConfirmationMethodClass::None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode => {
                ConfirmationMethodClass::Code
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => {
                ConfirmationMethodClass::Code
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => {
                ConfirmationMethodClass::Confirmation
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation => {
                ConfirmationMethodClass::Confirmation
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_MachineToken => {
                ConfirmationMethodClass::Stored
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_LegacyMachineAuth => {
                ConfirmationMethodClass::Stored
            }
        }
    }

    /// Get the token type required for the confirmation, if the confirmation asks for a code
    pub fn token_type(&self) -> Option<GuardTokenType> {
        match self.0.confirmation_type() {
            EAuthSessionGuardType::k_EAuthSessionGuardType_Unknown => None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_None => None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode => Some(GuardTokenType::Email),
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => {
                Some(GuardTokenType::Device)
            }
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation => None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_MachineToken => None,
            EAuthSessionGuardType::k_EAuthSessionGuardType_LegacyMachineAuth => None,
        }
    }
}

/// The class of confirmation method
#[derive(Eq, PartialEq, Debug, Clone)]
pub enum ConfirmationMethodClass {
    /// Provide a totp token
    Code,
    /// Confirm the login out-of-band
    Confirmation,
    /// Provide stored guard data
    Stored,
    /// No action required
    None,
}

/// The action to perform to confirm the login
#[non_exhaustive]
#[derive(Debug)]
pub enum ConfirmationAction {
    /// A totp token to send to the server
    GuardToken(SteamGuardToken, GuardTokenType),
    /// No action required
    None,
    /// Login has been canceled by the user
    Abort,
}

/// The type of guard token
#[derive(Debug)]
pub enum GuardTokenType {
    Email,
    Device,
}

impl From<GuardTokenType> for EAuthSessionGuardType {
    fn from(value: GuardTokenType) -> Self {
        match value {
            GuardTokenType::Device => EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode,
            GuardTokenType::Email => EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode,
        }
    }
}

/// A trait for handling login confirmations
///
/// The library comes with handlers for:
///
/// - Asking for a code from the terminal: [`ConsoleAuthConfirmationHandler`].
/// - Generating a code from the pre-shared secret: [`SharedSecretAuthConfirmationHandler`].
/// - Waiting for the user to confirm the login from the mobile app: [`DeviceConfirmationHandler`].
///
/// Additionally, apps can implement the trait to integrate the confirmation flow into the app.
pub trait AuthConfirmationHandler {
    /// Perform the confirmation action given a list of allowed confirmations for the login
    ///
    /// If the confirmation handler supports any of the allowed confirmations,
    /// it returns a [`ConfirmationAction`] with the required action.
    ///
    /// If you want to allow multiple possible confirmation methods, you can use a tuple, slice, array or vec
    /// of handlers.
    ///
    /// If the confirmation handler does not support any of the allowed confirmations it returns `None`.
    /// If no confirmation handler supports the allowed confirmations the login will fail.
    fn handle_confirmation<'this>(
        &'this mut self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Box<dyn Future<Output = Option<ConfirmationAction>> + 'this>;

    /// Wrap the handler in a box
    fn boxed(self) -> Box<dyn AuthConfirmationHandler>
    where
        Self: Sized + 'static,
    {
        Box::new(self)
    }
}

impl<Handler: AuthConfirmationHandler> AuthConfirmationHandler for &mut Handler {
    fn handle_confirmation<'this>(
        &'this mut self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Box<dyn Future<Output = Option<ConfirmationAction>> + 'this> {
        (**self).handle_confirmation(allowed_confirmations)
    }
}

/// Ask the user for the totp token from the terminal
pub type ConsoleAuthConfirmationHandler = UserProvidedAuthConfirmationHandler<Stdin, Stdout>;

/// Ask the user to provide the totp token
pub struct UserProvidedAuthConfirmationHandler<Read, Write> {
    input: BufReader<Read>,
    output: Write,
}

impl Default for ConsoleAuthConfirmationHandler {
    fn default() -> Self {
        ConsoleAuthConfirmationHandler {
            input: BufReader::new(stdin()),
            output: stdout(),
        }
    }
}

impl<Read, Write> UserProvidedAuthConfirmationHandler<Read, Write>
where
    Read: AsyncRead + Unpin + Send + Sync,
    Write: AsyncWrite + Unpin + Send + Sync,
{
    /// Create a confirmation handling using the provided I/O
    ///
    /// The handler will write details about the required tokens to the output
    /// and expect the newline terminated token from the input
    pub fn new(input: Read, output: Write) -> Self {
        UserProvidedAuthConfirmationHandler {
            input: BufReader::new(input),
            output,
        }
    }
}

impl<Read, Write> AuthConfirmationHandler for UserProvidedAuthConfirmationHandler<Read, Write>
where
    Read: AsyncRead + Unpin + Send + Sync,
    Write: AsyncWrite + Unpin + Send + Sync,
{
    fn handle_confirmation<'this>(
        &'this mut self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Box<dyn Future<Output = Option<ConfirmationAction>> + 'this> {
        for method in allowed_confirmations {
            if let Some(token_type) = method.token_type() {
                let msg = format!(
                    "{}: {}",
                    method.confirmation_type(),
                    method.confirmation_details()
                );

                return Box::new(async move {
                    self.output.write_all(msg.as_bytes()).await.ok();
                    self.output.flush().await.ok();
                    let mut buff = String::with_capacity(16);
                    self.input.read_line(&mut buff).await.ok();
                    buff.truncate(buff.trim().len());
                    if buff.is_empty() {
                        Some(ConfirmationAction::Abort)
                    } else {
                        let token = SteamGuardToken(buff);
                        Some(ConfirmationAction::GuardToken(token, token_type))
                    }
                });
            }
        }
        Box::new(async { None })
    }
}

/// Generate the steam guard totp token from the shared secret
///
/// This requires no user interaction during login but requires the user to retrieve the totp secret in advance
pub struct SharedSecretAuthConfirmationHandler {
    shared_secret: String,
}

impl SharedSecretAuthConfirmationHandler {
    /// The totp shared secret encoded as base64
    ///
    /// Note that the secret as found in `totp://` urls is base32 encoded, not base64
    pub fn new(shared_secret: &str) -> Self {
        SharedSecretAuthConfirmationHandler {
            shared_secret: shared_secret.into(),
        }
    }
}

impl AuthConfirmationHandler for SharedSecretAuthConfirmationHandler {
    fn handle_confirmation<'this>(
        &'this mut self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Box<dyn Future<Output = Option<ConfirmationAction>> + 'this> {
        for method in allowed_confirmations {
            if let Some(token_type) = method.token_type() {
                return Box::new(async move {
                    let auth_code = generate_auth_code(&self.shared_secret, None)
                        .expect("Could not generate auth code given shared secret.");
                    let token = SteamGuardToken(auth_code);
                    Some(ConfirmationAction::GuardToken(token, token_type))
                });
            }
        }
        Box::new(async { None })
    }
}

/// Wait for the user to confirm the login in the mobile app
#[derive(Default)]
pub struct DeviceConfirmationHandler;

impl AuthConfirmationHandler for DeviceConfirmationHandler {
    fn handle_confirmation(
        &mut self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Box<dyn Future<Output = Option<ConfirmationAction>> + '_> {
        for method in allowed_confirmations {
            if method.class() == ConfirmationMethodClass::Confirmation {
                return Box::new(async move { Some(ConfirmationAction::None) });
            }
        }
        Box::new(async { None })
    }
}

impl<Left, Right> AuthConfirmationHandler for (Left, Right)
where
    Left: AuthConfirmationHandler + Send + Sync,
    Right: AuthConfirmationHandler + Send + Sync,
{
    fn handle_confirmation(
        &mut self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Box<dyn Future<Output = Option<ConfirmationAction>> + '_> {
        let left = Box::into_pin(self.0.handle_confirmation(allowed_confirmations));
        let right = Box::into_pin(self.1.handle_confirmation(allowed_confirmations));
        Box::new(async move {
            match select(left, right).await {
                Either::Left((left_result, right_fut)) => match left_result {
                    None | Some(ConfirmationAction::None) => right_fut.await,
                    _ => left_result,
                },
                Either::Right((right_result, left_fut)) => match right_result {
                    None | Some(ConfirmationAction::None) => left_fut.await,
                    _ => right_result,
                },
            }
        })
    }
}

impl AuthConfirmationHandler for Box<dyn AuthConfirmationHandler> {
    fn handle_confirmation<'this>(
        &'this mut self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Box<dyn Future<Output = Option<ConfirmationAction>> + 'this> {
        self.as_mut().handle_confirmation(allowed_confirmations)
    }
}

fn first_some<T, S: Stream<Item = Option<T>> + Unpin>(
    stream: S,
) -> impl Future<Output = Option<T>> {
    stream
        .filter_map(ready)
        .into_future()
        .map(|(first, _rest)| first)
}

fn iter_handler<'a, Handler: AuthConfirmationHandler + 'a, I: Iterator<Item = &'a mut Handler>>(
    iter: I,
    allowed_confirmations: &[ConfirmationMethod],
) -> FuturesUnordered<impl Future<Output = Option<ConfirmationAction>> + Unpin + use<'a, Handler, I>>
{
    iter.map(|handler: &mut Handler| {
        Box::into_pin(handler.handle_confirmation(allowed_confirmations))
    })
    .collect::<FuturesUnordered<_>>()
}

impl<Handler: AuthConfirmationHandler> AuthConfirmationHandler for &mut [Handler] {
    fn handle_confirmation<'this>(
        &'this mut self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Box<dyn Future<Output = Option<ConfirmationAction>> + 'this> {
        let stream = iter_handler(self.iter_mut(), allowed_confirmations);
        Box::new(first_some(stream))
    }
}

impl<const N: usize, Handler: AuthConfirmationHandler> AuthConfirmationHandler for [Handler; N] {
    fn handle_confirmation<'this>(
        &'this mut self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Box<dyn Future<Output = Option<ConfirmationAction>> + 'this> {
        let stream = iter_handler(self.iter_mut(), allowed_confirmations);
        Box::new(first_some(stream))
    }
}

impl<Handler: AuthConfirmationHandler> AuthConfirmationHandler for Vec<Handler> {
    fn handle_confirmation<'this>(
        &'this mut self,
        allowed_confirmations: &[ConfirmationMethod],
    ) -> Box<dyn Future<Output = Option<ConfirmationAction>> + 'this> {
        let stream = iter_handler(self.iter_mut(), allowed_confirmations);
        Box::new(first_some(stream))
    }
}
