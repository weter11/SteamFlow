//! A set of core interfaces for [`steam-vent`].
//!
//! Applications will generally interface with [`steam-vent`] directly instead of this crate.
//!
//! The purpose of this crate is for high-level api wrappers to be able to work against a smaller api surface,
//! which in terms allows [`steam-vent`] to make some breaking changes without requiring new releases from all api wrappers.
//!
//! [`steam-vent`]: https://docs.rs/steam-vent/

mod connection;
mod message;
mod net;
mod service_method;

pub use crate::connection::{ConnectionTrait, ReadonlyConnection};
pub use crate::message::{DecodableMessage, EncodableMessage, ReceivableMessage, SendableMessage};
pub use crate::service_method::{ServiceMethodRequest, ServiceNotification};
pub use net::{JobId, NetMessageHeader, RawSteamId};
