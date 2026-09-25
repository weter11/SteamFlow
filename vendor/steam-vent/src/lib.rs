pub mod auth;
pub mod connection;
mod eresult;
mod game_coordinator;
pub mod message;
mod net;
mod serverlist;
mod session;
mod transport;

pub use connection::Connection;
pub use eresult::EResult;
pub use game_coordinator::{GameCoordinator, handshake::GenericGCHandshake};
pub use net::{NetworkError, RawNetMessage};
pub use serverlist::{DiscoverOptions, ServerDiscoveryError, ServerList};
pub use session::{ConnectionError, LoginError};
pub use steam_vent_core::{
    ConnectionTrait, NetMessageHeader, ReadonlyConnection, ReceivableMessage, SendableMessage,
    ServiceMethodRequest,
};
