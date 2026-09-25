use rand::prelude::*;
use rand::rng;
use reqwest::{Client, Error};
use serde::Deserialize;
use std::iter::Cycle;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::vec::IntoIter;
use thiserror::Error;
use tracing::debug;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ServerDiscoveryError {
    #[error("Failed send discovery request: {0:#}")]
    Network(reqwest::Error),
    #[error("steam returned an empty server list")]
    NoServers,
    #[error("steam returned an empty websocket server list")]
    NoWsServers,
}

impl From<reqwest::Error> for ServerDiscoveryError {
    fn from(value: Error) -> Self {
        ServerDiscoveryError::Network(value)
    }
}

/// Options to use for discovering steam api servers
#[derive(Default, Clone, Debug)]
pub struct DiscoverOptions {
    web_client: Option<Client>,
    // todo: some smart cell based routing based on
    // https://raw.githubusercontent.com/SteamDatabase/SteamTracking/6d23ebb0070998ae851278cfae5f38832f4ac28d/ClientExtracted/steam/cached/CellMap.vdf
    cell: u8,
}

impl DiscoverOptions {
    /// Set the request client to use to make requests to the web-api
    pub fn with_web_client(self, web_client: Client) -> Self {
        DiscoverOptions {
            web_client: Some(web_client),
            ..self
        }
    }

    /// Specify the steam cell ID to request servers for.
    pub fn with_cell(self, cell: u8) -> Self {
        DiscoverOptions { cell, ..self }
    }
}

/// A list of tcp and websocket servers to use for connecting
#[derive(Debug, Clone)]
pub struct ServerList {
    tcp_count: usize,
    tcp_servers: Arc<Mutex<Cycle<IntoIter<SocketAddr>>>>,
    ws_count: usize,
    ws_servers: Arc<Mutex<Cycle<IntoIter<String>>>>,
}

impl ServerList {
    /// Create a server list from the provided servers
    pub fn new(
        tcp_servers: Vec<SocketAddr>,
        ws_servers: Vec<String>,
    ) -> Result<Self, ServerDiscoveryError> {
        if tcp_servers.is_empty() {
            return Err(ServerDiscoveryError::NoServers);
        }
        if ws_servers.is_empty() {
            return Err(ServerDiscoveryError::NoWsServers);
        }

        Ok(ServerList {
            tcp_count: tcp_servers.len(),
            ws_count: ws_servers.len(),
            tcp_servers: Arc::new(Mutex::new(tcp_servers.into_iter().cycle())),
            ws_servers: Arc::new(Mutex::new(ws_servers.into_iter().cycle())),
        })
    }

    /// Discover the server list from the steam web-api with default options
    pub async fn discover() -> Result<ServerList, ServerDiscoveryError> {
        Self::discover_with(DiscoverOptions::default()).await
    }

    /// Discover the server list from the steam web-api with custom options
    pub async fn discover_with(
        options: DiscoverOptions,
    ) -> Result<ServerList, ServerDiscoveryError> {
        let client = options.web_client.unwrap_or_default();
        let cell = options.cell;

        let response: ServerListResponse = client
            .get(format!(
                "https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?cellid={cell}"
            ))
            .send()
            .await?
            .json()
            .await?;
        response.try_into()
    }

    /// Pick a server from the server list, rotating them in a round-robin way for reconnects.
    ///
    /// # Returns
    /// The selected `SocketAddr`
    pub fn pick(&self) -> SocketAddr {
        // SAFETY:
        // `lock` cannot panic as we cannot lock again within the same thread.
        // `unwrap` is safe as `discover_with` already checks for servers being present.
        let addr = self.tcp_servers.lock().unwrap().next().unwrap();
        debug!(addr = ?addr, "picked server from list");
        addr
    }

    /// Pick a WebSocket server from the server list, rotating them in a round-robin way for reconnects.
    ///
    /// # Returns
    /// A WebSocket URL to connect to, if the server list contains any servers.
    pub fn pick_ws(&self) -> String {
        // SAFETY: Same as for `pick`.
        let addr = self.ws_servers.lock().unwrap().next().unwrap();
        debug!(addr = ?addr, "picked websocket server from list");
        format!("wss://{addr}/cmsocket/")
    }

    pub fn tcp_servers(&self) -> Vec<SocketAddr> {
        let mut iter = self.tcp_servers.lock().unwrap();
        take_from_iter(&mut *iter, self.tcp_count)
    }

    pub fn ws_servers(&self) -> Vec<String> {
        let mut iter = self.ws_servers.lock().unwrap();
        take_from_iter(&mut *iter, self.ws_count)
    }
}

fn take_from_iter<T, I: Iterator<Item = T>>(iter: &mut I, count: usize) -> Vec<T> {
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        if let Some(item) = iter.next() {
            result.push(item)
        }
    }
    result
}

#[test]
fn test_save_servers() {
    use std::net::{IpAddr, Ipv4Addr};

    let socket1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234);
    let socket2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 2345);

    let ws1 = String::from("server1:1234");
    let ws2 = String::from("server2");
    let ws3 = String::from("server3");

    let list = ServerList::new(
        vec![socket1, socket2],
        vec![ws1.clone(), ws2.clone(), ws3.clone()],
    )
    .unwrap();

    assert_eq!(vec![socket1, socket2], list.tcp_servers());
    assert_eq!(
        vec![ws1.clone(), ws2.clone(), ws3.clone()],
        list.ws_servers()
    );

    let _ = list.pick();
    let _ = list.pick_ws();
    let _ = list.pick_ws();
    let _ = list.pick_ws();

    assert_eq!(vec![socket2, socket1], list.tcp_servers());
    assert_eq!(
        vec![ws1.clone(), ws2.clone(), ws3.clone()],
        list.ws_servers()
    );
}

impl TryFrom<ServerListResponse> for ServerList {
    type Error = ServerDiscoveryError;

    fn try_from(value: ServerListResponse) -> Result<Self, Self::Error> {
        let (mut servers, mut ws_servers) = (
            value.response.server_list,
            value.response.server_list_websockets,
        );
        servers.shuffle(&mut rng());
        ws_servers.shuffle(&mut rng());

        ServerList::new(servers, ws_servers)
    }
}

#[derive(Debug, Deserialize)]
struct ServerListResponse {
    response: ServerListResponseInner,
}

#[derive(Debug, Deserialize)]
struct ServerListResponseInner {
    #[serde(rename = "serverlist")]
    server_list: Vec<SocketAddr>,
    #[serde(rename = "serverlist_websockets")]
    server_list_websockets: Vec<String>,
}
