# Steam-Vent

### Interact with the Steam network via rust

Allows communication with the steam servers using the same protocol as the
regular steam client.

## State

Most forms of authenticating to steam are implemented, and you can send requests
for using protobufs that are either packaged by the project or that you bring
yourself.

While the api isn't fully stable yet, it's unlikely to receive major changes at
this point.

- [x] Anonymous sessions
- [x] Password Authentication
- [ ] QR Authentication
- [x] Steam guard (device or email) confirmation
- [x] Device notification confirmation
- [x] Saved machine token confirmation
- [x] Sending and receiving raw messages
- [x] Making RPC calls over the connection
- [x] Communicating with the game coordinator
- [x] Allow using messages from protobufs not included in the project

## Non-goals

This crate intentionally does not include any high level apis, instead it's
encouraged to implement high level apis in separate crates that wrap a
`Connection`.

See [steam-vent-chat](https://codeberg.org/steam-vent/chat) for an example
high-level library.

## Documentation

The main documentation can be found at
[steam-vent.grebedoc.dev](https://steam-vent.grebedoc.dev/), additional api
documentation can be at
[docs.rs/steam-vent](https://docs.rs/steam-vent/latest/steam_vent/).

## Usage

Note that this project is still in early development and apis might see large
changes.

```rust
use std::error::Error;
use steam_vent::connection::Connection;
use steam_vent::serverlist::ServerList;
use steam_vent_proto::steammessages_gameservers_steamclient::CGameServers_GetServerList_Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server_list = ServerList::discover().await?;
    let mut connection = Connection::anonymous(server_list).await?;

    let mut req = CGameServers_GetServerList_Request::new();
    req.set_limit(16);
    req.set_filter(r"\appid\440".into());
    let some_tf2_servers = connection.service_method(req).await?;
    for server in some_tf2_servers.servers {
        println!(
            "{}({}) playing {}",
            String::from_utf8_lossy(server.name()),
            server.addr(),
            server.map()
        );
    }

    Ok(())
}
```

## Protobuf packages

Game-specific probufs are packaged for the following games:

- [tf2](https://codeberg.org/steam-vent/proto-tf2)
- [csgo](https://codeberg.org/steam-vent/proto-csgo)
- [dota2](https://codeberg.org/steam-vent/proto-dota2)
- [deadlock](https://codeberg.org/steam-vent/proto-deadlock)

They can be used by either enabling the features in `steam-vent-proto` or by
depending on the protobuf package directly.

## Contribution guidelines

LLM driven contributions are not welcome in this project.

## Credit

This is in large parts inspired by and based of
[@DoctorMcKay's](https://github.com/DoctorMcKay) work on
[SteamUser](https://github.com/DoctorMcKay/node-steam-user/), massive credits go
to all who worked on that.
