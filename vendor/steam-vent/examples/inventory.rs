use protobuf::Message as _;
use std::collections::BTreeMap;
use std::env::args;
use std::error::Error;
use steam_vent::auth::{
    AuthConfirmationHandler, ClientInfo, ConsoleAuthConfirmationHandler, DeviceConfirmationHandler,
    FileGuardDataStore,
};
use steam_vent::proto::csgo::{base_gcmessages::CSOEconItem, gcsdk_gcmessages::CMsgClientHello};
use steam_vent::{Connection, ServerList};
use steam_vent_proto::csgo::GCHandshake;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let mut args = args().skip(1);
    let account = args.next().expect("no account");
    let password = args.next().expect("no password");

    let server_list = ServerList::discover().await?;
    let connection = Connection::login(
        &server_list,
        &account,
        &password,
        FileGuardDataStore::user_cache(),
        (
            ConsoleAuthConfirmationHandler::default(),
            DeviceConfirmationHandler,
        ),
        &ClientInfo::default(),
    )
    .await?;

    println!("starting game coordinator");

    let (_game_coordinator, welcome) = connection
        .game_coordinator(&GCHandshake {
            hello: CMsgClientHello {
                version: Some(2_000_651),
                client_session_need: Some(0),
                client_launcher: Some(0),
                steam_launcher: Some(0),
                ..Default::default()
            },
        })
        .await?;

    let mut inventory = BTreeMap::new();

    for soc in &welcome.outofdate_subscribed_caches {
        for kind in &soc.objects {
            if let Some(1) = kind.type_id {
                for data in &kind.object_data {
                    let item = CSOEconItem::parse_from_bytes(data)?;
                    inventory.insert(item.id(), item);
                }
            }
        }
    }

    println!("inventory = {inventory:#?}");

    Ok(())
}
