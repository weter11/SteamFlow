use std::env::args;
use std::error::Error;
use std::io::Cursor;
use steam_vent::auth::{
    ClientInfo, ConsoleAuthConfirmationHandler, DeviceConfirmationHandler, FileGuardDataStore,
};
use steam_vent::{Connection, ConnectionTrait, GenericGCHandshake, ServerList};
use steam_vent_proto::RpcMessage;
use steam_vent_proto::tf2::base_gcmessages::CSOEconItem;
use steam_vent_proto::tf2::gcsdk_gcmessages::{
    CMsgSOCacheSubscribed, CMsgSOCacheSubscriptionRefresh,
};

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

    let (game_coordinator, _welcome) = connection
        .game_coordinator(&GenericGCHandshake::new(440))
        .await?;

    println!("requesting backpack");

    let cache_future = game_coordinator.one::<CMsgSOCacheSubscribed>();
    game_coordinator
        .send(CMsgSOCacheSubscriptionRefresh {
            owner: Some(connection.steam_id().into()),
            ..Default::default()
        })
        .await?;
    let cache = cache_future.await?;
    for object in cache.objects.iter() {
        if object.type_id() == 1 {
            for item_data in object.object_data.iter() {
                if let Ok(item) = CSOEconItem::parse(&mut Cursor::new(item_data)) {
                    // this indexes into the item schema
                    println!("{}", item.def_index());
                }
            }
        }
    }

    Ok(())
}
