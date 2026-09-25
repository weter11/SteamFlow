use std::env::args;
use std::error::Error;
use steam_vent::auth::{
    ClientInfo, ConsoleAuthConfirmationHandler, DeviceConfirmationHandler, FileGuardDataStore,
    RefreshToken,
};
use steam_vent::{Connection, ConnectionTrait, ServerList};
use steam_vent_proto::steammessages_player_steamclient::CPlayer_GetOwnedGames_Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let mut args = args().skip(1);
    let account = args.next().expect("no account");
    let password = args.next().expect("no password");
    let refresh_token = args.next();

    let server_list = ServerList::discover().await?;
    let connection = match refresh_token {
        Some(token) => {
            let token = RefreshToken::new(token)?;
            match Connection::login_with_refresh_token(&server_list, &token).await {
                Ok(connection) => {
                    if connection.refresh_token() != &token {
                        println!("new token for future use: {}", token.token());
                    }

                    Some(connection)
                }
                Err(error) => {
                    eprintln!("connection using access token failed: {error}");
                    None // Fallback to password
                }
            }
        }
        None => None,
    };

    let connection = if let Some(connection) = connection {
        connection
    } else {
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

        println!(
            "refresh token for future use: {}",
            connection.refresh_token().token()
        );

        connection
    };

    println!("requesting games");

    let req = CPlayer_GetOwnedGames_Request {
        steamid: Some(connection.steam_id().into()),
        include_appinfo: Some(true),
        include_played_free_games: Some(true),
        ..CPlayer_GetOwnedGames_Request::default()
    };
    let games = connection.service_method(req).await?;
    println!(
        "{} owns {} games",
        connection.steam_id().steam3(),
        games.game_count()
    );
    for game in games.games {
        println!(
            "{}: {} {}",
            game.appid(),
            game.name(),
            game.playtime_forever()
        );
    }

    Ok(())
}
