use anyhow::{anyhow, Result};
use steamflow::config::{load_library_cache, load_session};
use steamflow::library::{build_game_library, scan_installed_app_info};
use steamflow::steam_client::SteamClient;
use steamflow::ui::SteamLauncher;
use tokio::runtime::Runtime;

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let runtime = Runtime::new()?;
    runtime.block_on(steamflow::config::ensure_config_dirs())?;
    let mut client = SteamClient::new()?;

    let library = runtime.block_on(async {
        let saved = load_session().await.unwrap_or_default();
        let cached_owned = load_library_cache().await.unwrap_or_default();
        let mut authenticated = false;

        if saved.refresh_token.is_some() && saved.account_name.is_some() {
            if client.restore_session().await.is_ok() {
                authenticated = true;
                tracing::info!("Restored Steam session from refresh token");
            } else {
                tracing::warn!(
                    "Stored refresh token failed; UI re-authentication will be required"
                );
            }
        }

        let owned = if authenticated {
            client
                .fetch_owned_games()
                .await
                .unwrap_or_else(|_| cached_owned)
        } else {
            cached_owned
        };

        let installed = scan_installed_app_info().await.unwrap_or_default();
        build_game_library(owned, installed)
    });

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([850.0, 680.0])
            .with_min_inner_size([400.0, 300.0]),
        ..Default::default()
    };
    eframe::run_native(
        "SteamFlow",
        options,
        Box::new(move |_cc| Ok(Box::new(SteamLauncher::new(runtime, client, library.games)))),
    )
    .map_err(|err| anyhow!("failed to start SteamFlow UI: {err}"))?;

    Ok(())
}
