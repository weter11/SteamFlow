use std::{error::Error, sync::Arc};
use steam_cdn::CDNClient;
use steam_vent::{Connection, ServerList};
use tokio::fs::{self, OpenOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server_list = ServerList::discover().await?;
    let connection = Arc::new(Connection::anonymous(&server_list).await?);
    let cdn = CDNClient::discover(connection).await?;

    let app_id = 730;
    let depot_id = 2347771;
    let manifest_id = 734640093393352243;

    let depot_key = cdn.get_depot_decryption_key(app_id, depot_id).await?;
    let request_code = cdn
        .get_manifest_request_code(app_id, depot_id, manifest_id)
        .await?;
    let manifest = cdn
        .get_manifest(depot_id, manifest_id, Some(request_code), depot_key)
        .await?;

    for manifest_file in manifest.files() {
        if manifest_file.filename().ends_with("server.dll") {
            fs::create_dir_all(manifest_file.path()).await?;

            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .write(true)
                .open(manifest_file.full_path())
                .await?;
            manifest_file
                .download(depot_key.unwrap(), &mut file, None)
                .await?;
        }
    }
    Ok(())
}
