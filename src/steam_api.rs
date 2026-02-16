use serde::Deserialize;
use anyhow::{Result, anyhow};

#[derive(Debug, Deserialize)]
struct ServerResponse {
    response: ServerResponseBody,
}

#[derive(Debug, Deserialize)]
struct ServerResponseBody {
    #[serde(default)]
    servers: Vec<ServerEntry>,
}

#[derive(Debug, Deserialize)]
struct ServerEntry {
    #[serde(rename = "type")]
    server_type: String, // We want "SteamCache" or "CDN" or "CS"
    host: String,
    #[serde(default)]
    _vhost: String,
    #[serde(default)]
    _https_support: String, // "mandatory" or "supported"
}

pub async fn fetch_content_servers(cell_id: u32) -> Result<Vec<String>> {
    tracing::info!("Fetching Content Servers for Cell ID: {}", cell_id);

    // Use Web API to get the list
    let url = format!(
        "https://api.steampowered.com/ISteamContentServer/GetServersForSteamPipe/v1/?cell_id={}&max_servers=20",
        cell_id
    );

    let client = reqwest::Client::new();
    let resp: ServerResponse = client.get(&url)
        .send()
        .await?
        .json()
        .await?;

    // Filter for valid CDN servers
    let mut server_hosts = Vec::new();
    for server in resp.response.servers {
        // Construct the host string (e.g., "valve404.steamcontent.com")
        if server.server_type == "SteamCache" || server.server_type == "CS" || server.server_type == "CDN" {
            server_hosts.push(server.host);
        }
    }

    if server_hosts.is_empty() {
        return Err(anyhow!("Web API returned no valid content servers"));
    }

    tracing::info!("Found {} servers via Web API.", server_hosts.len());
    Ok(server_hosts)
}

pub async fn fetch_servers_fallback() -> Vec<String> {
    tracing::info!("Fallback: Fetching Content Servers via Web API (Force Cell 17)...");

    // Use Cell ID 17 (Germany) to ensure high availability for EU
    let url = "https://api.steampowered.com/ISteamContentServer/GetServersForSteamPipe/v1/?cell_id=17&max_servers=20";
    let client = reqwest::Client::new();
    match client.get(url).send().await {
        Ok(resp) => match resp.json::<ServerResponse>().await {
            Ok(data) => {
                let list: Vec<String> = data
                    .response
                    .servers
                    .into_iter()
                    .map(|s| s.host)
                    .collect();
                tracing::info!("Web API returned {} servers.", list.len());
                if !list.is_empty() {
                    return list;
                }
            }
            Err(e) => tracing::error!("Failed to parse Web API JSON: {}", e),
        },
        Err(e) => tracing::error!("Web API Request failed: {}", e),
    }

    // Emergency Fallback: Hardcoded Valve CDN (US/EU)
    vec![
        "155.133.248.34".to_string(), // Frankfort
        "162.254.196.82".to_string(), // CM
        "162.254.197.72".to_string(), // CM
    ]
}
