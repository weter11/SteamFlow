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
    server_type: String, // We want "SteamCache" or "CDN"
    host: String,
    vhost: Option<String>,
    https_support: Option<String>, // "mandatory", "supported", or null
    weighted_load: Option<String>,
}

pub async fn fetch_content_servers(cell_id: u32) -> Result<Vec<String>> {
    tracing::info!("Fetching CDN Servers for Cell ID: {}...", cell_id);

    // Force Cell ID 17 (Germany) if input is 0, to ensure we get results.
    let effective_cell = if cell_id == 0 { 17 } else { cell_id };
    let url = format!(
        "https://api.steampowered.com/ISteamContentServer/GetServersForSteamPipe/v1/?cell_id={}&max_servers=20",
        effective_cell
    );

    let client = reqwest::Client::new();
    let resp: ServerResponse = client.get(&url)
        .send()
        .await?
        .json()
        .await?;

    let mut valid_hosts = Vec::new();

    for server in resp.response.servers {
        // CRITICAL FILTER: Only accept actual Content Servers
        if server.server_type == "SteamCache" || server.server_type == "CDN" {
            // Prefer HTTPS if available, but standard host:port is fine
            if let Some(https) = &server.https_support {
                if https == "mandatory" || https == "supported" {
                    valid_hosts.push(server.host.clone());
                    continue;
                }
            }
            // Fallback to standard host
            valid_hosts.push(server.host);
        }
    }

    if valid_hosts.is_empty() {
        return Err(anyhow!("No valid 'SteamCache' servers found in Web API response for Cell {}", effective_cell));
    }

    tracing::info!("Found {} valid CDN servers (Filtered from total).", valid_hosts.len());
    Ok(valid_hosts)
}

pub async fn fetch_servers_fallback() -> Vec<String> {
    tracing::info!("Fallback: Fetching Content Servers via Web API (Force Cell 17)...");

    match fetch_content_servers(17).await {
        Ok(list) => list,
        Err(e) => {
            tracing::error!("Fallback Web API Request failed: {}", e);
            // Emergency Fallback: Hardcoded Valve CDN (EU)
            vec![
                "155.133.248.34".to_string(), // Frankfort
                "155.133.248.35".to_string(), // Frankfort 2
            ]
        }
    }
}
