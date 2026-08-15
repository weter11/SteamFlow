//! Headless test-driving for SteamFlow (no GUI).
//!
//! Subcommands (run via `steamflow <subcommand>`):
//!   test-steam              Ensure the Windows Steam runtime is running
//!                           (installs it first if the prefix is missing).
//!   test-launch <appid>     Launch a game through the same pipeline the UI
//!                           "Play" button uses (spawn_game_process), then
//!                           keep the child attached and report its PID.
//!   test-mod <appid>        Launch a game's custom mod executable (Mods tab
//!                           "Play Mod" path, custom_exec_path) if configured.
//!   list                    List installed games with appid + install path.
//!   test-download-proton <name|appid> [--manifest-only] [--depot <id>]
//!                           Diagnose/download official Valve Proton depots via
//!                           steam-cdn. Prints each stage (PICS appinfo, depot
//!                           filtering, depot key, manifest code, CDN token,
//!                           manifest fetch) so failures pinpoint the break.
//!                           --manifest-only stops before the file download.
//!
//! Every launch prints `CHILD_PID=<pid>` on success so callers (scripts, the
//! agent) can monitor or kill the game process.

use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;
use std::sync::Arc;

use steam_cdn::web_api::content_service::CDNServer;
use steam_cdn::CDNClient;
use steam_vent::proto::steammessages_clientserver_appinfo::{
    cmsg_client_picsproduct_info_request, CMsgClientPICSAccessTokenRequest,
    CMsgClientPICSAccessTokenResponse, CMsgClientPICSProductInfoRequest,
    CMsgClientPICSProductInfoResponse,
};
use steam_vent::ConnectionTrait;

use crate::models::DepotPlatform;
use crate::steam_client::{
    find_vdf_in_pics, parse_pics_product_info, sanitize_install_dir, should_keep_depot,
};

pub async fn run(args: &[String]) -> Result<()> {
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    match cmd {
        "test-steam" => test_steam().await,
        "test-launch" => {
            let appid = parse_appid(args.get(1))?;
            test_launch(appid, false).await
        }
        "test-mod" => {
            let appid = parse_appid(args.get(1))?;
            test_launch(appid, true).await
        }
        "list" => list_games().await,
        "test-download-proton" => test_download_proton(args).await,
        "test-download-runtime" => test_download_runtime(args).await,
        "test-diff" => crate::parity::test_diff(args).await,
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        other => bail!("unknown subcommand: {other} (try `steamflow help`)"),
    }
}

fn parse_appid(arg: Option<&String>) -> Result<u32> {
    let raw = arg.ok_or_else(|| anyhow!("missing appid argument"))?;
    raw.parse::<u32>()
        .with_context(|| format!("invalid appid: {raw}"))
}

fn print_help() {
    println!(
        "SteamFlow headless test commands:\n  \
         steamflow test-steam                 ensure Windows Steam runtime is running\n  \
         steamflow test-launch <appid>        launch game via the UI Play pipeline\n  \
         steamflow test-mod <appid>           launch custom mod executable (Play Mod)\n  \
         steamflow list                       list installed games\n  \
         steamflow test-diff <appid>          env-parity: native proton log vs effective_env.json\n  \
         steamflow test-download-runtime <line>  fetch + provision a Steam Linux Runtime (scout/soldier/sniper/steamrt4)\n  \
         steamflow help                       this help"
    );
}

/// Ensure the Windows Steam runtime is up under the configured runner.
pub async fn test_steam() -> Result<()> {
    crate::config::ensure_config_dirs().await?;
    let launcher_config = crate::config::load_launcher_config().await.unwrap_or_default();

    let steam_cfg = crate::utils::get_master_steam_config();
    if crate::steam_client::SteamClient::is_steam_running_in_prefix(&steam_cfg.wine_prefix) {
        println!("Master Steam already running (prefix {})", steam_cfg.wine_prefix.display());
        return Ok(());
    }

    tracing::info!("Master Steam not running — starting it");
    crate::launch::install_master_steam(&launcher_config).await?;
    println!("Master Steam launched");
    Ok(())
}

/// List installed games (appid, name, install path).
pub async fn list_games() -> Result<()> {
    let installed = crate::library::scan_installed_app_info().await.unwrap_or_default();
    if installed.is_empty() {
        println!("No installed games found");
        return Ok(());
    }
    let mut entries: Vec<_> = installed.into_iter().collect();
    entries.sort_by_key(|(appid, _)| *appid);
    for (appid, info) in entries {
        println!(
            "{appid}\t{}\t{}",
            info.name.as_deref().unwrap_or("?"),
            info.install_path.display()
        );
    }
    Ok(())
}

/// Headless game launch.
///
/// * `use_mod_path` — launch via the game's `custom_exec_path` (Mods tab
///   "Play Mod" path) when configured; otherwise the full pipeline.
pub async fn test_launch(appid: u32, use_mod_path: bool) -> Result<()> {
    crate::config::ensure_config_dirs().await?;
    let launcher_config = crate::config::load_launcher_config().await.unwrap_or_default();
    let user_configs = crate::config::load_user_configs().await.unwrap_or_default();
    let user_config = user_configs.get(&appid).cloned();

    // Locate the game in the library (needed for name/install path).
    let installed = crate::library::scan_installed_app_info().await.unwrap_or_default();
    let game = installed
        .get(&appid)
        .map(|info| crate::models::LibraryGame {
            app_id: appid,
            name: info.name.clone().unwrap_or_else(|| format!("App {appid}")),
            playtime_forever_minutes: None,
            is_installed: true,
            install_path: Some(info.install_path.to_string_lossy().to_string()),
            local_manifest_ids: Default::default(),
            update_available: false,
            update_queued: false,
            active_branch: info.active_branch.clone(),
        })
        .ok_or_else(|| anyhow!("game {appid} not installed (no appmanifest found)"))?;

    // Play Mod path: custom_exec_path via launch_custom_exec.
    if use_mod_path {
        let exec_path = user_config
            .as_ref()
            .and_then(|c| c.custom_exec_path.clone())
            .filter(|p| !p.trim().is_empty())
            .ok_or_else(|| anyhow!("app {appid} has no custom_exec_path configured"))?;
        tracing::info!(appid, exec = %exec_path, "Launching custom mod executable (headless)");
        let child = crate::launch::launch_custom_exec(
            &launcher_config,
            user_config.as_ref().context("user_config missing")?,
            appid,
            &game.name,
            std::path::Path::new(&exec_path),
        )?;
        println!("CHILD_PID={}", child.id());
        wait_on(child);
        return Ok(());
    }

    // Pipeline path (UI "Play" equivalent).
    let mut client = crate::steam_client::SteamClient::new()?;
    let saved = crate::config::load_session().await.unwrap_or_default();
    if saved.refresh_token.is_some() && saved.account_name.is_some() {
        if let Err(e) = client.restore_session().await {
            tracing::warn!("session restore failed: {e}; continuing with cached launch metadata");
        }
    }

    let prefer_proton = true;
    let options = client.get_product_info(appid, prefer_proton).await?;
    let launch_info = options
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("no launch options for app {appid}"))?;

    let chosen_proton = match launch_info.target {
        crate::steam_client::LaunchTarget::NativeLinux => None,
        crate::steam_client::LaunchTarget::WindowsProton => {
            Some(launcher_config.proton_version.as_str())
        }
    };

    tracing::info!(appid, target = ?launch_info.target, "Launching game (headless pipeline)");
    let child = client
        .spawn_game_process(&game, &launch_info, chosen_proton, &launcher_config, user_config.as_ref())
        .await?;
    println!("CHILD_PID={}", child.id());
    wait_on(child);
    Ok(())
}

/// Block on the child so the headless process stays alive while the game runs.
/// (Mirrors the UI's `child.wait()` so a closed terminal doesn't matter.)
fn wait_on(mut child: std::process::Child) {
    match child.wait() {
        Ok(status) => tracing::info!("game process exited: {status}"),
        Err(e) => tracing::warn!("failed waiting on game process: {e}"),
    }
}

/// Headless diagnostic + installer for official Valve Proton depots.
///
/// Mirrors the UI's Install flow (ui.rs start_install -> SteamClient::install_game)
/// but logs every stage so a failure pinpoints the broken step:
///   stage 1: PICS appinfo fetch + VDF parse
///   stage 2: depot filtering (oslist/language/manifest lookup)
///   stage 3: content server list
///   stage 4: depot decryption key
///   stage 5: manifest request code
///   stage 6: per-host CDN auth token + manifest fetch
///   stage 7: full depot download (skipped with --manifest-only)
pub async fn test_download_proton(args: &[String]) -> Result<()> {
    let target = args.get(1).ok_or_else(|| {
        anyhow!("usage: test-download-proton <name|appid> [--manifest-only] [--depot <id>]")
    })?;
    let manifest_only = args.iter().any(|a| a == "--manifest-only");
    let filter_depot = args
        .iter()
        .position(|a| a == "--depot")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse::<u32>().ok());

    let appid: u32 = match target.parse() {
        Ok(id) => id,
        Err(_) => crate::proton::VALVE_PROTONS
            .iter()
            .find(|(label, _)| {
                crate::proton::normalize_name(label) == crate::proton::normalize_name(target)
            })
            .map(|(_, id)| *id)
            .ok_or_else(|| {
                anyhow!(
                    "unknown proton '{target}' (use an appid or one of {:?})",
                    crate::proton::VALVE_PROTONS
                        .iter()
                        .map(|(l, _)| *l)
                        .collect::<Vec<_>>()
                )
            })?,
    };

    crate::config::ensure_config_dirs().await?;
    let launcher_config = crate::config::load_launcher_config().await.unwrap_or_default();

    let mut client = crate::steam_client::SteamClient::new()?;
    let saved = crate::config::load_session().await.unwrap_or_default();
    if saved.refresh_token.is_some() && saved.account_name.is_some() {
        if let Err(e) = client.restore_session().await {
            tracing::warn!("session restore failed: {e}");
        }
    }
    let connection = client
        .connection()
        .cloned()
        .context("no steam connection — is a session saved?")?;

    println!("== stage 1: PICS appinfo for appid {appid}");
    // Owner-only tool apps (official Valve Protons) return `public_only=1`
    // with NO depots section unless the request carries the per-app access
    // token. Mirror the vendored CDN's get_product_info: fetch the access
    // token first (CMsgClientPICSAccessTokenRequest), then attach it.
    let token_resp: CMsgClientPICSAccessTokenResponse = connection
        .job(CMsgClientPICSAccessTokenRequest {
            appids: vec![appid],
            ..Default::default()
        })
        .await
        .context("PICS access-token request failed")?;
    let app_token = token_resp
        .app_access_tokens
        .iter()
        .find(|t| t.appid() == appid)
        .and_then(|t| t.access_token.clone());
    println!(
        "  access token for {appid}: {}",
        if app_token.is_some() {
            "present"
        } else {
            "MISSING (request may still go anonymous)"
        }
    );
    let mut request = CMsgClientPICSProductInfoRequest::new();
    request
        .apps
        .push(cmsg_client_picsproduct_info_request::AppInfo {
            appid: Some(appid),
            access_token: app_token,
            ..Default::default()
        });
    let response: CMsgClientPICSProductInfoResponse = connection
        .job(request)
        .await
        .context("PICS request failed")?;
    let app = response
        .apps
        .iter()
        .find(|entry| entry.appid() == appid)
        .ok_or_else(|| anyhow!("missing appinfo payload for app {appid}"))?;
    let appinfo_vdf_bytes = app.buffer().to_vec();
    let appinfo_vdf_text = String::from_utf8_lossy(&appinfo_vdf_bytes).to_string();
    println!(
        "  appinfo bytes: {} ({} chars VDF)",
        appinfo_vdf_bytes.len(),
        appinfo_vdf_text.len()
    );
    // Print the common section (root key, name, installdir) — tool apps often
    // differ from games here (this is where resolve_install_game_info looks).
    let common_head: String = appinfo_vdf_text.chars().take(900).collect();
    println!("  --- appinfo head ---\n{common_head}");
    if let Some(depots_idx) = appinfo_vdf_text.find("depots") {
        let slice = &appinfo_vdf_text[depots_idx..];
        let end = slice.find("\"appinfo\"").unwrap_or(slice.len()).min(2200);
        println!("  --- depots section ---\n{}", &slice[..end]);
    }

    let map = parse_pics_product_info(&appinfo_vdf_bytes)
        .context("stage 1 FAILED: parse_pics_product_info")?;
    println!("  parse_pics_product_info map: {map:?}");

    println!("== stage 2: depot filtering (mirrors install_game)");
    let vdf = find_vdf_in_pics(&appinfo_vdf_bytes).context("stage 1 FAILED: find_vdf_in_pics")?;
    let mut selections: Vec<(u32, u64)> = Vec::new();
    let depots_obj = vdf.as_obj().and_then(|root| {
        if vdf.key() == "appinfo" || vdf.key() == appid.to_string() {
            root.get("depots").and_then(|v| v.as_obj())
        } else {
            root.get("depots")
                .and_then(|v| v.as_obj())
                .or_else(|| {
                    root.get("appinfo")
                        .and_then(|v| v.as_obj())
                        .and_then(|o| o.get("depots"))
                        .and_then(|v| v.as_obj())
                })
        }
    });
    if let Some(depots) = depots_obj {
        for (key, value) in depots.iter() {
            if let Ok(d_id) = key.parse::<u32>() {
                let oslist = value
                    .get_obj(&["config"])
                    .and_then(|c| c.get("oslist"))
                    .and_then(|o| o.as_str());
                let lang = value
                    .get_obj(&["config"])
                    .and_then(|c| c.get("language"))
                    .and_then(|l| l.as_str());
                let manifest_id = map.get(&(d_id as u64)).copied();
                let mut keep = should_keep_depot(oslist, DepotPlatform::Linux);
                if keep {
                    if let Some(lang) = lang {
                        if lang != "english" && !lang.is_empty() {
                            keep = false;
                        }
                    }
                }
                if keep {
                    if let Some(fd) = filter_depot {
                        if fd != d_id {
                            keep = false;
                        }
                    }
                }
                println!(
                    "  depot {d_id}: oslist={oslist:?} language={lang:?} manifest={manifest_id:?} -> {}",
                    if keep { "SELECTED" } else { "skipped" }
                );
                if keep {
                    match manifest_id {
                        Some(m_id) => selections.push((d_id, m_id)),
                        None => println!(
                            "  depot {d_id}: SELECTED but NO manifest id in parse_pics_product_info map"
                        ),
                    }
                }
            }
        }
    }

    if selections.is_empty() {
        bail!("stage 2 FAILED: no depots selected — install_game would abort with \"No matching depots found for the selected platform.\"");
    }
    println!("  selections: {selections:?}");

    println!("== stage 3: content servers (cell {})", connection.cell_id());
    let hosts = client
        .get_content_servers(connection.cell_id())
        .await
        .context("stage 3 FAILED: get_content_servers")?;
    println!("  {} hosts: {}", hosts.len(), hosts.join(", "));

    let (game_name, pics_installdir) = client.resolve_install_game_info(appid).await;
    let installdir = pics_installdir.unwrap_or_else(|| sanitize_install_dir(&game_name));
    let library_root = launcher_config.steam_library_path.clone();
    let install_dir = std::path::Path::new(&library_root)
        .join("steamapps")
        .join("common")
        .join(&installdir);
    println!("== target install dir: {}", install_dir.display());

    for (depot_id, manifest_id) in &selections {
        println!("== stage 4: depot decryption key for {depot_id}");
        let key = match client.get_depot_key(appid, *depot_id).await {
            Ok(k) => {
                println!("  key OK ({} bytes)", k.len());
                if k.len() == 32 {
                    println!("  key hex: {}", hex::encode(&k));
                }
                k
            }
            Err(e) => {
                println!("  stage 4 FAILED: get_depot_key: {e}");
                continue;
            }
        };
        if key.len() != 32 {
            println!("  stage 4 FAILED: depot key has unexpected size {} (expected 32)", key.len());
            continue;
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key);

        println!("== stage 5: manifest request code");
        let manifest_code = match client
            .get_manifest_request_code(appid, *depot_id, *manifest_id)
            .await
        {
            Ok(code) => {
                println!("  code OK: {code}");
                Some(code)
            }
            Err(e) => {
                println!("  stage 5 FAILED: get_manifest_request_code: {e} (continuing without code)");
                None
            }
        };

        for host in &hosts {
            let (host_name, port) = if let Some(pos) = host.find(':') {
                (&host[..pos], host[pos + 1..].parse::<u16>().unwrap_or(80))
            } else {
                (host.as_str(), 80)
            };
            println!("== stage 6: CDN auth token + manifest from {host}");
            let token = match client.get_cdn_auth_token(appid, *depot_id, host).await {
                Ok(t) => {
                    println!("  token OK");
                    Some(t)
                }
                Err(e) => {
                    println!("  stage 6 WARN: get_cdn_auth_token: {e:?}");
                    None
                }
            };
            let cdn_server = CDNServer {
                r#type: "CDN".to_string(),
                https: port == 443,
                host: host_name.to_string(),
                vhost: host_name.to_string(),
                port,
                cell_id: connection.cell_id(),
                load: 0,
                weighted_load: 0,
                auth_token: token,
            };
            let cdn_client = CDNClient::with_server(Arc::new(connection.clone()), cdn_server);

            match cdn_client
                .get_manifest(appid, *depot_id, *manifest_id, manifest_code, Some(key_arr))
                .await
            {
                Ok(manifest) => {
                    let total: u64 = manifest.files().iter().map(|f| f.size()).sum();
                    println!(
                        "  manifest OK: {} files, {total} bytes",
                        manifest.files().len()
                    );
                    for f in manifest.files().iter().take(5) {
                        let c0 = f.chunks().first();
                        println!("    {} ({} bytes, first chunk {})", f.full_path(), f.size(), c0.map(|c| c.id()).unwrap_or_default());
                    }
                    if manifest_only {
                        println!(
                            "== MANIFEST-ONLY: stopping before download (would install to {})",
                            install_dir.display()
                        );
                        return Ok(());
                    }

                    println!("== stage 7: download_depot -> {}", install_dir.display());
                    std::fs::create_dir_all(&install_dir)?;
                    let on_progress: Arc<dyn Fn(u64, u64) + Send + Sync + 'static> =
                        Arc::new(|done: u64, total: u64| {
                            if total > 0 {
                                let pct = done * 100 / total;
                                if pct % 25 == 0 || done == total {
                                    println!("  progress: {done}/{total} ({pct}%)");
                                }
                            }
                        });
                    match cdn_client
                        .download_depot(
                            appid,
                            *depot_id,
                            *manifest_id,
                            &key_arr,
                            &install_dir,
                            manifest_code,
                            false,
                            None,
                            None,
                            Some(on_progress),
                            None,
                            None,
                        )
                        .await
                    {
                        Ok(()) => {
                            println!("== depot {depot_id} download COMPLETE");
                            // Phase 2 item 3: surface the runner's version into
                            // VERSIONS.txt at the install root (harvests the
                            // depot's version files + stamps the installdir).
                            crate::utils::write_runner_versions_txt(&install_dir, &installdir);
                        }
                        Err(e) => println!("  stage 7 FAILED: download_depot: {e}"),
                    }
                    return Ok(());
                }
                Err(e) => {
                    println!("  stage 6 FAILED: get_manifest from {host}: {e}");
                }
            }
        }
    }
    bail!("all hosts/depots failed — see stage output above")
}

/// Phase 4.3 depot hook: fetch + provision a Steam Linux Runtime.
///
/// Wires [`RuntimeManager::provision_from_archive`] into the asset-fetcher
/// pipeline: the SLR app is downloaded through the SAME `install_game` depot
/// machinery the UI uses (which lands it in the client-managed
/// `steamapps/common/SteamLinuxRuntime_<line>/` location), then that tree is
/// wrapped as an archive and provisioned into
/// `~/.config/SteamFlow/runtimes/<line>/`.
///
/// `line` is one of `scout` / `soldier` / `sniper` / `steamrt4`.
pub async fn test_download_runtime(args: &[String]) -> Result<()> {
    use crate::container::runtime::{ArchiveVerification, RuntimeManager, SteamRuntimeId};
    use crate::models::{DownloadProgressState, DownloadState};

    let name = args
        .get(1)
        .ok_or_else(|| anyhow!("usage: test-download-runtime <scout|soldier|sniper|steamrt4>"))?;
    let id = SteamRuntimeId::from_name(name);
    let appid = id.app_id();

    crate::config::ensure_config_dirs().await?;
    let launcher_config = crate::config::load_launcher_config().await.unwrap_or_default();

    let mut client = crate::steam_client::SteamClient::new()?;
    let saved = crate::config::load_session().await.unwrap_or_default();
    if saved.refresh_token.is_some() && saved.account_name.is_some() {
        if let Err(e) = client.restore_session().await {
            tracing::warn!("session restore failed: {e}");
        }
    }

    println!(
        "== fetching Steam Linux Runtime '{}' (app {}) via the depot pipeline",
        id.dir_name(),
        appid
    );

    let shared_state = Arc::new(std::sync::RwLock::new(DownloadState::default()));
    let mut rx = client
        .install_game(appid, DepotPlatform::Linux, None, None, shared_state)
        .await
        .context("install_game (asset fetcher) failed to start")?;

    let mut failed = false;
    while let Some(progress) = rx.recv().await {
        match progress.state {
            DownloadProgressState::Completed => println!("  depot download complete"),
            DownloadProgressState::Failed => {
                failed = true;
                println!("  depot download FAILED: {}", progress.current_file);
                break;
            }
            _ => {
                if progress.total_bytes > 0 {
                    println!(
                        "  progress {}/{} ({}%)",
                        progress.bytes_downloaded,
                        progress.total_bytes,
                        progress.bytes_downloaded * 100 / progress.total_bytes
                    );
                }
            }
        }
    }
    if failed {
        bail!("SLR depot download failed");
    }

    // The asset fetcher landed the runtime in the client-managed location.
    let library_root = PathBuf::from(&launcher_config.steam_library_path);
    let mgr = RuntimeManager::for_id(id);
    let client_dir = mgr
        .client_managed_runtime(&library_root)
        .ok_or_else(|| {
            anyhow!(
                "SLR depot downloaded but no client-managed runtime found under {}",
                library_root.join("steamapps/common").display()
            )
        })?;
    println!("== client-managed runtime: {}", client_dir.display());

    // Wrap the downloaded tree as an archive and provision it into
    // ~/.config/SteamFlow/runtimes/<line>/ via provision_from_archive.
    let state = mgr
        .provision_from_depot_dir(&client_dir, &ArchiveVerification::default(), false)
        .await
        .context("provision_from_depot_dir failed")?;
    println!(
        "== provisioned runtime '{}': present={} complete={} revision={:?}",
        id.dir_name(),
        state.present,
        state.complete,
        state.revision
    );
    if !state.is_usable() {
        bail!("provisioned runtime is not usable: {:?}", state.errors);
    }
    Ok(())
}
