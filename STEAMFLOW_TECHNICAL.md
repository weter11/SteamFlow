# SteamFlow

Rust prototype of a Steam launcher that uses `steam-vent` for protocol/auth transport and `egui` for desktop UI.

## Stack
- `steam-vent` (`0.4.2`) for Steam protocol and auth workflow.
- `steam-vent-proto` (`0.5.2`) for protobuf request/response types.
- `egui` / `eframe` for desktop GUI.
- `tokio` for async tasks and background downloads.
- `keyvalues-serde` for VDF parsing.

## Authentication flow (steam-vent 0.4.2)
SteamFlow now follows the full auth sequence used by steam-vent's login pipeline:

1. Discover CM endpoints via `ServerList::discover` (fallbacks to local endpoint list).
2. Run `Authentication.GetPasswordRSAPublicKey` + `BeginAuthSessionViaCredentials` internally through `Connection::login`.
3. Surface Steam Guard confirmation methods in the UI, then submit code/device confirmation through the login flow.
4. Poll `Authentication.PollAuthSessionStatus` until tokens are issued.
5. Perform client logon using the returned refresh token (steam-vent access-token login step).
6. Persist `account_name` and refresh token (`access_token()` from session) to `~/.config/SteamFlow/session.json`.
7. On next launch, call `Connection::access` with the persisted refresh token to restore the session.

Guard data is persisted through `FileGuardDataStore::user_cache()` so repeated Steam Guard prompts are reduced when Steam allows it.

## Library
- `fetch_owned_games()` via `Player.GetOwnedGames` service method.
- Local install scan from `steamapps/libraryfolders.vdf` and `appmanifest_*.acf`.
- VDF parsing now uses `keyvalues-serde` models (no line-based fallback parsing).
- Unified `GameLibrary` with per-game install status.
- **Steam Cloud Sync**: Automatic sync-down before launch and sync-up after game exit (if enabled in settings).

## GUI
- Context menu `Advanced > Depot Browser` opens a browser for app depots and manifest file trees.
- Per-file depot download support from the Depot Browser window.
- Integrated authentication panel (account/password + optional Steam Guard code).
- Confirmation-type specific Steam Guard hints: email/device code vs mobile approval flow.
- Validation messaging when a code is required but missing.
- Automatic re-auth fallback when token/session failures are detected in runtime actions (library refresh, launch metadata fetch).
- Sidebar game list and "Show Installed Only" filter.
- Steam CDN image download + on-disk cache (`./config/SteamFlow/images`) with egui texture loading.
- Launch actions:
  - installed -> green `PLAY`
  - not installed -> queue install/download pipeline skeleton

## Launch flow
- Product metadata lookup through PICS is integrated into `SteamClient::get_launch_info`.
- Linux-first launch target selection, then Windows fallback (Proton path required).

## Run
```bash
cargo run
```

## Install/download pipeline
- Install target now uses `<steam_library_path>/steamapps/common/<game>` instead of temp paths.
- App manifests are now written to `<steam_library_path>/steamapps/appmanifest_<appid>.acf` after installs complete so local scan works after restart.
- Implemented a four-phase pipeline in `src/download_pipeline.rs`:
  1. **Get Manifest ID**: PICS product info request + VDF parsing to find the correct depot and manifest GID for the target platform.
  2. **Get Security Info**: Request depot decryption keys + CDN server list and auth tokens.
  3. **Download/Decode Manifest**: Fetch manifest from CDN and decode the proprietary protobuf-based format (supporting raw, Gzip, and Xz).
  4. **Chunk Download Loop**: Concurrent download of file chunks, followed by AES-256-CBC decryption and decompression.
- The UI integration drives a staged download into a temporary or configured library directory.
