# Steam Client Registration, Login & Launch Modes

## Status
Proposed (validated manually 2026-08-02)

## Problem

Windows Steam games with strict Steamworks integration (e.g. Resident Evil 2, 883710)
exit ~2s with code 53, while games without `steam_api64.dll` (Little Nightmares EE,
2149010) work. Root cause (validated by +loaddll,+process trace): the game's
`SteamAPI_Init()` queries the Windows Steam client, which fails two gates:

1. **Install gate** — the client's `libraryfolders.vdf` registers only its own install
   dir with zero apps; games live in the native Linux Steam library.
2. **Ownership gate** — the client runs **anonymous** (`[Logged Off, 0, 0] [U:1:0]`):
   it has **no `ssfn*` sentry file**, so it can never auto-login and cannot answer
   "does this user own the app?".

Both must pass. The ACF file-probe (manifest next to the exe) is a third, game-specific
gate that must also be satisfied (copying the manifest into the game dir satisfied it).

### Why the manifest copy alone didn't fix it
The file probe passed but the API ownership query against the anonymous client still
fails -> exit 53.

### Why Little Nightmares works
It has no `steam_api64.dll` -> skips the Steam API ownership check entirely.

### SteamFlow has NO ACF writer
`grep appmanifest|SizeOnDisk|InstalledDepots src/` -> zero matches. The 6 "orphaned"
ACFs (883710, 620, 209000, 286690, 6910, 2368470 — present on disk, in no client's
apps map, missing `SizeOnDisk`) were created by the Windows client itself during the
earlier install churn. ACF synthesis/repair is a NEW capability to build.

## Architecture

### Stage 1 — Client login (blocking prerequisite, one-time)
- SteamFlow UI shows a one-time credential prompt (own dialog).
- Launches the client headless: `steam.exe -login <account> <password> -silent -tcp`
- On success Steam writes `ssfn*` + refreshes `loginusers.vdf`; subsequent launches
  auto-login with zero interaction.
- Preflight: `loginusers.vdf` + presence of `ssfn*` decides whether onboarding is needed.
- **Do NOT copy native Linux Steam's ssfn** (sentry is machine/install-bound; wine
  MachineGuid `299ed54b-...` differs -> would trigger email guard-code prompt).
- Evidence the client WAS logged in before: `userdata/137551487/` exists
  (137551487 = account id of 76561198097817215).

### Stage 2 — Library registration (validated)
Register native Linux Steam library folders in the Windows client:
- Write `libraryfolders.vdf` entry `"N"` = `Z:\<native lib path>` with all apps from
  native `appmanifest_*.acf` (client must be STOPPED while writing — Steam rewrites on
  exit).
- Handle orphaned ACFs: synthesize missing `SizeOnDisk` from `InstalledDepots` sums;
  register them regardless of apps-map presence.
- Validated manually: Steam accepted the Z:\ library, `librarycache/883710` present.

### Stage 3 — Three launch modes (Settings tab, per-game)
Mode selection lives in Settings; each game can override:

| Mode | Launch mechanism | Steam env | Webhelper | Use for |
|---|---|---|---|---|
| **Steam-mediated (Option C) — DEFAULT** | `steam://rungameid/<appid>` or `steam.exe -applaunch <appid>` | Client-managed session | Runs normally (client UI available) | Games with mods + Launch Options + Env Vars; best compat |
| **Use Steam Runtime** | Direct bare-wine + `STEAM_COMPAT_*` env | SteamFlow sets env | Controlled by "Steam Features" | Legacy/diagnostic |
| **Plain launch** | Direct bare-wine, no Steam env | None | n/a | Non-Steam games, debugging |

- **Option C must pass through**: game mods (game-dir DLLs — game-local priority already
  implemented), user Launch Options, and per-game Environment Variables. Validation
  checklist before promoting to default: RE2 launches past 53, Portal 2 RTX Remix loads,
  LN keeps working, mods + launch options + env vars all reach the game.
- When mode = Steam-mediated, the **"Steam Features" section is hidden** (client owns its
  UI; "Only applies when 'Use Steam Runtime' is enabled" becomes invisible).
- `-applaunch` runs from the client core; steamwebhelper (UI) is NOT required for
  launching — fits headless operation.

### Login-session nuance (webhelper works in all management paths)
- **Manage / Repair / Reinstall**: the pre-operation `kill_all_wine_in_prefix` is
  required to unlock files, but the relaunch path (`install_master_steam`) never kills
  webhelper afterward — with login restored, the client re-logs-in automatically and
  webhelper features (friends/chat/browser) work normally.
- **Game launch**: webhelper keeps running unless `no_browser` is explicitly checked
  (and that checkbox disappears in Steam-mediated mode).

## Fallback (user refuses Linux-folder sharing)
Per-game ACF injection + wine junction symlink into the client's own library (Option B).
Still requires Stage 1 (login) — unavoidable.

## Files to change (draft)

| Area | File | Change |
|---|---|---|
| Config | `src/config.rs` | `launch_mode` per game; `steam_account`; one-shot login prompt state |
| Login | `src/steam_client.rs` | `is_steam_logged_in()` (ssfn+loginusers), `run_one_time_login()`, `launch_steam_with_login()` |
| Registration | `src/steam_client.rs` | `register_native_libraries()` (parse native libraryfolders.vdf + ACFs, write prefix vdf while stopped) |
| Launch | `src/infra/runners/wine_tkg.rs` | steam-mediated launch path (`steam://rungameid` / `-applaunch`); pass-through of mods/Launch Options/env vars |
| UI | `src/ui.rs` | Settings tab: launch-mode selector (3 options); hide "Steam Features" in steam-mediated mode; one-time login dialog |
| Preflight | `src/launch/pipeline.rs` | stage: verify login + registration before spawn in steam modes; clear warning if missing |

## Validation checklist (user will test during implementation)
1. `steam.exe -login <user> <pass>` completes headless under wine; ssfn created.
2. After login: RE2 passes ownership gate (no more exit 53) with Steam-mediated launch.
3. Portal 2 RTX Remix loads with its own d3d9/DXVK-Remix + Launch Options + env vars.
4. Little Nightmares still works (regression).
5. Manage/Repair/Reinstall: webhelper runs and client is logged in afterward.
6. Steam Features section hidden in steam-mediated mode; visible in Use-Steam-Runtime mode.

## Open questions
1. Does `steam://rungameid` pass Launch Options + env vars through to the game, or must
   they be set via Steam's own config (`SetLaunchOption` / config.vdf)?
2. Does `-applaunch` work headless without steamwebhelper in this wine build?
3. Will Steam treat the Z:\ library folder as writable for updates/verify?
4. Should mode selection be global (Settings) with per-game override, or per-game only?
