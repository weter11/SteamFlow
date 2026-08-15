# Phase 4.1 — Offline Steam API Emulator Mode (Clientless Launcher)

> Status: **IMPLEMENTED + VERIFIED (2026-08-15)**. Branch `phase4/one-time-login-automation`.
> Companion to the Phase 4 one-time-login work (per-prefix session automation).
> `OnlineContainerized` (SteamRT4 pressure-vessel launch) is RESERVED for Phase 4.2/4.3 — not implemented here.

## Objective

Let a game run with **zero Steam client processes** (no Windows Steam under
wine, no Linux Steam) by answering Steamworks calls with a **local steam_api
emulator** (Goldberg SteamEmu class). The emulator binaries are
**user-supplied** — SteamFlow never ships them. User drops
`steam_api.dll` / `steam_api64.dll` into `~/.config/SteamFlow/steam_emulator/`.

## Config schema (`src/models.rs`)

```rust
pub enum SteamMode { Auto (default), OfflineEmulated, OnlineContainerized }
pub struct OfflineSettings { account_name: "Slavik", steam_id: 76561198000000000 }
// UserAppConfig: steam_mode: SteamMode (#[serde(default)]), offline_settings: OfflineSettings (#[serde(default)])
```

- `Auto` → falls back to `OfflineEmulated` **only** when the game needs the
  Steam API (per-game flag OR `steam_api*.dll` on disk) AND no native Steam
  host session is active. DRM-free games stay clean (no injection — the
  Amnesia 57300 lesson).
- Old `user_apps.json` files load fine (all new fields `#[serde(default)]`).

## The falsification that shaped the design (IMPORTANT)

First live test (Portal 2, `steam_mode=OfflineEmulated`) failed with the
classic **"Steam is not running. You must start Steam in order to play this
game."** Engine Error dialog. Root cause was proven, not guessed:

1. `WINEDLLOVERRIDES` ended with `steam_api=n,b;steam_api64=n,b` (appended
   last, so it wins) and `WINEDLLPATH` started with the emulator staging dir —
   the env was correct.
2. `WINEDEBUG=+loaddll` trace showed the game loaded
   `Z:\...\Portal 2\bin\steam_api.dll` (its OWN DLL) and then the real
   `C:\Program Files (x86)\Steam\steamclient.dll`; the staging dir was never
   probed.
3. `strings bin/vstdlib.dll` → `GSteamClient020`, `%s/bin/%s`,
   `steam_api.dll` — the **Source engine builds the module path
   `bin\steam_api.dll` itself** (tier0 runtime module system, same pattern as
   `bin\launcher.dll`).
4. **Wine bypasses WINEDLLPATH and DLL overrides for path-qualified loads** —
   so DLL shadowing is structurally ineffective for Source-engine games.

**Consequence:** the provisioner does an **in-place override** — the emulator
DLL is copied OVER the game's own `steam_api*.dll` wherever the game keeps it
(game root, `bin/`, …), with the original preserved as
`<dll>.steamflow-orig`. `WINEDLLPATH` staging + `WINEDLLOVERRIDES` remain as
belt-and-braces for engines that load by bare name.

## Implementation

| File | Change |
|---|---|
| `src/models.rs` | `SteamMode` enum, `OfflineSettings`, both on `UserAppConfig` |
| `src/infra/steam_emulator.rs` (new) | `SteamEmulatorManager::provision[_with_source]` — steam_appid.txt (game root + exe dir + staging), DLL staging into `<prefix>/drive_c/SteamFlow/steam_emulator/<appid>/`, **in-place override with `.steamflow-orig` backup**, steam_settings/ identity files (game root + deploy dirs + staging); `resolve_effective_steam_mode`, `game_requires_steam_api`, `native_steam_host_session_active`, `winedllpath_fragment` |
| `src/infra/runners/wine_tkg.rs` | Dispatch: OfflineEmulated skips client deployment/spawn/feature-enforcement/readiness gates; provisions instead of client-based steam_appid.txt; env: `steam_api=n,b;steam_api64=n,b` appended last to WINEDLLOVERRIDES + emulator staging dir FIRST in WINEDLLPATH; both Steam-readiness warnings suppressed in OfflineEmulated |
| `src/launch/stages/preflight.rs` | "Windows Steam Session" gate skipped when effective mode is OfflineEmulated |
| `src/ui.rs` | Properties → Runtime Settings → **Steam Client Mode** dropdown (Auto (Default) / Offline Emulated (Clientless) / Online Containerized (SteamRT4)), persists to user_apps.json |
| `docs/architecture/valve-stack-replication.md` | Phase 4.1 Status block |

## Verification

- `cargo check --all-targets` — clean.
- `cargo test --lib` — **118 passed, 0 failed** (5 in
  `infra::steam_emulator::tests`: serde defaults/overrides, Auto fallback
  matrix, provisioning with/without DLLs, backup + idempotency).
- **Live `steamflow test-launch 620`** (Portal 2, `steam_mode: OfflineEmulated`,
  Goldberg gbe_fork release-2026_07_19 regular x86+x86_64 staged):
  - ✅ emulator deployed in place (`bin/steam_api.dll` = emulator, original =
    `bin/steam_api.dll.steamflow-orig`), `steam_appid.txt` + steam_settings/
    written;
  - ✅ **zero Steam client processes** during the whole run;
  - ✅ no SteamAPI failure — game reached a live **"PORTAL 2 - Direct3D 9"
    2560×1440 window** with the RTX Remix bridge active (bridge handshake
    completed; winproc-1400 fix effective);
  - ✅ game exited only when the user closed it.

## Runtime state after the test (2026-08-15)

- `~/.config/SteamFlow/steam_emulator/` — Goldberg `steam_api.dll` (PE32
  32-bit) + `steam_api64.dll` (PE32+). P2 (620) is a **32-bit PE32 build** →
  needs the 32-bit DLL.
- P2 install: `bin/steam_api.dll` = emulator, `bin/steam_api.dll.steamflow-orig`
  = original Valve DLL; `steam_settings/` in game root. Steam Verify Integrity
  restores originals; then re-run `test-launch` to re-provision.
- `user_apps.json[620].steam_mode = "OfflineEmulated"` (backup:
  `user_apps.json.bak-phase41-*`).

## Open items / decisions (FLAG, not resolved)

1. **Mods-tab custom-exec (`launch_custom_exec`) is NOT yet steam_mode-aware** —
   `test-mod 620` in OfflineEmulated would still spawn the background Steam
   client. Extend the same effective-mode logic there if the Mods path needs
   clientless too.
2. **`OnlineContainerized`** is schema-only; Phase 4.2/4.3 will implement the
   SteamRT4 pressure-vessel launch (currently behaves like Auto).
3. In-place override mutates the game install (backed up, Steam-verify
   reversible) — a future per-game "don't touch game files" opt-out is
   possible if a name-loading engine makes shadowing sufficient.
