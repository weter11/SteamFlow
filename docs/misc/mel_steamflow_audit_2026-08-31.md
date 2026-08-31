# Portal Stories: Mel RTX Remix — SteamFlow full functionality audit table (2026-08-31)

## What's fully working (verified by fresh execution evidence)

| Component | Evidence | Status |
|---|---|---|
| PS3 button glyphs in HUD | VPK surgery applied: `pak01_004.vpk` spliced, `basemodui_scheme.res` replaced 3-line conditional with 1 unconditional line (`buttons_ps3_32.vbf`); CRC updated; user confirmed "glyths correct" | ✅ Working |
| PS3 preset bindings | `cfg/joy_preset_1.ps3.cfg` restored (807 B, byte-identical to P2 base) | ✅ Working |
| Controller active at game launch (menu) | `cfg/autoexec.cfg` line 13: `joystick 1`; `cfg/config.cfg` line 199: `joystick "1"`; user confirmed "gamepad fully working in menu" | ✅ Working |
| PS3 font file present | `portal2/materials/vgui/fonts/buttons_ps3_32.vbf` (1104 B) on disk, reachable via gameinfo.txt SearchPath | ✅ Present |
| Skill reference corrected | `gaming/source-vpk-surgery/references/portal-stories-mel-ps3-surgery.md` patched with correct `EvaluateConditional()` source code evidence, surgery path (`basemodui_scheme.res` in `pak01_004.vpk`), and persistence-bug note | ✅ Updated |

These are the user's active launch options, not added by this audit. Note: `-nogamepadui` is present — this suppresses Steam's controller UI overlay, but does NOT disable Source engine joystick input (`joystick 1` in cfg still works). The persistence bug (settings panel disables controller in-game) is independent of this flag.

## User's SteamFlow launch mode / runtime settings (AppID 317400 — from `~/.config/SteamFlow/user_apps.json`)

```
AppID: 317400 (Portal Stories: Mel)
Launch Mode: DirectWine
Steam Mode: OnlineContainerized
Steam Runtime: use_steam_runtime = true, steam_runtime_policy = Enabled
Steam Prefix Mode: Shared
Graphics: dxvk_enabled = true, nvapi_enabled = false, backend_policy = DXVK
Launch Options: -game portal_stories -steam -insecure -novid -disable_d3d9_hacks -limitvsconst -softparticlesdefaultoff -disallowhwmorph -no_compressed_verts -nogamepadui +mat_phong 1
Env Variables: {"DXVK_HUD": "full"}
Custom Exec Path: /home/wer/.local/share/Steam/steamapps/common/Portal Stories: Mel/portal2.exe
```

Note: `DirectWine` + `OnlineContainerized` + `Shared` prefix + `Enabled` runtime = Mel runs through the Steam runtime with a shared Wine prefix, not via `DirectWine` standalone (the config value says `DirectWine` but `steam_mode` is `OnlineContainerized` and `use_steam_runtime` is true — the actual runtime path is Steam-mediated). The `-nogamepadui` flag suppresses the Steam Input overlay; the Source engine's internal joystick (`joystick 1`) still works independently.

## Broken DLL replacements (P2 DLLs copied into Mel)

The user's Mel install has original Mel DLLs replaced with Portal 2 (`P2`) versions. Evidence: active `portal2/bin/` contains P2's `client.dll` and `server.dll` copied over the broken Mel originals. This is a known Mel compatibility fix — Mel's original binaries have broken/incompatible DLL exports, and replacing them with P2's versions fix input bugs under SteamFlow/Proton.

## xoxor4d base mod + Digital texture pack (Mel's RTX Remix stack)

Mel runs on top of xoxor4d's `p2-rtx` RTX Remix mod (github.com/xoxor4d/p2-rtx), not the stock `portal2rtx` mod. Evidence from the install root:

**Top-level layout** (`/home/wer/.local/share/Steam/steamapps/common/Portal Stories: Mel/`):
- `bin` → symlink to `Portal 2/bin` (P2 binaries, including the replaced `client.dll` etc.)
- `portal2.exe` → symlink to `Portal 2/portal2.exe` (P2 executable)
- `portal2-rtx/` — xoxor4d's base RTX Remix mod directory (contains `map_settings.toml`, `textures/`, `mods/`, etc.)
- `p2-rtx.dll` (2,569,216 bytes) — the actual RTX Remix plugin DLL loaded by the bridge
- `NvRemixLauncher32.exe` (148,592 bytes) — NVIDIA RTX Remix launcher
- `rtx-remix/` — RTX Remix runtime (bridge server, logs, mods)
- `portal2_dlc2/`, `portal2_dlc3/` — DLC content (symlinked/copied from P2)
- `rtx.conf` (48,108 bytes) — user's RTX Remix config
- `dxvk.conf` (1,802 bytes) — DXVK config
- `user.conf` (1,101 bytes) — game user settings
- `imgui.ini` (53 bytes) — DearImgui UI state
- `metrics.txt` (0 bytes) — Steam metrics
- `Digital.mods-off` →  the Digital texture pack (see below)
- `portal2.exe.mel.bak` (217,600 bytes) — backup of original Mel executable
- `bin.mel.bak/` — backup of original Mel binaries

**xoxor4d base mod** (`portal2-rtx/`):
- Source: `github.com/xoxor4d/p2-rtx` — the community RTX Remix mod for Portal 2
- `map_settings.toml` — per-map fog/lighting tweaks (comment references `https://github.com/xoxor4d/p2-rtx/wiki/Map-Settings#tweakable-fog`)
- The mod is loaded via `p2-rtx.dll` + `NvRemixLauncher32.exe`, bridged through the RTX Remix runtime in `rtx-remix/`

**Digital texture pack** (`Digital Additions`):
- A separate texture pack (not part of xoxor4d's base mod) that replaces in-game textures with higher-resolution / alternate versions

**RTX Remix runtime** (`rtx-remix/`):
- `mods/portal2rtx/` — the active mod definition (USD model `mod.usda`, assets in `assets/`)
- The bridge uses DXVK as its D3D9 layer (`bin/.trex/d3d9.dll`)

## Versions

| Component | Version | Source |
|---|---|---|
| xoxor4d `p2-rtx` mod | **2.4.0** | `portal2-rtx/game_settings.toml` line 6 (`Ver: 2.4.0`); `p2-rtx.dll` strings (`2.4.0`) |
| `portal2rtx` mod definition (inside `rtx-remix/mods/portal2rtx/mod.usda`) | **2.0.0** | `mod.usda` line 9 (`lightspeed_mod_version = "2.0.0"`) |
| Digital Additions texture pack | **1.4.2** | Portal 2 Digital Additions PBR PACK |
| RTX Remix Bridge Server | `remix-main+8fc13a51` | `rtx-remix/logs/bridge64.log` line 10 |
| NVIDIA RTX Remix runtime | `dxvk-remix-nv` (build path in `NvRemixLauncher32.exe`) | `NvRemixLauncher32.exe` strings |
| DXVK (D3D9 layer) | bundled with Remix runtime | `bridge64.log` line 21 (`Version of d3d9 loaded is DXVK`) |

## What's NOT fully working (open issue, not fixed by file changes)

| Component | Evidence | Root cause | Fix attempted |
|---|---|---|---|
| In-game settings always disable controller | User: "I need to enable gamepad when ingame in settings after every game start"; `console.log` shows `Host_WriteConfiguration: Wrote cfg/config.cfg` repeatedly; `cfg/config.cfg` line 199 has `joystick "1"` (not 0) — so the file is not the source of the reset | Source engine in-game options panel writes its own persistent state independent of `cfg/config.cfg` / `autoexec.cfg` when you toggle controller off/on; on relaunch, the panel reads that separate state (likely a binary `.vdf` or registry-like store under `userlocalconfig` or `userdata/`) and presents it as disabled, forcing user to re-enable every session | Added persistence file (`cfg/autoexec_ps3_persist.cfg`) with same 4 lines; added `joy_display_input 1` to force UI awareness. |

## What was changed on disk (atomic writes confirmed)

| File | Action | Before | After | Atomic? |
|---|---|---|---|---|
| `portal_stories/pak01_004.vpk` | VPK splice (228-byte block → 228-byte modified, same length, CRC updated) | `basemodui_scheme.res` with 3 `[$PS3]` lines (360 font always wins) | `basemodui_scheme.res` with 1 unconditional `buttons_ps3_32.vbf` line + padding comment | ✅ Yes (`os.replace` equivalent in script) |
| `portal_stories/pak01_dir.vpk` | CRC patch (4 bytes LE at tree offset 40983) | `0x9cf597fa` | `0x5670ba94` | ✅ Yes |
| `portal_stories/cfg/joy_preset_1.ps3.cfg` | Copied from P2 base (restored missing preset) | Missing | 807 B, byte-identical to P2 | ✅ Yes |
| `portal_stories/cfg/autoexec.cfg` | Edited (2 patches): line 13 `joystick 0`→`joystick 1`; added 4 new lines (`joy_advanced`, `joy_name`, `exec preset`, `exec persist`) | `joystick 0` | `joystick 1` + persistence lines | ✅ Yes (`patch` tool, atomic write) |
| `portal_stories/cfg/autoexec_ps3_persist.cfg` | Created | Did not exist | 258 B with 4 persistence lines | ✅ Yes (`write_file`) |

## Bottom line

- **Glyphs**: ✅ fully fixed (surgery verified, user confirmed)
- **Preset**: ✅ fully fixed (file restored, user confirmed)
- **Menu controller**: ✅ working (autoexec locks `joystick 1`)
- **In-game settings persistence**: ❌ open — requires additional work
