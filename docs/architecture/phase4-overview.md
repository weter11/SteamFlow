# Phase 4 — Containerized Steam Launch: Offline Emulator → Steam Linux Runtime

> Status: **IMPLEMENTED + LIVE-VERIFIED (2026-08-15)**. Merged into `main` via
> the `phase4/containerized-launch` branch (commits `9402712`…`ff71bfe`).
> This is the umbrella document for Phases 4.1–4.4; each sub-phase has its
> own design doc (see the index below).

## What Phase 4 delivered

SteamFlow can now run Windows games in **three** Steam-mediated modes, the
last of which puts the game inside Valve's official **Steam Linux Runtime
(SLR)** container:

| SteamMode | Client | Game runs in | Steamworks bridge |
|---|---|---|---|
| `Auto` | Windows Steam client (Wine prefix) | Wine/Proton prefix | Windows `steamclient.dll` (named pipe, wineserver-scoped) |
| `OfflineEmulated` | none | Wine prefix | local Goldberg-style emulator |
| `OnlineContainerized` | **native** Linux Steam (host) | SLR container (`steamrt4`) | Proton `lsteamclient.dll` → `steamclient.so` (network IPC) |

In `OnlineContainerized` **no secondary Windows `steam.exe` is ever spawned**
— the game's `SteamAPI_Init()` is intercepted by Proton's native
`lsteamclient.dll` and routed across the container namespace to the host
Steam client.

## Phase index

| Phase | Doc | Delivered |
|---|---|---|
| 4.1 | `phase4-offline-emulator-mode.md` | `OfflineEmulated` SteamMode — clientless launch with a local emulator satisfying the Steam API surface |
| 4.2 | `phase4-runtime-provisioning.md` | `RuntimeManager` (SLR download/verify/extract/parse into `~/.config/SteamFlow/runtimes/<id>/`) + `PressureVesselBuilder` (native Rust `pressure-vessel-wrap`/`bwrap` argv builder) |
| 4.3 | `phase4-containerized-launch.md` | `OnlineContainerized` pipeline — real `pressure-vessel-wrap` contract (runtime `run` script, `--filesystem`/`--env-if-host`/one `--`), Steam IPC bridge, live `test-launch` evidence |
| 4.4 | `phase4-runtime-repair.md` | Runtime integrity repair CLI (`runtime status` / `runtime repair --force`), `force_reprovision` + `purge`, whole-tree exec-bit fix, runtime status + inline Repair in the TUI, container-aware `test-diff` log capture, tool-app PICS access-token fix |

## Key components

- **`src/container/runtime.rs`** — `SteamRuntimeId` (`scout`/`soldier`/`sniper`/`steamrt4`),
  `RuntimeManager`: `provision_from_depot_dir` / `provision_from_archive`
  (tar, nested-layout normalization via `find_runtime_root`), `ArchiveVerification`
  (mtree/hash), `client_managed_runtime` (prefers Valve's
  `SteamLinuxRuntime_<line>` installs), `resolve_runtime_root`, hardened
  `is_usable_runtime_root` (non-empty entry point + `VERSIONS.txt`),
  `parse_versions_txt` (legacy `VERSION name rev`, `KEY=VALUE`, and the real
  tab-separated SLR table), `purge` + `force_reprovision`,
  `ensure_runtime_executable` (whole-tree exec-bit repair).
- **`src/container/pressure_vessel.rs`** — `HostResourceDetector`
  (Vulkan ICDs, EGL vendors, `/dev/dri` + `/dev/nvidia*`, X11/Wayland, audio
  sockets) and `PressureVesselBuilder` for the two command flavors.
- **`src/container/launch.rs`** — containerized command construction:
  per-game prefix (`compatdata/<appid>/pfx`) + game dir mounts, pure-PE
  Proton as the in-container runner, host resource pass-through.
- **`src/headless.rs`** — `runtime status [<line>]`, `runtime repair <line>
  [--force]`, `test-download-runtime`, `test-diff` (auto-captures
  `~/steam-<appid>.log` via `PROTON_LOG=1` when no reference exists).
- **`src/steam_client.rs`** — PICS access-token support so owner-only tool
  apps (SLR app 4183110, Valve Protons) expose depots + the real SteamDB
  `installdir` (`SteamLinuxRuntime_4`, not the sanitized display name).
- **`src/ui.rs`** — Runtime Settings shows
  `Runtime: Steam Linux Runtime 4.0 (steamrt4) [Valid · <rev>]` (or
  `[Missing / Corrupt]` + inline **Repair Runtime**), status via
  `AsyncOp::RuntimeRepaired`.

## Verification

- `cargo check --all-targets` — clean.
- `cargo test --all-targets` — 140 lib tests + all integration suites green
  (provisioning cycles, `VERSIONS.txt` parsing, exec-bit repair,
  force-reprovision, builder argv shape).
- **Live runtime repair** — `steamflow runtime repair steamrt4 --force`
  re-downloaded the corrupt SLR 4.0 depot (672 MB) and force-reprovisioned it:
  `✅ repaired (revision 4.0.20260805.254769)`, `✅ passes
  is_usable_runtime_root()`. The truncated `usr-mtree.txt.gz` (0 bytes →
  358 KB) and 0-byte `VERSIONS.txt`/`_v2-entry-point` were replaced.
- **Live containerized boot** — `steamflow test-launch 620` (OnlineContainerized,
  pure-PE Proton) boots Portal 2 inside `steamrt4`: `bwrap` up, Proton
  running, `portal2.exe` alive (RTX Remix bridge also loads), wine log shows
  d3dx asset loading. The Phase 4.3 truncated-archive error and the Phase 4.4
  "no common CPU arch" abort are both gone.

## Root-cause fixes discovered during Phase 4.4 live testing

1. **Tool-app PICS access token** — SLR/Proton appinfos return `public_only=1`
   with no depots or `installdir` unless the PICS request carries the per-app
   access token. Fixed in `install_game` + `resolve_install_game_info`.
2. **Depot downloads strip the executable bit** — every file lands 0644.
   That broke (a) preflight's "Runner binary is not executable" and (b)
   pressure-vessel's graphics-provider detection (its
   `libexec/steam-runtime-tools-0/*` tools must be +x, else provider
   enumeration fails and the container aborts with "None of the supported CPU
   architectures are common to the graphics provider and the container").
   Fixed by `ensure_runtime_executable` walking the whole tree.
3. **Real `VERSIONS.txt` is a tab-separated table** — not the legacy
   `VERSION <name> <rev>` form; `deployment_state` also wrongly required
   `manifest.json` (steamrt4 ships `metadata` instead). Both corrected.

> Note: the suggested `PRESSURE_VESSEL_ARCHS=x86_64-linux-gnu` knob does not
> exist (`PRESSURE_VESSEL_ARCHITECTURES` is the real variable, hardcoded by
> the runtime `run` script) and `--env-if-host` cannot change the host-side
> arch selection — empirically rejected in favor of the exec-bit fix.

## Known limitations / flags

- `OnlineContainerized` needs the **native** Linux Steam client on the host
  (its 32-bit core requires i386 libs this host lacks) — the container boot
  itself is verified; full Steamworks connectivity is environment-gated.
- `runtime repair --force` always re-downloads the depot even when the
  client-managed `SteamLinuxRuntime_<line>/` already passes
  `is_usable_runtime_root()`; a future optimization could skip the download.
