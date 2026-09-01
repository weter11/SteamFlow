<img src="Assets/steamflow-logo.png" alt="SteamFlow logo" title="SteamFlow" align="left" height="65" />

# SteamFlow

A custom, lightweight Steam launcher and client written in Rust.

SteamFlow is the modern successor to the OpenSteamClient project, leveraging Rust for performance, safety, and a better developer experience. It uses [`steam-vent`](https://codeberg.org/steam-vent/steam-vent) for Steam network communication and [`egui`](https://github.com/emilk/egui) for the user interface.

# Current status

SteamFlow is in active development and has reached a functional alpha-level state. Authentication, library management, install/update/verify, Steam Cloud, and the native Rhai game-fixup engine are implemented. Multi-task downloads, the launch pipeline (with both launch mode and Steam client/API mode), and the Windows Steam client lifecycle (Install / Manage / Repair / Backup / Restore) are partially implemented; see [Implemented](#implemented) below.

SteamFlow is **not affiliated with, endorsed by, or sponsored by Valve**. "Steam" and "Valve" are trademarks of Valve Corporation.

# Implemented

The following are present in the current code base. Phase status and design rationale live in [`docs/architecture/`](docs/architecture/).

## Core Steam

- **Authentication** — login with password, Steam Guard (email / device codes), Steam Guard Mobile App confirmation, session restoration via refresh tokens.
- **Library** — fetch owned games, scan local installs (including standalone mods such as AppID 601300), tier-aware cover caching (hero → library → header), search and filtering, basic game launching.
- **Installation & Updates** — Manifest → Security → Chunks download pipeline, case-insensitive path resolution, hash-checked chunk resume, Update / Uninstall / Verify Integrity.
- **Steam Cloud** — sync and restore.

## Launch pipeline

- **Launch modes (how the game is launched):**
  - `DirectWine` — run the game directly under the selected runner.
  - `SteamAppLaunch` — launch via the Windows Steam client using `-applaunch`.
  - `SteamProtocol` — launch via a `steam://rungameid/<id>//...` URI.
  These are configured per-game in **Game Properties**.
- **Steam client / API integration modes (how Steamworks is satisfied):**
  - `Auto` — default behavior.
  - `OfflineEmulated` — clientless launch via a local steam_api emulator (no Steam process is spawned).
  - `OnlineContainerized` — run the game inside Valve's `steamrt4` Steam Linux Runtime via `pressure-vessel-wrap`; Steamworks is bridged by Proton's native `lsteamclient.dll` over IPC to the host Steam client. Requires a Proton compatibility tool runner such as `steamflow-proton-11.0-purepe` (validated at save time).
- **Windows Steam client lifecycle** — Install / Manage / Repair / Backup / Restore. Repair reinstalls via the Wine uninstaller + `SteamSetup`, with user data (library, saves) staged and merged back.
- **Native Rhai game-fixup engine** — a `protonfixes`-style scripting API (`override_dll`, `set_env`, `disable_nvapi`, registry execution, launch args). Seed scripts ship for AppIDs `227300`, `359550`, `271590` (GTA V), `1151640`, `883710` (Resident Evil 2), and `489830` (Skyrim Special Edition), ported from `protonfixes/gamefixes/`.
- **Per-game runner override / runner mixing** — e.g. wine-tkg for the Steam background and CachyOS Proton for the game in the same `WINEPREFIX`.
- **Pre-launch VRAM exhaustion guard** — best-effort `nvidia-smi` probe before launch with a per-process modal and "Launch anyway" / Cancel / "Don't check again this session" (`LauncherConfig.vram_warn_threshold_pct`, default 75%; set to 0 to disable).
- **Graphics backend policy** — `GraphicsBackendPolicy`, `D3D7BackendPolicy`, and `D3D12ProviderPolicy` (Auto / explicit choices for WineD3D / DXVK / VKD3D-Proton / VKD3D-Wine / D7VK). Game-local DLL priority is absolute.
- **Developer debug overlay** — an optional `~/.config/SteamFlow/debug.json` is applied as the highest-precedence env overlay on every launch; a missing or malformed file is a no-op.

# Roadmap / next steps

- Collections / Categorization
- Friends list & Chat
- Workshop management (browse / subscribe / install — distinct from the current per-game **Mods** tab, which is a custom mod launcher/executable/script mechanism)
- Depot browser GUI refinements
- Replication of Steam input but based on other principals

# Getting started

## Prerequisites (Linux)

SteamFlow targets Linux-first. On Ubuntu 24.04 (or a comparable Debian-derived distribution):

```bash
sudo apt-get update
sudo apt-get install build-essential pkg-config libssl-dev libx11-dev libxi-dev libxrandr-dev libxinerama-dev libxcursor-dev libxkbcommon-dev libasound2-dev libudev-dev libwayland-dev libgtk-3-dev libpulse-dev libdbus-1-dev libegl1-mesa-dev libgles2-mesa-dev liblzma-dev
```

## Build and run

```bash
git clone https://github.com/weter11/SteamFlow.git
cd SteamFlow
cargo run --release
```

# Configuration

SteamFlow persists launcher-wide configuration under `~/.config/SteamFlow/` (resolved via `directories::ProjectDirs`, not relative to the executable). Notable files:

- `session.json` — encrypted refresh tokens used for auto-login.
- `user_apps.json` — per-game settings: launch mode, Steam client/API mode, runner override, launch options, custom mod executable/script, beta branch, graphics backend policies, custom env vars.
- `runtimes/<id>/` — Valve `steamrt4` SLR images provision here. Inspect or repair via the CLI (see [CLI / diagnostics](#cli--diagnostics)).
- `debug.json` (optional, dev-only) — env-var overlay applied as the **highest** launch precedence. Missing or malformed → silently ignored. Example:
  ```json
  { "env": { "WINEDEBUG": "+mfplat,+loaddll", "DXVK_LOG_LEVEL": "info" } }
  ```

Launcher-wide and per-game configuration are kept separate: global preferences (Steam Library path, default runner, VRAM threshold, `Skip Steam self-update`, `Steam Launch Config`, etc.) live under the launcher config; per-game overrides win over launcher defaults.

# Architecture & development notes

Reverse-engineering notes, phase design docs, and decision records live under [`docs/architecture/`](docs/architecture/). Topics covered there include:

- The containerized launch path and `steamrt4` runtime provisioning / repair.
- The `OfflineEmulated` and `OnlineContainerized` SteamModes and the save-time validation guard for `OnlineContainerized`.
- The pure-PE Proton 11.0 runner (`steamflow-proton-11.0-purepe`) and the `steamflow-runner-wine11-wow64` runtime — these are distinct artifacts.
- The native Rhai fixup engine and its `protonfixes` translation standard.
- The DXVK / VKD3D / D7VK resolver and `dxvk_enabled=false` end-to-end behavior.

Local development commands (run from the repo root):

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
```

`Cargo.toml` declares the package license as MIT; the full text is in [`LICENSE`](LICENSE).

# CLI / diagnostics

SteamFlow ships a headless CLI surface in addition to the GUI. The same `steamflow` binary dispatches subcommands instead of opening the window:

```bash
steamflow runtime status [<line>]          # show SLR runtime state
steamflow runtime repair <line> [--force]  # purge + re-provision
steamflow test-download-runtime <line>     # depot acquisition helper
steamflow test-diff <appid>                # auto-captures ~/steam-<appid>.log via PROTON_LOG=1
steamflow test-steam                       # exercise Steam auth/network paths
steamflow list                             # dump the owned library
steamflow test-launch <appid>              # drive a launch headlessly
steamflow test-mod <appid>                 # drive a mod-launch headlessly
steamflow test-download-proton <args>      # Proton tool-app depot helper
steamflow --help                           # full subcommand list
```

The CLI exists for scripting, server use, and CI / dogfooding; the GUI is the normal user surface.

SteamFlow itself does not use CEF, WebViews, or Electron for its UI. When SteamFlow launches the Windows Steam client (under `SteamAppLaunch` / `SteamProtocol`), that client does include web-based components — that is Steam's own UI, not SteamFlow's.

# Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

# Acknowledgments

SteamFlow builds on the reverse-engineering work of many projects. Special thanks to:

- **[OpenSteamClient](https://github.com/OpenSteamClient/OpenSteamClient)** — the original project and resource base that SteamFlow inherits and modernizes.
- **[steam-vent](https://codeberg.org/steam-vent/steam-vent)** — the Steam network protocol implementation used by SteamFlow.
- **[Aurelia](https://github.com/Drackrath/Aurelia)** — an independent, headless Rust Steam CLI by Drackrath. Aurelia and SteamFlow share the `steam-vent` network layer and the OpenSteamClient lineage, but pursue different goals: Aurelia is terminal-first and scriptable for headless / SSH / server workflows; SteamFlow is a native desktop application. They are independent projects, not companion components.
- **[egui](https://github.com/emilk/egui)** — the immediate-mode GUI library.
- **[open-steamworks](https://github.com/SteamRE/open-steamworks)** — research resources.
- Powered by `steam-cdn` (Vendored & Modified) and the `zip` crate.

# License

This project is licensed under the **MIT License** — see [`LICENSE`](LICENSE) for the full text.

# Q&A

## Is this a full replacement for Steam?

SteamFlow aims to provide a lightweight alternative for launching games and managing your library. Some features — VAC-secured games, ISteamHTMLSurface (Source engine MOTDs), and the official Steam workshop browser — may never be supported due to proprietary limitations.

## Is it safe to use?

SteamFlow uses official Steam protocols. However, it is a 3rd-party client and is not endorsed by Valve. Use at your own risk.
