<img src="Assets/opensteam-logo.svg" alt="SteamFlow logo" title="SteamFlow" align="left" height="65" />

# SteamFlow
A custom, lightweight Steam launcher and client written in Rust.

SteamFlow is the modern successor to the OpenSteamClient project, leveraging Rust for performance, safety, and a better developer experience. It uses `steam-vent` for Steam network communication and `egui` for the user interface.

# Current development status
SteamFlow is in active development and serves as the primary project. It has reached a highly functional alpha state, supporting core Steam features like authentication, library management, game installation/updates, and cloud synchronization.

## SteamFlow Roadmap
- [x] **Authentication**
  - [x] Login with password
  - [x] Steam Guard (Email/Device codes)
  - [x] Steam Guard Mobile App confirmation
  - [x] Session restoration (Refresh tokens)
- [x] **Library**
  - [x] Fetch owned games from Steam
  - [x] Scan local installed games
  - [x] Display game covers (automated caching)
  - [x] Basic game launching
  - [x] Search & Filtering
- [x] **Installation & Updates**
  - [x] Download pipeline (Manifest -> Security -> Chunks)
  - [x] Update management
  - [x] Uninstall support
  - [x] Verify Integrity
- [ ] **Features**
  - [ ] Collections / Categorization
  - [ ] Friends list & Chat
  - [x] Steam Cloud integration
  - [ ] Workshop management
  - [x] Proton/Wine integration improvements
  - [x] Depot browser (Download specific builds/files)

# Getting Started
## Prerequisites (Linux)
Ensure you have the following system dependencies installed (Ubuntu 24.04 example):
```bash
sudo apt-get install build-essential pkg-config libssl-dev libx11-dev libxi-dev libxrandr-dev libxinerama-dev libxcursor-dev libxkbcommon-dev libasound2-dev libudev-dev libwayland-dev libgtk-3-dev libpulse-dev libdbus-1-dev libegl1-mesa-dev libgles2-mesa-dev
```

## Build and Run
```bash
git clone https://github.com/OpenSteamClient/OpenSteamClient.git --recursive
cd OpenSteamClient
cargo run --release
```

# Features & Goals
- **No Web Technology:** Unlike the official Steam client, SteamFlow does not use CEF or WebViews for its core interface, making it extremely lightweight.
- **Fast and Responsive:** Built with Rust and `egui` for a native, snappy experience.
- **Privacy Focused:** Open-source implementation of Steam protocols.
- **Linux First:** Great support for Linux, including 64-bit clean architecture and better Proton management.

---

# Legacy: OpenSteamClient (C#)
The original C# implementation of OpenSteamClient has been moved to the `OpenSteamClient/` directory. It is maintained for reference and legacy purposes but is no longer in active development.

# Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

# Credits
- [steam-vent](https://github.com/n00b67/steam-vent) - Steam protocol implementation
- [egui](https://github.com/emilk/egui) - Immediate mode GUI library
- [open-steamworks](https://github.com/SteamRE/open-steamworks) - Research resources
- [Logo and sound assets by nPHYN1T3](https://github.com/nPHYN1T3)

# Q&A
## Is this a full replacement for Steam?
SteamFlow aims to provide a lightweight alternative for launching games and managing your library. Some features like VAC-secured games or ISteamHTMLSurface (Source engine MOTDs) may never be supported due to proprietary limitations.

## Is it safe to use?
SteamFlow uses official Steam protocols. However, it is a 3rd-party client and is not endorsed by Valve. Use at your own risk.
