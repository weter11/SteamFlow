# Comparison: OpenSteamClient vs. SteamFlow

This document compares the legacy C# implementation (`OpenSteamClient`) and the new Rust-based prototype (`SteamFlow`).

| Feature | OpenSteamClient | SteamFlow |
|-|-|-|
| **Language** | C# (Avalonia) | Rust (egui/eframe) |
| **Steam Integration** | Partially open; wraps Valve's `clientdll` binaries. | Fully open; uses `steam-vent` (pure Rust implementation of Steam protocol). |
| **Architecture** | Dependent on official Steam binary behavior and state. | Independent client implementation following Steam's network protocol. |
| **Authentication** | Handled by `clientdll`. | Custom implementation via `steam-vent` (supporting RSA auth and Steam Guard). |
| **Binary Size** | Larger (requires .NET runtime + Steam binaries). | Compact, single native binary. |
| **Platform Support** | Windows & Linux. | Primarily Linux-focused (targets Ubuntu 24.04). |
| **Download System** | Uses Steam's internal download manager. | Custom 4-phase pipeline (manifest -> security -> decode -> chunk). |
| **Development Status** | Feature-rich but legacy/heavy. | Lightweight prototype, rapidly evolving. |

## Why SteamFlow?
SteamFlow was started to explore a truly open-source alternative that doesn't rely on opaque, 32-bit legacy Steam binaries. By using `steam-vent`, we gain better control over the networking layer, improved performance, and a more modern development stack in Rust.

While `OpenSteamClient` remains more feature-complete in areas like UI widgets and settings, `SteamFlow` provides a more robust foundation for a modern, lightweight Linux launcher.
