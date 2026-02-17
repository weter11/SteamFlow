# Comparison: Official Steam vs. OpenSteamClient vs. SteamFlow

This document compares the official Steam client, the legacy `OpenSteamClient` project, and the modern `SteamFlow` client.

| Feature | Official Steam Client | OpenSteamClient | SteamFlow (This Project) |
|---|---|---|---|
| **Architecture** | Electron (UI) + C++ (Backend) | C++ / Qt | Pure Rust (Backend + UI) |
| **RAM Usage (Idle)** | ~400MB - 800MB | ~100MB - 200MB | < 50MB |
| **Download Engine** | CDN + P2P LAN | Standard CDN | Multi-Threaded CDN (Hybrid Architecture) |
| **Startup Speed** | Slow (Updates, Verifying) | Fast | Instant ("Just-In-Time" Client) |
| **Open Source** | No | Yes | Yes (MIT/Apache) |

## Why SteamFlow?
SteamFlow was started to explore a truly open-source alternative that doesn't rely on opaque, 32-bit legacy Steam binaries. By using `steam-vent`, we gain better control over the networking layer, improved performance, and a more modern development stack in Rust.

While `OpenSteamClient` remains a powerful reference, `SteamFlow` provides a more robust foundation for a modern, lightweight Linux launcher with superior performance and a smaller footprint.
