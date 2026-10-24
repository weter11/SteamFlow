# SteamFlow History

Covered up to: b12c52fe8dd8 (2026-02-28)

## February 2026

2026-02-13: Initial commit — Rust Steam client scaffold (steam-vent protocol, egui/eframe UI, Proton/Wine launch integration). 34ee632
2026-02-13: Reorganize project folders (manifest parsing hardening). 15f0505
2026-02-14: Exclusion-based depot filtering and platform selection UI. bde2d87
2026-02-14: Heuristic launch option selection. db8de96
2026-02-14: Multi-launch option support. 5db0b4a
2026-02-14: Game verification, delta updates, and uninstallation UI. 28a9e67
2026-02-14: Steam Branch (Beta) support. f0530e0
2026-02-14: Tabbed dashboard UI redesign with safe shortcuts. 6d3a472
2026-02-14: Game install and verification made fully async. 8be5fc7
2026-02-15: Permissive VDF parsing, fuzzy VDF fallback, depot selection feedback, and install pipeline improvements. PR #4
2026-02-16: Account tab, logout, and robust VDF parsing (PICS binary VDF, hybrid parsing, language filtering). PR #7
2026-02-16: Depot Manager and selective installation. c4b591c
2026-02-16: Server resolution added to game installation. b3c661c
2026-02-16: Switch to steam-cdn for hybrid download logic (dependency vendoring). 0542112
2026-02-17: ContentServerDirectory service and CDN auth tokens. PR #9
2026-02-17: Portability improvements, lazy metadata/image fetching, and download progress bar. PR #10
2026-02-17: App manifest writer with version tracking. f871154
2026-02-17: Unified download pipeline with smart updates; logo and asset refresh. f876dab
2026-02-18: Unified download pipeline, Verify Mode, Pause/Resume, custom launch options, and environment variables. PR #13
2026-02-18: Image cache directory support (config_dir, opensteam_image_cache_dir). 6bc4524
2026-02-19: Library cache loaded on startup before session restoration. PR #17
2026-02-20: Master Prefix architecture for Ghost Steam introduced. b0a195b
2026-02-20: Windows Proton launch environment injection and shielding (WINEPATH, SteamGameId, working directory, env shields). ff83210
2026-02-20: "Trojan Horse" batch script for registry healing and DRM reliability. 303bd65
2026-02-20: Background Steam and game launch unified into a single batch script. e2bc51c
2026-02-24: Master Prefix architecture finalized (environment shields, native vstdlib/tier0 DLL forcing). b7db597
2026-02-25: Prefix Surgery added to Trojan Horse script. 6c36f7d
2026-02-26: Ghost Executable evasion for Proton launch script. b41f9dc
2026-02-26: Smart runner resolution and standard Wine command structure. b66b9b0
2026-02-26: Batch script replaced with native Rust process orchestration. 765f87a
2026-02-26: Master Prefix architecture merged. PR #18
2026-02-27: Ultimate Batch Debugger added to Windows Proton launch script. PR #19
2026-02-28: Proton runner decoupled from Steam Runtime toggle. PR #21
