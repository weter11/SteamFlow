# SteamFlow History

Covered up to: b12c52fe8dd8 (2026-02-28)

Scope: 2026-02-13 – 2026-02-28 · 103 commits · 14 merged pull requests.

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
2026-02-16: Server resolution added to game installation, with steam-cdn vendored for the hybrid download pipeline and strict CDN server filtering. PR #8 (b3c661c, 0542112)
2026-02-17: ContentServerDirectory service and CDN auth tokens. PR #9
2026-02-17: Portability improvements, lazy metadata/image fetching, and download progress bar. PR #10
2026-02-17: App manifest writer with version tracking, logo/asset refresh, and unified download pipeline with smart updates. PR #12 (f871154, f876dab)
2026-02-18: Unified download pipeline, Verify Mode, Pause/Resume, custom launch options, and environment variables. PR #13
2026-02-18: Image cache directory support (config_dir, opensteam_image_cache_dir). 6bc4524
2026-02-19: Library cache loaded on startup before session restoration. PR #17
2026-02-20: Master Prefix architecture for Ghost Steam introduced. b0a195b
2026-02-20: Windows Proton launch environment injection and shielding (WINEPATH, SteamGameId, working directory, env shields). ff83210
2026-02-20: "Trojan Horse" batch script for registry healing and DRM reliability. 303bd65
2026-02-20: Background Steam and game launch unified into a single batch script. e2bc51c
2026-02-21: Properties modal removed; beta-branch selection and environment-variable editing moved into the per-game Properties tab, with lazy "Check for Beta Branches" and a persistent edit buffer that no longer resets every frame. 8a36327
2026-02-21: Background Steam launch fixed inside Wine's cmd.exe by changing into the Steam directory before `start steam.exe`, removing the path-parsing failures. 24ff957
2026-02-24: Master Prefix architecture finalized (environment shields, native vstdlib/tier0 DLL forcing). b7db597
2026-02-25: Prefix Surgery added to Trojan Horse script. 6c36f7d
2026-02-25: Trojan Horse script drops a physical steam_appid.txt for Source Engine games and the Steam boot wait grows to 10 s. 9e33c0c
2026-02-25: Launch script invoked through `cmd /c`, with tasklist output redirected to a physical C:\steamflow_debug.txt. b933f32
2026-02-26: Ghost Executable evasion (ghost_steam.exe decoy) — temporary experiment; reverted the same day in 33573fc. b41f9dc
2026-02-26: Trojan Horse script simplified: ghost decoy, DLL nuking (Prefix Surgery) and registry healing dropped; runner resolution extended to bare wine/wine64 binaries. 33573fc
2026-02-26: Smart runner resolution and standard Wine command structure. b66b9b0
2026-02-26: Batch script replaced with native Rust process orchestration. 765f87a
2026-02-26: Master Prefix architecture merged. PR #18
2026-02-27: Ultimate Batch Debugger added to Windows Proton launch script. PR #19
2026-02-28: Proton launch logic refactored: master steam.exe discovery helper, WINEPREFIX derived by walking up from steam.exe, actionable error when Steam is not installed. 18d8944
2026-02-28: SteamPrefixMode (shared master prefix vs per-game prefix) added to settings and per-game Properties; Cloud Sync upload now actually gated by the cloud-sync toggle. 084c947
2026-02-28: Proton runner decoupled from Steam Runtime toggle. PR #21

### February 2026 exclusions

Each reason below was checked against the commit's own diff, not its subject line.

- PR #1 (2026-02-14) — fix-only, compilation/clippy/CI: 050e18a, ac5184c, 2758f80.
- PR #2 (2026-02-15) — fix-only, Tokio runtime panics, Proton path resolution, Steam identity for native Linux, platform/VDF/launch-option fixes: 4ce501a, ead3cf7, 087ee68, 9bd5300.
- PR #20 (2026-02-27) — fix-only, runner mismatch, IPC safety lock, background Steam launch sequence: b96a56a, 9192d69, 51020a7.
- 41ff40d — debug prints plus a get_launch_info → get_product_info rename; no behaviour change.
- 51bb2cde — VDF/depot debug logging (hex dump) plus one unit test for should_keep_depot().
- 000e0b07 — debug logging only, inside install_game.
- 4657f683 — diagnostic manifest inspection in the decoder and the vendored steam-cdn tree.
- 5dd63e3 — refactor of the image-cache helpers; the behaviour it fixes is covered by the 6bc4524 entry.
- 762593c, d50bea3, a957d69, 8afeae0 — README/CONTRIBUTING/CI/documentation text only.

Commits inside a documented PR's branch are covered by that PR's entry; a commit is listed individually only when its own diff changed behaviour.
