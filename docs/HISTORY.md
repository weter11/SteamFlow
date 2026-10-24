# SteamFlow History

Covered up to: ebf7f4420573 (2026-06-27)

Scope: 2026-02-13 – 2026-06-27 · 229 commits · 37 merged pull requests.
Entries: 55 — February 36, March 12, April 1, May 0, June 6.

## February 2026 — 36 entries

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
2026-02-17: Server resolution added to game installation, with steam-cdn vendored for the hybrid download pipeline and strict CDN server filtering. PR #8 (merged from b3c661c, 0542112) [steam-cdn] Vendored steam-cdn 1.0.0 with a local patch adding `CDNClient::download_depot`, the `GetCDNAuthToken` handshake, and the steam-vent 0.3 → 0.4 bump.
2026-02-17: ContentServerDirectory service and CDN auth tokens. PR #9 [steam-cdn] Added `x-cdn-auth-token` header and `?token=` propagation, plus zip detection in manifest deserialisation.
2026-02-17: Portability improvements, lazy metadata/image fetching, and download progress bar. PR #10 [steam-cdn] Added `on_progress` / `on_manifest` callback hooks.
2026-02-18: App manifest writer with version tracking, logo/asset refresh, and unified download pipeline with smart updates. PR #12 (merged from f871154, f876dab) [steam-cdn] Added `ManifestFile::download()` with per-chunk verification.
2026-02-18: Unified download pipeline, Verify Mode, Pause/Resume, custom launch options, and environment variables. PR #13 [steam-cdn] Added existing-file length comparison for resume/delta; Verify Mode itself lives in SteamFlow, not in the crate.
2026-02-18: Image cache directory support (config_dir, opensteam_image_cache_dir). 6bc4524
2026-02-19: Library cache loaded on startup before session restoration. PR #17
2026-02-20: Master Prefix architecture for Ghost Steam introduced. b0a195b
2026-02-20: Windows Proton launch environment injection and shielding (WINEPATH, SteamGameId, working directory, env shields). ff83210
2026-02-20: "Trojan Horse" batch script for registry healing and DRM reliability. 303bd65
2026-02-20: Background Steam and game launch unified into a single batch script. e2bc51c
2026-02-21: Properties modal removed; beta-branch selection and environment-variable editing moved into the per-game Properties tab, with lazy "Check for Beta Branches" and a persistent edit buffer that does not reset every frame. 8a36327
2026-02-24: Master Prefix architecture finalized (environment shields, native vstdlib/tier0 DLL forcing). b7db597
2026-02-25: Prefix Surgery added to Trojan Horse script. 6c36f7d
2026-02-25: Trojan Horse script drops a physical steam_appid.txt for Source Engine games and the Steam boot wait grows to 10 s. 9e33c0c
2026-02-25: Launch script invoked through `cmd /c`. b933f32
2026-02-26: Ghost Executable evasion (ghost_steam.exe decoy) — temporary experiment; reverted the same day in 33573fc. b41f9dc
2026-02-26: Trojan Horse script simplified: ghost decoy, DLL nuking (Prefix Surgery) and registry healing dropped; runner resolution extended to bare wine/wine64 binaries. 33573fc
2026-02-26: Smart runner resolution and standard Wine command structure. b66b9b0
2026-02-26: Batch script replaced with native Rust process orchestration. 765f87a
2026-02-26: Master Prefix architecture merged. PR #18
2026-02-28: Proton launch logic refactored: master steam.exe discovery helper, WINEPREFIX derived by walking up from steam.exe. 18d8944
2026-02-28: SteamPrefixMode (shared master prefix vs per-game prefix) added to settings and per-game Properties; Cloud Sync upload gated by the cloud-sync toggle. 084c947
2026-02-28: Proton runner decoupled from Steam Runtime toggle. PR #21

### February 2026 exclusions

Each reason below was checked against the commit's own diff, not its subject line.

- PR #1 (2026-02-14) — fix-only, compilation/clippy/CI: 050e18a, ac5184c, 2758f80.
- PR #2 (2026-02-15) — fix-only, Tokio runtime panics, Proton path resolution, Steam identity for native Linux, platform/VDF/launch-option fixes: 4ce501a, ead3cf7, 087ee68, 9bd5300.
- PR #20 (2026-02-27) — fix-only, runner mismatch, IPC safety lock, background Steam launch sequence: b96a56a, 9192d69, 51020a7.
- PR #19 (2026-02-27) — diagnostic scaffolding: the "Ultimate Batch Debugger" is a debug block written into the generated .bat (a2fb219), not a feature.
- 24ff957 — fix-only: background Steam launch made path-safe inside Wine's cmd.exe (`cd /d` before `start steam.exe`).
- 41ff40d — debug prints plus a get_launch_info → get_product_info rename; no behaviour change.
- 51bb2cde — VDF/depot debug logging (hex dump) plus one unit test for should_keep_depot().
- 000e0b07 — debug logging only, inside install_game.
- 4657f683 — diagnostic manifest inspection in the decoder and the vendored steam-cdn tree.
- 5dd63e3 — refactor of the image-cache helpers; the behaviour it fixes is covered by the 6bc4524 entry.
- 762593c, d50bea3, a957d69, 8afeae0 — README/CONTRIBUTING/CI/documentation text only.

Commits inside a documented PR's branch are covered by that PR's entry; a commit is listed individually only when its own diff changed behaviour.

All 14 pull requests merged in February are accounted for: 10 entries, 4 exceptions.

## March 2026 — 12 entries

2026-03-02: Steam launch stabilisation: overlay injection and CEF/steamwebhelper disabled, readiness detection by log mtime and already-running-instance check, MangoHud injection for raw Wine runners, runner component detection (bundled/prefix/system DXVK, VKD3D), and a SteamLaunchConfig (no-browser, no-friends, no-overlay, no-chat, no-VR, big-picture) exposed in settings. PR #22
2026-03-03: Graphics layer management: DXVK, VKD3D and VKD3D-Proton installed into or removed from a prefix from the settings UI, with a GraphicsLayerConfig and generated DLL overrides. PR #23
2026-03-04: WINEPREFIX resolution centralised in resolve_master_wineprefix and shared between the settings UI and the launch path, with improved master-prefix layout detection. PR #24
2026-03-05: Launch refactored into a staged pipeline (resolve → prefix → components → command → spawn → finalize) behind a Runner abstraction, with structured per-session logging, stage timing and an override-conflict validator; unsafe default d3d/dxgi overrides dropped. PR #26
2026-03-07: Diagnostics and preflight: effective-environment snapshot with sanity checks, preflight validation of exe/cwd/runner/prefix, per-DLL provider priority resolver (game-local > runner > system), per-profile graphics backend policy (Auto/WineD3D/DXVK/VKD3D), and per-session command/env/preflight artifacts. PR #27
2026-03-07: Runner filesystem discovery with version parsing for wine-tkg and Proton layouts, plus authoritative game-path resolution. PR #28
2026-03-08: WINEDLLPATH set for bundled DLLs and hybrid-graphics (PRIME) detection. PR #29
2026-03-12: Per-game GPU selection, a conservative Auto graphics policy that stops aggressive environment injection, and a launch invariant validator that reports an effective launch configuration. PR #31
2026-03-13: Architecture-aware strict DXVK policy: executable architecture detection feeds DLL validation and Wine log diagnostics. PR #32
2026-03-15: Explicit DXVK made strict: no WineD3D fallback, strict-load and policy-violation invariants, and capability-set DLL validation. PR #33
2026-03-17: Symlink deployment mode (component DLLs symlinked into the prefix), custom DXVK/VKD3D component paths, effective game prefix separated from runtime deployment, NVAPI component detection. PR #34
2026-03-18: Launch verification record (verified / uncertain / failed_after_spawn) for early-exiting processes; per-game NVAPI toggle; D3D10 and D3D10.1 validation. PR #35

### March 2026 exclusions

- 1105dd6 — Batman early-startup investigation: Wine log capture and pipeline instrumentation only.
- 3477620 — Batman startup regression fix (invariant plus path handling); no new feature.
- 9cae845 — stops emitting d3d10/d3d10_1 alias overrides; part of the same fix.
- 71a4a7b — removes d3d10/d3d10_1 runtime logic and keeps real DXVK DLLs; fix-only.
- eb1f22e — adds startup-milestone classification (process bootstrap → Steam init → game-local DLLs) and logs where Batman stops next to an Amnesia comparison; diagnostics only.
- 76d13f4 — Batman early-startup fix plus extra environment diagnostics; fix-only.

All 12 pull requests merged in March are documented above; no merged PR was skipped.


## April 2026 — 1 entry

2026-04-19: Windows Steam discovery toggle and per-game runtime option. PR #40

### April 2026 exclusions

- PR #36 (2026-04-15) — diagnostics only: Steam handoff diagnostics, running-instance detection, prefix resolution unification.
- PR #37 (2026-04-16) — fix-only: SteamAPI visibility and per-game prefix settings.
- PR #39 (2026-04-16) — CI maintenance: Node.js 20 deprecation and artifact uploads.

## May 2026 — 0 entries

No new features or subsystems; documentation-only changes excluded.

### May 2026 exclusions

- c0222b7 — README clone-instruction text only.

## June 2026 — 6 entries

2026-06-18: Emergency kill button (kill all Wine processes in a prefix) for prefix recovery. 5efe1c9
2026-06-21: Modern Proton 11+ and CachyOS unified layout discovery. PR #46
2026-06-21: Proton/Wine Manager in Settings. PR #47
2026-06-21: Wine control panel settings action. PR #48
2026-06-21: Steam and game runner routing split. PR #50
2026-06-23: Repair/reinstall capability for the master Windows Steam prefix (backup/restore/repair lifecycle, full Steam Runtime lifecycle with bare Wine). PR #51

### June 2026 exclusions

- PR #43 (2026-06-18) — fix-only launch bugs; only the emergency kill button (5efe1c9) is documented above.
- PR #56 (2026-06-25) — test relocation only.
- PR #57 (merged 2026-07-24) — diagnostic capture and WINEDEBUG experiments: 27a1fc1, dc2d8f7, 3f04f29, a308a0c, 284efb4, 087aefb, 5b84623, 93d3d32, ebf7f44; the PR's remaining three commits (78073ca, b9927f3, 3951421) are dated 2026-07-24 and belong to the July section.
- 30c0043, a558bca, 929e915 — launch-bug fixes.
- d166f69, a9dd7ae — refactoring of component discovery (covered by PR #46).
- f4b4d5c, e4e63a8, 46f96fa — covered by PR #47, PR #48, and PR #50.
- a2c483b, 3aee8e4, 9596641 — covered by PR #51.
- 36c5b87 — covered by PR #56.

All 11 pull requests merged in April-June are accounted for: 6 as entries, 5 as exclusions above.
