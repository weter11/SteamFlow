# SteamFlow History

Covered up to: 488170b (2026-10-22)

Scope: 2026-02-13 – 2026-10-24 · 442 author-dated commits · 68 merged pull requests documented.
Entries: 82 — February 36, March 12, April 1, May 0, June 6, July 7, August 17, September 2, October 1.
PR dates follow their merge commits (e.g. PR #66: 2026-07-31); squash merges use the squash commit's date, and rebase merges the author date of the PR's final commit (PR #93: 2026-09-29).

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

## July 2026 — 7 entries

2026-07-24: Steam Runtime readiness gate ahead of launch: signal-based polling with a 30 s cap and early exit, a per-game "requires Steam API" toggle, DX12 overlay suppression, and cached diagnostic parameters. PR #57
2026-07-25: Per-game game runner override (Steam Runtime and game runner may differ), per-game Force WineD3D, a Smart Override action that matches the D3D12 policy to runner capabilities with vkd3d-proton → vkd3d fallback, and a Steam client self-update pin applied at launch. PR #60
2026-07-26: Steam feature enforcement after start-up: CEF/webhelper processes spawned in the prefix are detected once Steam is up and dropped to chmod 000, steamservice.exe joins the kill list, Steam respawns with the user's feature settings, and the no-VR / big-picture toggles are removed. PR #62
2026-07-27: Steam helper enforcement detached from game launch: disabled helpers (webhelper/CEF, friends) are enforced by PID with retries and a start-up delay, so a launch does not wait on them. PR #63
2026-07-30: Wine Tools menu (winecfg, winefile, regedit, taskmgr) and a clean Windows Steam reinstall through the Wine uninstaller that stages user data aside, restores it afterwards, and can skip the client self-update. PR #65
2026-07-31: Direct3D 7 (DX3–7) backend policy with D7VK auto/forced/off, VERSIONS.txt parsing for runner component versions, DXVK-NVAPI detection, an NVAPI checkbox in Graphics Rendering, and the Manual Overrides panel removed. PR #66
2026-07-31: vkd3d-proton launches pair native d3d8/d3d9/d3d10core/d3d11 with DXVK's dxgi, the amd_ags builtin override applies only when the runner ships that builtin, and the effective-backend classifier keys off distinctive DLLs rather than dxgi alone. ba9c7b9

### July 2026 exclusions

- PR #61 (2026-07-25) — internal helpers for runner and wineserver resolution (detect_wineserver_for_runner, kill_wineserver_in_prefix, resolve_effective_proton_name) serving runner-selection fixes; the runner-mixing capability is documented under PR #60.
- a3f2f2c (2026-07-24) — CI configuration: Windows build steps commented out in .github/workflows/rust.yaml.
- ba9c7b9 (2026-07-31) — fix-only: native D3D/DXGI pairing for vkd3d-proton, conditional amd_ags override, and a stricter effective-backend classifier.

6 of the 6 pull requests merged in July (API merged_at, 2026-07-01–2026-07-31) are documented above, plus PR #66 whose merged_at is 2026-08-01T00:27Z while its merge commit is dated 2026-07-31.

## August 2026 — 11 entries (first half, 2026-08-01 → 2026-08-15)

2026-08-01: Game-local DLL priority is absolute: a DLL the game ships itself is left untouched by override generation, and the blanket amd_ags override is dropped. PR #67
2026-08-01: Native Rhai game-fixup API: scripts call override_dll, disable_dll, disable_nvapi, set_reg_dword / set_reg_string, add_launch_arg and remove_env; fixup launch arguments and inline registry writes flow into the launch command, and translated protonfixes examples ship as seed scripts. PR #68
2026-08-03: Windows Steam client onboarding: a Stage 1 login flow inside the launcher and Stage 2 registration of installed libraries in the Windows client, with session detection for modern Steam. PR #69
2026-08-03: Steam client features are enabled by default and shown as positive controls (CEF browser, friends list, chat, overlay), with dependent options flagged while CEF is off. PR #71
2026-08-05: Launch modes with a global selector — Steam-mediated and custom exec — Steam Features collapsed to a single CEF toggle, and library repair for the Windows client. PR #72 [steam-cdn] Read-only target files are made writable before the crate opens them for writing.
2026-08-05: Every on-disk chunk is checked against its manifest SHA-1 in all modes — install, update, repair and verify — with file length only a precondition for the check. PR #73 [steam-cdn] Resume and verify share one SHA-1 chunk check instead of a length-only skip.
2026-08-05: Downloads pause, resume and cancel from the launcher, with operation state carried through the download crate and reflected in the progress display. PR #76 [steam-cdn] Adds OperationController (pause/resume/cancel) and threads it, with aggregate progress callbacks, through manifest downloads.
2026-08-05: File-level progress with an estimated remaining time, a reworked header layout, and cover-art retry. PR #77 [steam-cdn] download_depot reports per-file progress (path, done, total) beside the aggregate counter.
2026-08-05: A multi-task progress queue, a Mods tab with a custom-executable launcher and mod-library indexing, and a cover-art priority chain (hero → library → header). PR #78
2026-08-08: Depot access preflight with progress labels, and tier-aware cover-art fallbacks governed by a refresh cadence. PR #80 [steam-cdn] Depot VDF parsing moves to keyvalues_parser::parse and the crate builds without warnings.
2026-08-15: Valve stack replication, Phases 1–3: pure-PE Proton 11.0, a native Rust Proton ABI, an environment-parity harness, VERSIONS.txt visibility, native prefix seeding, and master Steam session state synced into per-game prefixes. PR #82 [steam-cdn] Zstd (VSZa) chunk decoding added.

### August 2026 exclusions

- PR #74 (2026-08-05) — CI: workflow triggers reduced to a single push/PR run.
- PR #79 (2026-08-06) — docs: AGENTS.md only.
- PR #81 (2026-08-08) — fix: launch-option forwarding in the custom-exec path.
- 0047c02, 5bd4cfd (2026-08-06) — agent-instruction documents (AGENTS.md rules, copilot instructions removed).
- a06a58f (2026-08-08) — CI: pull_request trigger removed from rust.yaml.

14 pull requests merged between 2026-08-01 and 2026-08-15 (API merged_at): 11 entries, 3 exclusions. The block stops at 39699b3, the merge of PR #82 and the last PR merge on that date; commits dated 2026-08-15 after it (f1873d5 onward; Phase 4.1 starts at 3e05637) open the next block. PR #82's branch spans 2026-08-11 → 2026-08-15 and is included whole.

## August 2026 (second half) — 6 entries

2026-08-15: Steam modes and containerised launches: SteamMode (Auto / Offline Emulated / Online Containerized), a local steam_api emulator for clientless launches, SteamRT4 runtime provisioning with pressure-vessel and bwrap command building, a containerised launch pipeline with a Steam IPC bridge, and a runtime repair command with UI status. 3e05637, 6f3212a, 6cc5e18, b8e9d19
2026-08-15: Windows Steam onboarding runs automatically when no session exists, and Shared-mode custom-exec launches prefer the prefix that holds a persisted login. fba444b, a587508
2026-08-15: Configuration guard that rejects Online Containerized with a non-Proton runner at save time. PR #84
2026-08-16: The launcher repaints only when work arrives, so an idle window stays at ~0% CPU. PR #86
2026-08-16: dxvk_enabled=false is honoured end to end: the resolver offers no DXVK candidates, game-local DLLs still win, and clean and RTX Remix runner profiles are separated. PR #87
2026-08-22: Pre-launch VRAM guard with a warning modal (75% threshold), the installed beta branch shown in the properties panel, and the egui/eframe stack at 0.36.1. PR #88

### August 2026 exclusions (second half)

- f1873d5 (2026-08-15) — fix: custom-exec honours the effective prefix mode (runner-mismatch guard).
- PR #83 (2026-08-15) — docs: Phase 4 umbrella overview.
- PR #85 (2026-08-16) — docs: P2-RTX corruption investigation.
- cfb639b (2026-08-15) — chore: runtime storage path moved to the config_dir convention.
- a33f5f6, ff71bfe (2026-08-15) — Phase 4 status documents.
- 6ea425e, 4dd1f14 (2026-08-15) — exec-bit handling for provisioned runtime trees (6ea425e also lands the Phase 4.4 note); this is what lets a downloaded runtime satisfy pressure-vessel preflight.
- 9c1b5fa (2026-08-15) — test only.
- 47fef59 (2026-08-22) — VRAM threshold tuning, reflected in the PR #88 entry.
- d8319af (2026-08-31) — fix: custom-exec relative path.
- 75c80ca, 55c5b6f, d6fba3a (2026-08-31) — audit document revisions.

6 of the 6 pull requests merged in 2026-08-15–2026-08-31 and not already documented (#83–#88) are accounted for: 4 entries, 2 exclusions.

## September 2026 — 2 entries

2026-09-25: Connection-manager recovery: websocket resets recover transparently with bounded retry windows, recovery boundaries survive compound paths, and CLI test modes cover update, verify and install. PR #92
2026-09-29: Steam login rebuilt on steam-vent 0.6.0 (vendored, with the upstream steam-vent PR #19): refresh-token login, cancelable password login on a persistent runtime, machine identity persisted outside session.json with owner-only atomic credential files, and connection-generation fencing of login commits. PR #93 [steam-cdn] The vendored crate moves to the split steam_vent_proto_* crates and a path-vendored steam-vent 0.6.0 (manifest and lockfile only).

### September 2026 exclusions

- PR #90 (2026-09-01) — docs: README project status and architecture overview.
- e2735f4 (2026-09-01) — docs: README status revision.

3 of the 3 pull requests merged in 2026-09-01–2026-09-30 (#90, #92, #93) are accounted for: 2 entries, 1 exclusion. PR #93 was rebase-merged, so it has no merge commit: its date is the author date of its final commit and its PR number comes from the commits/{sha}/pulls API.

## October 2026 — 1 entry

2026-10-22: Cover-art service with per-variant cache state: every art variant is cached and revalidated on its own, a transient store lookup backs off while the cached asset stays on screen, a good asset is kept through transient failures, obsolete cache files migrate away, and the UI draws artwork undistorted and always delivers a result. PR #94

### October 2026 exclusions

- None. All six commits in this block belong to PR #94; its test (e4b77e5) and formatting (450ff32) commits are covered by the entry, and no other commits landed in October.

1 of the 1 pull requests merged in 2026-10-01–2026-10-24 (#94) is documented. PR #94 was rebase-merged, so its date is the author date of its final commit, 488170b (2026-10-22), and its PR number comes from the commits/{sha}/pulls API. `vendor/steam-cdn` is unchanged in this block (`git log 74c889a..488170b -- vendor/steam-cdn` is empty), so no [steam-cdn] line applies.
