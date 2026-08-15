# Phase 4.4 — Runtime Integrity Repair, Environment Parity & UI Status

> Status: **IMPLEMENTED + LIVE-VERIFIED (2026-08-15)**. Branch
> `phase4/containerized-launch`. Closes Phase 4 by adding force-reprovision
> tooling for corrupt Steam Linux Runtime (SLR) installs, container-aware
> `test-diff` log capture, and a runtime status indicator + inline repair in
> the game Properties UI. Fixing the live repair exposed and corrected three
> latent launcher defects (see "Root-cause fixes" below).

## Objective

1. **Runtime integrity repair CLI** — `steamflow runtime repair <line>
   [--force]` re-downloads a corrupt/truncated SLR through the Steam-CDN depot
   pipeline and force-reprovisions it into `~/.config/SteamFlow/runtimes/`,
   purging the broken extraction first. Addresses the host's truncated
   `steamrt4` (`usr-mtree.txt.gz` = 0 bytes) that blocked Phase 4.3's
   containerized boot.
2. **Container-aware test-diff** — `steamflow test-diff <appid>` now
   auto-generates `~/steam-<appid>.log` via `PROTON_LOG=1` when no reference
   capture exists, instead of hard-failing on the missing prerequisite.
3. **UI runtime status** — Properties → Runtime Settings shows the active SLR
   status next to the Steam Client Mode selector
   (`Runtime: Steam Linux Runtime 4.0 (steamrt4) [Valid · <rev>]`), with an
   inline **Repair Runtime** action when missing/corrupt.

## Implementation

| File | Change |
|---|---|
| `src/container/runtime.rs` | `RuntimeManager::purge()` (removes provisioned root + staged archive) and `RuntimeManager::force_reprovision(source, verification)` (purge → `provision_from_depot_dir`). `is_usable_runtime_root()` now rejects **0-byte** `run`/`_v2-entry-point`/`VERSIONS.txt` (the truncated-download shape). `parse_versions_txt()` accepts Valve's real **tab-separated** `VERSIONS.txt` table (SLR 3.0/4.0) alongside the legacy `VERSION <name> <rev>` and `KEY=VALUE` forms. `deployment_state()` no longer errors when no `manifest.json` exists (steamrt4 components ship `metadata` instead). |
| `src/headless.rs` | `steamflow runtime status [<line>]` and `runtime repair <line> [--force]`. Shared `download_runtime_depot_with_client()` (depot acquisition) and `repair_runtime(client, config, id)` (download + force-reprovision) reused by both the CLI and the UI. `locate_game()` / `spawn_game()` extracted from `test-launch` for reuse by the parity log-capture path. |
| `src/parity.rs` | `capture_native_log(appid)`: when `find_native_log` misses, sets `PROTON_LOG=1` + `PROTON_LOG_DIR=$HOME`, spawns via `headless::spawn_game`, polls for the log header, kills the child. |
| `src/ui.rs` | Runtime status label + `[Repair Runtime]` button in Properties → Runtime Settings; new `AsyncOp::RuntimeRepaired(String)` status. |
| `src/steam_client.rs` | **Tool-app PICS access token** — `install_game` and `resolve_install_game_info` now fetch + attach the per-app access token (`CMsgClientPICSAccessTokenRequest`) so owner-only tool apps (SLR app 4183110, Valve Protons) expose their depots and real SteamDB `installdir` (e.g. `SteamLinuxRuntime_4`). |
| `tests/container_tests.rs` | `test_force_reprovision_purges_and_reprovisions` — corrupt root → `force_reprovision` → usable state. |

## Root-cause fixes (discovered while making repair actually work)

1. **`parse_versions_txt` could not read real SLR `VERSIONS.txt`.** Valve's
   live files are a tab-separated table (`#Name\tVersion\t…` /
   `steamrt4\t4.0.20260805.254769\t…`), not the `VERSION <name> <rev>` form
   the parser expected. `read_versions_txt` returned empty → every real
   runtime scanned as "VERSIONS.txt missing or empty".
2. **`deployment_state` wrongly required `manifest.json`.** The real steamrt4
   component layout is `files/` + `metadata` + `usr-mtree.txt.gz` — no
   `manifest.json`. Completeness is now gated on entry point + parseable
   `VERSIONS.txt` (the same contract as `is_usable_runtime_root`).
3. **Tool apps returned no depots/installdir to the PICS request.** Without
   the per-app access token, app 4183110's appinfo is `public_only=1`; the
   depot downloaded to `"Steam Linux Runtime 4.0"` (sanitized display name)
   while `client_managed_runtime` probes `SteamLinuxRuntime_4`. Both PICS
   call sites now fetch + attach the token.

## Verification

- `cargo check --all-targets` — clean (only pre-existing warnings).
- `cargo test --all-targets` — **139 lib tests + 13 integration suites, 0
  failures** (was 136 lib in Phase 4.3 → +3: `test_versions_txt_tab_separated_valve_table`,
  `test_is_usable_runtime_root_rejects_truncated`, `test_purge_removes_provisioned_root`;
  +1 integration `test_force_reprovision_purges_and_reprovisions`).
- `cargo clippy --all-targets` — no new warnings in touched files.
- **Live repair** (`steamflow runtime repair steamrt4 --force`, exit 0):

  ```
  depot download complete (672,162,947 bytes)
  == client-managed runtime: …/SteamLinuxRuntime_4
  ✅ Steam Linux Runtime 'steamrt4' repaired (revision 4.0.20260805.254769)
  ✅ runtime 'steamrt4' passes is_usable_runtime_root() at …/runtimes/steamrt4
  ```

  The repaired `usr-mtree.txt.gz` is 358,247 bytes (was 0). The repair pulled
  a **newer** revision (4.0.20260805.254769, replacing the corrupt
  4.0.20251216.191775).
- `steamflow runtime status steamrt4` → `present=true complete=true
  usable=true revision=4.0.20260805.254769`.

## Live test (Portal 2, AppID 620 — OnlineContainerized)

`steamflow test-launch 620` spawns the container via the repaired
`SteamLinuxRuntime_4/run` with the correct pressure-vessel argv
(`--filesystem=…`, `--env-if-host=DISPLAY=:0.0`, one `--`, pure-PE Proton
`run portal2.exe`). **Phase 4.3's truncated-archive error is gone** (the
repaired `usr-mtree.txt.gz` reads cleanly).

The next blocker found during the live test — `pressure-vessel-wrap: E: None
of the supported CPU architectures are common to the graphics provider and
the container (tried: x86_64-linux-gnu, i386-linux-gnu)` — was **not** a
missing-32-bit-libs issue. Root cause (empirically confirmed): the Steam-CDN
depot downloader strips the executable bit, and pressure-vessel's
graphics-provider detection needs its `pressure-vessel/libexec/steam-runtime-tools-0/*`
tools (`capsule-capture-libs`, `check-vulkan`, …) to be executable. Without
them, provider enumeration fails → empty architecture intersection → abort.
Reproduced with `/bin/true`; fixed by `ensure_runtime_executable()` now
walking the whole tree (commit `3bf2040`).

After the fix, `test-launch 620` boots the game inside the container:
`bwrap` up, pure-PE Proton running, `portal2.exe` alive (plus the RTX Remix
bridge), wine log showing d3dx asset loading. A proposed
`--env-if-host=PRESSURE_VESSEL_ARCHS=x86_64-linux-gnu` knob does **not**
exist (`PRESSURE_VESSEL_ARCHITECTURES` is the real variable, hardcoded by
the `run` script) and does not affect the host-side arch selection
(empirically still failed) — rejected in favor of the exec-bit fix.

## Decisions / flags

- **`runtime repair` always re-downloads the depot** even when the
  client-managed `SteamLinuxRuntime_<line>/` already passes
  `is_usable_runtime_root()`. Given `/home` is chronically ~100% full, a
  follow-up could skip the download when the source tree is already usable —
  flagged, not resolved.
- **620's live container test** was run with `steam_mode=OnlineContainerized`
  + `forced_proton_version=steamflow-proton-11.0-purepe` (both config files
  backed up as `*.bak-p44-<ts>`). The container launch is verified up to the
  graphics-provider stage; the full boot needs host 32-bit graphics libs
  (`libvulkan1:i386` + NVIDIA 32-bit driver libs) — flag for the user.
- `test-diff`'s auto-capture only materializes when the launch actually runs
  through Proton (OnlineContainerized or a Proton-kind runner) — otherwise it
  falls back to the manual-capture error.

## Disk (host constraint, unchanged)

`/home` is a 1.8T nvme chronically ~100% full. `cargo test` DEBUG builds can
exceed 6.3G; this phase built incrementally on the existing debug profile
(139 lib tests, no profile switch).
