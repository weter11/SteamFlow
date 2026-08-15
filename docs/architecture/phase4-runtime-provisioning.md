# Phase 4.2 — Steam Linux Runtime Provisioning + Pressure-Vessel Command Builder

> Status: **IMPLEMENTED + VERIFIED (2026-08-15)**. Branch
> `phase4/runtime-provisioning` (off `phase4/one-time-login-automation`).
> Delivers the container infrastructure for the `OnlineContainerized`
> SteamMode (SteamRT4 / sniper); the actual launch-pipeline wiring is
> Phase 4.3.

## Objective

Provide the two building blocks SteamFlow needs to launch games inside
Valve's official Steam Linux Runtime (SLR) containers:

1. **Runtime provisioner** — download / verify / extract / parse SLR images
   (`steamrt4`, plus the `scout`/`soldier`/`sniper` lines) into
   `~/.config/SteamFlow/runtimes/<id>/`.
2. **Pressure-vessel command builder** — a native Rust builder that
   programmatically constructs `pressure-vessel-wrap` (and `bwrap`) argv:
   host Vulkan/EGL/dri/nvidia pass-through, display sockets, audio sockets,
   read-write game/prefix mounts, and `--env-if-host` isolation.

## Implementation

| File | Change |
|---|---|
| `src/container/mod.rs` (new) | Module root; doc-links the two submodules. |
| `src/container/runtime.rs` (new) | `SteamRuntimeId` (scout/soldier/sniper/steamrt4 + alias parsing), `RuntimeManager` (`for_id` / `new` / `Default` = steamrt4 at `~/.config/SteamFlow/runtimes/steamrt4`), `deployment_state()` scan (entry point `run`/`_v2-entry-point`, VERSIONS.txt, per-component `manifest.json` → `RuntimeDeploymentState` with `present`/`complete`/`revision`/`versions`/`manifests`/`errors`), `provision_from_archive` (SHA256 via `sha2` + detached-GPG via `gpgv` → system-`tar` extraction → rescan), `provision_from_url`/`download_to` (reqwest chunk loop, mirrors `src/proton.rs`), `find_runtime_root` (normalizes tarballs that wrap the runtime in one top-level dir), `parse_versions_txt` (Valve `VERSION <name> <rev>` **and** `KEY=VALUE`), `parse_manifest` (all-optional fields, tolerant). |
| `src/container/pressure_vessel.rs` (new) | `CommandKind::{PressureVesselWrap, Bwrap}`, `HostResourceDetector` (Vulkan ICD dirs `/usr/share|/etc/vulkan/icd.d`, EGL `/usr/share|/etc/glvnd/egl_vendor.d`, `/dev/dri`, `/dev/nvidia*`, Wayland socket, `/tmp/.X11-unix`, audio `pulse/native` → `pipewire-0`; env-injectable for tests), `PressureVesselBuilder` (`runtime/arch/launcher/game_pid`, `filesystem`/`filesystem_ro`, `bind_mount`, `device`, `env_if_host`/`env`, `command`, `apply_host_resources`, `build`). pv-wrap emits `<opts> -- <env/mount flags> -- <program> <args>`; bwrap emits the bubblewrap equivalent (`--ro-bind / /`, `--bind`, `--dev-bind`, `--setenv`). |
| `src/lib.rs` | `pub mod container;` |
| `Cargo.toml` / `Cargo.lock` | `sha2 = "0.10"` (same RustCrypto family as the existing `sha1`). |
| `tests/container_tests.rs` (new) | End-to-end provision cycles against REAL tarballs built with system `tar`: flat archive + SHA256 verification + wrong-digest rejection (existing deployment survives), nested (wrapped) archive normalization, public-API pv-wrap/bwrap flag checks. |
| `docs/architecture/phase4-offline-emulator-mode.md` | Open item 2 updated: `OnlineContainerized` infrastructure now exists (this phase); launch wiring remains Phase 4.3. |

Design notes:

- **Extraction uses the system `tar` binary** (project convention,
  identical call shape to `src/proton.rs::install_github_package`) — no new
  archive crate.
- **Both integrity methods are optional-but-warned**: SHA256 (pure Rust,
  primary) and/or detached GPG via `gpgv`. With neither, provisioning logs a
  warning and proceeds — Steam CDN depot delivery (the Phase 4.3 acquisition
  path, feeding `provision_from_archive`) is already authenticated by
  Valve's own depot signature machinery.
- **`VERSIONS.txt` parsing is tolerant**: Valve's `VERSION <name> <rev>`
  lines AND SteamFlow's own `KEY=VALUE` runner format both parse, so the
  same code serves runner metadata and runtime metadata.
- **`deployment_state()` never fails**: a missing/half-provisioned runtime
  is a state with `errors`, not an exception — the UI can render it.
- **Runtime id aliases**: `sniper` → Steamrt3, `steamrt4` → Steamrt4;
  unknown names fall back to the default line rather than erroring.
- **`HostResourceDetector` is env-injectable** — tests construct it with
  temp dirs (real unix sockets via `UnixListener::bind`), so detection
  logic (glob `/dev/nvidia*`, pulse-over-pipewire priority, Wayland socket
  resolution) is covered deterministically.

## Verification

- `cargo check --all-targets` — clean (remaining warnings are pre-existing
  in `steam_client.rs` / `proton.rs` / `infra/runners/tests.rs`, untouched).
- `cargo clippy --all-targets` — **zero warnings in `src/container/*`**.
- `cargo test --all-targets` — **15/15 suites pass, 0 failures**:
  - lib: **127 passed** (was 118 in Phase 4.1 → +9 new unit tests,
    incl. the required `test_runtime_version_parsing` and
    `test_pressure_vessel_command_builder`);
  - integration `tests/container_tests.rs`: **4 passed**
    (provision cycles + builder API checks).
- `cargo fmt --all -- --check` — note: the repo's committed state is NOT
  fmt-clean (57 files churn under `fmt --all`); this phase intentionally
  avoids touching pre-existing formatting (single-line `lib.rs` diff).

## Open items / decisions (FLAG, not resolved)

1. **Depot-based acquisition (Phase 4.3 — RESOLVED)**: `steamflow
   test-download-runtime <line>` now fetches the SLR app through the
   `SteamClient::install_game` asset-fetcher pipeline (SLR appids verified
   against SteamDB: scout 1070560, soldier 1391110, sniper 1628350,
   **steamrt4 4183110**) and feeds `RuntimeManager::provision_from_archive`
   via `provision_from_depot_dir` (tar the depot tree → verify → extract).
   The direct-HTTP `provision_from_url` remains the interim source.
2. **Launch wiring (Phase 4.3 — RESOLVED)**: `OnlineContainerized` now
   dispatches to the pressure-vessel path (see
   `docs/architecture/phase4-containerized-launch.md`).
3. **Client-managed preference (Phase 4.3 — RESOLVED)**: `RuntimeManager::
   resolve_runtime_root` prefers the client-managed
   `steamapps/common/SteamLinuxRuntime_<line>/` copy (self-updating) and
   falls back to the SteamFlow-provisioned one. Note the steamrt4 client
   directory is `SteamLinuxRuntime_4` (SteamDB `installdir`), NOT
   `SteamLinuxRuntime_steamrt4`.
4. `AudioBackend` binds only the winning socket (pulse-compat first). A
   follow-up could bind both pulse and pipewire sockets when both exist.
