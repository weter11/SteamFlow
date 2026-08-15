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
   `~/.local/share/SteamFlow/runtimes/<id>/`.
2. **Pressure-vessel command builder** — a native Rust builder that
   programmatically constructs `pressure-vessel-wrap` (and `bwrap`) argv:
   host Vulkan/EGL/dri/nvidia pass-through, display sockets, audio sockets,
   read-write game/prefix mounts, and `--env-if-host` isolation.

## Implementation

| File | Change |
|---|---|
| `src/container/mod.rs` (new) | Module root; doc-links the two submodules. |
| `src/container/runtime.rs` (new) | `SteamRuntimeId` (scout/soldier/sniper/steamrt4 + alias parsing), `RuntimeManager` (`for_id` / `new` / `Default` = steamrt4 at `~/.local/share/SteamFlow/runtimes/steamrt4`), `deployment_state()` scan (entry point `run`/`_v2-entry-point`, VERSIONS.txt, per-component `manifest.json` → `RuntimeDeploymentState` with `present`/`complete`/`revision`/`versions`/`manifests`/`errors`), `provision_from_archive` (SHA256 via `sha2` + detached-GPG via `gpgv` → system-`tar` extraction → rescan), `provision_from_url`/`download_to` (reqwest chunk loop, mirrors `src/proton.rs`), `find_runtime_root` (normalizes tarballs that wrap the runtime in one top-level dir), `parse_versions_txt` (Valve `VERSION <name> <rev>` **and** `KEY=VALUE`), `parse_manifest` (all-optional fields, tolerant). |
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

1. **Depot-based acquisition (Phase 4.3)**: wire the steam-cdn depot
   pipeline to fetch SLR app 1628350 (sniper) / 4025700 (steamrt4) and feed
   `RuntimeManager::provision_from_archive`; the direct-HTTP
   `provision_from_url` (repo.steampowered.com tarballs) is the interim
   source.
2. **Launch wiring (Phase 4.3)**: `OnlineContainerized` still behaves like
   `Auto` in the launch pipeline; the builder + provisioner are the
   infrastructure it will call (runtime selection from deployment state →
   `PressureVesselBuilder::apply_host_resources` → spawn).
3. `--runtime-path` currently points at the provisioned root; when the SLR
   install also exists under the native Steam library
   (`SteamLinuxRuntime_sniper/`), prefer the client-managed copy (it
   self-updates) and only fall back to SteamFlow-provisioned ones.
4. `AudioBackend` binds only the winning socket (pulse-compat first). A
   follow-up could bind both pulse and pipewire sockets when both exist.
