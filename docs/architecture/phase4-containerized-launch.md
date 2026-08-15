# Phase 4.3 — Containerized Launch Pipeline & Steam IPC Bridge

> Status: **IMPLEMENTED + VERIFIED (2026-08-15)**. Branch `phase4/runtime-provisioning`
> (off `phase4/one-time-login-automation`). Delivers the `OnlineContainerized`
> dispatch: the game boots inside Valve's Steam Linux Runtime (SLR) container
> under a pure-PE Proton runner, bridged to the **native** Linux Steam client
> via Proton's `lsteamclient.dll` IPC wrapper.

## Objective

Wire the Phase 4.2 container infrastructure (`RuntimeManager` +
`PressureVesselBuilder`) into the launch pipeline so that
`SteamMode::OnlineContainerized` actually launches the game inside the SLR
container instead of behaving like `Auto`.

The mode's contract (vs. `OfflineEmulated` and classic client-based):

| SteamMode | Client | Game runs in | Steamworks bridge |
|---|---|---|---|
| `Auto` | Windows Steam client (Wine prefix) | Wine/Proton prefix | Windows `steamclient.dll` (named pipe, wineserver-scoped) |
| `OfflineEmulated` | none | Wine prefix | local Goldberg-style emulator |
| `OnlineContainerized` | **native** Linux Steam (host) | SLR container (`steamrt4`) | Proton `lsteamclient.dll` → `steamclient.so` (network IPC) |

Key consequence: in `OnlineContainerized` **no secondary Windows `steam.exe`
is ever spawned** — the game's `SteamAPI_Init()` is intercepted by Proton's
native `lsteamclient.dll` and routed across the container namespace to the
host Steam client.

## Implementation

| File | Change |
|---|---|
| `src/container/runtime.rs` | `SteamRuntimeId::app_id()` (scout 1070560 / soldier 1391110 / sniper 1628350 / **steamrt4 4183110**, SteamDB-verified) and `SteamRuntimeId::client_dir_names()` (scout `SteamLinuxRuntime`+`_scout`, soldier `SteamLinuxRuntime_soldier`, sniper `SteamLinuxRuntime_sniper`, **steamrt4 `SteamLinuxRuntime_4`**). `RuntimeManager::client_managed_runtime()` (scan `<library>/steamapps/common/` for a usable client runtime), `RuntimeManager::resolve_runtime_root()` (client-managed → provisioned), `RuntimeManager::provision_from_depot_dir()` + `archive_dir()` (depot hook: tar a downloaded depot tree → `provision_from_archive`), `is_usable_runtime_root()` (entry point + `VERSIONS.txt`). |
| `src/container/launch.rs` (new) | `ContainerizedLaunch` — turns resolved inputs into a `CommandSpec` via `PressureVesselBuilder`: `pressure-vessel-wrap` (fallback `bwrap`) `<opts> -- <env/mount flags> -- <proton>/proton run <exe> <args>`, with `apply_host_resources()` (GPU/display/audio) and the full game env forced via `--env=`. |
| `src/container/mod.rs` | `pub mod launch;` |
| `src/infra/runners/wine_tkg.rs` | `OnlineContainerized` dispatch: `prepare_prefix` skips the Windows Steam client spawn + CEF enforcement + `steam_appid.txt`; `build_env` skips the Windows-Steam readiness/lsteamclient gates, sets `STEAM_COMPAT_CLIENT_INSTALL_PATH` to the **native** client root and prepends `lsteamclient=n,b` to `WINEDLLOVERRIDES`, forces `SteamAppId`/`SteamGameId`/`STEAM_COMPAT_APP_ID`; `build_command` routes to `build_containerized_command` (runtime resolution → per-game `compatdata/<appid>/pfx` mount → `ContainerizedLaunch`). |
| `src/launch/stages/preflight.rs` | Skip the Windows-Steam session gate for `OnlineContainerized` (no Wine-prefix session exists). |
| `src/headless.rs` | `test-download-runtime <scout\|soldier\|sniper\|steamrt4>` — fetches the SLR app via the `install_game` asset-fetcher pipeline, then provisions it into `~/.config/SteamFlow/runtimes/<line>/` via `provision_from_depot_dir`. |
| `tests/container_tests.rs` | `test_provision_from_depot_dir` — depot tree → archive → provision cycle. |

## lsteamclient.dll environment wiring

For `OnlineContainerized`, `build_env` emits (overriding the classic
Windows-client path):

```
STEAM_COMPAT_CLIENT_INSTALL_PATH = $HOME/.steam/steam   (native client root, so
                                                         lsteamclient loads
                                                         linux64/steamclient.so +
                                                         ubuntu12_32/steamclient.so)
STEAM_COMPAT_DATA_PATH           = <library>/steamapps/compatdata/<appid>
SteamAppId / SteamGameId /
STEAM_COMPAT_APP_ID             = <appid>
WINEDLLOVERRIDES                = lsteamclient=n,b;<existing overrides>
```

`lsteamclient=n,b` (native, then builtin) forces Proton's native
`lsteamclient.dll` to intercept the game's `SteamAPI_Init()` and forward it
to the host Steam client across the container boundary. (`n,b` is the standard
Proton contract — the runner's own `lsteamclient.dll` is a native Linux
library, not a Windows PE.)

## Verification

- `cargo check --all-targets` — clean (only pre-existing warnings).
- `cargo test --all-targets` — **0 failures**; lib **136 passed** (was 127 in
  Phase 4.2 → +9: `container::launch` 5 + `container::runtime` 4),
  `tests/container_tests.rs` **5 passed** (+1 `test_provision_from_depot_dir`).
- `cargo clippy --all-targets` — **zero warnings in `src/container/*`** and
  in the new `build_containerized_command` (the remaining warnings are
  pre-existing across `steam_client.rs` / `proton.rs` / `ui.rs` / etc.).

## Phase 4.2 builder correction (discovered via live test)

The Phase 4.2 `PressureVesselBuilder` emitted flags that the real
`pressure-vessel-wrap` binary does not accept (`--runtime-path`,
`--runtime-version`, `--runtime-arch`, `--launcher`, `--game-pid`, `--env`,
`--bind-mount`, `--device`, `--filesystem-ro`, and a second `--`). The live
launch failed with the exact evidence:

```
pressure-vessel-wrap[789911]: E: Неизвестный параметр --runtime-path=…
```

The real contract (verified against the bundled binary's `--help` and the
runtime's `run` script) is:

- **Entry point** = the runtime's `run` script (Steam's canonical contract),
  which sets `PRESSURE_VESSEL_RUNTIME`/`RUNTIME_BASE`/`COPY_RUNTIME`/
  `VARIABLE_DIR` env and `exec`s the runtime's `pressure-vessel-unruntime`.
  Fallback: bundled `pressure-vessel/bin/pressure-vessel-wrap`, then host
  `pressure-vessel-wrap`, then host `bwrap`.
- **Flags** = `--filesystem=<path>` (rw) + `--env-if-host=NAME=VALUE`, then a
  single `--` before the command. GPU/display/audio pass-through is automatic
  (graphics provider + shared home/runtime dir); forced env is carried on the
  process environment.

The builder was corrected accordingly (runtime-flag fields removed, one `--`,
valid flag subset).

## System verification (Portal 2, AppID 620)

`steamflow test-launch 620` in `OnlineContainerized` mode now constructs the
correct container command and spawns it:

```
Program: "…/SteamLinuxRuntime_4/run"
Args: ["--filesystem=…/Portal 2", "--filesystem=…/compatdata/620/pfx",
       "--filesystem=/tmp/.X11-unix", "--env-if-host=DISPLAY=:0.0", "--",
       "…/steamflow-proton-11.0-purepe/proton", "run", "…/portal2.exe", …]
CHILD_PID=793929
```

The full game env (including `STEAM_COMPAT_CLIENT_INSTALL_PATH=$HOME/.steam/steam`
and `WINEDLLOVERRIDES=lsteamclient=n,b;…`) is carried on the process env, and no
secondary Windows `steam.exe` is spawned. The remaining boot failure is **a
runtime defect, not a launcher defect** — the host's `steamrt4` runtime has a
truncated `usr-mtree.txt.gz`:

```
pressure-vessel-wrap: E: While reading …/SteamLinuxRuntime_4/steamrt4_platform_4.0.20251216.191775/usr-mtree.txt.gz: Требуется больше вводных данных
```

The `sniper` runtime is intact (`SteamLinuxRuntime_sniper/run -- /bin/true` →
exit 0), proving the `run`-script contract the launcher emits is valid.

`steamflow test-diff 620` could not run: it requires a native `PROTON_LOG=1`
capture (`~/steam-620.log`) that does not exist on this host — an environment
prerequisite, unrelated to this phase's code.

## Decisions / flags (recorded, not resolved)

- **`Auto` + native Steam is NOT auto-routed to `OnlineContainerized`.** The
  task's "(or `Auto` with native Steam active)" parenthetical was treated as a
  product decision: silently flipping every `Auto` game into the container
  would change default behavior for all users. The explicit
  `steam_mode == OnlineContainerized` is the only trigger. Flag for product.
- **Container engine fallback:** runtime `run` entry point → bundled
  `pressure-vessel-wrap` → host `pressure-vessel-wrap` → host `bwrap`. `bwrap`
  alone does NOT set up the SLR library environment (that is
  `pressure-vessel`'s job); it is a degraded fallback, not an equivalent.
- **Containerized prefix is always per-game** (`compatdata/<appid>/pfx`),
  regardless of the configured Shared/PerGame mode — there is no shared
  Windows Steam prefix inside the container.
- **`steamrt4` runtime is corrupt on this host** (truncated
  `usr-mtree.txt.gz`); `sniper` works. Flag for the user — a reinstall of the
  Steam Linux Runtime 4.0 (app 4183110) is needed for a real steamrt4 boot.

## Disk (host constraint, unchanged from Phase 4.2)

`/home` is a 1.8T nvme chronically ~100% full. `cargo test` DEBUG builds can
exceed 6.3G and fail the link with `ld signal 7 Bus error` when the disk
fills. This phase built incrementally on the existing debug profile and
passed; a clean `cargo test --all-targets` after a `CARGO_PROFILE_DEV_DEBUG=0`
build (or vice-versa) will refill the disk — do not mix profiles on this host.
