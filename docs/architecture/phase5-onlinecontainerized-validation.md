# Phase 5 — OnlineContainerized Runner Validation Guard + Launch-Path Logging Facts

> Status: **IMPLEMENTED (2026-08-15)**, branch `phase5/container-mode-validation`.
> Phase 5 part 1: the `OnlineContainerized` config-save guard; part 2 documents the
> launch-path logging facts discovered during the Portal 2 (620) pure-PE rendering
> diagnostic.

## Part 1 — Validation guard

### Problem

`OnlineContainerized` runs the game through `<proton>/proton run` inside the Steam
Linux Runtime container (`src/container/launch.rs`). A plain Wine runner has no
`proton` entry script, so a misconfigured game fails **at launch** with
`OnlineContainerized requires a Proton compatibility tool` — a confusing error that
only appears when the user presses Play.

Worse, the configuration can be internally inconsistent without any warning: the
per-game `forced_proton_version` pin and the `steam_mode` are stored separately
(`config.json` vs `user_apps.json`), so a containerized test can silently run a
different runner than the file states (observed 2026-08-15: the running app held an
older in-memory config, launching purepe while the file pinned wine11-wow64).

### Rule

> If `steam_mode` is `OnlineContainerized`, the effective runner (per-game
> `forced_proton_version` → global `proton_version`, mirroring
> `resolve_effective_proton_name`) must classify as a Proton compatibility tool
> (`classify_runner` → `RunnerKind::Proton`, i.e. a `proton` entry script exists).

Rejected updates are refused at config-save time with:

> `OnlineContainerized mode requires a Proton compatibility tool runner (e.g., steamflow-proton-11.0-purepe). Bare Wine runners are not supported in container mode.`

### Implementation

- `src/config.rs` — `validate_online_containerized_runner(steam_mode, forced_proton_version, global_proton_version, library_root) -> Result<(), String>`.
  Pure function: non-`OnlineContainerized` modes always pass; container mode resolves
  the effective runner (`resolve_runner`) and requires `RunnerKind::Proton`.
- `src/ui.rs` — per-game settings save block: the guard runs before the
  `user_configs.insert` + `save_user_configs`; on rejection the update is NOT
  persisted and the status bar shows `Configuration rejected: <msg>`.
- Unit tests in `src/config.rs` (`online_containerized_rejects_bare_wine_and_accepts_proton`):
  Proton forced ✓, Proton global ✓, bare-Wine forced ✗ (exact message), bare-Wine
  global ✗, `OfflineEmulated`/`Auto` never blocked, empty forced → global fallback ✓.

## Part 2 — Launch-path logging facts (from the Phase 5 diagnostic)

### PROTON_LOG only works on the proton-script path

| Launch path | Proton script? | `PROTON_LOG=1` → `~/steam-<appid>.log` | Wine debug destination |
|---|---|---|---|
| `OnlineContainerized` (SLR → `<proton>/proton run`) | yes | **yes** (19.6 KB capture, proton-11.0-1b) | container stderr → `WINE_LOG_OUTPUT` |
| DirectWine, PlainWine runner (`steamflow-runner-wine11-wow64`) | no | **silent no-op** | `~/.config/SteamFlow/logs/wine_<appid>.log` (truncated per launch) |

The proton script also **rewrites `WINEDEBUG`** (its own
`+d3d,+winevulkan,+win32u,+mfplat,+wg_transform,+gstreamer,err+all`), so CLI
`WINEDEBUG="+loaddll,+vulkan,+d3d"` does not survive the container path.

### debug.json precedence

`~/.config/SteamFlow/debug.json` → `DebugConfig { env }` is applied **last** in
`build_env` (after per-game env vars and built-in debug toggles), so its keys win
over everything — including the CLI and the proton default. Caveat: setting
`WINEDLLOVERRIDES` there **replaces** the whole computed override string; include the
full base set when overriding it. Verify via `effective_env.json` in the session dir.

### OnlineContainerized × runner matrix

| steam_mode | effective runner kind | result |
|---|---|---|
| `OnlineContainerized` | Proton (e.g. `steamflow-proton-11.0-purepe`) | OK |
| `OnlineContainerized` | PlainWine / Unknown (e.g. `steamflow-runner-wine11-wow64`) | **rejected at save** (guard) / launch error (without guard) |
| `OfflineEmulated` / `Auto` | anything | never blocked |

## White-screen context (Portal 2 / RTX Remix, 2026-08-15)

Runner-independent remix render-path stall (0 GBuffer passes, all draws skipped,
dxvk-cache frozen, GPU 100%) + a Steam-session gate (game stuck on the loading
screen without a reachable Steam client). Stock D3D9 (mod off + `d3d9=n,b`) renders
under purepe — the runner/DXVK/Vulkan-ICD stack is healthy. Evidence:
`/home/wer/devis/tmp/p2-phase5-20260815/`; full detail in the `rtx-remix-modding`
skill.
