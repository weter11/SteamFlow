# Valve Stack Replication — Valve-Parallel Compatibility Stack

## Status
**Phase 1 VERIFIED (2026-08-11): RE2 (883710) launches and renders under the
pure-WoW64 wine-11 stack. Local worktree only — NOT pushed to GitHub.**

**Phase 2 item 1 IMPLEMENTED (2026-08-11): `steamflow test-diff <appid>`
env-parity harness (src/parity.rs) — parses native proton logs (PROTON_LOG=1:
`Options:` set → reverse-mapped `PROTON_*` env, `Effective/System/User settings
WINEDLLOVERRIDES`/`WINEDEBUG`, `PATH`) and diffs against SteamFlow's
`effective_env.json` (MISSING / EXTRA / MISMATCHED / MATCHED, priority-flagged).**

**Phase 2 item 2 IMPLEMENTED (2026-08-11): native Rust Proton ABI
(`src/runner/proton_abi.rs`) — port of Valve's `proton` script + `default_pfx`
launch semantics, no Python at game launch.** The Runner trait's `build_env`
now computes the per-app compat set (default_compat_config + forcelgadd
default + per-game `proton_compat_options`), merges Proton's env rules
(`WINE_LARGE_ADDRESS_AWARE`, `WINE_HEAP_*`, `PROTON_*` input vars,
`DXVK_ENABLE_NVAPI`, `WINE_MONO_HIDETYPES`, `__GLVND_DISALLOW_PATCHING`,
`PROTON_USE_XALIA`, …) and base DLL overrides (`steam.exe=b`, `opencl=n,d`,
…). `seed_prefix` does native prefix init (default_pfx copy + dosdevices c:/z:
symlinks + version stamp) without Python. **test-diff 883710 VERIFIED: the two
real gaps (PROTON_FORCE_LARGE_ADDRESS_AWARE, PROTON_USE_WINED3D) are now
MATCHED — 0 missing, 28 extra (log-format asymmetry), 2 matched.**

**Phase 2 tail COMPLETE (2026-08-11):** item 3 (`VERSIONS.txt` visibility,
kill `found(bundled)`) DONE via `utils::write_runner_versions_txt` at
extraction (GitHub tarball install, steam-cdn `install_game`, headless
`test_download_proton`); native `seed_prefix` wired into `prepare_prefix` (no
Python prefix init at game launch); i386-multilib item **CLOSED / REJECTED**
(host is pure 64-bit — never re-open). See "Session close" + "Phase 3" blocks.

**Phase 3 CLOSED (2026-08-12): containerized pure-PE WoW64 Proton 11.0 build
of Valve's `proton_11.0` source — COMPLETE.** Built with the branch-pinned
**steamrt4** SDK (`registry.gitlab.steamos.cloud/proton/steamrt4/sdk/x86_64:
4.0.20260331.220802-0`; not soldier — see §Phase 3), staged as
`compatibilitytools.d/steamflow-proton-11.0-purepe`, and **verified booting
RE2 live** (zero 32-bit ELF anywhere; 611×PE32 i386-windows + 613×PE32+
x86_64-windows; 0 ELF-32 files). Full record: `docs/architecture/
phase3-pure-pe-proton11.md`. i386-multilib remains permanently rejected.

**Phase 4.1 IMPLEMENTED + VERIFIED (2026-08-15): Offline Steam API Emulator
Mode (`steam_mode: OfflineEmulated`) — fully clientless game launches via a
local steam_api emulator (Goldberg SteamEmu).** Schema: `SteamMode`
(Auto/OfflineEmulated/OnlineContainerized) + `OfflineSettings` in
`user_apps.json` (`#[serde(default)]` — old configs unaffected). Provisioner
`src/infra/steam_emulator.rs`: steam_appid.txt (game root/exe dir/staging),
emulator DLLs from `~/.config/SteamFlow/steam_emulator/`, steam_settings/
identity files (game root + deploy dirs + staging). **KEY FINDING (falsified
2026-08-15, +loaddll trace on Portal 2): the Source engine loads
`%s/bin/steam_api.dll` by CONSTRUCTED path via its tier0 module system —
path-qualified loads bypass WINEDLLPATH/overrides, so shadowing alone fails
("Steam is not running"); the provisioner therefore OVERWRITES the game's own
steam_api*.dll in place (original preserved as `<dll>.steamflow-orig`).**
All Steam client spawn/readiness gates bypassed (wine_tkg.rs dispatch +
preflight session gate). UI: Properties → Runtime Settings "Steam Client
Mode" dropdown. Verified: 118/118 unit tests; live `test-launch 620`
(clientless, 2560×1440 window, RTX Remix active, zero Steam processes). Full
record: `docs/architecture/phase4-offline-emulator-mode.md`.

## Problem

SteamFlow historically maintained a parallel compatibility stack (custom
`steamflow-runner-wine11-wow64`, wine-tkg builds tracking wine master). The
compat universe is unbounded: wine master changes weekly (RE2's
`NtGdiDdDDIQueryStatistics` D3DKMT stub broke on wine 11.14+53 commits), dxvk /
vkd3d-proton churn, ~500k games. Debugging every combination yourself is a
multi-year treadmill.

**Decision (architecture directive, approved):** no Proton ≤ 10; standardize on
the **11.x line / steamrt4 / pure-WoW64**; Valve's shipped artifacts + launch
semantics are the reference; SteamFlow = thin launcher. Wine/dxvk/vkd3d are
pinned, vendored dependencies with an upgrade button.

## Phase 1 spike — what actually happened (2026-08-11)

### Environment facts (this host)
- **No 32-bit host libs** (`/lib/i386-linux-gnu` exists but lacks libfreetype-32,
  libXext-32, libgobject-32, libgnutls-32, libva-32). Only **pure new-WoW64**
  wine builds can run anything here. This validates the directive's WoW64
  standard — and rules out every classic-wow64 prebuilt.
- Anonymous Steam depot downloads for Proton tools are **blocked by Valve**
  ("missing license for depot"). Official Proton 11.0 (app **4628710**, depot
  **4628711**, x86_64, 1.35 GiB) requires a **logged-in steamcmd session**:
  `steamcmd +login <account> +download_depot 4628710 4628711 +quit`.

### Runner reality matrix (empirically tested)

| Runner | Wine | wow64 | Windows Steam client | RE2 (883710) | Verdict |
|---|---|---|---|---|---|
| GE-Proton11-3 | 11.0 (Staging)+bleeding | classic (i386-unix) | ❌ `tier0_s64.dll` access violation | — (client blocked) | ✗ on this host |
| proton-cachyos 11.0-20260703 (vendored as `steamflow-proton-11.0`) | 11.0 (CachyOS) | classic (i386-unix) | ❌ `steamclient_init` AV + missing 32-bit freetype/libXext; no `lsteamclient.so` in x86_64-unix | ❌ crashed via `proton run` path (no display driver) | ✗ on this host |
| proton_tkg bleeding edge 11.0.405815 | 11.0.x | classic | untested (same class) | — | likely ✗ |
| **`steamflow-runner-wine11-wow64` (custom)** | 11.14.r4 TkG | **pure new-WoW64** (no i386-unix) | ✅ proven (client logs in) | known crash (master D3DKMT regression) | client-capable; RE2 broken |
| **`wine-tkg-staging-git-11.13.r6`** | 11.13 TkG | **pure new-WoW64** | ✅ verified 2026-08-11 (Logged On) | ✅ **RUNS — verified 2026-08-11** (vkd3d-proton rendering, 1.66 GB RSS, no crash) | **current stack** |

### Key findings
1. **The Windows Steam client (32-bit) requires the wine builtin steamclient
   shim to be suppressed on ANY runner kind** (`WINEDLLOVERRIDES` =
   `vstdlib_s=n;tier0_s=n;steamclient=n;steamclient64=n;steam_api=n;steam_api64=n;lsteamclient=`
   — the PlainWine path at `src/launch/mod.rs:164`). Proton-kind envs leave the
   builtin active → `CLIENTENGINE_INTERFACE_VERSION005` not recognized /
   `steamclient_init` access violation. **Code change candidate:** apply this
   override set for the client process in the Proton-kind branch too (keep the
   real `STEAM_COMPAT_CLIENT_INSTALL_PATH`).
2. **wine 11.0-class builds crash the client** (GE: `tier0_s64` AV; cachyos:
   `steamclient_init` AV) — the client needs wine ≥ 11.13. GE's bleeding-edge
   commits (post-20260703) are what broke cachyos's working line.
3. **RE2's D3DKMT crash is master-only (wine 11.14+53).** wine 11.13 predates
   the `NtGdiDdDDIQueryStatistics` regression → RE2 runs clean (adapter table
   populates, D3D12 command lists execute). This empirically confirms the
   earlier investigation's fix: *pin to a settled wine tag*.
4. **Same-prefix = same wineserver = same runner.** Game on 11.13 + client on
   11.14 → `wine client error: version mismatch 958/957`. The
   `effective_game_proton` doc-comment claims per-game freedom, but in Shared
   prefix mode the game runner must equal the runtime runner (or get its own
   prefix). The stale-wineserver guard spares Steam's server, so the mismatch
   is not cleaned up automatically. **IMPLEMENTED 2026-08-12:** the
   runner-mismatch guard `effective_prefix_mode` (wine_tkg.rs) now auto-falls
   a Shared configuration back to PerGame when the Steam Runtime runner ≠ the
   game runner (with a visible warning) — see
   `phase3-pure-pe-proton11.md` "Post-Phase-3 follow-up".
5. **`proton run` via the script path does NOT SIGSYS anymore** (unlike the old
   skill note) — but on this host the classic-wow64 proton scripts can't load
   their display driver anyway (missing 32-bit host libs).

### Phase 1 result
**PASS for RE2 (883710):** launches through the headless pipeline
(`steamflow test-launch 883710`), passes the Steam API ownership gate (client
logged in), initializes D3D12/vkd3d-proton, renders continuously (196% CPU,
1.66 GB RSS). The pre-spike failure (adapter-table null deref at
`0x141f543d6`) does not occur on wine 11.13.

## Architecture

### Tier 0 — pinned 11.x pure-WoW64 runner (Phase 1 done)
- **Current stack (config.json):** `steam_runtime_runner` +
  `proton_version` + RE2 `forced_proton_version` =
  `wine-tkg-staging-git-11.13.r6.g3604946c` (pure new-WoW64, wine 11.13).
- `skip_steam_self_update = true` (updater-rename guard, load-bearing for
  Proton-kind; harmless for PlainWine).
- `steamflow-proton-11.0` (cachyos 11.0 copy) kept as a runner dir for
  future experiments but is **not usable on this host** (classic-wow64).
- **Official Proton 11.0 stable** (app 4628710) remains the end-state target:
  once fetched via a logged-in steamcmd, re-test client + RE2; if Valve's
  wine ≥ 11.13-class it should work (possibly + the shim-suppression fix).

### Tier 1 — launch-semantics parity (Phase 2)
1. **Env-parity harness:** capture SteamFlow's `effective_env.json` +
   `PROTON_LOG=1` output vs native Steam's launch env for reference games;
   diff → divergence list = SteamFlow bug list. (Headless: extend
   `src/headless.rs` with a `test-diff <appid>` subcommand.)
   **DONE 2026-08-11** — `steamflow test-diff <appid>` in `src/parity.rs`.
   Native log auto-discovery: `~/steam-<appid>.log`, `~/Фото, видео/…`,
   `~/Emulators/…`, shallow HOME scan; `--native-log`/`--session` overrides.
   Session discovery: newest `logs/<session>/effective_env.json` whose
   `SteamAppId` matches. Verified on RE2 (883710) — see §test-diff findings.
2. Per-game quirks as config (map `user_settings.sample.py` knobs →
   `user_apps.json` env). Flag table changes per pin (e.g. `noesync` obsolete
   in Proton 11).
   **PIVOTED (user directive 2026-08-11):** replaced by the native Rust Proton
   ABI (`src/runner/proton_abi.rs`) — a dynamic per-runner adapter on the
   `Runner` trait that applies Proton's launch semantics in Rust (compat
   config, env assembly, DLL overrides, prefix seeding) instead of static
   per-game quirk maps. Per-game `proton_compat_options` (user_apps.json)
   feeds the compat set; the ABI translates to `PROTON_*`/`WINE_*` env.
   Eliminates external Python script invocation at game launch.
3. Surface runner versions into `VERSIONS.txt` (kill `found(bundled)`).
   **DONE 2026-08-11 (tail commit)** — `utils::write_runner_versions_txt`
   (harvest + `RUNNER_VERSION` stamp) at extraction; see session-close block.

### Tier 2 — Valve-source build (only for custom deltas)
`git clone --recurse-submodules` + `configure.sh` + `make` (docker/podman,
Proton SDK images), `make module=<module> module` fast loop, pins lockfile.
Blocked on this host until podman/docker exist (deferred).

### Tier 3 — runtime parity (future)
pressure-vessel / steamrt4 adoption. `SteamLinuxRuntime_4` (appid 4183110)
present locally; 11.0-line tools (GE/cachyos) declare it in `toolmanifest.vdf`.

## What SteamFlow keeps owning
Launcher, session management, library/ACF handling, config, the steamclient
bridge, RTX Remix modding layer, D7VK/D3D7 policy knobs, per-game fixups
(`seed_scripts/883710.rhai`), and (Phase 2) the env-parity harness.

## Non-goals / decisions
- **No wine-master tracking.** A new tag = pin bump + conformance run.
- Do not copy Proton trees into `compatibilitytools.d` unless exact-pinning
  (disk pressure: 29 GB free).
- `Proton - Experimental`, GE, cachyos stay **per-game only**, never default —
  and on this host they're unusable anyway (classic-wow64).
- Official Proton 11.0 fetched (2026-08-11) via the steam-cdn pipeline with
  the saved session + per-app PICS access token (owner-only tools need it;
  see Phase 1b and src/headless.rs test_download_proton). On disk at
  `steamapps/common/Proton 11.0` — unbootable on this host (classic-wow64,
  no 32-bit host libs), kept as the vendored end-state artifact.

## Phase 2 — `test-diff` findings (2026-08-11, RE2 883710)

Run: `steamflow test-diff 883710` (native log auto-discovered at
`~/Фото, видео/steam-883710.log`; SteamFlow session = newest with
`SteamAppId=883710`).

**Divergences found: 24 (2 missing, 22 extra, 0 mismatched, 0 matched).**

- **MISSING (native-only) — the real parity gaps:**
  - `PROTON_FORCE_LARGE_ADDRESS_AWARE=1` — native run used the `forcelgadd`
    launch option (old log: `Options: {'forcelgadd', 'wined3d'}`); SteamFlow
    never sets this.
  - `PROTON_USE_WINED3D=1` — native run forced wined3d; SteamFlow uses
    DXVK/vkd3d-proton instead (deliberate, but a divergence to track).
- **EXTRA (SteamFlow-only, 22)** — mostly expected: SteamFlow injects
  `WINEDLLOVERRIDES`/`WINEDLLPATH`/`WINEPREFIX`, the steamclient shim-suppression
  set, `STEAM_COMPAT_*` (client install path + compatdata), `__VK_LAYER_NV_optimus`/
  `__GLX_VENDOR_LIBRARY_NAME`/`__NV_PRIME_*` (NVIDIA offload), `VKD3D_DEBUG`,
  `DXVK_ENABLE_NVAPI=0`, `WINEDEBUG`, `DISPLAY`, `XDG_RUNTIME_DIR`, Steam API ids.
  The 2022-era GE-Proton log dumps no env vars at all (only the header block),
  so the EXTRA bucket is inflated by log-format asymmetry — a fresh native
  capture (Proton 9+/11 log with `Effective WINEDLLOVERRIDES:` lines) would
  move most of these into MISMATCHED/MATCHED.
- **0 mismatched / 0 matched** — consequence of the same asymmetry (no native
  env values to compare).

**Caveat:** the only native RE2 log on this host is from 2022 (GE-Proton7-41,
`PROTON_LOG=1` bash-era format) — useful for header facts and the `Options:`
reverse-map, but not a full env capture. The harness handles both formats and
accepts `--native-log <path>` for a fresh capture. For a true apples-to-apples
env diff, launch RE2 from native Steam with `PROTON_LOG=1` (modern Proton
writes `Effective WINEDLLOVERRIDES`/`WINEDEBUG`), then re-run `test-diff`.

**Follow-ups (Phase 2 items 2–3):** ~~map per-game quirks → `user_apps.json`
env~~ — **PIVOTED + DONE 2026-08-11** to the native Rust Proton ABI
(`src/runner/proton_abi.rs`, see Status header); item 3 — surface runner
versions into `VERSIONS.txt` (kill `found(bundled)`) — **DONE 2026-08-11
(tail commit)** via `utils::write_runner_versions_txt` at extraction.

## Revert / state
- Config backups: `config.json.bak-valve-phase1` (pre-directive),
  plus the working config now pins wine-tkg 11.13.
- Steam client currently running under wine-tkg 11.13; RE2 verified live.
- Kill pattern pitfall: `pkill -f 'steam.exe'` matches your own shell — use
  bracketed patterns (`steam[.]exe`) or explicit PIDs.

## Phase 1b — Official Valve depot downloads (steam-cdn) — FIXED 2026-08-11

**Problem:** downloading official Valve Protons via the steam-cdn pipeline (UI
Install → `install_game`, or `steamflow test-download-proton`) failed on chunk
download with `decompress: invalid Zip archive: Could not find EOCD`.

**Root cause (verified against SteamKit2 sources):** modern Valve depots
(Proton Experimental / 11.0, 2026) ship **Zstd-compressed chunks** (magic
`56 53 5A 61` = `"VSZa"`); the vendored `steam-cdn` crate only handled LZMA
(`"VZa"`) and fell back to ZIP. Decryption was correct all along (AES with
ECB-decrypted IV + CBC-PKCS7 — matches SteamKit2 `CryptoHelper.SymmetricDecrypt`;
the `"VSZa"` plaintext is the proof). The missing piece was decompression.

**Fix (vendored crate, in-tree):** added `utils/zstd.rs` (VZstd format per
SteamKit2 `VZstdUtil`: `"VSZa"` + u32 crc32 + zstd frame + footer `[crc32 u32,
size u32, "zsv"` in the LAST 3 bytes]) + `zstd` dependency;
`depot_chunk::decrypt_and_decompress` now branches LZMA → VZstd → ZIP.
Verified: depot 4862111 (65 MB `amdxcffx64.dll`) downloads and decompresses to
exactly the manifest size (65,657,608 bytes, valid PE32+); full Proton -
Experimental (1493711, 1.45 GB) follows the same path.

**Also fixed along the way:**
- **Tool installdir** (`resolve_install_game_info`): tools put `installdir`
  under `appinfo.config`, not `common` (and `parse_appinfo` can fail entirely on
  tool VDFs) → direct `find_vdf_in_pics` walk (common → config) → Proton
  installs into `steamapps/common/Proton - Experimental` (same dir real Steam
  uses; `resolve_runner` + `list_installed` pick it up), not `App 1493710`.
- **CDN auth token** (`get_cdn_auth_token`): `ContentServerDirectory.
  GetCDNAuthToken` service variant returns ERESULT Fail; switched to the
  job-based `CMsgClientGetCDNAuthToken` (EMsg 5546, same pattern as
  `GetDepotDecryptionKey`). Server-side it still times out on this session, but
  it's **non-fatal**: the CDN serves chunks tokenless (verified by curl);
  SteamKit2 itself only requests a token after a 403. No token = no `?token=`
  param = works.
- **Headless diagnostic:** `steamflow test-download-proton <name|appid>
  [--manifest-only] [--depot <id>]` — stage-logged reproduction of
  `install_game` (PICS appinfo → depot filter → content servers → depot key →
  manifest code → CDN token → manifest → download).

**State:** everything local, nothing pushed. The full download was running at
close of the spike; the vendored runner story continues from
"Phase 1 — current stack" above.

---

## Session close — 2026-08-11 (state for resuming)

**Worktree:** local only, NOT pushed (user's sequential-phase workflow; next
phase opens its own branch/PR off current `main`). `git status` new files:
`src/runner/` (proton_abi.rs + mod.rs), `src/parity.rs`, `src/headless.rs`,
`docs/architecture/valve-stack-replication.md`; modified: `src/lib.rs`,
`src/models.rs` (proton_compat_options), `src/infra/runners/wine_tkg.rs`
(ABI hook in build_env), `src/launch/mod.rs` (Proton shim-suppression +
steamclient override in Proton branch), `src/steam_client.rs`, `src/ui.rs`,
`src/main.rs`, `Cargo.lock`, `vendor/steam-cdn/*` (zstd + PICS access token).

**Delivered this session:**
1. **Official Proton 11.0 (4628710) vendored** — fetched via steam-cdn with
   the saved session + per-app PICS access-token fix (`test_download_proton`
   in headless.rs). On disk at `steamapps/common/Proton 11.0` — **unbootable
   on this host** (classic-wow64, no 32-bit host libs → `client_api.cpp:601`
   assert). Verified `wine-11.0` runs; kept as the vendored end-state artifact.
2. **Proton shim-suppression fix** (`src/launch/mod.rs`) — the builtin
   steamclient shim must be suppressed on ANY runner kind (Valve-stack
   finding #1); applied the PlainWine override set to the Proton branch too,
   keeping the real `STEAM_COMPAT_CLIENT_INSTALL_PATH`.
3. **Phase 2 item 1 — `test-diff` env-parity harness** (`src/parity.rs`):
   native proton-log parser (legacy + modern headers, `Options:` →
   `PROTON_*` reverse-map, `Effective WINEDLLOVERRIDES`/`WINEDEBUG`), session
   discovery, MISSING/EXTRA/MISMATCHED/MATCHED diff with priority flags.
   Initial run on 883710: 2 real gaps found.
4. **Phase 2 item 2 — native Rust Proton ABI** (`src/runner/proton_abi.rs`):
   port of Valve's `proton` script + `default_pfx` semantics (compat config
   table, env rules, base DLL overrides, `seed_prefix` prefix init) — no
   Python at game launch. Wired into the Runner trait's `build_env`; per-game
   `proton_compat_options` in `user_apps.json` (883710 → `["wined3d"]`).
   **Verified: `test-diff 883710` now 0 missing / 2 matched — both real gaps
   (PROTON_FORCE_LARGE_ADDRESS_AWARE, PROTON_USE_WINED3D) resolved.**
   RE2 renders under the ABI env (89% CPU, 1.54 GB RSS).

**Tests:** `cargo test --lib` = 89 passed (10 ABI + 3 parity + 76 prior).
Build clean (`cargo build`).

**Config state:** `config.json` restored to the verified wine-tkg 11.13 stack
(backups: `config.json.bak-valve-phase1`, `config.json.bak-valve-phase1b`).
`user_apps.json` 883710 gained `proton_compat_options: ["wined3d"]`.
RE2 display mode is USER-CONTROLLED (windowed per user) — do not override.

**Open items / next steps:**
- ~~Phase 2 item 3: surface runner versions into `VERSIONS.txt` (kill `found(bundled)`).~~
  **DONE 2026-08-11 (tail commit)** — `utils::write_runner_versions_txt` writes a
  canonical `VERSIONS.txt` at the runner root during extraction (harvests the
  tarball's component `version` files + stamps `RUNNER_VERSION` from the root
  `version` file or the release tag). Hooked into `install_github_package`,
  `install_game` (steam-cdn UI install), and headless `test_download_proton`.
  Never overwrites an existing `VERSIONS.txt` (the custom
  `steamflow-runner-wine11-wow64` ships an authoritative one). Fixes the
  `found(bundled)` display for flat-layout Proton trees (e.g. official 11.0's
  `files/lib/wine/x86_64-windows/*.dll` has no adjacent `version` files, so
  detection's flat-layout rule returns `"found"` until the override fills it).
- ~~Optional: fresh native `PROTON_LOG=1` capture of RE2 (modern format) to
  shrink the EXTRA bucket via real MATCHED/MISMATCHED comparison.~~
  **RE-RUN DONE 2026-08-11** — `steamflow test-diff 883710` against the newest
  session: **0 missing / 2 matched / 28 extra / 0 mismatched** (was 2 missing,
  22 extra pre-ABI). The two real gaps (PROTON_FORCE_LARGE_ADDRESS_AWARE from
  `forcelgadd`, PROTON_USE_WINED3D from `wined3d`) are now MATCHED; the EXTRA
  bucket is the documented 2022-log format asymmetry (bash-era header dumps no
  env values → inflated) + SteamFlow's own injections (shim suppression,
  STEAM_COMPAT_*, NVIDIA offload, WINEDLLPATH). A truly fresh native capture
  still requires launching RE2 from native Steam with `PROTON_LOG=1` — the only
  native log on this host remains the 2022 GE-Proton7-41 one.
- ~~Official Proton 11.0 boot on this host requires i386 multilib packages
  (user decision pending); keep wine-tkg 11.13 as the working stack.~~
  **CLOSED / REJECTED (user directive 2026-08-11): the host is pure 64-bit —
  host `i386-multilib` packages are permanently rejected. Do NOT install,
  suggest, or test them; never re-open this item.** Official Proton 11.0
  (classic-wow64, `i386-unix` present) therefore remains unbootable on this
  host; wine-tkg 11.13 stays the working stack. The path forward for official
  Proton is **Phase 3: a containerized pure-PE WoW64 build of Valve's
  `proton_11.0` source** (Valve Proton SDK image) with zero host 32-bit ELF
  library dependencies — see §Phase 3 below.
- ~~RE2 relaunch under the ABI env already done; `seed_prefix` (native prefix
  init) is unit-tested but not yet exercised against a real Proton-tree
  prefix — natural next integration point for Proton-kind runners.~~
  **DONE 2026-08-11 (tail commit)** — `seed_prefix` is now wired into
  `prepare_prefix` (`src/infra/runners/wine_tkg.rs`): when a game's prefix is
  fresh (no `system.reg`) and the runner ships `files/share/default_pfx`
  (Proton-kind trees), SteamFlow seeds the prefix natively (copy tree +
  dosdevices symlinks + version marker) with no external Python init scripts.
  Non-fatal on failure (wine's own init takes over). The wine-tkg 11.13 stack
  has no `default_pfx` (PlainWine) so the current stack is unaffected.

## Phase 3 — containerized pure-PE WoW64 Proton build (CLOSED 2026-08-12)

**Goal (ACHIEVED):** build Valve's `proton_11.0` source into a **pure PE
WoW64 runner** (zero host 32-bit ELF library dependencies) so official
Proton runs on this pure-64-bit host — resolving the i386-multilib rejection
above. No host `i386-multilib` was ever involved; all 32-bit needs are
satisfied by the container's toolchain and the runner's bundled PE DLLs.
Result: `compatibilitytools.d/steamflow-proton-11.0-purepe`, E2E-verified on
RE2 (883710). Full execution record with every gate result lives in
`docs/architecture/phase3-pure-pe-proton11.md`.

**Prerequisite:** podman or docker on this host (none installed — Tier 2 was
deferred on this). Install podman first (pure-64-bit friendly, rootless).

**Pipeline:**
1. **Base image:** `registry.gitlab.steamos.cloud/proton/steamrt4/sdk/x86_64`
   — the official Valve Proton SDK for the **proton_11.0** line (the branch
   pins `:4.0.20260331.220802-0` in `Makefile.in`; `soldier/sdk` is for older
   Proton lines and was NOT used). Tag: the branch's own pin, verified
   anonymously pullable.
2. **Source:** `git clone --recurse-submodules -b proton_11.0
   https://github.com/ValveSoftware/Proton.git` inside the container (or
   volume-mounted from the host for incremental builds).
3. **Configure + build:** follow the repo's `README.md` (Valve-supported path):
   `./configure.sh --proton-name "proton_11.0-wow64" --build-name
   "steamflow-pure"` then `make` (or `make module=<module> module` fast loop
   for deltas: `wine`, `dxvk`, `vkd3d-proton`, `dxvk-nvapi`, `wine-mono`,
   `wine-gecko`). The SDK image builds **both** PE halves of wine (WoW64) and
   produces the `dist/` tree.
4. **Pure-PE verification gate (the point of Phase 3):** the built
   `dist/` must contain **no `i386-unix` ELF loader** — i.e. no
   `files/lib/wine/i386-unix/` dir. Presence of `files/lib/wine/i386-windows/`
   (32-bit PE DLLs) is REQUIRED (WoW64 32-bit side); presence of
   `i386-unix/` is the classic-wow64 failure mode. Host-side check:
   `find dist -name '*.so' | grep i386` must be empty and `file
   files/bin/wine` must say PE32+ (not ELF 32-bit).
5. **Runtime env on this host:** because the runner is pure PE WoW64, it needs
   only the **64-bit** host GL/Vulkan/X libs (present) — no 32-bit host libs.
   The `files/share/default_pfx` ships in `dist/` and `seed_prefix`
   (Phase 2 tail) seeds new game prefixes natively.
6. **Install:** stage the built `dist/` as
   `compatibilitytools.d/proton_11.0-wow64/` (or
   `steamapps/common/Proton 11.0` replacement), chmod +x the wine binaries,
   then re-run the client + RE2 conformance (shim-suppression env applies —
   the 32-bit Steam client still needs it).
7. **Conformance checklist (reuse Phase 1 gates):** Windows Steam client boots
   (client_api.cpp:601 must NOT appear), RE2 (883710) passes the ownership
   gate + first-frame render, `test-diff 883710` parity holds, `VERSIONS.txt`
   written at extraction (Phase 2 tail) shows real component versions.

**Open questions (RESOLVED during execution):** SDK image tag — branch pin
`4.0.20260331.220802-0` (steamrt4, **not** soldier — proton_11.0 switched
lines; soldier is for older Proton); disk budget — tight (~14G), managed via
incremental cache cleanup + `-j8` (ccache not installed, needs sudo);
wine-mono/gecko — fetched in-container during the build (host networking
wrapper); podman rootless — solved with `uidmap` + `~/.local/bin/podman`
host-network wrapper + `image_copy_tmp_dir` on /home.
