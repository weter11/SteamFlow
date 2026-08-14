# Phase 3 — Pure-PE WoW64 Proton Build (CLOSED 2026-08-12)

**Branch:** `phase3/pure-pe-proton11` (rebased onto `origin/main`; 0 behind /
7 ahead — ready to push)

**Dates:** initiated 2026-08-11 · closed 2026-08-12

**Goal (restated):** build Valve's `proton_11.0` source into a **pure PE
WoW64 runner** — zero host 32-bit ELF library dependencies — so official
Proton runs on this pure-64-bit host (resolution to the permanently-rejected
i386-multilib item).

## ✅ OUTCOME — Phase 3 COMPLETE

The containerized build produced a working **pure-PE WoW64 Proton 11.0**
runner, staged as `compatibilitytools.d/steamflow-proton-11.0-purepe`
(1.4 GB), and it **booted RE2 end-to-end**:

- **Build:** `make -j8 redist` → `REDIST_EXIT: 0` in podman (rootless,
  host-network wrapper) using the branch-pinned **steamrt4** SDK
  (`registry.gitlab.steamos.cloud/proton/steamrt4/sdk/x86_64:4.0.20260331.220802-0`),
  not the soldier image originally assumed in the plan.
- **Pure-PE gate — ALL PASS on the staged redist:**
  - `find . -type f -exec file {} + | grep -c 'ELF 32-bit'` → **0**
  - `files/lib/wine/i386-windows/` = 611 × **PE32**; `x86_64-windows/` = 613 × **PE32+**
  - `i386-unix/` contains only the 64-bit `wine64` loader (Valve's own layout;
    official depot has **35 ELF-32 .so** there — the multilib dependency we removed)
- **Live E2E:** `steamflow test-launch 883710` → RE2 window
  `"RESIDENT EVIL 2"` (class `steam_proton`, IsViewable, 1926×1112 windowed)
  rendering under pure-PE wine with its own isolated wineserver; vkd3d-proton
  swapchain 1920×1080 created; **no i386-multilib anywhere**.
- **Parity:** `test-diff 883710` → 0 missing / 0 mismatched / 2 matched.
- **VERSIONS.txt** stamped (`proton-11.0-1b-purepe` + component versions) —
  Phase 2 tail visibility fix applied to the staged runner.

## 1. Container prerequisites — status: DONE (2026-08-11)

| Check | Result |
|---|---|
| `podman` | ✅ 4.9.3 installed (user action, apt) |
| `uidmap` (newuidmap/newgidmap) | ✅ installed (user action) — rootless multi-ID mapping |
| `slirp4netns` / `pasta` | ❌ absent (no sudo); worked around with `~/.local/bin/podman` wrapper injecting `--network=host` |
| rootless networking | ✅ host-network wrapper (valid rootless, full connectivity for in-container wget fetches) |
| image unpacking | ✅ `~/.config/containers/containers.conf` → `image_copy_tmp_dir` on /home (root `/` only 31G) |
| SDK image | ✅ pulled: steamrt4 `4.0.20260331.220802-0` (~7G) — **branch pin, not soldier** |
podman info | grep -A2 rootless
```

**IMPORTANT — the task-spec SDK image is wrong for proton_11.0.** The task
said `registry.gitlab.steamos.cloud/proton/soldier/sdk` — soldier is the SDK
for older Proton lines. The `proton_11.0` branch pins **steamrt4**:
```
# Makefile.in (proton_11.0, line 30)
STEAMRT_IMAGE ?= registry.gitlab.steamos.cloud/proton/steamrt4/sdk/x86_64:4.0.20260331.220802-0
```
**Both images are anonymously pullable** (verified via the standard Docker
Bearer token flow — no credentials needed):
- `proton/steamrt4/sdk/x86_64`: 7 tags, pinned tag `4.0.20260331.220802-0`
  present (also `-2`, `-3` patch tags)
- `proton/soldier/sdk`: 25 tags, `latest` present
- JWT auth realm: `https://gitlab.steamos.cloud/jwt/auth` (service
  `container_registry`) — anonymous scope `repository:...:pull` grants tokens

`configure.sh` discovers the engine itself; force podman with
`--container-engine=podman` (avoids the `/etc/containers/nodocker` podman-docker
shim check).

## 2. Source workspace — status: ✅ DONE

```
/home/wer/devis/steamflow-phase3/proton
```
- Branch: `proton_11.0` @ `0745bfb` (lsteamclient networking_message wow64 fix, 2026-07-27)
- Clone: `git clone --depth 1 --branch proton_11.0 --recurse-submodules --shallow-submodules`
  (shallow to protect the 22G disk budget)
- 23 submodules checked out (wine @ 81d78e4, dxvk @ 0a70623, vkd3d-proton @
  ef20c02, dxvk-nvapi @ c68c350, vkd3d @ 30b93dc, FEX, kaldi, vosk-api, …)
- Size: **3.9G**; disk free dropped 22G → **19G**
- `configure.sh`, `Makefile`, `Makefile.in`, `proton`, `default_pfx.py` all present

## 3. Configure & build — status: ✅ MODULE TEST BUILD PASSED (classic-wow64)

### Environment solved (2026-08-11, this session)
- podman 4.9.3 installed (user action); **`uidmap`** package installed (user
  action) → rootless works
- **`slirp4netns` missing** (no sudo) → solved with host networking via
  `~/.local/bin/podman` wrapper injecting `--network=host` (configure.sh
  `--container-engine=$HOME/.local/bin/podman`); container only needs
  outbound HTTPS for gecko/mono/xalia fetches, so host networking suffices
- **root `/` partition full during image pull** → `~/.config/containers/
  containers.conf` `[engine] image_copy_tmp_dir = "/home/wer/.cache/
  podman-image-tmp"` (image unpack now lands on the big /home NVMe)
- SDK image `proton/steamrt4/sdk/x86_64:4.0.20260331.220802-0` pulled (~7G;
  /home 27G→20G)
- ccache NOT installed (needs sudo) — skipped; disk is the constraint anyway

### Build commands (validated)
```bash
mkdir -p /home/wer/devis/steamflow-phase3/build && cd ...
../proton/configure.sh --container-engine=$HOME/.local/bin/podman \
  --build-name=pure_pe_wow64
make -j8 module=winex11.drv module   # -j8 not -j16: 14G-RAM box hung at -j16
```
- `configure.sh` ✅ generated build/Makefile
- `make module=winex11.drv module` ✅ **MODULE_EXIT: 0** after regenerating
  `src-wine/include/wine/server_protocol.h` (`perl tools/make_requests` —
  the module target's `wine-configure` prerequisite doesn't regenerate it;
  the tracked header in the wine repo is stale vs `server/protocol.def`)
- Build artifacts verified:
  - `obj-wine-x86_64/dlls/winex11.drv/x86_64-windows/winex11.drv` → **PE32+**
  - `obj-wine-i386/dlls/winex11.drv/i386-windows/winex11.drv` → **PE32**
  - `obj-wine-i386/dlls/winex11.drv/winex11.so` → **ELF 32-bit** ← PROBLEM
- First attempt hung the box at `-j16` (14G RAM, kaldi/parallel gcc);
  `-j8` completed. System hang + RAM limitation were the interruption cause.

### ⚠️ CRITICAL FINDING: Valve's default build is CLASSIC-WOW64, not pure-PE
The `module` target built **both** PE halves AND a full 32-bit unix tree:
- `obj-wine-i386` is configured `--host=i686-linux-gnu` (a real 32-bit host
  build producing ELF-32 `.so` unix libs) — this is exactly the layout that
  requires host `i386-multilib` and is **permanently rejected** on this host.
- Proton's `Makefile.in:73-78`:
  ```make
  ARCHS := i386-windows x86_64-windows
  ifeq ($(TARGET_ARCH),x86_64)
      ARCHS += i386-unix x86_64-unix     # ← adds the 32-bit ELF unix side
  ```
  and `WINE_x86_64_AUTOCONF_ARGS` (line 619) maps `unix_ARCHS` into
  `--enable-archs=…`. The official Proton 11.0 depot ships this classic
  layout (verified: `files/lib/wine/i386-unix/bcrypt.so` etc. are ELF 32-bit
  with `/lib/ld-linux.so.2`).

### The pure-PE path (Phase 3 next step)
Wine 11's **new WoW64 mode** is PE-only: `--enable-archs=i386-windows,
x86_64-windows` in a **single 64-bit tree** — the 32-bit side ships as PE32
DLLs (`i386-windows/`) with NO `i386-unix` ELF loader at all. The Proton
Makefile's `windows_ARCHS` machinery (line 86) already supports this; the
needed change is to drop `i386-unix` from `ARCHS` for `TARGET_ARCH=x86_64`
(i.e. `ARCHS := i386-windows x86_64-windows`, no `+= i386-unix …`), so:
- wine x86_64 tree gets `--enable-archs=i386-windows,x86_64-windows`
- the separate `obj-wine-i386` full-32-bit tree is not built
- dist has `lib/wine/i386-windows/` (PE32) + `lib/wine/x86_64-windows/`
  (PE32+) + `lib/wine/x86_64-unix/` — **zero 32-bit ELF**
This is a build-config patch to Proton's `Makefile.in` (or a
`--target-arch`-style override); it does not touch wine source.

**Revised gate after this finding:**
1. `find dist/lib/wine -name '*.so' -path '*i386*'` → empty (no i386-unix)
2. `find dist -type f -exec file {} + | grep 'ELF 32-bit'` → empty
3. `dist/lib/wine/i386-windows/` (PE32) + `x86_64-windows/` (PE32+) present
4. `file dist/bin/wine` → PE32+ loader; `wine64` ELF 64-bit

## 3b. PURE-PE BUILD VERIFIED (2026-08-11, later same day)

**Patch applied to `proton/Makefile.in` (3 edits, all build-config only, no
wine source changes):**
1. `ARCHS += i386-unix x86_64-unix` → `ARCHS += x86_64-unix` (line 78) —
   drops the i386-unix side; `rules-common.mk`/`rules-wine-tools.mk`/
   `rules-makedep.mk`/`rules-autoconf.mk` all gate on `$(arch)-$(os) ∈ ARCHS`,
   so every i386-unix tree (wine, kaldi, vosk, openfst, gstreamer family,
   ffmpeg, dav1d, libsoup, graphene, glslang, gst_plugins_rs, lsteamclient,
   steamexe, vrclient) is skipped automatically. i386-windows PE components
   (dxvk, dxvk-nvapi, vkd3d, vkd3d-proton, vulkan-headers, spirv-headers)
   remain, as their rules are `i386,windows`.
2. `WINE_x86_64_AUTOCONF_ARGS` then expands to `--enable-archs=x86_64,i386
   --enable-win64` — single 64-bit host tree cross-compiling BOTH PE halves
   (verified in `make -n` dry run; `--host=x86_64-linux-gnu`, `i386_CC=
   i686-w64-mingw32-gcc` retained for PE32 cross-compile).
3. **kaldi serialization block gated** on `findstring i386-unix` (the
   `.kaldi-x86_64-configure: .kaldi-i386-configure` edges hard-coded the
   i386 tree; broke with "No rule to make target .kaldi-i386-configure").
4. **module64 aliased to module32** — in pure-PE the single tree builds both
   PE halves; running both recipes concurrently raced on shared archives
   (`dlls/ntdll/i386-windows/libntdll.a: file truncated`).

**Module build (after cleanup + wine-x86_64 reconfigure):**
`make -j8 module=winex11.drv module` → **MODULE_EXIT: 0**

**Pure-PE gate scan on `obj-wine-x86_64/dlls/winex11.drv`:**
- `x86_64-windows/winex11.drv` → **PE32+** (x86-64) ✅
- `i386-windows/winex11.drv` → **PE32** (Intel 80386) ✅
- `winex11.so` (the only .so) → **ELF 64-bit** (unix side; 64-bit host libs
  only) ✅
- ELF 32-bit files in module output → **0** ✅

**Tree-wide gate on the whole build dir:**
- ELF 32-bit files → **0** ✅
- `i386-unix` dirs → **0** ✅

**Disk pre-flight:** freed 10G→14G by deleting the now-dead i386-unix obj/dst
trees (obj-wine-i386, obj-kaldi-i386, obj-vosk-i386, obj-openfst-i386,
gstreamer family, ffmpeg, dav1d, libsoup, graphene, glslang, gst_plugins_rs,
lsteamclient, steamexe, vrclient — NOT the i386-windows PE ones). NOTE: the
`/home/wer/devis/tmp/p2-*` dirs are P2-RTX research artifacts (stock-runtime
backup 5.8G, mod backups) — deliberately left untouched (research policy).

**Remaining caveat:** this verified the module-level proof (winex11.drv both
PE halves, zero 32-bit ELF). The full `make` still needs to complete (wine
tree is only partially built — kernel32/ntdll/ucrtbase i386-windows archives
exist, but a full dist needs all dlls + dxvk/vkd3d-proton i386-windows PE
staging), then `make redist` for the compat tool tree and the dist-level gate.

## 4. Pure-PE gate — status: DEFINITION FINALIZED (build-verified)

**Correction from the earlier plan:** the gate is NOT "no `i386-unix/` dir" —
Valve's own Makefile.in (`proton_11.0`) always creates `dist/lib/wine/
i386-unix/` and installs ONLY the **64-bit** loader there. And the module
build proved the default build ALSO produces a full 32-bit ELF unix tree
(`obj-wine-i386` with `--host=i686-linux-gnu` ELF-32 `.so` libs) — i.e.
**classic-wow64** layout. See §3 "CRITICAL FINDING" for the build-config
change needed (drop `i386-unix` from `ARCHS`).

**Verified classic-wow64 reference (official Proton 11.0 depot on disk):**
`files/lib/wine/i386-unix/` contains **32-bit ELF `.so` files** — bcrypt.so,
crypt32.so, dwrite.so, kerberos.so, … — and an ELF-32 `wine` executable
(interpreter `/lib/ld-linux.so.2`). Those are what need host 32-bit libs.

**The gate (final, build-grounded):**
1. `find dist/lib/wine -name '*.so' -path '*i386*'` → **empty** (no i386-unix
   ELF side)
2. `find dist -type f -exec file {} + | grep 'ELF 32-bit'` → **empty**
3. 32-bit PE side present: `dist/lib/wine/i386-windows/` (PE32 DLLs) +
   `dist/lib/wine/x86_64-windows/` (PE32+).
4. `file dist/bin/wine` → PE32+ (or ELF-64 loader); `wine64` ELF 64-bit.
5. `i386-unix/` may exist but must contain ONLY 64-bit ELF (`wine64`,
   `wine64-preloader`) — no `*.so`, no ELF-32 binaries.

**Expected result:** a dist tree with PE-only 32-bit side → boots on this
pure-64-bit host (64-bit host GL/Vulkan/X libs only), no i386-multilib.

## 5. Full build + staging + E2E — status: ✅ COMPLETE (2026-08-12)

### Full redist build
`make -j8 redist` → **REDIST_EXIT: 0** (resumable via make stamps through
three disk-full recoveries). Version stamp: `proton-11.0-1b`.

### Blocker fixes along the way (all committed)
| Blocker | Root cause | Fix |
|---|---|---|
| `wined3d.dll` link failed ("file not recognized") | single `-L` in `VKD3D_PE_LIBS` served both archs; i386-windows link grabbed the x86_64-windows `libvkd3d-1.dll` (PE32+ in a PE32 link) | `VKD3D_PE_LIBS` = `-l:` names only; per-arch `-L` routed through `i386_LDFLAGS`/`x86_64_LDFLAGS` make-var append (keeps media LIBFLAGS) |
| disk full (×3) | wine tree 3G + kaldi 2.3G + dxvk 2.7G + dist staging vs ~14G budget | freed `SteamFlow/target` caches (incremental/release) + phase3 `dist/` mirror + build logs; ccache absent (needs sudo) so disk is the only lever |
| wineopenxr i386 cross-compile `-Werror=pointer-to-int-cast` | `--enable-archs=x86_64,i386` made makedep build the i386 half; Valve's own comment: "32-bit is not supported by SteamVR, so we don't build it" | `WINEOPENXR_x86_64_PE_ARCHS = x86_64` (same mechanism Valve already uses for aarch64) |

### Staging + dist-level gate (ALL PASS)
Staged `redist/` → `compatibilitytools.d/steamflow-proton-11.0-purepe` (1.4G;
moved, not copied — ext4 has no reflink and /home was at 100%). Gates on the
staged tree:
- `find . -type f -exec file {} + | grep -c 'ELF 32-bit'` → **0**
- `find files/lib/wine -name '*.so' -exec file {} + | grep -c 'ELF 32-bit'` → **0**
  (official depot: **35** — the removed multilib dependency)
- `i386-windows/` 611 × PE32; `x86_64-windows/` 613 × PE32+
- `i386-unix/` = only `wine64` + `wine64-preloader` (ELF 64-bit — Valve's
  own layout)
- `VERSIONS.txt` stamped (RUNNER_VERSION=proton-11.0-1b-purepe + component
  versions); `classify_runner` → Proton kind (root `proton` script +
  `files/bin/wine` ELF-64)

### E2E launch — SUCCESS
`steamflow test-launch 883710` (after `test-diff 883710` → 0 missing /
0 mismatched / 2 matched) launched RE2 under the pure-PE runner:
- window `"RESIDENT EVIL 2"` (class `steam_proton`), IsViewable,
  1926×1112 windowed at (317,182) — user's own display mode, untouched
- 5 render threads @ ~99% CPU; vkd3d-proton swapchain 1920×1080 created;
  own isolated wineserver (no wine-tkg collision)
- ran stable until the user closed it

### Post-E2E fix (SteamFlow code, `9d4779a`)
**PerGame background-Steam spawn:** with PerGame prefix mode the pipeline
seeds `compatdata/<appid>/pfx` from the game runner's `default_pfx`, but
spawned the background Steam client with the hardcoded Steam Runtime Runner
(default wine-tkg, classic-wow64) → `init_wow64: could not load wow64.dll`
→ exit 53 (pure-PE wine has no unix-side wow64.dll shim). Fix: PerGame mode
now spawns background Steam with the **game's own runner**. Verified:
`test-launch 883710` → `WINEPREFIX=…/compatdata/883710/pfx`, Steam spawns
cleanly, no exit 53. (Also fixed `deploy_dll_symlinks` EEXIST on dangling
runner symlinks — `symlink_metadata()` instead of `exists()`, `3ff4347`.)

### Post-Phase-3 follow-up: Shared→PerGame runner-mismatch guard (2026-08-12)

**Context:** the pure-PE client investigation (see the
`steamflow-proton-runtime-debugging` skill) determined that the Windows Steam
client cannot boot under the purepe runner (CEF GPU-process crash + a second
32-bit `steam.exe` network-init stall), so the recommended split is **Steam
Runtime runner = wine-tkg** (hosts the client) + **per-game runner = purepe**
(games). But `effective_game_proton` no longer force-equals the game runner
to the runtime runner, so a **Shared** prefix would host two different wine
builds (two wineservers, different pipe protocols) →
`wine client error: version mismatch ... your wine binary was not upgraded
correctly` at launch.

**Change:** `WineTkgRunner` resolves an **effective prefix mode**
(`effective_prefix_mode(ctx)` + pure core `effective_prefix_mode_impl`, both
in `src/infra/runners/wine_tkg.rs`): it applies the configured mode (per-game
user config → launcher default) and, when that mode is `Shared` **and** the
Steam Runtime runner resolves to a different path than the game runner,
auto-falls back to `PerGame` with a visible warning:

```
[SteamFlow] Runner mismatch detected (Steam Runtime: "{steam}", Game: "{game}").
Automatically switching to PerGame prefix mode to prevent wineserver protocol collision.
```

The effective mode is threaded through every prefix decision point:

- `steam_wineprefix_for_game` (src/utils.rs) gained an
  `Option<SteamPrefixMode>` parameter: `Some(mode)` = effective mode from the
  launch pipeline; `None` = legacy configured-mode callers (UI management
  buttons, `launch_custom_exec` Mods-tab path).
- `prepare_prefix` + `build_env` (game WINEPREFIX, background-Steam spawn,
  CEF-enforcement prefix, the Shared+Steam-running warning gate) use the
  effective mode.
- Pipeline stages `prepare_prefix.rs` (symlink deployment),
  `resolve_game_fixups.rs` (registry fixups) and `resolve_dll_providers.rs`
  (component detection) resolve the same effective mode so nothing targets
  the wrong prefix.

**Tests** (`src/infra/runners/tests.rs`):
- Shared + `"wine-tkg"` runtime runner + `"steamflow-proton-11.0-purepe"`
  game runner → `PerGame` (the exact recommended split).
- Matching runners → stays `Shared`.
- No runtime runner configured → stays `Shared`.

**Effect:** the recommended split-runner config now works with the global
prefix mode left at its default — the launcher detects the mismatch and
isolates the runners into separate prefixes automatically.

### Post-Phase-3 follow-up: prefix self-heal for dangling builtin DLL symlinks (2026-08-12)

**Context:** the RE2 prefix (`compatdata/883710/pfx`) was seeded on
2026-08-11 while the game ran the vendored cachyos copy
(`compatibilitytools.d/steamflow-proton-11.0`). Seeding created **absolute
symlinks** into that runner's `files/lib/wine/{x86_64,i386}-windows/` tree
for every builtin DLL (kernel32, ntdll, user32, …). When the vendored copy
was later removed (only `steamflow-proton-11.0-purepe` remained), **599 of
609 system32 links dangled** and ANY wine — game runner or background Steam
— died before launch with:

```
wine: could not load kernel32.dll, status c0000135   →  exit 53
```

`seed_prefix` only seeds when `system.reg` is absent, and
`deploy_dll_symlinks` only covers game-DLL providers (dxvk/vkd3d/nvapi), so
the broken prefix was never repaired automatically.

**Change:** `utils::repair_dangling_prefix_symlinks(prefix, runner_root)`
walks `drive_c/windows/{system32,syswow64}`, re-points dangling links at the
**active runner's** equivalent `lib/wine` file (same relative subpath), and
drops links the active runner doesn't ship (pure-PE omits amdxc64/atidxx64/
winsqlite3/winewayland/wpcap/umu — a fresh prefix wouldn't have them).
`WineTkgRunner::prepare_prefix` runs it on every launch (no-op scan on
healthy prefixes; non-fatal on error).

**Verification:**
- Unit test `test_repair_dangling_prefix_symlinks` (repoint / drop /
  untouched-healthy / idempotent second pass).
- Live: after re-pointing the RE2 prefix's 1,306 links (16 dropped), the
  exact background-Steam invocation boots `steam.exe` under pure-PE wine
  (was exit 53 in ~1s; now alive past 20s with CEF/explorer/uiautomation).

### Post-Phase-3 follow-up: background Steam in master prefix under runtime runner (2026-08-13)

**Context:** with the pure-PE game runner split, PerGame mode spawned the
background Steam client with the **game's runner (purepe)** in the
**per-game prefix**. The client cannot boot under purepe (documented
2026-08-12: CEF GPU crash + network-init stall) → `exit 1` in ~2s, no
Steam logs, launch aborted at PreparePrefix. The stale-wineserver guard
and the "is Steam running" check also targeted the per-game prefix, so even
a running master-prefix client (launched via Manage) was not detected and
a doomed duplicate was spawned anyway. A second, compounding cause: the
per-game client-file deployment only symlinked `if !dst.exists()`, so a
stale real `steam.exe` (Feb-14 copy) was never refreshed and self-exited
with code 1.

**Change (commit b5f5c0a):** the client ALWAYS belongs to the master prefix
under the Steam Runtime runner (wine-tkg), in Shared AND PerGame mode:
- PerGame `prefix_steam_dir`/`steam_wineprefix` resolve to the master Steam
  dir + master prefix; the per-game prefix still receives the client-file
  deployment for `STEAM_COMPAT_CLIENT_INSTALL_PATH`.
- `steam_runner` is always the configured runtime runner, never the game's.
- Stale-wineserver guard targets the GAME prefix (`effective_game_prefix`),
  so it cannot kill the running master client.
- Deployed client files are REFRESHED from master when a stale real-file
  copy differs (byte-compare; symlinks are up-to-date by construction).

**Verification:** `test-launch 883710` → background Steam under wine-tkg,
ready signal in 6s, `effective_steam_wineprefix` = master prefix, game
launches under purepe (DXVK cache + swapchain), session `result: Success`.

### Follow-up: master-prefix split was a REGRESSION — client returns to per-game prefix (2026-08-13)

**b5f5c0a's verification was insufficient.** It checked "Steam ready in 6s +
swapchain created" — the same shallow 2s alive-check that masks graceful
post-spawn exits — so the split shipped green while breaking every launch.

**Observed failures (all `result: Success` per SteamFlow, all real failures):**
- RE2 (883710): game window appears, then clean self-exit ~3s later
  (`mfplat:MFShutdown`, no segfault, `MainMenu=False` written to
  `re2_config.ini`). Confirmed across policy `Enabled` AND `Disabled`
  (no client at all → SteamAPI_Init fails the same way).
- Portal 2 (620): "Steam must be running" dialog while the master-prefix
  client WAS running (`steam_running_before_launch=true`) — the game in
  `compatdata/620/pfx` simply cannot reach a client in the master prefix.

**Root cause:** Wine named pipes are **per-wineserver**. A game's
`steamclient.dll` connects to the client via `\\.\pipe\SteamClient…`, which
exists only in the client's own wineserver. b5f5c0a parked the client in the
master prefix (wine-tkg wineserver) while the game runs in the per-game
prefix (pure-PE wineserver) → pipe unreachable → `SteamAPI_Init` fails →
games self-exit or show "Steam must be running".

**Control case (the config that demonstrably worked):** the 08-12 E2E
sessions (16:09/16:56) had `effective_steam_wineprefix ==
effective_game_wineprefix == compatdata/883710/pfx` — client in the SAME
prefix as the game → ran stable until the user closed it. That is 8a56ed2's
layout (client with the game's runner in the per-game prefix).

**Change (revert of b5f5c0a's placement, keeping its file-refresh):**
- PerGame `prefix_steam_dir`/`steam_wineprefix` resolve back to the
  per-game prefix (client runs in the game's wineserver).
- `steam_runner` in PerGame mode is the GAME's runner again (8a56ed2);
  Shared mode keeps the configured runtime runner.
- The client-file REFRESH logic from b5f5c0a is kept (byte-compare vs
  master, refresh stale real copies — this fixed the real exit-1 cause,
  the stale Feb-14 `steam.exe`).
- The stale-wineserver guard still targets `effective_game_prefix`.

**Also fixed: `launch_verification` masked the whole class.** It only
checked the process was alive at 2s, so a game that self-exits 3-5s after
the window was recorded as "Success". Now two-phase: 2s fast-fail (instant
crashes) + sustained-liveness window to 8s (polled every 500ms) — any exit
inside the window is `failed_after_spawn` with the real lifetime. New test
`test_launch_verification_graceful_self_exit_caught` covers the 4s self-exit
case that the old 2s check missed.

### Session-auth sync for per-game prefixes — implemented; Portal 2 blocker root-caused (2026-08-14)

**What shipped (commit `feat(steam): …` 2026-08-14):**
`SteamClient::sync_master_session_to_prefix()` copies the master client's auth
state into a per-game prefix's Steam dir before the headless client spawns there:
`config/loginusers.vdf` (wholesale), the `config/config.vdf` Authentication block
— the `RememberedMachineID` JWT — (merged, target's other keys preserved), legacy
`ssfn*` sentries, and the `HKCU\Software\Valve\Steam` section of `user.reg`
(per-key overlay, EOL preserved). Guards: no-op if master has no session; never
downgrades a per-game login as fresh as master's; non-fatal. Wired into the
PerGame spawn path in `wine_tkg.rs` (runs only when no client is running in the
target prefix). 8 new unit tests; 105 lib tests + 15 suites green. Live run
verified the 620 prefix receives master's loginusers.vdf timestamp (1786715012),
the fresh machine JWT (iss `r:0012_28A6B9E0_68319`, exp 2027-03), and the
registry login keys.

**What it does NOT do (hard fact):** it does not produce a logged-in per-game
client. Sync is necessary but not sufficient — see the two blockers below.

**CONCLUSION — a second client process in the per-game prefix IS required; the
pointer-only model is disproven.** b5f5c0a parked the client in the master prefix
(wine-tkg wineserver) while games run in per-game prefixes (pure-PE wineserver);
Wine named pipes are per-wineserver, so the game's steamclient.dll cannot reach
the client's pipe → `SteamAPI_Init` failed (RE2 self-exit ~3s, Portal 2 "Steam
must be running"). That is exactly why 284e697 reverted b5f5c0a (client back in
the per-game prefix, 8a56ed2 layout) and why `STEAM_COMPAT_CLIENT_INSTALL_PATH`
alone cannot bridge the gap — it is a location hint (it already points at the
master client), not an IPC bridge. Do not re-derive this; the b5f5c0a experiment
already answered it.

**Portal 2 (620) blocker — hard state, evidence on disk:**
1. **purepe ClientAPI failure:** every per-game client run under purepe writes an
   assert dump whose message is `Assert( ClientAPI_InitGlobalInstance:
   InternalAPI_Init_Internal failed, most likely because you are missing a 32-bit
   dependency of steamclient.dll (the Steam client is a 32-bit app).
   ):…\src\common\steam\client_api.cpp:601` (identical text in every dump under
   `compatdata/620/pfx/drive_c/Program Files (x86)/Steam/dumps/`).
   `WINEDEBUG=+loaddll` shows zero unresolved modules — it is Steam's generic
   catch-all, not a literal missing file. Result: client runs but stays anonymous
   forever (webhelper `-steamid=0`; `connection_log.txt` has zero login attempts).
   Note: this is the same `client_api.cpp:601` the conformance gate below claims
   "✅" for — the gate only covers the master (wine-tkg) stack, not purepe.
2. **Machine-bound token rejection:** the SAME 620 prefix with the client spawned
   under **wine-tkg** (not purepe) boots fine AND connects to Steam CM for the
   first time ever (connection_log.txt 2026-08-14 16:22:39 `Connect() … 
   ConnectionCompleted() (185.25.182.20:27030, WebSocket)`) but login is refused:
   `Clearing in-memory token - 5 (Invalid Password): LogonFailureReceived` — the
   copied RememberedMachineID JWT is bound to the source install's machine
   identity and the server rejects it. Copying credentials into a second prefix
   creates a second machine identity; the token does not follow.

**MachineGuid doc/code mismatch (real bug, NOT yet fixed):** module doc in
`src/runner/proton_abi.rs:16` claims `seed_prefix()` does "MachineGuid
preservation"; the body (lines 480–511) does only copy_tree + dosdevices symlinks
+ version marker. Measured: MachineGuid is UNIQUE per prefix (master
`705bc93a-fec3-4716-b240-ef3304859be3`; 620 `4e849ba2-31f0-483a-8e17-a0b9bf066a08`;
883710 `92cfc9d1-…`; 203160 `e6056f5f-…`; 108710 `e10b7828-…`) — wine generates a
fresh one per prefix. Whether Steam's machine-token validation keys on MachineGuid
is UNPROVEN — that is the next probe.

**Committed vs open:** the sync machinery + this doc section are committed
(2026-08-14). Still open: (1) the per-game client must run under a runner whose
ClientAPI works (wine-tkg proven; requires relaxing the stale-wineserver guard
for the client's wineserver, since it currently kills foreign-runner wineservers
in the game prefix); (2) the machine-bound token rejection must be solved for a
per-game client to log in without the one-time `steam.exe -login` bridge.

**Single next step:** run the wine-tkg client in the 620 prefix with master's
MachineGuid injected into `compatdata/620/pfx/system.reg`
(`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`), watch
`connection_log.txt` ~90s. Login completes → MachineGuid is the binding:
implement preservation in `seed_prefix()` + include it in the sync, and the sync
work becomes sufficient. Still `Invalid Password` → MachineGuid is not the
binding; probe the client's own key store next, with the one-time `-login` bridge
per prefix as the fallback.

### Conformance gates (Phase 1 reuse) — status
- Windows Steam client boots without client_api.cpp:601 → ✅ (wine-tkg master
  stack unchanged; pure-PE runs game-side)
- RE2 ownership gate + first-frame render → ✅ (window + render threads +
  swapchain)
- `test-diff 883710` parity → ✅ (0 missing / 0 mismatched / 2 matched)
- `VERSIONS.txt` real component versions → ✅

## Known limitation (documented, not a Phase 3 defect)
First RE2 boot under pure-PE showed a black screen while rendering (render
threads pegged, swapchain created, window live). Likely first-run shader/
pipeline-cache compilation (vkd3d-proton cache was being built). Tracked as a
post-Phase-3 follow-up, not a blocker for the pure-PE goal.

## Open items — ALL CLOSED
- [x] **USER:** `sudo apt-get install -y --no-install-recommends podman`
- [x] podman rootless smoke test (`podman info`) — worked after `uidmap`
- [x] disk headroom decision — freed caches incrementally; -j8; ccache skipped
- [x] SDK tag choice — pinned `4.0.20260331.220802-0` (branch pin; `-2`/`-3` exist)
- [x] first `configure.sh` + `make` pass; module-loop verification
- [x] pure-PE gate scan on `dist/`; install + conformance

**Phase 3 verdict: CLOSED — pure-PE WoW64 Proton 11.0 built, staged, and
verified booting RE2 on the pure-64-bit host with zero 32-bit ELF
dependencies. i386-multilib remains permanently rejected (host constraint).**
