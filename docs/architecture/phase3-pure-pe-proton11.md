# Phase 3 — Pure-PE WoW64 Proton Build (Bootstrap Status)

**Branch:** `phase3/pure-pe-proton11` (off local `main` 172984d; origin/main is
3 commits ahead — rebase when merging)

**Date:** 2026-08-11

**Goal (restated):** build Valve's `proton_11.0` source into a **pure PE
WoW64 runner** — zero host 32-bit ELF library dependencies — so official
Proton runs on this pure-64-bit host (resolution to the permanently-rejected
i386-multilib item).

---

## 1. Container prerequisites — status: BLOCKED on one user action

| Check | Result |
|---|---|
| `podman` | ❌ NOT INSTALLED |
| `docker` | ❌ NOT INSTALLED |
| `nerdctl` / `buildah` | ❌ NOT INSTALLED |
| apt candidate | ✅ `podman 4.9.3+ds1-1ubuntu0.2` (noble) available; deps crun, fuse-overlayfs, passt, slirp4netns all in repo |
| user permissions | ✅ `wer` is in `sudo` group; `sudo` requires a password (no NOPASSWD) |
| rootless support | ✅ podman 4.9.3 on noble supports rootless via `fuse-overlayfs` + `slirp4netns` |
| SELinux | ✅ not in use (Ubuntu) — no `--relabel-volumes` needed |

**Action needed (user):** run once:
```bash
sudo apt-get install -y --no-install-recommends podman
# rootless verification (no sudo):
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

## 5. Post-build install + conformance (next session)

1. Stage `dist/` as `compatibilitytools.d/proton_11.0-wow64/` (chmod +x wine
   binaries; depot artifacts ship `-rw-`).
2. Shim-suppression env still applies (32-bit Steam client needs
   `steamclient=n;…` — Phase 2 launch/mod.rs fix).
3. Conformance gates (reuse Phase 1): Windows Steam client boots without
   client_api.cpp:601; RE2 (883710) ownership gate + first-frame render;
   `steamflow test-diff 883710` parity; `VERSIONS.txt` written at extraction
   (Phase 2 tail) shows real component versions.

## Open items
- [ ] **USER:** `sudo apt-get install -y --no-install-recommends podman`
- [ ] podman rootless smoke test (`podman info`)
- [ ] disk headroom decision for full build (19G free; wine build + ccache)
- [ ] SDK tag choice: pinned `4.0.20260331.220802-0` vs newer `-2`/`-3`
- [ ] first `configure.sh` + `make` pass; module-loop verification
- [ ] pure-PE gate scan on `dist/`; install + conformance
