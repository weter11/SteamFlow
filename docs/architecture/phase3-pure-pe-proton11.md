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

## 3. Configure & build — status: BLOCKED on podman install

Once podman is installed, in a fresh build dir (per README):
```bash
mkdir -p /home/wer/devis/steamflow-phase3/build && cd /home/wer/devis/steamflow-phase3/build
../proton/configure.sh --container-engine=podman --enable-ccache --build-name=steamflow-pure
make 2>&1 | tee build.log          # first full pass
make module=winex11.drv module     # single-module iteration loop (both 32/64-bit)
```
- `configure.sh` runs container permission checks (UID mapping, rootless
  detection); with podman rootless the inner UID maps to `$(id -u)` →
  `ROOTLESS_CONTAINER=0` path.
- ccache is highly recommended (`--enable-ccache`; `$CCACHE_DIR` mounted into
  the container) — the first full wine build is many GB of object files and
  the disk budget is tight (19G free).
- **Disk risk (flagged):** full build artifacts + ccache will likely exceed
  19G free. Plan: build in `/home/wer/devis/steamflow-phase3/build` and free
  space before the full pass, or clear `~/.ccache` after the module test.

## 4. Pure-PE gate — status: DEFINITION CORRECTED (source-verified)

**Correction to the earlier Phase 2 plan:** the gate is NOT "no `i386-unix/`
dir". Valve's own Makefile.in (`proton_11.0`) always creates
`dist/lib/wine/i386-unix/` and installs ONLY the **64-bit** loader there:
```make
# Makefile.in lines 661-663 (.wine-x86_64-post-build)
mkdir -p $(DST_DIR)/lib/wine/i386-unix
$(call install-strip,$(WINE_x86_64_DST)/lib/wine/x86_64-unix/wine64,$(DST_DIR)/lib/wine/i386-unix)
$(call install-strip,$(WINE_x86_64_DST)/lib/wine/x86_64-unix/wine64-preloader,$(DST_DIR)/lib/wine/i386-unix)
```
Wine is configured `--enable-win64` (Makefile.in:620) → 32-bit side is
**PE-only** (`i386-windows`), no 32-bit ELF unix build.

**Verified classic-wow64 reference (official Proton 11.0 depot on disk):**
`files/lib/wine/i386-unix/` contains **32-bit ELF `.so` files** — bcrypt.so,
crypt32.so, dwrite.so, kerberos.so, … — and an ELF-32 `wine` executable
(interpreter `/lib/ld-linux.so.2`). Those are what need host 32-bit libs.

**The gate (source-grounded):**
1. `dist/lib/wine/i386-unix/` may exist but must contain ONLY 64-bit ELF
   (`wine64`, `wine64-preloader`) — **no `*.so` files, no ELF-32 binaries**:
   ```bash
   find dist/lib/wine/i386-unix -name '*.so'          # must be EMPTY
   file dist/lib/wine/i386-unix/*                     # all must say ELF 64-bit
   ```
2. 32-bit PE side present: `dist/lib/wine/i386-windows/` (PE32 DLLs) +
   `dist/lib/wine/x86_64-windows/` (PE32+).
3. `file dist/bin/wine` → PE32+ (or the 64-bit ELF loader with a PE32
   wow64 32-bit half) — i.e. **no ELF 32-bit anywhere in dist**:
   ```bash
   find dist -type f -exec file {} + | grep 'ELF 32-bit'   # must be EMPTY
   ```

**Expected result:** a dist tree with `i386-unix` holding only the 64-bit
loader → boots on this pure-64-bit host (64-bit host GL/Vulkan/X libs only).

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
