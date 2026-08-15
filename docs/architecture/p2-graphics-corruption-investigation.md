# P2-RTX Graphical Corruption Investigation (Phase 5, 2026-08-15)

> Status: **OPEN — root cause hypothesis identified, A/B pending**.
> Branch `phase5/p2-graphics-investigation`. Companion to
> `phase5-onlinecontainerized-validation.md` (Part 2 continued) and the
> `rtx-remix-modding` skill references (`p2rtx-diag-pass-20260815.md`).

## Problem

Portal 2 RTX (620) renders **corrupted frames** under RTX Remix
(`remix-main+8fc13a51`, stock p2-rtx 2.4.3 runtime) — on **both** runners:

- wine11-wow64 DirectWine (15:24 run)
- pure-PE Proton 11.0 in the SLR container (16:19 run, `OfflineEmulated`)

The corruption is **runner-independent by construction**: the 16:19 container
run (purepe) exhibits byte-identical symptoms to the 15:24 DirectWine run.
Observed variants (user report, phase-5 testing): white screen (compositor /
stall), two distinct "broken but RTX" variants, and a non-RTX rasterized
variant. The RTX pipeline is confirmed *running* (MangoHud: ~25 fps RTX vs
~120 fps non-RTX; camera accepted in-map; draw-classification streaming).

Visual corruption spans the full spectrum: very dark/black with only lights,
flickering/noisy speckles, wrong colors/over-bright, stretched/garbage
geometry, missing textures/black materials.

## Verified evidence (2026-08-15 evening)

### 1. Core mod files are pristine — file corruption ruled out

| File | Installed md5 | Pristine zip md5 | Match |
|---|---|---|---|
| `bin/d3d9.dll` | `9187d43b…` | `9187d43b…` | ✅ |
| `bin/winmm.dll` | `ab9f8828…` | `ab9f8828…` | ✅ |
| `portal2_dlc3/pak01_dir.vpk` | `71103856…` | `71103856…` | ✅ |

### 2. PRIME SUSPECT — dual-mod conflict: `Digital` pack loaded alongside the base mod

`rtx-remix/mods/` contains **two** mod directories, each with its own
`mod.usda`:

- `portal2rtx/` — current base mod (p2-rtx-base-mod master, installed
  2026-08-06, 42 `.usda` stages)
- `Digital/` — **Feb-2026 real directory**, the Digital-additions pack built
  for **p2-rtx 2.1** (not a symlink; `mod.usda` + `materials/` + `water.usda`
  + `assets/`)

The runtime loads every `mods/*` directory containing a `mod.usda`, so the
2.1-era Digital replacement stages overlay the 2.4.x base mod → replacement
binding conflicts → wrong materials / missing textures / garbage geometry.

**Direct log proof — both runs:**

```
warn:  A suboptimal replacement texture detected: z:\…\rtx-remix\mods\Digital\assets\portal mel\907…   (25× 15:24 run, 23× 16:19 run)
err:   Texture (20480x6144) doesn't fit into STAGING memory for streaming (TEXTURE=160MB, but STAGING=96MB). Forcing synchronous upload, disabling…
err:   Texture (10240x10240) doesn't fit into STAGING memory for streaming (TEXTURE=133MB, but STAGING=96MB)…
err:   Texture (32768x4096) doesn't fit into STAGING memory for streaming (TEXTURE=170MB, but STAGING=96MB)…   (16:19 run only)
```

Digital's 2.1-era replacement textures are enormous (160–170 MB each) vs the
runtime's 96 MB streaming staging buffer → **forced synchronous uploads**
(frame-killing stutter → the ~25 fps) + streaming failures → black/missing
textures. Both failures are identical across runners because they are driven
by the same game data.

### 3. Co-suspects (secondary)

- **`rtx.conf` mutation**: installed 48,088 B vs pristine 39.5 KB (runtime
  rewrites it; `graphicsPreset = 4`, `integrateIndirectMode = 2`,
  `autoExposure.evMaxValue = 6`, Digital-era leftovers). Corrupt/absent
  settings can produce dark/wrong-exposure output.
- **NRC failure → Importance-Sampled fallback + NRD denoiser state**: NRC
  init fails under wine (expected); the debugoptimized build asserts
  `"Invalid denoiser mode"` at `rtx_nrd_settings.cpp:245` — in the release
  build the assert is compiled out, so the denoiser may run in a bad mode →
  noise/flicker.
- **`Texture 0 without valid hash` skips** (60× pre-init per run): skipped
  textures → black materials (benign pre-init volume, but compounds).

## VERDICT — CONFIRMED (2026-08-15 evening)

User retested after the `.trex` restore (Digital out): **Portal 2 renders perfectly**.
Root cause confirmed: the partial 2026-08-08 `.trex` restore (missing USD plugin
resources + foreign d3d9.dll) was the corruption source, not the Digital pack.
The Digital pack remains a secondary concern only for its oversized 2.1-era
textures (staging-buffer warnings).

Mel (317400) follow-up: installed the same 2.4.3 chain (bin/.trex + wrapper +
p2-rtx.dll + known-good rtx.conf) + base mod + real Digital pack into Mel's
dir; 317400 SteamFlow entry created (purepe + OnlineContainerized,
`-game portal_stories +map sp_a1_mel_intro`).

## Test log — 2026-08-15 evening (follow-up)

### NEW ROOT-CAUSE CANDIDATE — the `.trex` runtime was a partial restore (now fixed)

Full audit of `bin/.trex` vs the 2.4.3 archive (the ONLY valid reference — the
runtime is xoxor's modified build inside the archive, NOT stock 1.5.2):

- **124 of 165 archive files were MISSING**, including **all `usd/` plugin
  resources** (`plugInfo.json` + Hydra `*.glslfx` shaders) — the USD
  stage/material loader ran without its plugin registry → broken/black
  materials, garbage geometry.
- **37 diag-artifact leftovers** (`d3d9.pdb` 102 MB, `cudart64_13.dll`,
  `nvrtc64_130_0.dll` 101 MB, `python311.dll`, `tbb*.dll`, 26 `usd_*.dll` +
  `usd/` folder, 2 crash dumps) from the 2026-08-07 CI deploy.
- `.trex/d3d9.dll` was a **different binary** than the archive's (`24c7cf…`
  vs `9e301a…`, same 203,802,112 bytes, same `remix-main+8fc13a51` string) —
  the bridge server (`NvRemixBridge.exe`, archive-matching) was paired with a
  foreign runtime DLL.
- The 2026-08-08 00:04 "restore" was PARTIAL — it brought back only ~41 of
  165 files (backup dir `~/devis/tmp/p2-stock-runtime-backup/` is now empty).

**Fix applied (reversible, backup at `~/devis/tmp/p2-trex-mixed-backup-20260815/`):**
extract the archive's full `bin/.trex` over the install + delete artifact
leftovers. Verified: `d3d9.dll` md5 = `9e301a…` (archive), `usd/` resources
present, shared top-level files md5-OK. This is runner-independent (shared
game data) and a far stronger corruption source than the Digital pack.

### A/B step 1 (Digital removed) was INVALID — the mod never loaded

User moved `mods/Digital` out, but the 16:53 run rendered with **wine builtin
wined3d** (`wined3d_dll_init Application name portal2.exe\Direct3D` — 15M trace
lines; zero bridge/remix logs; `bin/dxwrapper-portal2.log` not updated → the
winmm → dxwrapper → p2-rtx → d3d9-bridge chain never started). "RTX Remix not
initialized" + no MangoHud overlay + no RTX menu; only menu/subtitles render.

### Launch-matrix isolation (same mod files, same prefix)

| run | runner / mode | WINEPREFIX | mod chain |
|---|---|---|---|
| 15:24 | wine11-wow64 DirectWine | compatdata/620/pfx | ✅ bridge + RTX |
| 15:54 | wine11-wow64 DirectWine | master_steam_prefix/pfx | ✅ DxWrapper log |
| 16:19 | purepe **OnlineContainerized** | compatdata/620/pfx | ✅ bridge + RTX + Digital |
| 16:53 | purepe **DirectWine (bare)** | compatdata/620/pfx | ❌ wined3d fallback |

**Finding: purepe's bare `files/bin/wine` (DirectWine mode) does not engage the
mod's bin-dir DLL chain** — the game falls back to wine builtin d3d9 (wined3d).
wine11-wow64 bare and purepe-in-container both load the chain. DirectWine +
purepe is therefore not a valid configuration for p2-rtx testing; the Digital
A/B must run under wine11-wow64 DirectWine or purepe OnlineContainerized.

Pending: valid A/B (wine11-wow64 DirectWine, Digital out) → judge visuals.

## A/B plan (in order)

1. **Move `Digital` out** (backup, don't delete):
   `mv "…/rtx-remix/mods/Digital" ~/devis/tmp/p2-digital-pack-backup-20260815/`
   → relaunch (`+map sp_a1_intro1`). If corruption clears: **root cause
   confirmed** (dual-mod conflict).
2. Restore pristine `rtx.conf` (from `p2rtx-2.4.3.zip`) + minimal overrides
   (`rtx.graphicsPreset = 4`, `rtx.showUI = 2`) → retest (exposure/darkness).
3. `rtx.integrateIndirectMode = 0` (skip NRC entirely) → retest (noise/denoiser).
4. If still corrupt: capture per-variant screenshots and classify against the
   five corruption classes to isolate the failing pass.

## Test configuration for reproduction (current, 2026-08-15)

- `config.json` → `game_configs[620].forced_proton_version =
  steamflow-proton-11.0-purepe` (pure-PE Proton 11.0)
- `user_apps.json[620]` → `steam_mode = OfflineEmulated` (phase-4-proven
  container boot; **no native Steam required** — do NOT use
  `OnlineContainerized` for this investigation, it needs native Steam +
  system i386 GL libs)
- `launch_options` carry `+map sp_a1_intro1`; remap watcher
  (`~/devis/tmp/auto-remap-p2rtx.sh`) still required for the compositor white.
- Logs land in `~/remix_logs` (`DXVK_LOG_PATH` is honored by the remix fork
  and bridge).

## References

- Evidence dirs: `/home/wer/devis/tmp/p2-diag-pass-20260815/`
  (15:24 run logs + screenshots), `/home/wer/remix_logs/` (16:19 run logs)
- Skill `rtx-remix-modding`: references/p2rtx-diag-pass-20260815.md,
  references/p2rtx-white-screen-stale-mods.md
- `docs/architecture/phase5-onlinecontainerized-validation.md`
