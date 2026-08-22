# dxvk_enabled=false Contract + Runner Split (clean vs RTX Remix debug)

Date: 2026-08-16
Branch: `fix/dxvk-enabled-clean-runner`

## 1. The bug: `dxvk_enabled: false` was silently ignored

For any game launched through `steamflow-proton-11.0-purepe` with
`dxvk_enabled: false` (the default) and `d3d12_policy: Auto`, DXVK still ran.
Two independent mechanisms defeated the setting:

1. **WINEDLLOVERRIDES pairing leak** (`src/utils.rs::build_dll_overrides`):
   `d3d12_policy Auto` + a runner that bundles VKD3D-Proton (purepe does) set
   `effective_vkd3d_proton = true`, and the VKD3D-Proton pairing block pushed
   `d3d8/d3d9/d3d10core/d3d11=n,b` for *every* game — regardless of
   `dxvk_enabled`. Those native overrides hand the game the DXVK DLLs.

2. **Proton-script DXVK provisioning**: the purepe `proton` script installs
   DXVK DLLs into the prefix `syswow64`/`system32` by default (its
   `use_wined3d` flag only turns on when the compat set contains `wined3d`,
   i.e. `PROTON_USE_WINED3D=1`). SteamFlow never set it, so even a game with
   no DXVK override would find the provisioned DXVK d3d9.dll in the prefix.

**Observed impact**: Alan Wake (108710) crashed with `0xC0000005` on the
renderer thread (EIP in no loaded module) right after the intro cutscene —
running on DXVK master `0a70623de9c5c69` (debug-symbol build) despite
`dxvk_enabled: false`, instead of the WineD3D path the setting implies.
Alan Wake is known (Proton issue #156) to be sensitive to the DXVK/nvapi
stack: "preset other than very low → black screen/glitchy textures,
probably nvapi is a stub".

## 2. The fix (three coordinated changes)

### 2.1 `dll_provider_resolver.rs` — resolver honors `dxvk_enabled`

`resolve()` / `resolve_single()` / `get_custom_dll_path()` /
`get_runner_dll_path()` gained a `dxvk_enabled: bool` parameter (threaded
from `resolve_dll_providers.rs`, read from
`graphics_layers.dxvk_enabled`). When `false`:

- the runner's `*/dxvk/` subdirs are never candidates — the plain builtin
  dirs (`files/lib/wine/i386-windows/…`, WineD3D) are the only runner paths;
- a custom DXVK path (`custom_dxvk_path`) is ignored;
- system DXVK paths (`/usr/lib/dxvk/…`) are not listed either, so a runner
  without a builtin cannot fall back to system DXVK.

Unit tests: `test_dxvk_disabled_resolves_builtin_not_dxvk`,
`test_dxvk_disabled_ignores_custom_dxvk_path` (plus the pairing regression
test `test_build_dll_overrides_dxvk_disabled_no_d3d9_native_override` in
`utils.rs`).

### 2.2 `utils.rs::build_dll_overrides` — no native D3D pairing without DXVK

The VKD3D-Proton "pair D3D10/11 with native dxgi" loop now only pushes
`d3d8/d3d9/d3d10core/d3d11=n,b` when `dxvk_active`. `d3d12=n,b` +
`d3d12core=n,b` + `dxgi=n,b` remain (needed for D3D12 games regardless; with
WineD3D active the proton script installs the wined3d dxgi, so "native dxgi"
is the wined3d builtin — consistent, no null-import crash).

### 2.3 `wine_tkg.rs` — suppress DXVK provisioning via `wined3d` compat

When `!effective_dxvk && is_proton_game`, the compat set gets `wined3d`
inserted → `apply_proton_env_rules` emits `PROTON_USE_WINED3D=1` → the
proton script installs WineD3D builtins into the prefix **overwriting any
leftover DXVK DLLs** from an earlier launch. This is the same mechanism RE2
(883710) already used via `proton_compat_options: ["wined3d"]`.

## 3. Runner split: clean release vs RTX Remix debug

The debug-optimized runner (DXVK master `0a70623` debug-symbol build, used by
the RTX Remix mod chain) was renamed to
`steamflow-proton-11.0-purepe-rtx_remix_debug`; a clean release runner was
provisioned at the original name `steamflow-proton-11.0-purepe` (same
proton-11.0-1b wine, **DXVK 3.0.2 release** instead of master).

Registry updates:

- `config.json` `proton_version` → `steamflow-proton-11.0-purepe` (clean) —
  the default for non-Remix games.
- `config.json` `game_configs` `forced_proton_version`:
  - `108710` → clean (explicit)
  - `620` (Portal 2), `317400` (Portal Stories: Mel), `6910` (Deus Ex) →
    `steamflow-proton-11.0-purepe-rtx_remix_debug` (they ship RTX Remix
    bridges in their game dirs: `.trex/NvRemixBridge*`).
- `user_apps.json`: `620/317400/6910` `dxvk_enabled: true` — their RTX Remix
  runtime is DXVK-based, so the new `dxvk_enabled=false` → WineD3D contract
  must not change their effective stack (their overrides stay identical to
  before the fix). `108710` gets `proton_compat_options: ["wined3d"]`
  (explicit, same pattern as RE2).

The `master_steam_prefix` registry font paths reference
`…/steamflow-proton-11.0-purepe/files/share/wine/fonts` — still valid, since
the clean runner sits at that exact path with the same layout.

## 4. Verification

- `cargo test --all-targets` (CARGO_PROFILE_DEV_DEBUG=0, disk-constrained) —
  all green.
- Alan Wake (108710) `test-launch`: clean runner + `wined3d` path — no DXVK
  log, no Remedy minidump, no access violation; game transitions past the
  intro into the first level.
