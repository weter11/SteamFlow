# Protonfixes → Rhai Translation Standard

SteamFlow runs game-specific tweaks through its **native Rhai engine**
(`src/launch/fixups/mod.rs`) instead of Python `protonfixes`. This document is
the canonical mapping used when porting community `protonfixes` scripts
(Valve Proton, Proton-GE, GE-Proton) into per-AppID `.rhai` fixup files.

## Where fixups live

| Location | Purpose |
|---|---|
| `~/.config/SteamFlow/fixups/<appid>.rhai` | User/ported per-game fixup (created on first launch by `seed_default_fixups()`) |
| `src/launch/fixups/seed_scripts/` | Bundled seed scripts shipped in the binary |

Priority (strict, evaluated in this order — later wins):

1. **Global runner environment** (steamflow-runner defaults)
2. **Game Rhai fixup** (`fixups/<appid>.rhai`) — overrides global
3. **User Custom Launch Options** (SteamFlow UI) — override Rhai

## Function mapping

| protonfixes (Python) | SteamFlow Rhai |
|---|---|
| `util.set_environment('KEY', 'value')` | `set_env("KEY", "value")` |
| `util.remove_environment('KEY')` | `remove_env("KEY")` |
| `util.winedll_override('dll', 'n,b')` | `override_dll("dll", "native,builtin")` |
| `util.disable_dll('dll')` | `disable_dll("dll")` |
| `util.disable_nvapi()` | `disable_nvapi()` (bundles `nvapi`, `nvapi64` disable + `DXVK_ENABLE_NVAPI=0`) |
| `util.append_argument('-flag')` | `add_launch_arg("-flag")` |
| `util.set_registry_dword(path, key, val)` | `set_reg_dword(path, key, val)` |
| `util.set_registry_string(path, key, val)` | `set_reg_string(path, key, val)` |
| `util.log('msg')` | `log("msg")` |
| `app.appid`, `app.appname` | `ctx.app_id`, `ctx.app_name` (getters) |
| `app.install_dir` | `ctx.install_dir` |
| `app.wineprefix` | `ctx.wineprefix` |

## override_dll type translation

| Rhai override_type | WINEDLLOVERRIDES fragment |
|---|---|
| `"builtin"` | `dll=b` |
| `"native"` | `dll=n` |
| `"native,builtin"` / `"n,b"` | `dll=n,b` |
| `"builtin,native"` / `"b,n"` | `dll=b,n` |
| `""` | `dll=` (disable override) |
| anything else | passed through verbatim (raw fragment) |

## Registry execution

`set_reg_dword` / `set_reg_string` queue `RegOp`s that are applied **inline**
right after the Rhai script succeeds and before the game spawns:

```
wine reg.exe add "HKCU\..." /v Key /t REG_DWORD|REG_SZ /d Value /f
```

Non-zero `reg.exe` exits log `fixup_registry_warning` and **do not** halt the
launch.

## Porting examples

### Example A — Resident Evil 2 / 3 / 7 (AMD AGS / NVAPI fix)
`protonfixes/gamefixes/883710.py`:

```python
from protonfixes import util
def main():
    util.disable_nvapi()
    util.winedll_override('amd_ags_x64', 'b')
```

`fixups/883710.rhai`:

```rhai
// Resident Evil 2 Biohazard
override_dll("amd_ags_x64", "builtin");
disable_nvapi();
```

### Example B — GTA V / Rockstar Launcher (memory & window fix)
`protonfixes/gamefixes/271590.py`:

```python
from protonfixes import util
def main():
    util.set_environment('WINE_LARGE_ADDRESS_AWARE', '1')
    util.set_environment('STAGING_SHARED_MEMORY', '1')
    util.append_argument('-ignoredifferentvideocard')
```

`fixups/271590.rhai`:

```rhai
// Grand Theft Auto V
set_env("WINE_LARGE_ADDRESS_AWARE", "1");
set_env("STAGING_SHARED_MEMORY", "1");
add_launch_arg("-ignoredifferentvideocard");
```

### Example C — Skyrim / older DirectX audio fixes (XAudio / D3D compiler)
`protonfixes/gamefixes/489830.py`:

```python
from protonfixes import util
def main():
    util.winedll_override('x3daudio1_7', 'n,b')
    util.winedll_override('d3dcompiler_46', 'n,b')
```

`fixups/489830.rhai`:

```rhai
// Skyrim Special Edition
override_dll("x3daudio1_7", "native,builtin");
override_dll("d3dcompiler_46", "native,builtin");
```

## Notes

- Full upstream `protonfixes` repo scraping is a separate future effort; the
  three examples above are the canonical reference ports.
- Method-style `ctx.set_env(...)` still works for backward compatibility but
  new fixups must use the free-function style.
- A malformed or failing Rhai script logs `fixup_script_error` and the launch
  continues without the fixup — never abort.
