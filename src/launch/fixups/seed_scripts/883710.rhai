// Resident Evil 2 Biohazard
// NOTE: amd_ags_x64 override intentionally NOT set — the minimal
// steamflow-runner-wine11-wow64 does not bundle the AGS builtin stub, so
// `override_dll("amd_ags_x64", "builtin")` makes the game's own working
// amd_ags_x64.dll unresolvable (exit 53). Game-local DLL priority wins
// (PR #67 rule). Full Proton builds that bundle the stub don't need the
// override either — their builtin is ABI-compatible with the game's usage.
disable_nvapi();
log("NVAPI disabled (port of 883710.py); amd_ags left game-local");
