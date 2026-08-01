// Resident Evil 2 Biohazard
// Ported from protonfixes/gamefixes/883710.py
override_dll("amd_ags_x64", "builtin");
disable_nvapi();
log("AMD AGS forced builtin; NVAPI disabled (port of 883710.py)");
