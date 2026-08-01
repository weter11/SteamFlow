// Grand Theft Auto V
// Ported from protonfixes/gamefixes/271590.py
set_env("WINE_LARGE_ADDRESS_AWARE", "1");
set_env("STAGING_SHARED_MEMORY", "1");
add_launch_arg("-ignoredifferentvideocard");
// Native dinput8 for launcher/mod compatibility (ScriptHookV etc.)
override_dll("dinput8", "native,builtin");
log("GTA V: large-address-aware + staging shared memory + launch arg + native dinput8 (port of 271590.py)");
