//! Tests for the custom-exec ("Play Mod" / `test-mod`) launch path.
//!
//! Regression coverage for Phase 4 Task 1: `launch_custom_exec` must honor the
//! EFFECTIVE prefix mode (the runner-mismatch guard from
//! `wine_tkg::effective_prefix_mode`) instead of passing `None` to
//! `steam_wineprefix_for_game` and falling back to the RAW configured mode.
//! Without the guard, a Shared-configured game whose runner differs from the
//! Steam Runtime runner (e.g. 620 Shared + purepe game runner) resolves to the
//! MASTER prefix, where the purepe game cannot run against the wine-tkg
//! client's wineserver and dies before Steam.

use super::*;
use crate::models::{SteamPrefixMode, SteamRuntimePolicy};

fn test_config() -> LauncherConfig {
    LauncherConfig {
        steam_library_path: "/tmp/steamflow-test-lib".to_string(),
        proton_version: "steamflow-proton-11.0-purepe".to_string(),
        steam_runtime_runner: PathBuf::from("steamflow-runner-wine11-wow64"),
        steam_prefix_mode: SteamPrefixMode::Shared,
        ..Default::default()
    }
}

fn test_user_config(policy: SteamRuntimePolicy) -> crate::models::UserAppConfig {
    crate::models::UserAppConfig {
        steam_prefix_mode: SteamPrefixMode::Shared,
        steam_runtime_policy: policy,
        ..Default::default()
    }
}

fn per_game_prefix(library: &str, app_id: u32) -> PathBuf {
    PathBuf::from(library)
        .join("steamapps")
        .join("compatdata")
        .join(app_id.to_string())
        .join("pfx")
}

#[test]
fn custom_exec_resolves_per_game_prefix_on_runner_mismatch() {
    // Shared config, but the Steam Runtime runner (wine-tkg client) differs
    // from the game runner (purepe): the effective mode must fall back to
    // PerGame so the game lands in its own compatdata prefix, NOT the master
    // prefix where the purepe wineserver cannot attach to the client.
    let config = test_config(); // steam_runtime_runner = steamflow-runner-wine11-wow64
    let user = test_user_config(SteamRuntimePolicy::Enabled);
    // proton_version (game default) = steamflow-proton-11.0-purepe != steam runner.

    let prefix = custom_exec_effective_prefix(&config, &user, 620);

    assert_eq!(
        prefix,
        per_game_prefix(&config.steam_library_path, 620),
        "runner mismatch must route custom-exec to the per-game prefix"
    );
}

#[test]
fn custom_exec_keeps_shared_master_prefix_when_runners_match() {
    // 620 forced to the SAME runner as the Steam Runtime runner (wine-tkg
    // matching wine-tkg): no protocol collision possible, Shared is preserved
    // and the game runs in the master prefix against the logged-in client.
    let mut config = test_config();
    config.game_configs.insert(
        620,
        crate::config::GameConfig {
            forced_proton_version: Some("steamflow-runner-wine11-wow64".to_string()),
            platform_preference: None,
        },
    );
    let user = test_user_config(SteamRuntimePolicy::Enabled);

    let prefix = custom_exec_effective_prefix(&config, &user, 620);

    assert_ne!(
        prefix,
        per_game_prefix(&config.steam_library_path, 620),
        "matching runners must keep the Shared (master) prefix"
    );
}

#[test]
fn custom_exec_uses_raw_config_when_steam_runtime_disabled() {
    // No Steam Runtime runner configured → nothing can collide in the prefix;
    // the configured mode applies as-is (Shared → master).
    let mut config = test_config();
    config.steam_runtime_runner = PathBuf::new();
    let user = test_user_config(SteamRuntimePolicy::Enabled);

    let prefix = custom_exec_effective_prefix(&config, &user, 620);

    assert_ne!(
        prefix,
        per_game_prefix(&config.steam_library_path, 620),
        "empty Steam Runtime runner must not force PerGame"
    );
}

// --- Task 2: prefer a prefix with a running logged-in client ---
//
// The session-preference decision is PURE (extracted for testability): given
// the effective-mode choice and the alternate per-game candidate, prefer the
// one with a persisted login session. The runner-mismatch guard (PerGame)
// must NEVER be overridden by session preference — a purepe game cannot run
// in the wine-tkg master prefix even if it has a session.

#[test]
fn prefers_per_game_prefix_when_master_lacks_session() {
    let master = PathBuf::from("/master/pfx");
    let per_game = PathBuf::from("/lib/steamapps/compatdata/620/pfx");
    // chosen (master) has NO session; per-game HAS one → prefer per-game.
    let result = prefer_session_prefix(&master, &per_game, |p| p == &per_game);
    assert_eq!(result, per_game);
}

#[test]
fn keeps_master_prefix_when_it_has_session() {
    let master = PathBuf::from("/master/pfx");
    let per_game = PathBuf::from("/lib/steamapps/compatdata/620/pfx");
    // master HAS a session → keep it (Shared semantics preserved).
    let result = prefer_session_prefix(&master, &per_game, |p| p == &master);
    assert_eq!(result, master);
}

#[test]
fn keeps_effective_choice_when_neither_prefix_has_session() {
    let master = PathBuf::from("/master/pfx");
    let per_game = PathBuf::from("/lib/steamapps/compatdata/620/pfx");
    // Neither has a session → keep the effective-mode choice (login
    // onboarding will handle it), do not guess.
    let result = prefer_session_prefix(&master, &per_game, |_| false);
    assert_eq!(result, master);
}
