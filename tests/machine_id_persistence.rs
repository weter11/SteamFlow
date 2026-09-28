//! The machine identity must survive a LOGOUT, not merely a re-login.
//!
//! Regression test for a bug that only a real login -> logout -> login cycle
//! exposed: the identity was originally persisted inside session.json, and
//! `delete_session` removes that file wholesale. Logging out therefore erased
//! the machine identity along with the refresh token, so the next login minted
//! a fresh random machine ID and presented it to Steam as a new device.
//!
//! These tests redirect `config_dir` at a scratch directory via `HOME`, so they
//! never read or write the developer's real SteamFlow config.

use std::path::PathBuf;

use steam_vent::auth::ClientInfo;

/// Point `config_dir` (which reads `$HOME`) at a scratch dir for one test.
///
/// Serialized against every other test in this binary, because `HOME` is
/// process-global: a concurrent test in this process would see the temporary
/// value. A `tokio::sync::Mutex` (not `std::sync`) because the guard is held
/// across awaits; the tests never actually contend, so locking is uncontended
/// and the ordering guarantee is what matters.
async fn scratch_home(tag: &str) -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let guard = LOCK.lock().await;

    let dir = std::env::temp_dir().join(format!("steamflow-machine-id-test-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    std::env::set_var("HOME", &dir);

    guard
}

fn config_path(name: &str) -> PathBuf {
    std::env::temp_dir()
        .join(std::env::var("HOME").expect("HOME"))
        .join(".config/SteamFlow")
        .join(name)
}

/// The regression: login, logout, login again. The second login must reuse the
/// identity the first one wrote.
#[tokio::test]
async fn machine_identity_survives_logout() {
    let _guard = scratch_home("survives-logout").await;

    // --- first login: nothing persisted yet, so one is generated and written.
    assert!(
        steamflow::config::load_client_info()
            .await
            .unwrap()
            .is_none(),
        "no identity should exist before the first login"
    );
    let first = ClientInfo::default();
    steamflow::config::save_client_info(&first).await.unwrap();
    assert!(
        config_path("machine_id.json").exists(),
        "the identity must be written to its own file"
    );

    // The commit also writes session.json, which is what logout deletes. The
    // identity is deliberately NOT part of it: that mirror is gone, and
    // session.json must not be able to carry the identity any more.
    steamflow::config::save_session(&steamflow::models::SessionState {
        account_name: Some("tester".to_string()),
        refresh_token: Some("token".to_string()),
        ..Default::default()
    })
    .await
    .unwrap();
    assert!(config_path("session.json").exists());
    let written_session = std::fs::read_to_string(config_path("session.json")).unwrap();
    assert!(
        !written_session.contains("client_info"),
        "session.json must not mirror the machine identity: {written_session}"
    );

    // --- logout: deletes session.json wholesale.
    steamflow::config::delete_session().await.unwrap();
    assert!(
        !config_path("session.json").exists(),
        "logout must remove the session file"
    );

    // THE ASSERTION THAT FAILED BEFORE THE FIX: the identity file is untouched
    // by logout, because logout only knows about session.json.
    assert!(
        config_path("machine_id.json").exists(),
        "logout must NOT delete the machine identity"
    );

    // --- second login: reuses the persisted identity rather than minting one.
    let reloaded = steamflow::config::load_client_info()
        .await
        .unwrap()
        .expect("identity must still be loadable after logout");
    assert_eq!(
        serde_json::to_string(&reloaded).unwrap(),
        serde_json::to_string(&first).unwrap(),
        "the identity after logout must be byte-identical to the first login's"
    );
}

/// A missing identity file is not an error — it just means "generate one".
#[tokio::test]
async fn missing_identity_file_is_not_an_error() {
    let _guard = scratch_home("missing").await;
    assert!(steamflow::config::load_client_info()
        .await
        .unwrap()
        .is_none());
}

/// A corrupt identity file must not fail a login; it degrades to generating a
/// fresh one, because an unparseable machine ID is not worth blocking on.
#[tokio::test]
async fn corrupt_identity_file_degrades_to_generating_one() {
    let _guard = scratch_home("corrupt").await;

    let path = config_path("machine_id.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{ this is not json").unwrap();

    assert!(
        steamflow::config::load_client_info()
            .await
            .unwrap()
            .is_none(),
        "a corrupt identity must degrade to None, not error"
    );
}

/// A written identity round-trips through its own file unchanged.
#[tokio::test]
async fn identity_round_trips_through_its_own_file() {
    let _guard = scratch_home("roundtrip").await;

    let original = ClientInfo::default();
    steamflow::config::save_client_info(&original)
        .await
        .unwrap();
    let restored = steamflow::config::load_client_info()
        .await
        .unwrap()
        .expect("identity must load back");

    assert_eq!(
        serde_json::to_string(&original).unwrap(),
        serde_json::to_string(&restored).unwrap(),
        "machine identity must round-trip unchanged"
    );
}

/// A TRUNCATED identity file must converge on the same recovery path as a
/// syntactically corrupt one: `Ok(None)`, so the next login regenerates.
///
/// `save_client_info` now writes via temp-file-plus-rename, so a partial file
/// should no longer be reachable in normal operation. This test still pins the
/// recovery contract, because the file can predate the atomic writer, or be
/// truncated by something outside SteamFlow, and an unparseable machine ID must
/// never surface as a login error.
#[tokio::test]
async fn truncated_identity_file_converges_with_the_corrupt_path() {
    let _guard = scratch_home("truncated").await;

    // A complete, valid identity first — so the truncation below is a genuine
    // partial write of real content, not just an empty file.
    let original = ClientInfo::default();
    steamflow::config::save_client_info(&original)
        .await
        .unwrap();
    let full = std::fs::read(config_path("machine_id.json")).expect("read written identity");
    assert!(full.len() > 40, "sanity: the real file should not be tiny");

    // Truncate to half: valid JSON prefix, unterminated object.
    let truncated = &full[..full.len() / 2];
    std::fs::write(config_path("machine_id.json"), truncated).unwrap();

    // Must return Ok(None) — NOT Err. An Err here would propagate into login()'s
    // `unwrap_or_else`, which already degrades to None, but the load contract
    // should hold on its own.
    let loaded = steamflow::config::load_client_info()
        .await
        .expect("a truncated identity must not surface as an error");
    assert!(
        loaded.is_none(),
        "a truncated identity must degrade to None so a new one is generated"
    );

    // And recovery completes: a fresh identity can be written and read back.
    let regenerated = ClientInfo::default();
    steamflow::config::save_client_info(&regenerated)
        .await
        .unwrap();
    let recovered = steamflow::config::load_client_info()
        .await
        .unwrap()
        .expect("a regenerated identity must load");
    assert_ne!(
        serde_json::to_string(&recovered).unwrap(),
        serde_json::to_string(&original).unwrap(),
        "recovery must produce a NEW identity, not the truncated one"
    );
}
