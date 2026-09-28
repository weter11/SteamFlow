//! Both credential files must be owner-only and written atomically.
//!
//! `session.json` holds the Steam refresh token and `machine_id.json` holds the
//! machine identity. Both used to be written with a plain `fs::write`, which
//! means the mode comes from the umask (typically `0644`, world-readable) and a
//! crash mid-write leaves a truncated file that a later load has to recover
//! from. Both now go through one `write_secret_file` helper, and these tests
//! hold that helper to the two properties it promises.
//!
//! The permission tests are meaningless under a restrictive umask, so the mode
//! is asserted on an explicitly pre-widened file: a `0o644` file that the helper
//! must tighten, plus a fresh file that must never be created world-readable.
//! That makes the test independent of whatever umask the runner happens to have.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use steamflow::models::SessionState;

/// Serialize the `HOME` redirect against every other test in this binary.
/// `HOME` is process-global, so without this a concurrent test would observe
/// another test's scratch directory.
async fn scratch_home(tag: &str) -> (tokio::sync::MutexGuard<'static, ()>, PathBuf) {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let guard = LOCK.lock().await;

    let dir = std::env::temp_dir().join(format!("steamflow-secret-file-test-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    std::env::set_var("HOME", &dir);

    (guard, dir)
}

fn mode_of(path: &std::path::Path) -> u32 {
    std::fs::metadata(path)
        .expect("stat file")
        .permissions()
        .mode()
        & 0o777
}

/// The refresh token file must be `0600`, and must be tightened even if it
/// already existed with looser permissions.
#[tokio::test]
async fn session_file_is_owner_only_and_tightens_an_existing_file() {
    let (_guard, dir) = scratch_home("session-mode").await;

    // Pre-create the target world-readable, as an older SteamFlow or a manual
    // copy might have left it.
    let path = dir.join(".config/SteamFlow/session.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        mode_of(&path),
        0o644,
        "precondition: file starts world-readable"
    );

    steamflow::config::save_session(&SessionState {
        account_name: Some("tester".to_string()),
        refresh_token: Some("super-secret-token".to_string()),
        ..Default::default()
    })
    .await
    .expect("save_session must succeed");

    assert_eq!(
        mode_of(&path),
        0o600,
        "session.json holds the refresh token and must be owner-only"
    );
}

/// The machine identity file gets the same treatment, from a clean slate.
#[tokio::test]
async fn machine_id_file_is_owner_only() {
    let (_guard, dir) = scratch_home("machine-mode").await;

    steamflow::config::save_client_info(&steam_vent::auth::ClientInfo::default())
        .await
        .expect("save_client_info must succeed");

    let path = dir.join(".config/SteamFlow/machine_id.json");
    assert!(path.exists(), "the identity must have been written");
    assert_eq!(mode_of(&path), 0o600, "machine_id.json must be owner-only");
}

/// A write must not leave a temp file behind next to the target, whether it
/// succeeded or not. The temp name is derived from the target, so a leftover
/// `.session.json.<pid>.tmp` would both leak a token and confuse the next run.
#[tokio::test]
async fn a_successful_write_leaves_no_temp_file() {
    let (_guard, dir) = scratch_home("no-temp").await;

    steamflow::config::save_session(&SessionState {
        account_name: Some("tester".to_string()),
        refresh_token: Some("token".to_string()),
        ..Default::default()
    })
    .await
    .unwrap();

    let config = dir.join(".config/SteamFlow");
    let leftovers: Vec<String> = std::fs::read_dir(&config)
        .unwrap()
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().to_string_lossy().into_owned();
            name.contains(".tmp").then_some(name)
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "atomic write must not leave temp files behind, found {leftovers:?}"
    );
}

/// Atomicity in the sense that matters here: the previous file survives a
/// failed write, and is replaced only once the new content is complete.
///
/// The rename is a single syscall, so this cannot be observed mid-write from
/// another process without a fault injection point. What IS observable — and
/// what the plain `fs::write` version got wrong — is that an unwritable
/// directory leaves the OLD file intact rather than truncating it. Writing into
/// a read-only directory fails at the create step, so the old content must
/// still be there afterwards.
#[tokio::test]
async fn a_failed_write_leaves_the_previous_file_intact() {
    let (_guard, dir) = scratch_home("atomic").await;

    let config = dir.join(".config/SteamFlow");
    std::fs::create_dir_all(&config).unwrap();
    let path = config.join("machine_id.json");

    // A good identity first.
    let original = steam_vent::auth::ClientInfo::default();
    steamflow::config::save_client_info(&original)
        .await
        .unwrap();
    let before = std::fs::read(&path).unwrap();

    // Now make the directory unwritable, so the temp-file create fails.
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o500)).unwrap();
    let write = steamflow::config::save_client_info(&steam_vent::auth::ClientInfo::default()).await;
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).unwrap();

    // Running as root defeats the permission check entirely; the assertion is
    // about the failure path, so skip rather than assert something untrue.
    if write.is_ok() {
        eprintln!("skipping: write succeeded despite a read-only directory (running as root?)");
    } else {
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "a failed write must not destroy or truncate the previous file"
        );
    }
}
