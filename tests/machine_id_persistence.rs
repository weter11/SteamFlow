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

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use steam_vent::auth::ClientInfo;

/// Point `config_dir` (which reads `$HOME`) at a scratch dir for one test.
///
/// Exclusive right to redirect `HOME` for the duration of a test.
///
/// `cargo test` runs a binary's tests on parallel threads and `HOME` is
/// process-global, so two tests redirecting it concurrently make each other
/// read the wrong directory. Every test in this file holds one of these for as
/// long as it has `HOME` redirected.
///
/// `tokio::sync::Mutex` rather than `std::sync::Mutex` because the guard is held
/// across awaits and would otherwise make the future non-`Send`. The
/// subprocess test is a plain `#[test]` with no runtime, so it takes the lock
/// through [`block_on_home_lock`] instead — the same mutex, reached from a
/// runtime it owns, so the two cannot get out of step.
async fn scratch_home(tag: &str) -> HomeGuard {
    let guard = HomeGuard::acquire().await;

    let dir = std::env::temp_dir().join(format!("steamflow-machine-id-test-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    std::env::set_var("HOME", &dir);

    guard
}

/// The one lock guarding `HOME` in this test binary.
fn home_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &LOCK
}

/// Held for as long as a test has `HOME` redirected. Dropping it releases the
/// lock; nothing else does.
struct HomeGuard(#[allow(dead_code)] tokio::sync::MutexGuard<'static, ()>);

impl HomeGuard {
    async fn acquire() -> Self {
        HomeGuard(home_lock().lock().await)
    }
}

/// Take [`home_lock`] from a synchronous test, for its whole body.
///
/// `block_in_place` rather than `Runtime::block_on` on a current-thread runtime:
/// a current-thread runtime cannot make progress on a task that is itself
/// blocked inside `block_on`, which is exactly the shape here. `block_in_place`
/// hands the worker thread to the blocking closure and keeps the rest of the
/// runtime running, so a sibling async test parked on the same lock can still
/// be polled and release it.
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

/// FAIL CLOSED. If the identity cannot be persisted it must not be returned,
/// because `login` would then send Steam a machine ID that is lost the moment
/// the process exits — the next attempt would present a different machine,
/// which is the whole failure this mechanism exists to prevent.
///
/// Made unwritable with a read-only config directory, which fails at the create
/// step. Running as root defeats that, so the test skips rather than assert
/// something untrue.
#[tokio::test]
async fn a_persistence_failure_is_reported_rather_than_returned() {
    let _guard = scratch_home("fail-closed").await;
    let config = std::env::temp_dir()
        .join(std::env::var("HOME").expect("HOME"))
        .join(".config/SteamFlow");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o500)).unwrap();

    let result = steamflow::config::load_or_create_client_info().await;

    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).unwrap();

    if let Ok(info) = result {
        // Root ignored the read-only directory, so the write succeeded and this
        // run proves nothing either way.
        let _ = info;
        eprintln!("skipping: identity write succeeded despite a read-only config dir (root?)");
        return;
    }
    assert!(
        !config.join("machine_id.json").exists(),
        "a failed identity write must not leave a partial file behind"
    );
}

/// Concurrent TASKS in one process, starting with no identity, must all get the
/// same one. `load_or_create_client_info` serializes them, so only the first
/// generates and the rest reuse what it wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_tasks_share_one_generated_identity() {
    let _guard = scratch_home("concurrent-tasks").await;
    let existing = steamflow::config::load_client_info().await.unwrap();
    assert!(existing.is_none(), "precondition: no identity exists yet");

    const TASKS: usize = 8;
    let mut handles = Vec::with_capacity(TASKS);
    for _ in 0..TASKS {
        handles.push(tokio::spawn(async {
            steamflow::config::load_or_create_client_info()
                .await
                .expect("identity initialization must succeed")
        }));
    }

    let mut identities = Vec::with_capacity(TASKS);
    for handle in handles {
        identities.push(handle.await.expect("task must not panic"));
    }

    let first = serde_json::to_string(&identities[0]).unwrap();
    for (index, identity) in identities.iter().enumerate() {
        assert_eq!(
            serde_json::to_string(identity).unwrap(),
            first,
            "task {index} was handed a different machine identity"
        );
    }

    // And the shared identity is the one actually on disk, so the next login
    // presents the same machine.
    let persisted = steamflow::config::load_client_info()
        .await
        .unwrap()
        .expect("the identity must be persisted");
    assert_eq!(serde_json::to_string(&persisted).unwrap(), first);
}

/// The child half of the cross-process test. A no-op unless the parent set the
/// environment, so running the suite normally is unaffected.
#[test]
fn identity_subprocess_helper() {
    let Ok(dir) = std::env::var("STEAMFLOW_IDENTITY_HELPER_DIR") else {
        return;
    };
    let tag = std::env::var("STEAMFLOW_IDENTITY_HELPER_TAG").expect("helper tag");
    let dir = PathBuf::from(dir);

    // Readiness/start barrier: every child announces itself, then all of them
    // block until the parent releases the start. Without it the children would
    // run one after another and the race under test would never be exercised —
    // and the test would pass for the wrong reason.
    std::fs::write(dir.join(format!("ready-{tag}")), b"").expect("signal readiness");
    let go = dir.join("go");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !go.exists() {
        assert!(
            Instant::now() < deadline,
            "start barrier was never released; refusing to hang"
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("child runtime");
    let identity = runtime
        .block_on(steamflow::config::load_or_create_client_info())
        .expect("child identity initialization");
    println!(
        "IDENTITY:{}",
        serde_json::to_string(&identity).expect("serialize identity")
    );
}

/// Concurrent PROCESSES starting with no identity must converge on one.
///
/// Two SteamFlow instances launched at once — the realistic case is a relaunch
/// racing a still-exiting previous one — used to each see "no identity", each
/// generate one, and each present a different machine to Steam. The lock in
/// `load_or_create_client_info` serializes them, and the file is re-read after
/// the lock is taken, so the second process reuses what the first persisted.
#[test]
fn concurrent_processes_share_one_generated_identity() {
    // Redirecting HOME is process-global, so this takes the SAME lock the
    // sibling tests use and holds it for the whole test body. Without it, this
    // test and a sibling can redirect HOME concurrently and each reads the
    // other's directory, which surfaces as failures that look like product
    // bugs. The children get HOME passed explicitly, but this test still reads
    // it itself, so it needs the lock regardless.
    //
    // Acquired through a runtime this test owns, which is what lets a plain
    // `#[test]` share a `tokio::sync::Mutex` with the `#[tokio::test]`s above.
    // Nothing else is scheduled on that runtime, so parking here simply blocks
    // the siblings until this test finishes.
    let _home_lock = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("home lock runtime")
        .block_on(HomeGuard::acquire());

    let home = std::env::temp_dir().join("steamflow-machine-id-test-concurrent-processes");
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join(".config/SteamFlow")).unwrap();
    std::env::set_var("HOME", &home);
    assert!(
        !home.join(".config/SteamFlow/machine_id.json").exists(),
        "precondition: no identity exists yet"
    );

    let barrier_dir = home.join("barrier");
    std::fs::create_dir_all(&barrier_dir).unwrap();

    const PROCESSES: usize = 4;
    let exe = std::env::current_exe().expect("test binary path");
    let mut children = Vec::with_capacity(PROCESSES);
    for index in 0..PROCESSES {
        let output = std::process::Command::new(&exe)
            .arg("--exact")
            .arg("identity_subprocess_helper")
            .arg("--nocapture")
            .env("HOME", &home)
            .env("STEAMFLOW_IDENTITY_HELPER_DIR", &barrier_dir)
            .env("STEAMFLOW_IDENTITY_HELPER_TAG", index.to_string())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn helper child");
        children.push((index, output));
    }

    // Wait for every child to reach the barrier, with a bound.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let ready = std::fs::read_dir(&barrier_dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().starts_with("ready-"))
                    .count()
            })
            .unwrap_or(0);
        if ready == PROCESSES {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "only {ready}/{PROCESSES} children reached the barrier; refusing to hang"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    std::fs::write(barrier_dir.join("go"), b"").expect("release barrier");

    let mut identities = Vec::with_capacity(PROCESSES);
    for (index, child) in children {
        let output = child.wait_with_output().expect("wait for helper child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout
            .lines()
            .find(|line| line.starts_with("IDENTITY:"))
            .unwrap_or_else(|| {
                panic!(
                    "child {index} produced no identity (status {:?})\nstdout:\n{stdout}\nstderr:\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        identities.push(line.trim_start_matches("IDENTITY:").to_string());
    }

    let first = &identities[0];
    for (index, identity) in identities.iter().enumerate() {
        assert_eq!(
            identity, first,
            "process {index} generated a different machine identity"
        );
    }
    let persisted = std::fs::read_to_string(home.join(".config/SteamFlow/machine_id.json"))
        .expect("the identity must be on disk");
    let persisted: ClientInfo =
        serde_json::from_str(&persisted).expect("persisted identity parses");
    let handed_out: ClientInfo = serde_json::from_str(first).expect("reported identity parses");
    assert_eq!(
        serde_json::to_value(&persisted).unwrap(),
        serde_json::to_value(&handed_out).unwrap(),
        "the persisted identity must be the one every process was handed"
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
