//! Regression tests for the Steam CM zombie-connection fix.
//!
//! Background: steam-vent's read loop exits silently when the CM WebSocket is
//! reset (`ResetWithoutClosingHandshake`) while the heartbeat task keeps
//! logging `AlreadyClosed`. Before this fix the held `Connection` became a
//! permanent zombie and every depot/cloud/profile call failed until app
//! restart. These tests pin the offline-verifiable parts of the recovery
//! machinery:
//!
//! 1. the dead-flag state machine (`mark_connection_dead` /
//!    `is_connection_dead`),
//! 2. fail-fast behaviour of `get_active_connection()` /
//!    `connection_or_reconnect()` when there is nothing to recover,
//! 3. the transport-error classifier that feeds `with_healthy_connection`.
//!
//! ISOLATION CONTRACT: `config::config_dir()` resolves `$HOME/.config/SteamFlow`,
//! so every client-touching test redirects `HOME` into a temp dir. Because
//! `std::env::set_var` is PROCESS-global and cargo runs the tests of one
//! binary on parallel threads, all HOME-touching tests serialize through
//! `TestHome`, which holds a static mutex plus the temp dir until the test
//! body ends. Without the lock, a sibling test restoring the real `$HOME`
//! mid-flight makes the "no saved session" precondition read the developer's
//! live session.json (observed as a flaky full-suite failure).
//!
//! What is intentionally NOT covered here: the live half of the re-auth
//! (refresh-token -> new Connection -> dead flag cleared). steam-vent offers
//! no way to construct a `Connection` without a real login round-trip, so
//! that path is exercised in production; the flag-clearing commit block is
//! shared by `login()`, `restore_session()`, and `active_connection_locked()`
//! (single code path in steam_client.rs), which keeps the invariant
//! structural rather than snapshot-tested.

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

/// Serializes every test that mutates the process-global `HOME`.
static HOME_LOCK: Mutex<()> = Mutex::new(());

struct TestHome {
    /// Held for the whole test body: blocks sibling threads from touching HOME.
    _lock: MutexGuard<'static, ()>,
    original: Option<String>,
    /// Some(_) while alive; dropped last so the temp dir outlives every read.
    dir: Option<tempfile::TempDir>,
}

impl TestHome {
    fn acquire() -> Self {
        // Poisoned lock is fine to recover from: the critical section has no
        // invariant worth propagating, just mutual exclusion.
        let lock = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        let original = std::env::var("HOME").ok();
        std::env::set_var("HOME", dir.path());
        TestHome {
            _lock: lock,
            original,
            dir: Some(dir),
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.as_ref().expect("temp dir still alive").path().to_path_buf()
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        match &self.original {
            Some(home) => std::env::set_var("HOME", home),
            None => std::env::remove_var("HOME"),
        }
        // Dropping `dir` deletes the temp tree AFTER HOME is restored.
    }
}

#[tokio::test]
async fn fresh_client_is_not_marked_dead() {
    let home = TestHome::acquire();
    let _client_home = &home; // keep alive for whole body
    let client = steamflow::steam_client::SteamClient::new().expect("client");

    assert!(
        !client.is_connection_dead(),
        "a freshly constructed client must not carry the dead flag"
    );
    assert!(
        !client.is_authenticated(),
        "no connection yet, so is_authenticated must be false"
    );
    assert!(
        client.connection().is_none(),
        "fresh client holds no CM connection"
    );
}

#[tokio::test]
async fn mark_connection_dead_drops_connection_and_sets_flag() {
    let home = TestHome::acquire();
    let _client_home = &home;
    let client = steamflow::steam_client::SteamClient::new().expect("client");

    client.mark_connection_dead();

    assert!(
        client.is_connection_dead(),
        "mark_connection_dead must set the dead flag"
    );
    assert!(
        client.connection().is_none(),
        "the zombie Connection handle must be dropped so stale clones stop being handed out"
    );
    assert!(
        !client.is_authenticated(),
        "is_authenticated must go false once the socket is known-dead"
    );
}

#[tokio::test]
async fn reconnect_without_saved_session_fails_fast_instead_of_returning_zombie() {
    let home = TestHome::acquire();
    let client = steamflow::steam_client::SteamClient::new().expect("client");
    client.mark_connection_dead();

    // Precondition: the isolated HOME has no persisted session, so recovery
    // has nothing to re-authenticate FROM.
    let session_path = home.path().join(".config/SteamFlow/session.json");
    assert!(
        !session_path.exists(),
        "precondition: isolated HOME must have no session at {}",
        session_path.display()
    );

    let result = client.connection_or_reconnect().await;
    assert!(
        result.is_err(),
        "with no stored session, recovery must fail fast — never hand back the dead handle"
    );

    let result = client.get_active_connection().await;
    assert!(
        result.is_err(),
        "get_active_connection must surface the failure instead of returning a zombie"
    );
}

#[test]
fn transport_error_classifier_matches_cm_reset_signatures() {
    // No HOME dependency: pure error-classification check.
    // The exact signatures observed in production logs after game
    // installs/updates rotate the CM websocket.
    let reset = anyhow::anyhow!("Ws(Protocol(ResetWithoutClosingHandshake))");
    let closed = anyhow::anyhow!("Failed to send heartbeat message error=Ws(AlreadyClosed)");
    let eof = anyhow::anyhow!("NetworkError(Timeout(EOF while waiting for response))");

    // Wrapped contexts (anyhow .context()) must still classify correctly —
    // the classifier walks the whole error chain.
    let wrapped = anyhow::anyhow!("Ws(Protocol(ResetWithoutClosingHandshake))")
        .context("failed requesting appinfo product info");

    assert!(steamflow::steam_client::SteamClient::is_transport_error_public(&reset));
    assert!(steamflow::steam_client::SteamClient::is_transport_error_public(&closed));
    assert!(steamflow::steam_client::SteamClient::is_transport_error_public(&eof));
    assert!(steamflow::steam_client::SteamClient::is_transport_error_public(&wrapped));

    // Ordinary failures must NOT trigger the reconnect dance.
    let auth = anyhow::anyhow!("InvalidPassword");
    let missing = anyhow::anyhow!("missing app info payload for app 440");
    assert!(!steamflow::steam_client::SteamClient::is_transport_error_public(&auth));
    assert!(!steamflow::steam_client::SteamClient::is_transport_error_public(&missing));
}
