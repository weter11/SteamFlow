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
use steam_vent::NetworkError;

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

    client.mark_connection_dead().await;

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
    client.mark_connection_dead().await;

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
fn transport_error_classifier_recognizes_real_websocket_reset() {
    let error = anyhow::Error::new(steam_vent::NetworkError::Ws(
        tungstenite::Error::Protocol(
            tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
        ),
    ))
    .context("failed calling Player.GetOwnedGames");
    assert!(
        steamflow::steam_client::SteamClient::is_transport_error_public(&error),
        "the retry wrapper must recognize a real websocket reset: {error:#}"
    );
}

#[test]
fn transport_error_classifier_recognizes_real_closed_socket() {
    let error = anyhow::Error::new(steam_vent::NetworkError::Ws(
        tungstenite::Error::AlreadyClosed,
    ))
    .context("failed calling Player.GetOwnedGames");
    assert!(
        steamflow::steam_client::SteamClient::is_transport_error_public(&error),
        "the retry wrapper must recognize a real closed-socket send: {error:#}"
    );
}

#[test]
fn transport_error_classifier_recognizes_real_job_eof() {
    // job() maps a dead read loop to NetworkError::EOF ("Unexpected end of
    // stream") — the Display text alone must not be the only signal.
    let error = anyhow::Error::new(steam_vent::NetworkError::EOF)
        .context("failed calling Player.GetOwnedGames");
    assert!(
        steamflow::steam_client::SteamClient::is_transport_error_public(&error),
        "the retry wrapper must recognize a real job EOF: {error:#}"
    );
}

#[test]
fn transport_error_classifier_recognizes_real_io_reset_kinds() {
    use std::io::{Error as IoError, ErrorKind};

    for kind in [
        ErrorKind::ConnectionReset,
        ErrorKind::ConnectionAborted,
        ErrorKind::BrokenPipe,
        ErrorKind::UnexpectedEof,
    ] {
        let direct = anyhow::Error::new(NetworkError::IO(IoError::from(kind)));
        assert!(steamflow::steam_client::SteamClient::is_transport_error_public(&direct));

        let websocket = anyhow::Error::new(NetworkError::Ws(tungstenite::Error::Io(
            IoError::from(kind),
        )));
        assert!(steamflow::steam_client::SteamClient::is_transport_error_public(&websocket));

        let bare = anyhow::Error::new(IoError::from(kind));
        assert!(steamflow::steam_client::SteamClient::is_transport_error_public(&bare));
    }
}

#[test]
fn transport_error_classifier_rejects_tls_and_unrelated_io() {
    use std::io::{Error as IoError, ErrorKind};

    let tls = anyhow::Error::new(NetworkError::Ws(tungstenite::Error::Tls(
        tungstenite::error::TlsError::InvalidDnsName,
    )));
    assert!(!steamflow::steam_client::SteamClient::is_transport_error_public(&tls));

    let timed_out = anyhow::Error::new(NetworkError::Ws(tungstenite::Error::Io(IoError::from(
        ErrorKind::TimedOut,
    ))));
    assert!(!steamflow::steam_client::SteamClient::is_transport_error_public(&timed_out));

    let would_block = anyhow::Error::new(NetworkError::IO(IoError::from(ErrorKind::WouldBlock)));
    assert!(!steamflow::steam_client::SteamClient::is_transport_error_public(&would_block));
}

#[test]
fn transport_error_classifier_rejects_bare_timeout_and_non_reset_io() {
    use std::io::{Error as IoError, ErrorKind};

    for kind in [ErrorKind::TimedOut, ErrorKind::WouldBlock, ErrorKind::ConnectionRefused] {
        let error = anyhow::Error::new(IoError::from(kind));
        assert!(
            !steamflow::steam_client::SteamClient::is_transport_error_public(&error),
            "bare io::Error {kind:?} must not be classified as a dead CM transport"
        );
    }
}

#[test]
fn transport_error_classifier_ignores_timeouts_and_api_errors() {
    // Deliberate policy: a slow response is NOT proof the transport died;
    // blindly retrying every timeout would duplicate job side effects.
    let timeout = anyhow::Error::new(steam_vent::NetworkError::Timeout)
        .context("failed calling Player.GetOwnedGames");
    let api = anyhow::Error::new(steam_vent::NetworkError::ApiError(
        steam_vent::EResult::Busy,
    ))
    .context("failed calling Player.GetOwnedGames");
    assert!(!steamflow::steam_client::SteamClient::is_transport_error_public(&timeout));
    assert!(!steamflow::steam_client::SteamClient::is_transport_error_public(&api));
}

#[test]
fn transport_error_classifier_does_not_treat_context_as_transport_evidence() {
    let timeout = anyhow::Error::new(steam_vent::NetworkError::Timeout)
        .context("AlreadyClosed/EOF recovery attempt timed out");
    assert!(!steamflow::steam_client::SteamClient::is_transport_error_public(&timeout));
    let payload = anyhow::anyhow!("EOF while parsing cached app info");
    assert!(!steamflow::steam_client::SteamClient::is_transport_error_public(&payload));
}

#[test]
fn transport_error_classifier_rejects_untyped_log_strings() {
    // No HOME dependency: pure error-classification check.
    // Logged signatures are useful diagnostics, not typed retry evidence.
    let reset = anyhow::anyhow!("Ws(Protocol(ResetWithoutClosingHandshake))");
    let closed = anyhow::anyhow!("Failed to send heartbeat message error=Ws(AlreadyClosed)");
    let eof = anyhow::anyhow!("NetworkError(Timeout(EOF while waiting for response))");

    // Adding context cannot turn an untyped string into transport evidence.
    let wrapped = anyhow::anyhow!("Ws(Protocol(ResetWithoutClosingHandshake))")
        .context("failed requesting appinfo product info");

    assert!(!steamflow::steam_client::SteamClient::is_transport_error_public(&reset));
    assert!(!steamflow::steam_client::SteamClient::is_transport_error_public(&closed));
    assert!(!steamflow::steam_client::SteamClient::is_transport_error_public(&eof));
    assert!(!steamflow::steam_client::SteamClient::is_transport_error_public(&wrapped));

    // Ordinary failures must NOT trigger the reconnect dance.
    let auth = anyhow::anyhow!("InvalidPassword");
    let missing = anyhow::anyhow!("missing app info payload for app 440");
    assert!(!steamflow::steam_client::SteamClient::is_transport_error_public(&auth));
    assert!(!steamflow::steam_client::SteamClient::is_transport_error_public(&missing));
}
