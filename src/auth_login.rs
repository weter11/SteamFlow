//! Cancelable local-runtime boundary for steam-vent password login.
//!
//! steam-vent 0.6 erases its confirmation-handler future to
//! `Box<dyn Future<Output = Option<ConfirmationAction>> + 'this>` with no `Send`
//! bound, so `SteamClient::login` is not `Send` and cannot be handed to
//! `Runtime::spawn` or `tokio::task::spawn`. Dropping that future through
//! `tokio::select!` still works, but only on a future that is polled in place —
//! so password login runs on a dedicated OS thread with its own current-thread
//! runtime. Dropping the UI's result receiver is NOT equivalent: the send would
//! fail, but the worker would keep polling network/auth work until Steam
//! answered.
//!
//! Only this operation needs the boundary; every other UI operation stays on
//! the shared multi-thread runtime.

use std::future::Future;
use std::thread::JoinHandle;

/// Monotonic attempt tracking so a late result from a superseded (or
/// cancelled) login attempt can never mutate account or session state.
#[derive(Debug, Default)]
pub struct AuthLoginState {
    current_attempt: u64,
}

impl AuthLoginState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a new attempt, superseding any previous one, and return its ID.
    pub fn begin_attempt(&mut self) -> u64 {
        self.current_attempt += 1;
        self.current_attempt
    }

    /// Retire the current attempt so any in-flight or delayed result for it is
    /// rejected. Used on logout, panel close, and app shutdown.
    pub fn invalidate_current(&mut self) {
        self.current_attempt += 1;
    }

    /// True only for the most recent attempt.
    pub fn is_current(&self, attempt: u64) -> bool {
        attempt == self.current_attempt
    }
}

/// Owns the worker thread for one login attempt.
///
/// `Drop` requests cancellation and detaches. It never joins, so the egui
/// update/drop path can never block on network or auth work.
pub struct AuthLoginTask {
    attempt: u64,
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl AuthLoginTask {
    pub fn attempt(&self) -> u64 {
        self.attempt
    }

    /// Signal the worker to drop its login future. Idempotent.
    pub fn cancel(&mut self) {
        if let Some(tx) = self.cancel.take() {
            let _ = tx.send(());
        }
    }

    /// Has the worker thread exited?
    pub fn is_finished(&self) -> bool {
        self.worker
            .as_ref()
            .is_none_or(|handle| handle.is_finished())
    }

    /// Reap a finished worker without ever blocking: an unfinished handle is
    /// kept, a finished one is joined (which cannot block) and dropped.
    pub fn reap(&mut self) {
        if let Some(handle) = self.worker.as_ref() {
            if !handle.is_finished() {
                return;
            }
        }
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
        self.cancel = None;
    }
}

impl Drop for AuthLoginTask {
    fn drop(&mut self) {
        self.cancel();
        // Detach instead of joining: Drop may run on the egui thread during
        // app shutdown, and the worker can still be inside a network read.
        self.worker = None;
    }
}

/// Run `factory`'s future on a dedicated current-thread runtime.
///
/// `factory` and `on_result` are `Send + 'static` because they cross the thread
/// boundary. The future they produce is NOT required to be `Send` — it is
/// created and polled on the worker thread, which is the whole point of this
/// boundary.
///
/// `on_result` is not called when the attempt is cancelled.
pub fn spawn_local_task<F, Fut, T>(
    attempt: u64,
    factory: F,
    on_result: impl FnOnce(T) + Send + 'static,
) -> AuthLoginTask
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = T> + 'static,
    T: Send + 'static,
{
    let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
    let worker = std::thread::Builder::new()
        .name(format!("steamflow-auth-login-{attempt}"))
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    tracing::error!(attempt, "failed to build local login runtime: {err}");
                    return;
                }
            };

            // The future is constructed INSIDE the worker thread so the
            // non-Send confirmation handler is never moved across threads.
            let outcome = runtime.block_on(async move {
                let future = factory();
                tokio::pin!(future);
                tokio::select! {
                    biased;
                    _ = &mut cancel_rx => None,
                    value = &mut future => Some(value),
                }
            });

            if let Some(value) = outcome {
                on_result(value);
            }
        });

    let worker = match worker {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!(attempt, "failed to spawn local login worker: {err}");
            // No worker means no future to cancel; the attempt is simply dead.
            return AuthLoginTask {
                attempt,
                cancel: None,
                worker: None,
            };
        }
    };

    AuthLoginTask {
        attempt,
        cancel: Some(cancel_tx),
        worker: Some(worker),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    /// A future that is deliberately !Send: it holds an `Rc` created INSIDE the
    /// future body across an await. The factory that produces it is still
    /// `Send` (it only owns plain data), which is exactly the shape
    /// `SteamClient::login` has — the non-Send part is the future, not the
    /// inputs.
    async fn non_send_future(value: String) -> String {
        let held_across_await = Rc::new(value);
        tokio::task::yield_now().await;
        (*held_across_await).clone()
    }

    /// Poll `predicate` until it holds or `timeout` elapses. Thread exit is
    /// observed asynchronously, so asserting `is_finished()` immediately after
    /// a send is a race, not a behaviour.
    fn wait_until(mut predicate: impl FnMut() -> bool, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if predicate() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        predicate()
    }

    #[test]
    fn non_send_future_runs_on_local_runtime_and_delivers_result() {
        let (tx, rx) = mpsc::channel();

        let mut task = spawn_local_task(
            1,
            move || non_send_future("session".to_string()),
            move |value| {
                let _ = tx.send(value);
            },
        );

        let received = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("local-runtime worker did not deliver its result");
        assert_eq!(received, "session");
        assert!(
            wait_until(|| task.is_finished(), Duration::from_secs(10)),
            "worker thread did not exit after delivering its result"
        );
        task.reap();
        assert!(task.worker.is_none());
    }

    #[test]
    fn cancellation_drops_pending_future_and_sends_no_result() {
        let polled = Arc::new(AtomicBool::new(false));
        let polled_in_worker = polled.clone();
        let (tx, rx) = mpsc::channel::<&'static str>();

        // A future that never completes: only cancellation can end it.
        let mut task = spawn_local_task(
            7,
            move || async move {
                polled_in_worker.store(true, Ordering::SeqCst);
                std::future::pending::<()>().await;
                "unreachable"
            },
            move |value| {
                let _ = tx.send(value);
            },
        );

        // Let the worker poll the future at least once before cancelling, so
        // this proves cancellation interrupts real pending work.
        for _ in 0..200 {
            if polled.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(polled.load(Ordering::SeqCst), "future was never polled");

        task.cancel();
        assert!(
            wait_until(|| task.is_finished(), Duration::from_secs(10)),
            "worker did not exit after cancel"
        );

        // No result may be produced after cancellation.
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "cancelled attempt must not deliver a result"
        );

        task.reap();
        assert!(task.worker.is_none(), "worker handle was not reaped");
    }

    #[test]
    fn cancelling_twice_is_safe_and_task_drop_does_not_panic() {
        let mut task = spawn_local_task(1, || async { std::future::pending::<()>().await }, |_| {});
        task.cancel();
        task.cancel();
        // Drop must detach rather than block on a still-pending worker.
        drop(task);
    }

    #[test]
    fn stale_attempt_results_are_rejected_after_a_new_attempt() {
        let mut state = AuthLoginState::new();
        let first = state.begin_attempt();
        assert!(state.is_current(first));

        let second = state.begin_attempt();
        assert_ne!(first, second);
        assert!(state.is_current(second));
        assert!(
            !state.is_current(first),
            "superseded attempt result must be rejected"
        );
    }

    #[test]
    fn invalidate_rejects_in_flight_and_late_results() {
        let mut state = AuthLoginState::new();
        let attempt = state.begin_attempt();
        state.invalidate_current();
        assert!(
            !state.is_current(attempt),
            "result after invalidation must be rejected"
        );
    }
}
