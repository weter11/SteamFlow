//! Cancelable off-thread boundary for steam-vent password login.
//!
//! steam-vent 0.6 erases its confirmation-handler future to
//! `Box<dyn Future<Output = Option<ConfirmationAction>> + 'this>` with no `Send`
//! bound, so `SteamClient::login` is not `Send` and cannot be handed to
//! `Runtime::spawn` or `tokio::task::spawn`. Dropping that future through
//! `tokio::select!` still works, but only on a future that is polled in place —
//! so password login runs on a dedicated OS thread. Dropping the UI's result
//! receiver is NOT equivalent: the send would fail, but the worker would keep
//! polling network/auth work until Steam answered.
//!
//! The thread drives the app's PERSISTENT runtime via [`tokio::runtime::Handle`]
//! rather than a private one. `Handle::block_on` — unlike `spawn` — imposes no
//! `Send` bound on the future, so the non-`Send` confirmation handler is polled
//! in place exactly as before, while every task steam-vent spawns during the
//! login (the message reader in `connection/filter.rs`, the heartbeat in
//! `connection/raw.rs`) lands on the shared long-lived scheduler. That matters
//! because those tasks own the WebSocket's receiving half: on a throwaway
//! current-thread runtime they were aborted when the worker returned, leaving a
//! `Connection` that still looked live in `ConnectionState` but could never
//! receive a response again.
//!
//! Only this operation needs the thread boundary; every other UI operation
//! stays on the shared multi-thread runtime directly.

use std::future::Future;
use std::thread::JoinHandle;
use tokio::runtime::Handle;

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

/// Run `factory`'s future on a dedicated OS thread, driven by `handle`.
///
/// `factory` and `on_result` are `Send + 'static` because they cross the thread
/// boundary. The future they produce is NOT required to be `Send` — it is
/// created and polled on the worker thread, which is the whole point of this
/// boundary. `Handle::block_on` (not `spawn`) is what permits that.
///
/// `handle` must belong to a runtime that OUTLIVES this worker. Anything
/// steam-vent spawns during the login — the message reader and the heartbeat —
/// is bound to it, and those tasks own the WebSocket's receiving half. On a
/// private current-thread runtime they died with the worker and left a
/// `Connection` that looked live but could never answer a job.
///
/// `on_result` is not called when the attempt is cancelled.
pub fn spawn_local_task<F, Fut, T>(
    attempt: u64,
    handle: Handle,
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
            // The future is constructed INSIDE the worker thread so the
            // non-Send confirmation handler is never moved across threads.
            // `handle` is the app's persistent runtime, so every task spawned
            // underneath this login outlives the worker.
            let outcome = handle.block_on(async move {
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

    /// The app's persistent runtime, standing in for `SteamLauncher::runtime`.
    ///
    /// The `OnceLock` stores the `Runtime` itself, NOT a `Handle` cloned from a
    /// temporary: dropping a `Runtime` shuts its scheduler down, and a `Handle`
    /// does not keep it alive. Storing a `Runtime` borrowed into a `Handle`
    /// would make every spawned task abort with `JoinError::Cancelled` — the
    /// exact defect `tasks_spawned_during_login_outlive_the_worker_thread`
    /// guards against, reintroduced here. Cloning the `Handle` out of the
    /// stored `Runtime` per call is cheap and safe.
    fn persistent_runtime() -> Handle {
        static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
        RUNTIME
            .get_or_init(|| tokio::runtime::Runtime::new().expect("build persistent runtime"))
            .handle()
            .clone()
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
    fn non_send_future_runs_on_worker_thread_and_delivers_result() {
        let (tx, rx) = mpsc::channel();

        let mut task = spawn_local_task(
            1,
            persistent_runtime(),
            move || non_send_future("session".to_string()),
            move |value| {
                let _ = tx.send(value);
            },
        );

        let received = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("worker-thread login did not deliver its result");
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
            persistent_runtime(),
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
        let mut task = spawn_local_task(
            1,
            persistent_runtime(),
            || async { std::future::pending::<()>().await },
            |_| {},
        );
        task.cancel();
        task.cancel();
        // Drop must detach rather than block on a still-pending worker.
        drop(task);
    }

    /// Regression test for the zombie-connection defect: a task spawned from
    /// inside the login future must still be alive after the worker thread has
    /// exited.
    ///
    /// This models exactly what steam-vent does during `Connection::login` — it
    /// spawns the message reader (`connection/filter.rs`) and the heartbeat
    /// (`connection/raw.rs`), and those tasks own the WebSocket's receiving
    /// half. When the worker drove a private current-thread runtime, dropping
    /// that runtime aborted them and left a `Connection` that still looked live
    /// in `ConnectionState` but could never receive a response again.
    #[test]
    fn tasks_spawned_during_login_outlive_the_worker_thread() {
        let (jh_tx, jh_rx) = mpsc::channel::<tokio::task::JoinHandle<u32>>();
        let (done_tx, done_rx) = mpsc::channel::<&'static str>();

        let mut task = spawn_local_task(
            1,
            persistent_runtime(),
            move || {
                let jh_tx = jh_tx.clone();
                async move {
                    // Stand-in for steam-vent's reader/heartbeat: spawned from
                    // inside the login future, on the runtime driving it.
                    let handle = tokio::spawn(async {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        42u32
                    });
                    // Hand the live task out of the worker, which is what a live
                    // `Connection` does with the tasks it spawned.
                    let _ = jh_tx.send(handle);
                    "login finished"
                }
            },
            move |value| {
                let _ = done_tx.send(value);
            },
        );

        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("worker did not deliver its result"),
            "login finished"
        );
        let spawned = jh_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("worker did not hand out the spawned task handle");

        assert!(
            wait_until(|| task.is_finished(), Duration::from_secs(10)),
            "worker thread did not exit after delivering its result"
        );
        task.reap();

        // THE decisive assertion: the worker thread is gone, and the task it
        // spawned is still running. This is only possible because the task was
        // bound to the persistent runtime rather than a throwaway one.
        let rt = tokio::runtime::Runtime::new().expect("build observer runtime");
        let result = rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), spawned)
                .await
                .expect("task spawned during login was aborted with the worker")
                .expect("spawned task panicked")
        });
        assert_eq!(result, 42, "spawned task must complete its work");
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
