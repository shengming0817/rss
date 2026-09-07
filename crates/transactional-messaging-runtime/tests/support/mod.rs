use rss_request_context::{Clock, Deadline, ExecutionTimer};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub struct AdvancingTimer {
    now: Mutex<Duration>,
    sleeps: Mutex<Vec<std::time::Instant>>,
    wake: tokio::sync::watch::Sender<Duration>,
}

impl AdvancingTimer {
    pub fn new() -> Self {
        Self {
            now: Mutex::new(Duration::ZERO),
            sleeps: Mutex::new(Vec::new()),
            wake: tokio::sync::watch::channel(Duration::ZERO).0,
        }
    }

    pub fn advance(&self, duration: Duration) {
        let mut now = self.now.lock().expect("clock");
        *now = now.saturating_add(duration);
        let advanced = *now;
        drop(now);
        self.wake.send_replace(advanced);
    }

    pub fn registered(&self, deadline: Duration) -> bool {
        self.sleeps
            .lock()
            .expect("sleeps")
            .contains(&(epoch() + deadline))
    }

    pub async fn wait_registered(&self, deadline: Duration) {
        while !self.registered(deadline) {
            tokio::task::yield_now().await;
        }
    }
}

impl Clock for AdvancingTimer {
    fn now(&self) -> std::time::Instant {
        epoch() + *self.now.lock().expect("clock")
    }
}

impl ExecutionTimer for AdvancingTimer {
    async fn sleep_until(&self, deadline: Deadline) {
        let mut wake = self.wake.subscribe();
        self.sleeps.lock().expect("sleeps").push(deadline.instant());
        while !deadline.remaining(self.now()).unwrap_or_default().is_zero() {
            tokio::task::unconstrained(wake.changed())
                .await
                .expect("advancing timer sender remains live");
        }
    }
}

pub struct ScriptedTimer {
    ready_calls: Vec<usize>,
    calls: AtomicUsize,
}

impl ScriptedTimer {
    pub fn new(ready_calls: impl IntoIterator<Item = usize>) -> Self {
        Self {
            ready_calls: ready_calls.into_iter().collect(),
            calls: AtomicUsize::new(0),
        }
    }
}

impl Clock for ScriptedTimer {
    fn now(&self) -> std::time::Instant {
        epoch()
    }
}

impl ExecutionTimer for ScriptedTimer {
    async fn sleep_until(&self, _deadline: Deadline) {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if !self.ready_calls.contains(&call) {
            std::future::pending().await
        }
    }
}

pub async fn wait_for_count(counter: &AtomicUsize, expected: usize) {
    while counter.load(Ordering::SeqCst) < expected {
        tokio::task::yield_now().await;
    }
}

/// A host-owned timer borrowed by a directly awaited worker.
pub struct BorrowedTimer<'a, T>(pub &'a T);

impl<T: Clock> Clock for BorrowedTimer<'_, T> {
    fn now(&self) -> std::time::Instant {
        self.0.now()
    }
}

impl<T: ExecutionTimer> ExecutionTimer for BorrowedTimer<'_, T> {
    async fn sleep_until(&self, deadline: Deadline) {
        self.0.sleep_until(deadline).await;
    }
}

/// Await a task with a test deadline; never detach timed-out work.
pub async fn join_worker(
    mut task: tokio::task::JoinHandle<
        Result<(), rss_transactional_messaging::error::MessagingError>,
    >,
) -> Result<(), rss_transactional_messaging::error::MessagingError> {
    let result = tokio::time::timeout(Duration::from_secs(1), &mut task).await;
    if result.is_err() {
        task.abort();
        let _ = task.await;
    }
    result
        .expect("worker completes within host budget")
        .expect("worker does not panic")
}

#[allow(clippy::disallowed_methods)]
// reason: the injected deterministic fixtures share one fixed Instant origin.
pub fn epoch() -> std::time::Instant {
    static ORIGIN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    *ORIGIN.get_or_init(std::time::Instant::now)
}

/// Find the platform's representational boundary to exercise real checked-add overflow.
pub fn last_instant() -> std::time::Instant {
    let mut instant = epoch();
    for make_duration in [Duration::from_secs, Duration::from_nanos] {
        let mut step = 1_u64 << 63;
        while step != 0 {
            if let Some(next) = instant.checked_add(make_duration(step)) {
                instant = next;
            }
            step >>= 1;
        }
    }
    instant
}
