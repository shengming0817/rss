use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rss_transactional_messaging::policy::{
    AbsoluteDeadline, Clock, ExecutionTimer, MonotonicInstant,
};

pub struct AdvancingTimer {
    now: Mutex<Duration>,
    sleeps: Mutex<Vec<Duration>>,
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
        self.sleeps.lock().expect("sleeps").contains(&deadline)
    }

    pub async fn wait_registered(&self, deadline: Duration) {
        while !self.registered(deadline) {
            tokio::task::yield_now().await;
        }
    }
}

impl Clock for AdvancingTimer {
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_elapsed(*self.now.lock().expect("clock"))
    }
}

impl ExecutionTimer for AdvancingTimer {
    async fn sleep_until(&self, deadline: AbsoluteDeadline) {
        let mut wake = self.wake.subscribe();
        self.sleeps
            .lock()
            .expect("sleeps")
            .push(deadline.instant().elapsed());
        while !deadline.remaining(self).is_zero() {
            wake.changed()
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
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_elapsed(Duration::ZERO)
    }
}

impl ExecutionTimer for ScriptedTimer {
    async fn sleep_until(&self, _deadline: AbsoluteDeadline) {
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
