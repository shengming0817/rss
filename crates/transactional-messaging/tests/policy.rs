#![allow(clippy::expect_used)]
// reason: fixed policy fixtures must fail loudly if construction unexpectedly regresses.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use rss_transactional_messaging::error::MessagingErrorKind;
use rss_transactional_messaging::policy::{
    AbsoluteDeadline, Clock, ExecutionBudget, ExecutionDeadlines, ExecutionTimer,
    LeaseRenewalPolicy, LeaseRenewalPolicyError, MonotonicInstant, within,
};

struct ManualTimer {
    now: Mutex<Duration>,
    wake: tokio::sync::Notify,
    now_calls: AtomicUsize,
}

struct SequencedTimer(Mutex<VecDeque<Duration>>);

impl Clock for SequencedTimer {
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_elapsed(
            self.0
                .lock()
                .expect("clock script")
                .pop_front()
                .expect("clock observation"),
        )
    }
}

impl ExecutionTimer for SequencedTimer {
    async fn sleep_until(&self, _deadline: AbsoluteDeadline) {
        std::future::pending().await
    }
}

impl ManualTimer {
    fn new(now: Duration) -> Self {
        Self {
            now: Mutex::new(now),
            wake: tokio::sync::Notify::new(),
            now_calls: AtomicUsize::new(0),
        }
    }

    fn advance(&self, duration: Duration) {
        let mut now = self.now.lock().expect("clock lock");
        *now = now.saturating_add(duration);
        drop(now);
        self.wake.notify_waiters();
    }
}

impl Clock for ManualTimer {
    fn now(&self) -> MonotonicInstant {
        self.now_calls.fetch_add(1, Ordering::SeqCst);
        MonotonicInstant::from_elapsed(*self.now.lock().expect("clock lock"))
    }
}

impl ExecutionTimer for ManualTimer {
    async fn sleep_until(&self, deadline: AbsoluteDeadline) {
        while !deadline.remaining(self).is_zero() {
            self.wake.notified().await;
        }
    }
}

struct ControlledFuture {
    ready: Arc<AtomicBool>,
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl Future for ControlledFuture {
    type Output = &'static str;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if self.ready.load(Ordering::SeqCst) {
            Poll::Ready("ready")
        } else {
            context.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

impl Drop for ControlledFuture {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn lease_renewal_is_one_third_of_ttl_with_one_millisecond_floor() {
    assert_eq!(
        LeaseRenewalPolicy::from_ttl(Duration::ZERO),
        Err(LeaseRenewalPolicyError::ZeroTtl)
    );
    assert_eq!(
        LeaseRenewalPolicy::from_ttl(Duration::from_nanos(1))
            .expect_err("lease cannot outlive minimum renewal"),
        LeaseRenewalPolicyError::TooShort
    );
    assert_eq!(
        LeaseRenewalPolicy::from_ttl(Duration::from_millis(2))
            .expect("usable ttl")
            .interval(),
        Duration::from_millis(1)
    );
    assert_eq!(
        LeaseRenewalPolicy::from_ttl(Duration::from_millis(9))
            .expect("ttl")
            .interval(),
        Duration::from_millis(3)
    );
    assert_eq!(
        LeaseRenewalPolicy::from_ttl(Duration::from_millis(10))
            .expect("ttl")
            .interval(),
        Duration::from_nanos(3_333_333)
    );
}

#[test]
fn execution_deadlines_are_minted_from_one_clock_read() {
    let timer = ManualTimer::new(Duration::from_secs(7));
    let budget = ExecutionBudget::new(Duration::from_secs(10), Duration::from_secs(2))
        .expect("execution budget");

    let deadlines = ExecutionDeadlines::from_budget(&timer, budget).expect("deadlines");

    assert_eq!(timer.now_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        deadlines.operation().instant().elapsed(),
        Duration::from_secs(15)
    );
    assert_eq!(
        deadlines.settlement().instant().elapsed(),
        Duration::from_secs(17)
    );
}

#[test]
fn messaging_error_labels_are_exhaustive_and_stable() {
    let labels = [
        (MessagingErrorKind::Transient, "transient"),
        (MessagingErrorKind::Permanent, "permanent"),
        (MessagingErrorKind::Conflict, "conflict"),
        (MessagingErrorKind::OwnershipLost, "ownership_lost"),
        (MessagingErrorKind::Invariant, "invariant"),
        (MessagingErrorKind::DeadlineElapsed, "deadline_elapsed"),
    ];

    for (kind, expected) in labels {
        assert_eq!(kind.as_label(), expected);
    }
}

#[tokio::test]
async fn zero_relative_timeout_is_an_elapsed_deadline() {
    let timer = ManualTimer::new(Duration::ZERO);
    let deadline = AbsoluteDeadline::from_timeout(&timer, Duration::ZERO).expect("deadline");
    let starts = AtomicUsize::new(0);

    let error = within(&timer, deadline, |_| {
        starts.fetch_add(1, Ordering::SeqCst);
        async {}
    })
    .await
    .expect_err("zero timeout must already be elapsed");

    assert_eq!(error.kind(), MessagingErrorKind::DeadlineElapsed);
    assert_eq!(starts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn within_uses_one_snapshot_for_start_decision_and_watchdog() {
    let timer = SequencedTimer(Mutex::new(VecDeque::from([
        Duration::ZERO,
        Duration::ZERO,
        Duration::from_secs(1),
    ])));
    let deadline =
        AbsoluteDeadline::from_timeout(&timer, Duration::from_secs(1)).expect("deadline");
    let observed = Mutex::new(None);

    within(&timer, deadline, |operation| {
        *observed.lock().expect("observed") = Some(operation.timeout());
        async {}
    })
    .await
    .expect("provider completes under the snapshot");

    assert_eq!(
        *observed.lock().expect("observed"),
        Some(Duration::from_secs(1))
    );
}

#[tokio::test]
async fn within_returns_ready_provider_output_before_deadline() {
    let timer = ManualTimer::new(Duration::ZERO);
    let deadline =
        AbsoluteDeadline::from_timeout(&timer, Duration::from_secs(1)).expect("deadline");

    let output = within(&timer, deadline, |_| async { "ready" })
        .await
        .expect("provider output");

    assert_eq!(output, "ready");
}

#[tokio::test]
async fn elapsed_deadline_does_not_start_provider_future() {
    let timer = ManualTimer::new(Duration::ZERO);
    let deadline =
        AbsoluteDeadline::from_timeout(&timer, Duration::from_secs(1)).expect("deadline");
    timer.advance(Duration::from_secs(1));
    let starts = AtomicUsize::new(0);

    let error = within(&timer, deadline, |_| {
        starts.fetch_add(1, Ordering::SeqCst);
        async { "late" }
    })
    .await
    .expect_err("elapsed deadline");

    assert_eq!(error.kind(), MessagingErrorKind::DeadlineElapsed);
    assert_eq!(starts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn deadline_wins_a_simultaneously_ready_provider_and_drops_it() {
    let timer = Arc::new(ManualTimer::new(Duration::ZERO));
    let deadline =
        AbsoluteDeadline::from_timeout(timer.as_ref(), Duration::from_secs(1)).expect("deadline");
    let ready = Arc::new(AtomicBool::new(false));
    let polls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
        let timer = Arc::clone(&timer);
        let ready = Arc::clone(&ready);
        let polls = Arc::clone(&polls);
        let drops = Arc::clone(&drops);
        async move {
            within(timer.as_ref(), deadline, |_| ControlledFuture {
                ready,
                polls,
                drops,
            })
            .await
        }
    });
    while polls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    ready.store(true, Ordering::SeqCst);
    timer.advance(Duration::from_secs(1));
    let error = task
        .await
        .expect("race task")
        .expect_err("deadline must win");

    assert_eq!(error.kind(), MessagingErrorKind::DeadlineElapsed);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn capped_deadline_never_extends_its_parent() {
    let timer = ManualTimer::new(Duration::from_secs(5));
    let deadline =
        AbsoluteDeadline::from_timeout(&timer, Duration::from_secs(10)).expect("deadline");

    assert_eq!(
        deadline
            .capped(&timer, Duration::from_secs(3))
            .instant()
            .elapsed(),
        Duration::from_secs(8)
    );
    assert_eq!(
        deadline
            .capped(&timer, Duration::from_secs(30))
            .instant()
            .elapsed(),
        Duration::from_secs(15)
    );
}
