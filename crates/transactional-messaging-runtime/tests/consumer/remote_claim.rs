use super::*;
use rss_transactional_messaging::fence::ExecutionBinding;
use rss_transactional_messaging::policy::{LeaseRenewalPolicy, RemoteClaimWaitPolicyError};

#[test]
fn remote_wait_standard_and_representation_limits() {
    let standard = RemoteClaimWaitPolicy::STANDARD;
    assert_eq!(standard.initial_base(), Duration::from_micros(2500));
    assert_eq!(standard.max_base(), Duration::from_secs(1));
    assert_eq!(
        standard.final_window(Duration::MAX),
        Duration::from_millis(250)
    );
    let tick = Duration::from_nanos(1);
    let max = Duration::from_nanos(u64::MAX);
    let new = RemoteClaimWaitPolicy::new;
    assert!(new(max, max, max).is_ok());
    for args in [
        (Duration::ZERO, tick, tick),
        (tick, Duration::ZERO, tick),
        (tick, tick, Duration::ZERO),
    ] {
        assert_eq!(
            new(args.0, args.1, args.2),
            Err(RemoteClaimWaitPolicyError::ZeroDuration)
        );
    }
    assert_eq!(
        new(tick * 2, tick, tick),
        Err(RemoteClaimWaitPolicyError::BaseExceedsCap)
    );
    assert_eq!(
        new(tick, max + tick, tick),
        Err(RemoteClaimWaitPolicyError::JitterRange)
    );
    assert_eq!(
        new(tick, tick, max + tick),
        Err(RemoteClaimWaitPolicyError::JitterRange)
    );
}

struct ProbeInbox<'a, C> {
    clock: &'a C,
    inner: FakeInbox,
    probes: Mutex<Vec<(std::time::Instant, Duration)>>,
    stall_claim: bool,
    reservations: AtomicUsize,
    retry_gate: Option<Arc<tokio::sync::Semaphore>>,
}

impl<'a, C> ProbeInbox<'a, C> {
    fn busy(clock: &'a C, hint: Option<Duration>) -> Self {
        Self {
            clock,
            inner: FakeInbox {
                capacity: None,
                lease: LeaseStatus::Held {
                    remaining: Duration::from_secs(30),
                },
                disposition: Mutex::new(Some(IdempotencyDisposition::InProgress {
                    retry_after: hint,
                })),
            },
            probes: Mutex::default(),
            stall_claim: false,
            reservations: AtomicUsize::default(),
            retry_gate: None,
        }
    }

    fn release_owner(&self) {
        *self.inner.disposition.lock().expect("owner") =
            Some(IdempotencyDisposition::Acquired(Claim));
    }
}

impl<C: Clock> InboxStore for ProbeInbox<'_, C> {
    type Claim = Claim;
    type Permit = (OperationDeadline, Option<tokio::sync::OwnedSemaphorePermit>);
    fn lease_policy(&self) -> LeaseRenewalPolicy {
        self.inner.lease_policy()
    }
    fn reserve_claim(
        &self,
        _: ExecutionBinding,
        _: &ConsumerIdentity,
        deadline: OperationDeadline,
    ) -> Result<ClaimAdmission<'_, Self::Permit>, MessagingError> {
        if self.reservations.fetch_add(1, Ordering::SeqCst) != 0
            && let Some(gate) = &self.retry_gate
        {
            let gate = gate.clone();
            return Ok(ClaimAdmission::Waiting(Box::pin(async move {
                Ok((
                    deadline,
                    Some(gate.acquire_owned().await.expect("test semaphore open")),
                ))
            })));
        }
        Ok(ClaimAdmission::Ready((deadline, None)))
    }
    async fn claim(
        &self,
        permit: Self::Permit,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        let count = {
            let mut probes = self.probes.lock().expect("probes");
            probes.push((self.clock.now(), permit.0.timeout()));
            probes.len()
        };
        if self.stall_claim && count == 2 {
            return std::future::pending().await;
        }
        self.inner.claim(()).await
    }
    async fn read_terminal(
        &self,
        binding: ExecutionBinding,
        id: &ConsumerIdentity,
        d: OperationDeadline,
    ) -> Result<Option<TerminalReceipt>, MessagingError> {
        self.inner.read_terminal(binding, id, d).await
    }
    async fn extend(
        &self,
        claim: &Claim,
        d: OperationDeadline,
    ) -> Result<LeaseStatus, MessagingError> {
        self.inner.extend(claim, d).await
    }
    async fn release(&self, claim: Claim, d: OperationDeadline) -> Result<(), MessagingError> {
        self.inner.release(claim, d).await
    }
}

fn tuned() -> RemoteClaimWaitPolicy {
    RemoteClaimWaitPolicy::new(
        Duration::from_millis(4),
        Duration::from_millis(32),
        Duration::from_millis(15),
    )
    .expect("custom schedule")
}

async fn busy_probes(policy: ConsumerExecutionPolicy, hint: Option<Duration>) -> Duration {
    let clock = ManualTimer::new();
    let start = clock.now();
    let inbox = ProbeInbox::busy(&clock, hint);
    let msg = envelope(|_| {});
    let sub = subscription(&msg);
    let execution = ConsumerExecution::new(
        ConsumerGroup::parse("probe").expect("group"),
        &TrustedIngress,
        &sub,
        &clock,
        policy,
        &NoopEmitter,
    );
    let tx = FakeTx {
        calls: Arc::default(),
        disposition: TerminalDisposition::Succeeded,
    };
    let recorder = RecordingSettlement::new();
    let processing = consume_once(
        &inbox,
        &tx,
        &execution,
        Delivery::new(msg, recorder.clone()),
    );
    tokio::pin!(processing);
    let operation = policy.budget().total() - policy.budget().settlement_reserve();
    let wait = policy.remote_claim_wait();
    let latest = operation - wait.final_window(operation);
    let mut base = wait.initial_base();
    loop {
        if let std::task::Poll::Ready(result) = futures::poll!(&mut processing) {
            assert_eq!(
                result.expect("known busy"),
                ProcessingDisposition::InProgress
            );
            break;
        }
        let elapsed = clock.now().saturating_duration_since(start);
        let delay = clock.next_sleep().expect("bounded wait");
        assert!(elapsed + delay <= operation);
        if elapsed + delay < latest - wait.final_window(operation) {
            let floor = hint
                .unwrap_or(base)
                .clamp((base / 2).max(wait.initial_base()), base);
            assert!((floor..floor * 2).contains(&delay));
        }
        base = (base * 2).min(wait.max_base());
        clock.advance(delay);
    }
    let probes = inbox.probes.lock().expect("probes");
    let last = probes
        .last()
        .expect("final probe")
        .0
        .saturating_duration_since(start);
    assert!((latest - wait.final_window(operation)..=latest).contains(&last));
    for (at, remaining) in probes.iter() {
        assert_eq!(*at + *remaining, start + operation);
    }
    assert!(probes.windows(2).all(|p| p[0].0 < p[1].0));
    assert_eq!(clock.now(), start + operation);
    assert_eq!(recorder.settlements(), [SettlementKind::Requeue]);
    assert_eq!(recorder.abandon_count(), 0);
    assert_eq!(tx.calls.load(Ordering::SeqCst), 0);
    last
}

#[tokio::test]
async fn remote_probes_follow_the_selected_tiers_and_spread_the_last_probe() {
    for policy in [
        consumer_policy(),
        ConsumerExecutionPolicy::new(
            RetryPolicy::STANDARD,
            ExecutionBudget::new(Duration::from_millis(350), Duration::from_millis(50))
                .expect("budget"),
            tuned(),
        ),
    ] {
        // Independent deliveries with the same logical start receive independent jitter.
        let finals = futures::future::join_all((0..8).map(|_| busy_probes(policy, None))).await;
        assert!(finals.windows(2).any(|p| p[0] != p[1]));
        busy_probes(policy, Some(Duration::ZERO)).await; // the owner keeps renewing a short lease
        busy_probes(policy, Some(Duration::MAX)).await;
    }
}

#[derive(Clone, Copy)]
enum Action {
    ReleaseEarly,
    ExpireAtHint,
    LateWake,
    PendingClaim,
    Cancel,
}

#[tokio::test]
async fn remote_ownership_and_cancellation_use_the_original_short_cutoffs() {
    let wait = tuned();
    let operation = wait.initial_base() * 2;
    let reserve = wait.initial_base();
    let policy = ConsumerExecutionPolicy::new(
        RetryPolicy::STANDARD,
        ExecutionBudget::new(operation + reserve, reserve).expect("budget"),
        wait,
    );
    let latest = operation - wait.final_window(operation);
    let dispatch_lag = wait.final_window(operation) / 2;
    for action in [
        Action::ReleaseEarly,
        Action::ExpireAtHint,
        Action::LateWake,
        Action::PendingClaim,
        Action::Cancel,
    ] {
        let clock = ManualTimer::new();
        let start = clock.now();
        let hint = matches!(action, Action::ExpireAtHint).then_some(latest);
        let mut inbox = ProbeInbox::busy(&clock, hint);
        inbox.stall_claim = matches!(action, Action::PendingClaim);
        let msg = envelope(|_| {});
        let sub = subscription(&msg);
        let execution = ConsumerExecution::new(
            ConsumerGroup::parse("probe").expect("group"),
            &TrustedIngress,
            &sub,
            &clock,
            policy,
            &NoopEmitter,
        );
        let tx = FakeTx {
            calls: Arc::default(),
            disposition: TerminalDisposition::Succeeded,
        };
        let recorder = RecordingSettlement::new();
        {
            let processing = consume_once(
                &inbox,
                &tx,
                &execution,
                Delivery::new(msg, recorder.clone()),
            );
            tokio::pin!(processing);
            assert!(futures::poll!(&mut processing).is_pending());
            let delay = clock.next_sleep().expect("final wake");
            assert!((latest - wait.final_window(latest)..=latest).contains(&delay));
            let tick = Duration::from_nanos(1);
            match action {
                Action::Cancel => (),
                Action::ReleaseEarly | Action::ExpireAtHint => {
                    if hint.is_some() {
                        assert_eq!(delay, latest);
                    }
                    clock.advance(delay - tick);
                    inbox.release_owner();
                    assert!(futures::poll!(&mut processing).is_pending());
                    // Round the boundary hint's fine-grained wake up by a Tokio timer tick.
                    let lag = if hint.is_some() {
                        Duration::from_millis(1)
                    } else {
                        Duration::ZERO
                    };
                    clock.advance(tick + lag);
                    assert_eq!(
                        futures::poll!(&mut processing).map(|r| r.expect("acquire")),
                        std::task::Poll::Ready(ProcessingDisposition::Committed(
                            TerminalDisposition::Succeeded
                        ))
                    );
                    assert_eq!(
                        *inbox.probes.lock().expect("probes"),
                        [
                            (start, operation),
                            (start + delay + lag, operation - delay - lag)
                        ]
                    );
                    assert_eq!(recorder.settlements(), [SettlementKind::Acknowledge]);
                    assert_eq!(tx.calls.load(Ordering::SeqCst), 1);
                }
                Action::LateWake => {
                    clock.advance(latest + dispatch_lag + tick);
                    assert!(futures::poll!(&mut processing).is_pending());
                    assert_eq!(inbox.reservations.load(Ordering::SeqCst), 1);
                    clock.advance(operation - latest - dispatch_lag - tick);
                    assert_eq!(
                        futures::poll!(&mut processing).map(|r| r.expect("busy")),
                        std::task::Poll::Ready(ProcessingDisposition::InProgress)
                    );
                    assert_eq!(inbox.probes.lock().expect("probes").len(), 1);
                    assert_eq!(recorder.settlements(), [SettlementKind::Requeue]);
                }
                Action::PendingClaim => {
                    clock.advance(delay);
                    assert!(futures::poll!(&mut processing).is_pending());
                    clock.advance(operation - delay);
                    assert_eq!(
                        futures::poll!(&mut processing)
                            .map(|r| r.expect_err("unacknowledged claim").kind()),
                        std::task::Poll::Ready(MessagingErrorKind::DeadlineElapsed)
                    );
                    assert!(recorder.settlements().is_empty());
                    assert_eq!(recorder.abandon_count(), 1);
                }
            }
        }
        if matches!(action, Action::Cancel) {
            clock.advance(operation + reserve);
            assert_eq!(inbox.probes.lock().expect("probes").len(), 1);
            assert!(recorder.settlements().is_empty());
            assert_eq!(recorder.abandon_count(), 0);
        }
    }
}

#[tokio::test]
async fn remote_retry_leaves_the_local_permit_queue_at_its_latest_start() {
    let wait = tuned();
    let budget = ExecutionBudget::STANDARD;
    let operation = budget.total() - budget.settlement_reserve();
    let reserve = wait.final_window(operation);
    let latest = operation - (reserve - reserve / 2);
    for late_transfer in [false, true] {
        let clock = ManualTimer::new();
        let mut inbox = ProbeInbox::busy(&clock, None);
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        inbox.retry_gate = Some(gate.clone());
        let msg = envelope(|_| {});
        let sub = subscription(&msg);
        let execution = ConsumerExecution::new(
            ConsumerGroup::parse("probe").expect("group"),
            &TrustedIngress,
            &sub,
            &clock,
            ConsumerExecutionPolicy::new(RetryPolicy::STANDARD, budget, wait),
            &NoopEmitter,
        );
        let tx = FakeTx {
            calls: Arc::default(),
            disposition: TerminalDisposition::Succeeded,
        };
        let recorder = RecordingSettlement::new();
        let processing = consume_once(
            &inbox,
            &tx,
            &execution,
            Delivery::new(msg, recorder.clone()),
        );
        tokio::pin!(processing);
        assert!(futures::poll!(&mut processing).is_pending());
        let wake = clock.next_sleep().expect("ordinary wake");
        clock.advance(wake);
        assert!(futures::poll!(&mut processing).is_pending());
        assert_eq!(inbox.reservations.load(Ordering::SeqCst), 2);
        let elapsed = if late_transfer {
            latest + Duration::from_nanos(1)
        } else {
            latest
        };
        clock.advance(elapsed - wake);
        if late_transfer {
            gate.add_permits(1);
        }
        assert!(futures::poll!(&mut processing).is_pending());
        if !late_transfer {
            gate.add_permits(1);
        }
        // A live queued waiter or a held reservation would consume this permit.
        let slot = gate
            .try_acquire()
            .expect("permit available at latest start");
        drop(slot);
        assert!(recorder.settlements().is_empty());
        clock.advance(operation - elapsed);
        assert_eq!(
            futures::poll!(&mut processing).map(|r| r.expect("known remote owner")),
            std::task::Poll::Ready(ProcessingDisposition::InProgress)
        );
        assert_eq!(inbox.probes.lock().expect("probes").len(), 1);
        assert_eq!(recorder.settlements(), [SettlementKind::Requeue]);
        assert_eq!(recorder.abandon_count(), 0);
    }
}

#[tokio::test]
async fn already_elapsed_remote_wait_yields_before_the_next_claim() {
    // Every clock observation takes longer than the configured probe interval.
    struct Ticking {
        ticks: AtomicUsize,
        defer_first: bool,
    }
    impl Clock for Ticking {
        fn now(&self) -> std::time::Instant {
            support::epoch()
                + Duration::from_nanos(self.ticks.fetch_add(10, Ordering::SeqCst) as u64)
        }
    }
    impl ExecutionTimer for Ticking {
        async fn sleep_until(&self, at: Deadline) {
            let mut defer = self.defer_first;
            std::future::poll_fn(|cx| {
                if at.is_expired(self.now()) && !std::mem::take(&mut defer) {
                    std::task::Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            })
            .await
        }
    }
    for defer_first in [false, true] {
        let timer = Ticking {
            ticks: AtomicUsize::default(),
            defer_first,
        };
        let tick = Duration::from_nanos(1);
        let wait = RemoteClaimWaitPolicy::new(tick, tick, tick).expect("minimum jitter");
        let msg = envelope(|_| {});
        let sub = subscription(&msg);
        let events = Arc::new(Mutex::new(Vec::new()));
        let emitter = RecordingEmitter(events.clone());
        let execution = ConsumerExecution::new(
            ConsumerGroup::parse("probe").expect("group"),
            &TrustedIngress,
            &sub,
            &timer,
            ConsumerExecutionPolicy::new(
                RetryPolicy::STANDARD,
                ExecutionBudget::new(Duration::from_millis(10), Duration::from_millis(1))
                    .expect("budget"),
                wait,
            ),
            &emitter,
        );
        let inbox = FakeInbox {
            capacity: None,
            disposition: Mutex::new(Some(IdempotencyDisposition::InProgress {
                retry_after: None,
            })),
            lease: LeaseStatus::Lost,
        };
        let tx = FakeTx {
            calls: Arc::default(),
            disposition: TerminalDisposition::Succeeded,
        };
        let processing = consume_once(
            &inbox,
            &tx,
            &execution,
            Delivery::new(msg, RecordingSettlement::new()),
        );
        tokio::pin!(processing);
        assert!(futures::poll!(&mut processing).is_pending());
        assert_eq!(
            events
                .lock()
                .expect("events")
                .iter()
                .filter(|e| matches!(
                    e,
                    TransactionalMessagingObservation::ConsumerClaimInProgress
                ))
                .count(),
            1
        );
    }
}

#[tokio::test(start_paused = true)]
async fn submillisecond_final_reserve_observes_early_release_on_tokios_rounded_clock() {
    let base = Duration::from_millis(20);
    let cap = Duration::from_micros(100);
    let wait = RemoteClaimWaitPolicy::new(base, base, cap).expect("submillisecond cap");
    for operation in [base, Duration::from_micros(400)] {
        for hint in [None, Some(operation - cap)] {
            let budget = ExecutionBudget::new(operation + base, base).expect("budget");
            let policy = ConsumerExecutionPolicy::new(RetryPolicy::STANDARD, budget, wait);
            let clock = RealtimeClock::new();
            let start = clock.now();
            let msg = envelope(|_| {});
            let sub = subscription(&msg);
            let execution = ConsumerExecution::new(
                ConsumerGroup::parse("rounded-clock").expect("group"),
                &TrustedIngress,
                &sub,
                &clock,
                policy,
                &NoopEmitter,
            );
            let inbox = FakeInbox {
                capacity: None,
                disposition: Mutex::new(Some(IdempotencyDisposition::InProgress {
                    retry_after: hint,
                })),
                lease: LeaseStatus::Held {
                    remaining: Duration::from_secs(30),
                },
            };
            let tx = FakeTx {
                calls: Arc::default(),
                disposition: TerminalDisposition::Succeeded,
            };
            let recorder = RecordingSettlement::new();
            let processing = consume_once(
                &inbox,
                &tx,
                &execution,
                Delivery::new(msg, recorder.clone()),
            );
            tokio::pin!(processing);
            assert!(futures::poll!(&mut processing).is_pending());
            *inbox.disposition.lock().expect("early release") =
                Some(IdempotencyDisposition::Acquired(Claim));
            let outcome = tokio::time::timeout(operation, &mut processing)
                .await
                .expect("probe fits operation")
                .expect("reclaim");
            assert_eq!(
                outcome,
                ProcessingDisposition::Committed(TerminalDisposition::Succeeded)
            );
            assert!(clock.now() <= start + operation - cap / 2);
            assert_eq!(tx.calls.load(Ordering::SeqCst), 1);
            assert_eq!(recorder.settlements(), [SettlementKind::Acknowledge]);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn ordinary_retry_dispatched_in_the_final_window_spends_the_last_probe_once() {
    let operation = Duration::from_millis(20);
    let cap = Duration::from_micros(100);
    let base = Duration::from_micros(9400);
    let wait = RemoteClaimWaitPolicy::new(base, base, cap).expect("rounded ordinary tier");
    let policy = ConsumerExecutionPolicy::new(
        RetryPolicy::STANDARD,
        ExecutionBudget::new(operation * 2, operation).expect("budget"),
        wait,
    );
    // All initial jitter draws are ordinary (<18.8 ms). Dispatch after the safe
    // planned wake (18.95 ms), on either side of actual admission (19.95 ms).
    for (advance, release) in [
        (Duration::from_millis(19), true),
        (Duration::from_millis(19), false),
        (Duration::from_micros(19960), true),
        (operation, true),
    ] {
        let clock = RealtimeClock::new();
        let inbox = ProbeInbox::busy(&clock, None);
        let msg = envelope(|_| {});
        let sub = subscription(&msg);
        let execution = ConsumerExecution::new(
            ConsumerGroup::parse("rounded-ordinary").expect("group"),
            &TrustedIngress,
            &sub,
            &clock,
            policy,
            &NoopEmitter,
        );
        let tx = FakeTx {
            calls: Arc::default(),
            disposition: TerminalDisposition::Succeeded,
        };
        let recorder = RecordingSettlement::new();
        let processing = consume_once(
            &inbox,
            &tx,
            &execution,
            Delivery::new(msg, recorder.clone()),
        );
        tokio::pin!(processing);
        assert!(futures::poll!(&mut processing).is_pending());
        if release {
            inbox.release_owner();
        }
        tokio::time::advance(advance).await;
        let admitted = advance <= operation - (cap - cap / 2);
        if admitted && release {
            assert_eq!(
                futures::poll!(&mut processing).map(|r| r.expect("reclaim")),
                std::task::Poll::Ready(ProcessingDisposition::Committed(
                    TerminalDisposition::Succeeded
                ))
            );
            assert_eq!(recorder.settlements(), [SettlementKind::Acknowledge]);
        } else {
            if advance < operation {
                assert!(futures::poll!(&mut processing).is_pending());
                // Even if the store stays busy, there is no third immediate or delayed probe.
                tokio::task::yield_now().await;
                assert!(futures::poll!(&mut processing).is_pending());
                tokio::time::advance(operation - advance).await;
            }
            assert_eq!(
                futures::poll!(&mut processing).map(|r| r.expect("busy")),
                std::task::Poll::Ready(ProcessingDisposition::InProgress)
            );
            assert_eq!(recorder.settlements(), [SettlementKind::Requeue]);
        }
        let expected = 1 + usize::from(admitted);
        assert_eq!(inbox.probes.lock().expect("probes").len(), expected);
        assert_eq!(inbox.reservations.load(Ordering::SeqCst), expected);
    }
}
