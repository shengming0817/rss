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

struct ProbeInbox<'a> {
    clock: &'a ManualTimer,
    inner: FakeInbox,
    probes: Mutex<Vec<(std::time::Instant, Duration)>>,
    stall_claim: bool,
}

impl<'a> ProbeInbox<'a> {
    fn busy(clock: &'a ManualTimer, hint: Option<Duration>) -> Self {
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
        }
    }

    fn release_owner(&self) {
        *self.inner.disposition.lock().expect("owner") =
            Some(IdempotencyDisposition::Acquired(Claim));
    }
}

impl InboxStore for ProbeInbox<'_> {
    type Claim = Claim;
    type Permit = OperationDeadline;
    fn lease_policy(&self) -> LeaseRenewalPolicy {
        self.inner.lease_policy()
    }
    fn reserve_claim(
        &self,
        _: ExecutionBinding,
        _: &ConsumerIdentity,
        deadline: OperationDeadline,
    ) -> Result<ClaimAdmission<'_, Self::Permit>, MessagingError> {
        Ok(ClaimAdmission::Ready(deadline))
    }
    async fn claim(
        &self,
        permit: Self::Permit,
    ) -> Result<IdempotencyDisposition<Self::Claim>, MessagingError> {
        let count = {
            let mut probes = self.probes.lock().expect("probes");
            probes.push((self.clock.now(), permit.timeout()));
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
                    clock.advance(tick);
                    assert_eq!(
                        processing.await.expect("acquire"),
                        ProcessingDisposition::Committed(TerminalDisposition::Succeeded)
                    );
                    assert_eq!(
                        *inbox.probes.lock().expect("probes"),
                        [(start, operation), (start + delay, operation - delay)]
                    );
                    assert_eq!(recorder.settlements(), [SettlementKind::Acknowledge]);
                    assert_eq!(tx.calls.load(Ordering::SeqCst), 1);
                }
                Action::LateWake => {
                    clock.advance(latest + tick);
                    assert!(futures::poll!(&mut processing).is_pending());
                    clock.advance(operation - latest - tick);
                    assert_eq!(
                        processing.await.expect("busy"),
                        ProcessingDisposition::InProgress
                    );
                    assert_eq!(inbox.probes.lock().expect("probes").len(), 1);
                    assert_eq!(recorder.settlements(), [SettlementKind::Requeue]);
                }
                Action::PendingClaim => {
                    clock.advance(delay);
                    assert!(futures::poll!(&mut processing).is_pending());
                    clock.advance(operation - delay);
                    assert_eq!(
                        processing.await.expect_err("unacknowledged claim").kind(),
                        MessagingErrorKind::DeadlineElapsed
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
