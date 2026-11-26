use super::*;
use rss_transactional_messaging::outbox::OutboxScanProgress;
use rss_transactional_messaging::{fence::ExecutionBinding, outbox::OutboxWriter};
use rss_transactional_messaging_testkit::memory::MemoryOutboxStore;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

type Memory = MemoryOutboxStore<Vec<u8>>;
type PublishGate = (String, oneshot::Sender<()>);

struct GatePublisher(mpsc::UnboundedSender<PublishGate>);

impl Publisher<Vec<u8>> for GatePublisher {
    type Receipt = ();

    async fn publish(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> PublishOutcome<()> {
        let (release, gate) = oneshot::channel();
        self.0
            .send((message.id().as_str().to_owned(), release))
            .expect("test receives publication");
        gate.await.expect("publication released");
        PublishOutcome::Confirmed(())
    }
}

// Block the response after acquisition to model a committed claim whose reply is pending.
struct ObservedStore {
    memory: Memory,
    calls: AtomicUsize,
    owned: AtomicUsize,
    peak: AtomicUsize,
    limits: Mutex<Vec<usize>>,
    first_extend_at: AtomicUsize,
    block_call: usize,
    fail_call: usize,
    failure: MessagingErrorKind,
    reply: Semaphore,
    fail_settle: Option<&'static str>,
    settle_calls: AtomicUsize,
    empty_until: usize,
    empty_action: OutboxScanProgress,
}

impl ObservedStore {
    fn new(block_call: usize, fail_call: usize, failure: MessagingErrorKind) -> Self {
        Self {
            memory: Memory::new(),
            calls: 0.into(),
            owned: 0.into(),
            peak: 0.into(),
            limits: Default::default(),
            first_extend_at: usize::MAX.into(),
            block_call,
            fail_call,
            failure,
            reply: Semaphore::new(0),
            fail_settle: None,
            settle_calls: 0.into(),
            empty_until: 0,
            empty_action: OutboxScanProgress::Complete,
        }
    }

    async fn append(&self, id: &str, partition: &str) {
        self.memory
            .append(&mut (), partitioned_message(id, Some(partition)))
            .await
            .expect("append");
    }
}

impl OutboxRelayStore<Vec<u8>> for ObservedStore {
    type Claim = <Memory as OutboxRelayStore<Vec<u8>>>::Claim;
    type PublishReceipt = ();
    fn delivery_budget(&self) -> DeliveryBudget {
        self.memory.delivery_budget()
    }

    async fn claim_partition_heads(
        &self,
        binding: ExecutionBinding,
        limit: NonZeroUsize,
        deadline: OperationDeadline,
    ) -> Result<OutboxClaimBatch<Self::Claim>, MessagingError> {
        self.limits.lock().expect("claim limits").push(limit.get());
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_call {
            return Err(MessagingError::new(
                self.failure,
                std::io::Error::other("scripted claim failure"),
            ));
        }
        if call <= self.empty_until {
            return OutboxClaimBatch::try_from_provider(Vec::new(), limit, self.empty_action)
                .map_err(|e| MessagingError::new(MessagingErrorKind::Invariant, e));
        }
        let batch = self
            .memory
            .claim_partition_heads(binding, limit, deadline)
            .await?;
        let owned = self.owned.fetch_add(batch.len(), Ordering::SeqCst) + batch.len();
        self.peak.fetch_max(owned, Ordering::SeqCst);
        if call == self.block_call {
            self.reply.acquire().await.expect("claim gate").forget();
        }
        Ok(batch)
    }

    async fn extend(
        &self,
        claim: &Self::Claim,
        deadline: OperationDeadline,
    ) -> Result<OutboxLeaseStatus, MessagingError> {
        self.first_extend_at
            .fetch_min(self.calls.load(Ordering::SeqCst), Ordering::SeqCst);
        self.memory.extend(claim, deadline).await
    }

    fn message(claim: &Self::Claim) -> &PendingMessage<Vec<u8>> {
        Memory::message(claim)
    }

    async fn settle(
        &self,
        claim: Self::Claim,
        settlement: OutboxSettlement<()>,
        deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        self.settle_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_settle == Some(Self::message(&claim).message_id().as_str()) {
            return Err(MessagingError::new(
                MessagingErrorKind::OwnershipLost,
                std::io::Error::other("fenced settlement"),
            ));
        }
        self.memory.settle(claim, settlement, deadline).await?;
        self.owned.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn empty_continuation_has_a_bounded_request_slice() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut observed = ObservedStore::new(0, 0, MessagingErrorKind::Transient);
        observed.empty_until = 78;
        observed.empty_action = OutboxScanProgress::Continue;
        let store = Arc::new(observed);
        store.append("tail", "ordered").await;
        let mut run = Run::with_limits(store.clone(), 32, 1);
        for slice in 1..=9 {
            run.timer
                .wait_registered(Duration::from_millis(slice * 100))
                .await;
            assert_eq!(store.calls.load(Ordering::SeqCst), slice as usize * 8);
            run.timer.advance(Duration::from_millis(100));
        }
        let (id, finish) = run.next().await;
        assert_eq!(id, "tail");
        assert_eq!(store.calls.load(Ordering::SeqCst), 79);
        run.stop.cancel();
        finish.send(()).expect("settle tail");
        support::join_worker(run.worker).await.expect("drain");
    })
    .await
    .expect("bounded continuation");
}

#[tokio::test]
async fn caller_driven_action_and_worker_retry_cadence() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for action in [
            OutboxScanProgress::Complete,
            OutboxScanProgress::RetryLater,
            OutboxScanProgress::Continue,
        ] {
            let mut observed = ObservedStore::new(0, 0, MessagingErrorKind::Transient);
            observed.empty_action = action;
            observed.empty_until = usize::MAX;
            let store = Arc::new(observed);
            let timer = Arc::new(AdvancingTimer::new());
            let publisher = Arc::new(ScriptedPublisher::new([]));
            let report = relay_once(
                execution(fixture_tenant(), 1),
                &*store,
                &*publisher,
                &*timer,
                &NoopEmitter,
                NonZeroUsize::MIN,
            )
            .await
            .expect("report");
            assert_eq!(report.scan_progress(), action);
            if action == OutboxScanProgress::Continue {
                continue;
            }
            store.calls.store(0, Ordering::SeqCst);
            let config = RelayConfig::new(
                NonZeroUsize::MIN,
                NonZeroUsize::MIN,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .expect("config");
            let worker = RelayWorker::new(
                store.clone(),
                publisher,
                timer.clone(),
                Arc::new(NoopEmitter),
                config,
            );
            let stop = CancellationToken::new();
            let task = tokio::spawn(worker.run(execution(fixture_tenant(), 1), stop.clone()));
            let delay = if action == OutboxScanProgress::Complete {
                Duration::from_secs(30)
            } else {
                Duration::from_millis(100)
            };
            timer.wait_registered(delay).await;
            timer.advance(delay - Duration::from_millis(1));
            tokio::task::yield_now().await;
            assert_eq!(store.calls.load(Ordering::SeqCst), 1);
            timer.advance(Duration::from_millis(1));
            support::wait_for_count(&store.calls, 2).await;
            stop.cancel();
            support::join_worker(task).await.expect("stop");
        }
    })
    .await
    .expect("bounded worker scenario");
}

struct Run {
    stop: CancellationToken,
    timer: Arc<AdvancingTimer>,
    published: mpsc::UnboundedReceiver<PublishGate>,
    worker: tokio::task::JoinHandle<Result<(), MessagingError>>,
}

impl Run {
    fn start(store: Arc<ObservedStore>) -> Self {
        Self::with_limits(store, 1, 2)
    }

    fn with_limits(store: Arc<ObservedStore>, claim_limit: usize, capacity: usize) -> Self {
        let stop = CancellationToken::new();
        let timer = Arc::new(AdvancingTimer::new());
        let (tx, published) = mpsc::unbounded_channel();
        let config = RelayConfig::new(
            NonZeroUsize::new(claim_limit).expect("claim limit"),
            NonZeroUsize::new(capacity).expect("capacity"),
            Duration::from_millis(100),
            Duration::from_millis(200),
        )
        .expect("config");
        let worker = RelayWorker::new(
            store,
            Arc::new(GatePublisher(tx)),
            timer.clone(),
            Arc::new(NoopEmitter),
            config,
        );
        let worker = tokio::spawn(worker.run(execution(fixture_tenant(), 1), stop.clone()));
        Self {
            stop,
            timer,
            published,
            worker,
        }
    }

    async fn next(&mut self) -> PublishGate {
        self.published.recv().await.expect("worker publishes")
    }
}

#[tokio::test]
async fn refills_across_partitions_while_the_slow_head_blocks_its_successor() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let store = Arc::new(ObservedStore::new(0, 0, MessagingErrorKind::Transient));
        store.append("slow", "ordered").await;
        store.append("successor", "ordered").await;
        store.append("fast-0", "lane-0").await;
        let mut run = Run::start(store.clone());
        let first = run.next().await;
        let second = run.next().await;
        let (slow, mut fast) = if first.0 == "slow" {
            (first, second)
        } else {
            (second, first)
        };
        assert_eq!(slow.0, "slow");
        for n in 1..=3 {
            assert_eq!(fast.0, format!("fast-{}", n - 1));
            store
                .append(&format!("fast-{n}"), &format!("lane-{n}"))
                .await;
            fast.1.send(()).expect("finish fast publish");
            fast = run.next().await;
        }
        assert_eq!(fast.0, "fast-3");
        assert_eq!(store.memory.settlements().len(), 3);
        assert_eq!(store.peak.load(Ordering::SeqCst), 2);
        run.stop.cancel();
        slow.1.send(()).expect("finish slow publish");
        fast.1.send(()).expect("finish last fast publish");
        support::join_worker(run.worker).await.expect("drain");
        assert_eq!(store.calls.load(Ordering::SeqCst), 5);
        assert_eq!(
            store.memory.settlements(),
            [OutboxDisposition::Published; 5]
        );
        assert_eq!(store.memory.pending_len(), 1);
        assert_eq!(store.owned.load(Ordering::SeqCst), 0);
    })
    .await
    .expect("independent progress with frozen time");
}

#[tokio::test]
async fn drain_includes_a_claim_whose_durable_reply_is_pending() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let store = Arc::new(ObservedStore::new(2, 0, MessagingErrorKind::Transient));
        store.append("first", "a").await;
        store.append("second", "b").await;
        let mut run = Run::start(store.clone());
        let first = run.next().await;
        assert_eq!(first.0, "first");
        support::wait_for_count(&store.owned, 2).await;
        run.stop.cancel();
        first.1.send(()).expect("complete during scan");
        while store.memory.settlements().is_empty() {
            tokio::task::yield_now().await;
        }
        assert!(!run.worker.is_finished());
        store.reply.add_permits(1);
        let second = run.next().await;
        assert_eq!(second.0, "second");
        second.1.send(()).expect("drain admitted reply");
        support::join_worker(run.worker).await.expect("drain");
        assert_eq!(store.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            store.memory.settlements(),
            [OutboxDisposition::Published; 2]
        );
    })
    .await
    .expect("pending claim and settlement both progress");
}

#[tokio::test]
async fn a_completion_cannot_shorten_error_backoff_and_empty_scans_wait() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let store = Arc::new(ObservedStore::new(0, 2, MessagingErrorKind::Transient));
        store.append("first", "a").await;
        let mut run = Run::start(store.clone());
        let (_, release) = run.next().await;
        run.timer.wait_registered(Duration::from_millis(200)).await;
        release.send(()).expect("complete in backoff");
        while store.memory.settlements().is_empty() {
            tokio::task::yield_now().await;
        }
        for (step, expected) in [(199, 2), (1, 3), (99, 3), (1, 4)] {
            run.timer.advance(Duration::from_millis(step));
            support::wait_for_count(&store.calls, expected).await;
            if step == 1 {
                run.timer
                    .wait_registered(Duration::from_millis(if expected == 3 { 300 } else { 400 }))
                    .await;
            }
            tokio::task::yield_now().await;
            assert_eq!(store.calls.load(Ordering::SeqCst), expected);
        }
        run.stop.cancel();
        support::join_worker(run.worker).await.expect("empty drain");
    })
    .await
    .expect("independent scan and error timers");
}

#[tokio::test]
async fn fatal_claim_error_stops_admission_and_drains_the_first_claim() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let store = Arc::new(ObservedStore::new(0, 2, MessagingErrorKind::OwnershipLost));
        store.append("first", "a").await;
        let mut run = Run::start(store.clone());
        let (_, release) = run.next().await;
        support::wait_for_count(&store.calls, 2).await;
        release.send(()).expect("complete in drain");
        let error = support::join_worker(run.worker).await.expect_err("fatal");
        assert_eq!(error.kind(), MessagingErrorKind::OwnershipLost);
        assert_eq!(store.calls.load(Ordering::SeqCst), 2);
        assert_eq!(store.memory.settlements(), [OutboxDisposition::Published]);
    })
    .await
    .expect("fatal drain completes");
}

#[tokio::test]
async fn ready_claims_start_before_refill_and_last_request_fits_the_free_slot() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let store = Arc::new(ObservedStore::new(0, 0, MessagingErrorKind::Transient));
        for id in ["a", "b", "c", "d"] {
            store.append(id, id).await;
        }
        let mut run = Run::with_limits(store.clone(), 2, 3);
        let a = run.next().await;
        let b = run.next().await;
        let c = run.next().await;
        assert_eq!(store.first_extend_at.load(Ordering::SeqCst), 1);
        assert_eq!(*store.limits.lock().expect("limits"), [2, 1]);
        assert_eq!(store.peak.load(Ordering::SeqCst), 3);
        run.stop.cancel();
        for gate in [a, b, c] {
            gate.1.send(()).expect("finish");
        }
        support::join_worker(run.worker).await.expect("drain");
    })
    .await
    .expect("all slots started");
}

#[tokio::test]
async fn fatal_settlement_during_claim_keeps_its_error_and_drains_the_reply() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut observed = ObservedStore::new(2, 0, MessagingErrorKind::Transient);
        observed.fail_settle = Some("first");
        let store = Arc::new(observed);
        store.append("first", "a").await;
        store.append("second", "b").await;
        let mut run = Run::start(store.clone());
        let first = run.next().await;
        support::wait_for_count(&store.owned, 2).await;
        first.1.send(()).expect("attempt fenced settlement");
        support::wait_for_count(&store.settle_calls, 1).await;
        assert!(!run.worker.is_finished());
        store.reply.add_permits(1);
        let second = run.next().await;
        assert_eq!(second.0, "second");
        second.1.send(()).expect("settle admitted reply");
        let error = support::join_worker(run.worker)
            .await
            .expect_err("retain settlement error");
        assert_eq!(error.kind(), MessagingErrorKind::OwnershipLost);
        assert_eq!(store.calls.load(Ordering::SeqCst), 2);
        assert_eq!(store.memory.settlements(), [OutboxDisposition::Published]);
    })
    .await
    .expect("admitted reply drains");
}

#[tokio::test]
async fn unrepresentable_scan_delays_fail_before_claim() {
    for (idle, backoff) in [
        (Duration::MAX, Duration::from_secs(1)),
        (Duration::from_secs(1), Duration::MAX),
    ] {
        let store = Arc::new(ObservedStore::new(0, 0, MessagingErrorKind::Transient));
        let config =
            RelayConfig::new(NonZeroUsize::MIN, NonZeroUsize::MIN, idle, backoff).expect("floor");
        let worker = RelayWorker::new(
            store.clone(),
            Arc::new(ScriptedPublisher::new([])),
            Arc::new(FakeClock::new()),
            Arc::new(NoopEmitter),
            config,
        );
        let error = worker
            .run(execution(fixture_tenant(), 1), CancellationToken::new())
            .await
            .expect_err("clock overflow");
        assert_eq!(error.kind(), MessagingErrorKind::Invariant);
        assert_eq!(store.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn durable_retry_gives_other_due_heads_a_turn() {
    let store = Memory::new();
    let clock = store.clock();
    let binding = execution(fixture_tenant(), 1);
    for (id, partition) in [("retry", "a"), ("successor", "a"), ("ready", "b")] {
        store
            .append(&mut (), partitioned_message(id, Some(partition)))
            .await
            .expect("append");
    }
    let publisher = ScriptedPublisher::new([
        deadline_elapsed_outcome(),
        PublishOutcome::Confirmed(()),
        PublishOutcome::Confirmed(()),
    ]);
    let once = || {
        relay_once(
            binding,
            &store,
            &publisher,
            clock,
            &NoopEmitter,
            NonZeroUsize::MIN,
        )
    };
    assert_eq!(once().await.expect("retry").retried(), 1);
    assert_eq!(once().await.expect("independent head").published(), 1);
    assert_eq!(once().await.expect("no eligible head").claimed(), 0);
    clock.advance(Duration::from_secs(1)).expect("retry due");
    assert_eq!(once().await.expect("original head").published(), 1);
    let ids = publisher.message_ids();
    assert_eq!(
        ids.iter().map(MessageId::as_str).collect::<Vec<_>>(),
        ["retry", "ready", "retry"]
    );
}

fn deadline_elapsed_outcome() -> PublishOutcome<()> {
    PublishOutcome::Ambiguous(PublishFailure::new(
        PublishFailureKind::Transient,
        PublishFailureStage::Confirm,
        PublishFailureReason::DeadlineElapsed,
    ))
}

#[tokio::test]
async fn settling_a_head_wakes_an_empty_scan_without_advancing_time() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let store = Arc::new(ObservedStore::new(0, 0, MessagingErrorKind::Transient));
        store.append("head", "ordered").await;
        store.append("successor", "ordered").await;
        let mut run = Run::start(store.clone());
        let head = run.next().await;
        assert_eq!(head.0, "head");
        run.timer.wait_registered(Duration::from_millis(100)).await;
        assert_eq!(store.calls.load(Ordering::SeqCst), 2);
        head.1.send(()).expect("settle ordered head during idle");
        let successor = run.next().await;
        assert_eq!(successor.0, "successor");
        run.stop.cancel();
        successor.1.send(()).expect("drain successor");
        support::join_worker(run.worker).await.expect("drain");
        assert_eq!(
            store.memory.settlements(),
            [OutboxDisposition::Published; 2]
        );
    })
    .await
    .expect("successor starts while idle clock is frozen");
}
