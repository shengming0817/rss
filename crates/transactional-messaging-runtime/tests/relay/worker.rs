use super::*;
use rss_transactional_messaging::{fence::ExecutionBinding, outbox::OutboxWriter};
use rss_transactional_messaging_testkit::memory::MemoryOutboxStore;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

type Memory = MemoryOutboxStore<Vec<u8>>;
type PublishGate = (String, oneshot::Sender<()>);

struct GatePublisher(mpsc::UnboundedSender<PublishGate>);

impl Publisher<Vec<u8>> for GatePublisher {
    type Receipt = ();

    async fn publish(&self, message: &MessageEnvelope<Vec<u8>>, _: OperationDeadline) -> PublishOutcome<()> {
        let (release, gate) = oneshot::channel();
        self.0.send((message.id().as_str().to_owned(), release)).expect("test receives publication");
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
    block_call: usize,
    fail_call: usize,
    failure: MessagingErrorKind,
    reply: Semaphore,
}

impl ObservedStore {
    fn new(block_call: usize, fail_call: usize, failure: MessagingErrorKind) -> Self {
        Self { memory: Memory::new(), calls: 0.into(), owned: 0.into(), peak: 0.into(),
            block_call, fail_call, failure, reply: Semaphore::new(0) }
    }

    async fn append(&self, id: &str, partition: &str) {
        self.memory.append(&mut (), partitioned_message(id, Some(partition))).await.expect("append");
    }
}

impl OutboxRelayStore<Vec<u8>> for ObservedStore {
    type Claim = <Memory as OutboxRelayStore<Vec<u8>>>::Claim;
    type PublishReceipt = ();
    fn delivery_budget(&self) -> DeliveryBudget { self.memory.delivery_budget() }

    async fn claim_partition_heads(&self, binding: ExecutionBinding, limit: NonZeroUsize, deadline: OperationDeadline)
        -> Result<OutboxClaimBatch<Self::Claim>, MessagingError> {
        assert_eq!(limit.get(), 1);
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_call {
            return Err(MessagingError::new(self.failure, std::io::Error::other("scripted claim failure")));
        }
        let batch = self.memory.claim_partition_heads(binding, limit, deadline).await?;
        let owned = self.owned.fetch_add(batch.len(), Ordering::SeqCst) + batch.len();
        self.peak.fetch_max(owned, Ordering::SeqCst);
        if call == self.block_call {
            self.reply.acquire().await.expect("claim gate").forget();
        }
        Ok(batch)
    }

    async fn extend(&self, claim: &Self::Claim, deadline: OperationDeadline) -> Result<OutboxLeaseStatus, MessagingError> {
        self.memory.extend(claim, deadline).await
    }

    fn message(claim: &Self::Claim) -> &PendingMessage<Vec<u8>> { Memory::message(claim) }

    async fn settle(&self, claim: Self::Claim, settlement: OutboxSettlement<()>, deadline: OperationDeadline)
        -> Result<(), MessagingError> {
        self.memory.settle(claim, settlement, deadline).await?;
        self.owned.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }
}

struct Run {
    stop: CancellationToken,
    timer: Arc<AdvancingTimer>,
    published: mpsc::UnboundedReceiver<PublishGate>,
    worker: tokio::task::JoinHandle<Result<(), MessagingError>>,
}

impl Run {
    fn start(store: Arc<ObservedStore>) -> Self {
        let stop = CancellationToken::new();
        let timer = Arc::new(AdvancingTimer::new());
        let (tx, published) = mpsc::unbounded_channel();
        let config = RelayConfig::new(NonZeroUsize::MIN, NonZeroUsize::new(2).expect("capacity"),
                                      Duration::from_millis(100), Duration::from_millis(200)).expect("config");
        let worker = RelayWorker::new(store, Arc::new(GatePublisher(tx)), timer.clone(), Arc::new(NoopEmitter), config);
        let worker = tokio::spawn(worker.run(execution(fixture_tenant(), 1), stop.clone()));
        Self { stop, timer, published, worker }
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
        let (slow, mut fast) = if first.0 == "slow" { (first, second) } else { (second, first) };
        assert_eq!(slow.0, "slow");
        for n in 1..=3 {
            assert_eq!(fast.0, format!("fast-{}", n-1));
            store.append(&format!("fast-{n}"), &format!("lane-{n}")).await;
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
        assert_eq!(store.memory.settlements(), [OutboxDisposition::Published; 5]);
        assert_eq!(store.memory.pending_len(), 1);
        assert_eq!(store.owned.load(Ordering::SeqCst), 0);
    }).await.expect("independent progress with frozen time");
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
        while store.memory.settlements().is_empty() { tokio::task::yield_now().await; }
        assert!(!run.worker.is_finished());
        store.reply.add_permits(1);
        let second = run.next().await;
        assert_eq!(second.0, "second");
        second.1.send(()).expect("drain admitted reply");
        support::join_worker(run.worker).await.expect("drain");
        assert_eq!(store.calls.load(Ordering::SeqCst), 2);
        assert_eq!(store.memory.settlements(), [OutboxDisposition::Published; 2]);
    }).await.expect("pending claim and settlement both progress");
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
        while store.memory.settlements().is_empty() { tokio::task::yield_now().await; }
        for (step, expected) in [(199, 2), (1, 3), (99, 3), (1, 4)] {
            run.timer.advance(Duration::from_millis(step));
            support::wait_for_count(&store.calls, expected).await;
            if step == 1 {
                run.timer.wait_registered(Duration::from_millis(if expected == 3 {300} else {400})).await;
            }
            tokio::task::yield_now().await;
            assert_eq!(store.calls.load(Ordering::SeqCst), expected);
        }
        run.stop.cancel();
        support::join_worker(run.worker).await.expect("empty drain");
    }).await.expect("independent scan and error timers");
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
    }).await.expect("fatal drain completes");
}
