use super::*;
use rss_transactional_messaging::policy::RemoteClaimWaitPolicy;

use rss_transactional_messaging_runtime::consumer::{
    ConsumerExecution, ProcessingDisposition, consume_once,
};

pub(super) async fn install_counter(owner: &sqlx::PgPool) -> anyhow::Result<()> {
    // BEFORE INSERT observes even an ON CONFLICT attempt that changes no row.
    sqlx::raw_sql(
        "
        CREATE SEQUENCE public.window_claims CACHE 1;
        GRANT USAGE ON SEQUENCE public.window_claims TO tmsg_runtime;
        CREATE FUNCTION public.count_window_claim() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN PERFORM nextval('public.window_claims'); RETURN NEW; END $$;
        CREATE TRIGGER count_window_claim BEFORE INSERT ON rss_transactional_messaging.inbox
        FOR EACH ROW WHEN (NEW.message_id LIKE 'window-%')
        EXECUTE FUNCTION public.count_window_claim()",
    )
    .execute(owner)
    .await?;
    Ok(())
}

pub(super) async fn claim_count(owner: &sqlx::PgPool) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM public.window_claims",
    )
    .fetch_one(owner)
    .await?)
}

fn subscription(message: &MessageEnvelope<Vec<u8>>) -> SubscriptionIdentity {
    let meta = message.metadata();
    SubscriptionIdentity::new(
        meta.domain().clone(),
        meta.route().clone(),
        meta.contract().clone(),
    )
}

pub(super) async fn cancel_waiter(
    inbox: &PgInboxStore,
    runtime: &Arc<PgRuntime>,
) -> anyhow::Result<()> {
    let msg = message("window-cancelled");
    let sub = subscription(&msg);
    let clock = FakeClock::new();
    let busy = Sink(Arc::new(Notify::new()));
    let execution = ConsumerExecution::new(
        ConsumerGroup::parse("suite")?,
        &Validator,
        &sub,
        &clock,
        ConsumerExecutionPolicy::new(
            RetryPolicy::STANDARD,
            ExecutionBudget::STANDARD,
            RemoteClaimWaitPolicy::STANDARD,
        ),
        &busy,
    );
    let tx = PgConsumerTx::receipt_only(runtime.clone(), Effect(TerminalDisposition::Succeeded));
    let recorder = RecordingSettlement::new();
    {
        let processing = consume_once(inbox, &tx, &execution, Delivery::new(msg, recorder.clone()));
        tokio::pin!(processing);
        tokio::select! {
            result = &mut processing => anyhow::bail!("saturated local delivery completed: {result:?}"),
            () = busy.0.notified() => {}
        }
    }
    assert!(recorder.settlements().is_empty());
    assert_eq!(recorder.abandon_count(), 0);
    Ok(())
}

struct RemoteBusy(Notify);
impl TransactionalMessagingEmitter for RemoteBusy {
    fn emit(&self, observation: TransactionalMessagingObservation) {
        if matches!(
            observation,
            TransactionalMessagingObservation::ConsumerClaimInProgress
        ) {
            self.0.notify_one();
        }
    }
}

#[derive(Clone, Copy)]
enum OwnerAction {
    Hold,
    Release,
    Commit,
}

async fn verify_row_hint(
    owner: &sqlx::PgPool,
    inbox: &PgInboxStore,
    binding: &VerifiedConsumerBinding,
) -> anyhow::Result<()> {
    for seconds in [10_i32, 120] {
        sqlx::query("UPDATE rss_transactional_messaging.inbox SET lease_until=clock_timestamp()+make_interval(secs => $1) WHERE message_id=$2")
            .bind(f64::from(seconds)).bind(binding.identity().message_id().as_str()).execute(owner).await?;
        let permit = inbox
            .reserve_claim(binding.execution(), binding.identity(), deadline())?
            .acquire()
            .await?;
        let IdempotencyDisposition::InProgress {
            retry_after: Some(hint),
        } = inbox.claim(permit).await?
        else {
            anyhow::bail!("live database lease must supply its measured hint");
        };
        let limit = Duration::from_secs(seconds as u64);
        assert!(
            (limit - Duration::from_secs(5)..=limit).contains(&hint),
            "row hint {hint:?} for {seconds}s lease"
        );
    }
    Ok(())
}

async fn verify_unbounded_lease(
    owner: &sqlx::PgPool,
    inbox: &PgInboxStore,
    binding: &VerifiedConsumerBinding,
    terminal: bool,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE rss_transactional_messaging.inbox SET lease_until='infinity' WHERE message_id=$1",
    )
    .bind(binding.identity().message_id().as_str())
    .execute(owner)
    .await?;
    let receipt = inbox
        .read_terminal(binding.execution(), binding.identity(), deadline())
        .await?;
    assert_eq!(receipt.is_some(), terminal);
    let permit = inbox
        .reserve_claim(binding.execution(), binding.identity(), deadline())?
        .acquire()
        .await?;
    match (inbox.claim(permit).await?, receipt) {
        (IdempotencyDisposition::Terminal(duplicate), Some(read)) => {
            assert!(binding.validate_terminal(read).is_ok());
            assert!(binding.validate_terminal(duplicate).is_ok());
        }
        (IdempotencyDisposition::InProgress { retry_after: None }, None) => {}
        _ => anyhow::bail!("unbounded lease changed durable disposition"),
    }
    Ok(())
}

pub(super) async fn remote_cases(
    config: PgConfig,
    holder_runtime: Arc<PgRuntime>,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    let waiter = Arc::new(
        PgRuntime::connect(
            config.with_pool_limits(0, 2),
            Timer::new(),
            fence_fixture::storage(),
        )
        .await?,
    );
    let policy = LeaseRenewalPolicy::from_ttl(Duration::from_secs(60))?;
    let holder = Peer::new(holder_runtime, policy)?;
    let waiting = Peer::new(waiter.clone(), policy)?;
    row_hint_cases(owner, &holder, &waiting.inbox).await?;
    for (id, action) in [
        ("window-remote-held", OwnerAction::Hold),
        ("window-remote-released", OwnerAction::Release),
        ("window-remote-terminal", OwnerAction::Commit),
    ] {
        remote_delivery(owner, &holder, &waiting, id, action).await?;
    }
    waiter.close().await;
    Ok(())
}

async fn row_hint_cases(
    owner: &sqlx::PgPool,
    holder: &Peer,
    waiting: &PgInboxStore,
) -> anyhow::Result<()> {
    let msg = message("window-hint");
    let binding = binding(&msg);
    let claim = holder.acquire(&binding).await?;
    verify_unbounded_lease(owner, waiting, &binding, false).await?;
    verify_row_hint(owner, waiting, &binding).await?;
    let committed = holder
        .tx
        .execute(&claim, &msg, binding.receipt_intent(), deadline())
        .await;
    assert_eq!(committed.status(), rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::Committed);
    verify_unbounded_lease(owner, waiting, &binding, true).await
}

struct Peer {
    inbox: PgInboxStore,
    tx: PgConsumerTx<Effect>,
}

impl Peer {
    fn new(runtime: Arc<PgRuntime>, policy: LeaseRenewalPolicy) -> anyhow::Result<Self> {
        Ok(Self {
            inbox: PgInboxStore::new(runtime.clone(), policy)?,
            tx: PgConsumerTx::receipt_only(runtime, Effect(TerminalDisposition::Succeeded)),
        })
    }

    async fn acquire(&self, binding: &VerifiedConsumerBinding) -> anyhow::Result<PgInboxClaim> {
        let permit = self
            .inbox
            .reserve_claim(binding.execution(), binding.identity(), deadline())?
            .acquire()
            .await?;
        match self.inbox.claim(permit).await? {
            IdempotencyDisposition::Acquired(claim) => Ok(claim),
            _ => anyhow::bail!("fixture owner must acquire"),
        }
    }

    async fn on_probe(
        &self,
        action: OwnerAction,
        claim: &mut Option<PgInboxClaim>,
        msg: &MessageEnvelope<Vec<u8>>,
        binding: &VerifiedConsumerBinding,
    ) -> anyhow::Result<()> {
        match action {
            OwnerAction::Release => {
                self.inbox
                    .release(claim.take().expect("single release"), deadline())
                    .await?
            }
            OwnerAction::Commit => {
                let committed = self
                    .tx
                    .execute(
                        claim.as_ref().expect("held"),
                        msg,
                        binding.receipt_intent(),
                        deadline(),
                    )
                    .await;
                assert_eq!(committed.status(), rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::Committed);
            }
            OwnerAction::Hold => {}
        }
        Ok(())
    }
}

async fn remote_delivery(
    owner: &sqlx::PgPool,
    holder: &Peer,
    waiting: &Peer,
    id: &str,
    action: OwnerAction,
) -> anyhow::Result<()> {
    let msg = message(id);
    let binding = binding(&msg);
    let sub = subscription(&msg);
    let claimed = holder.acquire(&binding).await?;
    let mut claim = Some(claimed);
    let before = claim_count(owner).await?;
    let clock = FakeClock::new();
    let origin = clock.now();
    let emitter = RemoteBusy(Notify::new());
    let policy = ConsumerExecutionPolicy::new(
        RetryPolicy::STANDARD,
        ExecutionBudget::STANDARD,
        RemoteClaimWaitPolicy::STANDARD,
    );
    let execution = ConsumerExecution::new(
        ConsumerGroup::parse("suite")?,
        &Validator,
        &sub,
        &clock,
        policy,
        &emitter,
    );
    let operation = policy.budget().total() - policy.budget().settlement_reserve();
    let schedule = probe_schedule(policy.remote_claim_wait(), operation);
    // Release midway or commit just before the last probe observes the durable result.
    let change_at = match action {
        OwnerAction::Hold => None,
        OwnerAction::Release => Some(schedule.len() / 2),
        OwnerAction::Commit => Some(schedule.len() - 1),
    };
    let recorder = RecordingSettlement::new();
    let processing = consume_once(
        &waiting.inbox,
        &waiting.tx,
        &execution,
        Delivery::new(msg.clone(), recorder.clone()),
    );
    tokio::pin!(processing);
    let mut probes = 0;
    let outcome = loop {
        tokio::select! {
            result = &mut processing => break result?,
            () = emitter.0.notified() => {}
        }
        probes += 1;
        assert!(probes <= schedule.len());
        if change_at == Some(probes) {
            holder.on_probe(action, &mut claim, &msg, &binding).await?;
        }
        let next = schedule.get(probes).copied().unwrap_or(operation);
        clock.advance(next - clock.now().saturating_duration_since(origin))?;
    };
    let claims = claim_count(owner).await? - before;
    assert_eq!(
        claims as usize,
        change_at.map_or(schedule.len(), |busy| busy + 1)
    );
    check_result(action, count(owner, id).await, outcome, &recorder);
    Ok(())
}

// Step to the upper edge of each jitter interval so SQL counts are deterministic.
fn probe_schedule(policy: RemoteClaimWaitPolicy, operation: Duration) -> Vec<Duration> {
    let latest = operation - policy.final_window(operation);
    let mut schedule = vec![Duration::ZERO];
    let mut at = Duration::ZERO;
    let mut base = policy.initial_base();
    while at < latest {
        at = (at + base * 2).min(latest);
        schedule.push(at);
        base = (base * 2).min(policy.max_base());
    }
    schedule
}

fn check_result(
    action: OwnerAction,
    effects: i64,
    outcome: ProcessingDisposition,
    recorder: &RecordingSettlement,
) {
    let expected = match action {
        OwnerAction::Hold => {
            assert_eq!(effects, 0);
            assert_eq!(recorder.settlements(), [SettlementKind::Requeue]);
            ProcessingDisposition::InProgress
        }
        OwnerAction::Release | OwnerAction::Commit => {
            assert_eq!(effects, 1);
            assert_eq!(recorder.settlements(), [SettlementKind::Acknowledge]);
            if matches!(action, OwnerAction::Release) {
                ProcessingDisposition::Committed(TerminalDisposition::Succeeded)
            } else {
                ProcessingDisposition::Duplicate(TerminalDisposition::Succeeded)
            }
        }
    };
    assert_eq!(outcome, expected);
    assert_eq!(recorder.abandon_count(), 0);
}
