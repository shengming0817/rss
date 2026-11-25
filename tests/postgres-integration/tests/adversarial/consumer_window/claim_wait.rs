use super::*;
use rss_request_context::{Clock, Deadline, ExecutionTimer};
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
        ConsumerExecutionPolicy::new(RetryPolicy::STANDARD, ExecutionBudget::STANDARD),
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

// Poll the delivery and this observer on one task. After an InProgress observation
// the delivery has registered its probe sleep before control returns to the driver.
struct ProbeClock {
    timer: FakeClock,
    wake: Mutex<Option<Deadline>>,
}
impl Clock for ProbeClock {
    fn now(&self) -> std::time::Instant {
        self.timer.now()
    }
}
impl ExecutionTimer for ProbeClock {
    async fn sleep_until(&self, deadline: Deadline) {
        *self.wake.lock().expect("probe deadline") = Some(deadline);
        self.timer.sleep_until(deadline).await;
    }
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
    let holder_inbox = PgInboxStore::new(holder_runtime.clone(), policy)?;
    let waiter_inbox = PgInboxStore::new(waiter.clone(), policy)?;
    let holder_tx =
        PgConsumerTx::receipt_only(holder_runtime, Effect(TerminalDisposition::Succeeded));
    let waiter_tx =
        PgConsumerTx::receipt_only(waiter.clone(), Effect(TerminalDisposition::Succeeded));

    for (id, action) in [
        ("window-remote-held", OwnerAction::Hold),
        ("window-remote-released", OwnerAction::Release),
        ("window-remote-terminal", OwnerAction::Commit),
    ] {
        let msg = message(id);
        let binding = binding(&msg);
        let sub = subscription(&msg);
        let permit = holder_inbox
            .reserve_claim(binding.execution(), binding.identity(), deadline())?
            .acquire()
            .await?;
        let IdempotencyDisposition::Acquired(holder) = holder_inbox.claim(permit).await? else {
            anyhow::bail!("fixture owner must acquire");
        };
        let mut holder = Some(holder);
        let before = claim_count(owner).await?;
        let clock = ProbeClock {
            timer: FakeClock::new(),
            wake: Mutex::new(None),
        };
        let emitter = RemoteBusy(Notify::new());
        let execution = ConsumerExecution::new(
            ConsumerGroup::parse("suite")?,
            &Validator,
            &sub,
            &clock,
            ConsumerExecutionPolicy::new(RetryPolicy::STANDARD, ExecutionBudget::STANDARD),
            &emitter,
        );
        let recorder = RecordingSettlement::new();
        let processing = consume_once(
            &waiter_inbox,
            &waiter_tx,
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
            assert!(probes <= 16);
            match action {
                OwnerAction::Hold => {}
                OwnerAction::Release if probes == 10 => {
                    holder_inbox
                        .release(holder.take().expect("single release"), deadline())
                        .await?
                }
                OwnerAction::Commit => {
                    let committed = holder_tx
                        .execute(
                            holder.as_ref().expect("held"),
                            &msg,
                            binding.receipt_intent(),
                            deadline(),
                        )
                        .await;
                    assert_eq!(committed.status(), rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::Committed);
                }
                OwnerAction::Release => {}
            }
            let wake = clock
                .wake
                .lock()
                .expect("probe clock")
                .take()
                .expect("registered probe");
            clock
                .timer
                .advance(wake.remaining(clock.now()).unwrap_or_default())?;
        };
        let claims = claim_count(owner).await? - before;
        let expected = match action {
            OwnerAction::Hold => {
                assert!((12..=16).contains(&claims));
                assert_eq!(count(owner, id).await, 0);
                assert_eq!(recorder.settlements(), [SettlementKind::Requeue]);
                ProcessingDisposition::InProgress
            }
            OwnerAction::Release | OwnerAction::Commit => {
                assert_eq!(
                    claims,
                    if matches!(action, OwnerAction::Release) {
                        11
                    } else {
                        2
                    }
                );
                assert_eq!(count(owner, id).await, 1);
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
    waiter.close().await;
    Ok(())
}
