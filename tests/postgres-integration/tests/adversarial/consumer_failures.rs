use super::*;
use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus as Status;

#[derive(Clone, Copy)]
enum Mode {
    Handler,
    Infrastructure,
    Pending,
}
struct FailingEffect {
    mode: Mode,
    pid: Arc<AtomicI32>,
    entered: Arc<Notify>,
}
impl PgConsumerEffect<Vec<u8>> for FailingEffect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &MessageEnvelope<Vec<u8>>,
        deadline: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        Effect(TerminalDisposition::Succeeded)
            .apply(tx, message, deadline)
            .await?;
        let pid = tx
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        self.pid.store(pid, Ordering::SeqCst);
        self.entered.notify_one();
        match self.mode {
            Mode::Handler => Err(PgConsumerEffectFailure::handler_transient(
                std::io::Error::other("handler failure"),
            )),
            Mode::Infrastructure => Err(PgConsumerEffectFailure::infrastructure(
                std::io::Error::other("infrastructure failure"),
            )),
            Mode::Pending => std::future::pending().await,
        }
    }
}
#[allow(clippy::cognitive_complexity)]
// reason: keep each fault mode beside its outcome, durable-state and connection-state assertions.
pub(super) async fn run(runtime: Arc<PgRuntime>, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    let inbox = PgInboxStore::new(
        runtime.clone(),
        rss_transactional_messaging::policy::LeaseRenewalPolicy::from_ttl(Duration::from_secs(60))?,
    )?;
    for (id, mode, failed_rollback, expected) in [
        (
            "consumer-handler-failure",
            Mode::Handler,
            false,
            Status::HandlerTransient,
        ),
        (
            "consumer-infra-failure",
            Mode::Infrastructure,
            false,
            Status::InfrastructureTransient,
        ),
        (
            "consumer-rollback-failed",
            Mode::Handler,
            true,
            Status::RollbackFailed,
        ),
    ] {
        let message = message(id);
        let binding = binding(&message);
        let IdempotencyDisposition::Acquired(claim) =
            inbox.claim(binding.identity(), deadline()).await?
        else {
            panic!("new claim")
        };
        let pid = Arc::new(AtomicI32::new(0));
        let consumer = PgConsumerTx::new(
            runtime.clone(),
            FailingEffect {
                mode,
                pid: pid.clone(),
                entered: Arc::new(Notify::new()),
            },
        );
        if failed_rollback {
            runtime.inject_next_transaction_fault(PgTransactionFault::RollbackFailedAfterAck);
        }
        let outcome = consumer
            .execute(&claim, &message, binding.receipt_intent(), deadline())
            .await;
        assert_eq!(outcome.status(), expected);
        assert_eq!(
            outcome.may_retry(),
            matches!(expected, Status::HandlerTransient)
        );
        assert_eq!(count(owner, id).await, 0);
        assert!(
            inbox
                .read_terminal(binding.identity(), deadline())
                .await?
                .is_none()
        );
        if failed_rollback {
            connection_gone(owner, pid.load(Ordering::SeqCst)).await;
        }
    }
    for cancel in [true, false] {
        let id = if cancel {
            "consumer-cancel"
        } else {
            "consumer-timeout"
        };
        let message = message(id);
        let binding = binding(&message);
        let identity = binding.identity().clone();
        let IdempotencyDisposition::Acquired(claim) = inbox.claim(&identity, deadline()).await?
        else {
            panic!("new claim")
        };
        let pid = Arc::new(AtomicI32::new(0));
        let entered = Arc::new(Notify::new());
        let consumer = PgConsumerTx::new(
            runtime.clone(),
            FailingEffect {
                mode: Mode::Pending,
                pid: pid.clone(),
                entered: entered.clone(),
            },
        );
        let task = tokio::spawn(async move {
            let clock = Timer::new();
            let bound = AbsoluteDeadline::from_timeout(&clock, Duration::from_millis(150))
                .expect("deadline")
                .operation(&clock);
            consumer
                .execute(&claim, &message, binding.receipt_intent(), bound)
                .await
        });
        entered.notified().await;
        if cancel {
            task.abort();
            assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        } else {
            assert_eq!(task.await?.status(), Status::CommitUnknown);
        }
        connection_gone(owner, pid.load(Ordering::SeqCst)).await;
        assert_eq!(count(owner, id).await, 0);
        assert!(inbox.read_terminal(&identity, deadline()).await?.is_none());
    }
    Ok(())
}
