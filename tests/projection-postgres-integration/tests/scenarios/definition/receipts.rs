use super::*;

pub(super) async fn queries(
    store: &PgStore,
    owner: &PgPool,
    scope: &ProjectionScope,
    definition: DefinitionIdentity,
    wrong: DefinitionIdentity,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    use rss_projection::ReceiptQuery;
    let before = state(owner, scope).await?;
    let query = ReceiptQuery::new(scope.clone(), definition, "one")?;
    let observed = store.receipt_status(&query, control).await?;
    let expected = Checkpoint {
        position: Some(Position::new(0)?),
        bound: ReplayBound::Live,
    };
    assert_eq!(observed, ReceiptStatus::Settled(expected));
    assert_eq!(observed.checkpoint(), Some(expected));
    let pending = store
        .receipt_status(
            &ReceiptQuery::new(scope.clone(), definition, "absent")?,
            control,
        )
        .await?;
    assert_eq!(pending, ReceiptStatus::Pending(expected));
    assert_eq!(pending.checkpoint(), Some(expected));
    absent_scopes(store, scope, definition, control).await?;
    interruptions(store, owner, &query).await?;
    settlement(store, &query, wrong, control).await?;
    assert_eq!(
        store
            .receipt_status(&ReceiptQuery::new(scope.clone(), wrong, "one")?, control)
            .await,
        Err(ErrorKind::Conflict.into())
    );
    assert_eq!(
        before,
        state(owner, scope).await?,
        "receipt query changed worker ownership"
    );
    Ok(())
}

async fn absent_scopes(
    store: &PgStore,
    scope: &ProjectionScope,
    definition: DefinitionIdentity,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    for other in [
        ProjectionScope::new(
            SourceScope::new(TenantId::parse(OTHER)?, scope.source().source())?,
            scope.projection(),
            scope.generation(),
        )?,
        ProjectionScope::new(
            SourceScope::new(scope.source().tenant(), "other-source")?,
            scope.projection(),
            scope.generation(),
        )?,
        ProjectionScope::new(
            scope.source().clone(),
            "other-projection",
            scope.generation(),
        )?,
        ProjectionScope::new(
            scope.source().clone(),
            scope.projection(),
            "other-generation",
        )?,
    ] {
        let absent = store
            .receipt_status(&ReceiptQuery::new(other, definition, "one")?, control)
            .await?;
        assert_eq!(absent, ReceiptStatus::Uninitialized);
        assert_eq!(absent.checkpoint(), None);
    }
    Ok(())
}

struct TriggeredDeadline(CancellationToken);
impl Timer for TriggeredDeadline {
    fn now(&self) -> Duration {
        Duration::ZERO
    }
    async fn sleep_until(&self, _: Duration) {
        self.0.cancelled().await;
    }
}

async fn interruptions(
    store: &PgStore,
    owner: &PgPool,
    query: &ReceiptQuery,
) -> anyhow::Result<()> {
    for expected in [ErrorKind::Cancelled, ErrorKind::Deadline] {
        let cancel = CancellationToken::new();
        let timer = TriggeredDeadline(CancellationToken::new());
        let control = Control::new(&timer, Duration::from_secs(30), &cancel);
        store.inject_next_fault(PgFault::CommitPending);
        let interrupt = async {
            let pid = loop {
                let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='projection_runtime' AND state='idle in transaction' AND query LIKE 'SELECT c.definition_identity%AS settled%'")
                    .fetch_optional(owner).await?;
                if let Some(pid) = pid {
                    break pid;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            };
            if expected == ErrorKind::Cancelled {
                cancel.cancel();
            } else {
                timer.0.cancel();
            }
            Ok::<_, anyhow::Error>(pid)
        };
        let (result, pid) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(store.receipt_status(query, &control), interrupt)
        })
        .await?;
        assert_eq!(result, Err(expected.into()));
        let pid = pid?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
            )
            .bind(pid)
            .fetch_one(owner)
            .await?
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
    }
    Ok(())
}

async fn settlement(
    store: &PgStore,
    query: &ReceiptQuery,
    wrong: DefinitionIdentity,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    store.inject_next_fault(PgFault::CommitUnknownAfterAck);
    assert_eq!(
        store.receipt_status(query, control).await,
        Err(ErrorKind::Unavailable.into())
    );
    store.inject_next_fault(PgFault::RollbackFailedAfterAck);
    let wrong = ReceiptQuery::new(query.scope().clone(), wrong, query.event_id())?;
    assert_eq!(
        store.receipt_status(&wrong, control).await,
        Err(ErrorKind::Unavailable.into())
    );
    assert!(store.receipt_status(query, control).await?.is_settled());
    Ok(())
}
