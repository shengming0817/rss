//! A confirmed broker receipt retains its original database lease across allocator contention.
use super::*;
use rss_transactional_messaging::error::MessagingErrorKind;

pub(super) async fn run(
    runtime: Arc<PgRuntime>,
    raw: &PgPool,
    owner: &PgPool,
) -> anyhow::Result<()> {
    // Sequence visibility survives rollback and witnesses that real settlement reached UPDATE.
    sqlx::raw_sql("CREATE SEQUENCE public.settle_seen; CREATE FUNCTION public.observe_confirmed() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN PERFORM nextval('public.settle_seen');
        IF NEW.message_id='confirmed-OtherLock' THEN RAISE EXCEPTION 'fixture busy' USING ERRCODE='55P03',CONSTRAINT='other_lock'; END IF;
        RETURN NEW; END $$;
        CREATE TRIGGER observe_confirmed BEFORE UPDATE OF status ON rss_transactional_messaging.outbox
        FOR EACH ROW WHEN (OLD.domain='confirmed-relay' AND NEW.status='published') EXECUTE FUNCTION public.observe_confirmed()")
        .execute(owner).await?;
    let store = PgOutboxStore::<()>::new(
        runtime.clone(),
        MessagingDomain::parse("confirmed-relay")?,
        outbox_budget(Duration::from_secs(30)),
    )?;
    for mode in [
        Mode::Release,
        Mode::Expiry,
        Mode::Deadline,
        Mode::RollbackFailed,
        Mode::OtherLock,
        Mode::UnknownCommit,
    ] {
        scenario(&runtime, &store, raw, owner, mode).await?;
    }
    sqlx::raw_sql("DROP TRIGGER observe_confirmed ON rss_transactional_messaging.outbox; DROP FUNCTION public.observe_confirmed(); DROP SEQUENCE public.settle_seen").execute(owner).await?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Release,
    Expiry,
    Deadline,
    RollbackFailed,
    OtherLock,
    UnknownCommit,
}

async fn claimed(
    store: &PgOutboxStore<()>,
    raw: &PgPool,
    name: &str,
) -> anyhow::Result<PgOutboxClaim> {
    let message = ordered(name, "confirmed-relay", name);
    let tenant = message.metadata().tenant_id();
    let mut seed = sql_tx(raw, tenant).await?;
    sql_prepare(&mut seed, serde_json::json!([["confirmed-relay", name]])).await?;
    sql_append(&mut seed, &message).await?;
    seed.commit().await?;
    let claim = store
        .claim_partition_heads(crate::execution(tenant, 1), NonZeroUsize::MIN, deadline())
        .await?
        .into_iter()
        .next()
        .expect("fresh claim");
    assert_eq!(
        PgOutboxStore::<()>::message(&claim).message_id().as_str(),
        name
    );
    Ok(claim)
}

async fn wait_for_attempt(owner: &PgPool) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if sqlx::query_scalar::<_, bool>("SELECT is_called FROM public.settle_seen")
                .fetch_one(owner)
                .await?
            {
                return anyhow::Ok(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    Ok(())
}

async fn scenario(
    runtime: &PgRuntime,
    store: &PgOutboxStore<()>,
    raw: &PgPool,
    owner: &PgPool,
    mode: Mode,
) -> anyhow::Result<()> {
    let name = format!("confirmed-{mode:?}");
    let tenant = message(&name).metadata().tenant_id();
    let claim = claimed(store, raw, &name).await?;
    let mut writer = sql_tx(raw, tenant).await?;
    if mode != Mode::UnknownCommit {
        sql_prepare(&mut writer, serde_json::json!([["confirmed-relay", name]])).await?;
    }
    if mode == Mode::UnknownCommit {
        runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    }
    sqlx::query("SELECT setval('public.settle_seen',1,false)")
        .execute(owner)
        .await?;
    if mode == Mode::RollbackFailed {
        runtime.inject_next_transaction_fault(PgTransactionFault::RollbackFailedAfterAck);
    }
    let budget = if mode == Mode::Deadline {
        OperationDeadline::from_remaining(Duration::from_millis(150))
    } else {
        deadline()
    };
    let operation = store.settle(claim, OutboxSettlement::Published(()), budget);
    let result = match mode {
        Mode::Release | Mode::Expiry => {
            let release = async {
                wait_for_attempt(owner).await?;
                if mode == Mode::Expiry {
                    sqlx::query("UPDATE rss_transactional_messaging.outbox SET lease_until=clock_timestamp() WHERE message_id=$1")
                        .bind(&name).execute(owner).await?;
                }
                writer.commit().await?;
                anyhow::Ok(())
            };
            let (result, released) = tokio::join!(operation, release);
            released?;
            result
        }
        _ => {
            let result = operation.await;
            writer.rollback().await?;
            result
        }
    };
    assert_result(owner, &name, mode, result.err().map(|e| e.kind())).await
}

async fn assert_result(
    owner: &PgPool,
    name: &str,
    mode: Mode,
    kind: Option<MessagingErrorKind>,
) -> anyhow::Result<()> {
    let expected = match mode {
        Mode::Release => None,
        Mode::Expiry => Some(MessagingErrorKind::OwnershipLost),
        Mode::Deadline => Some(MessagingErrorKind::DeadlineElapsed),
        Mode::RollbackFailed | Mode::OtherLock | Mode::UnknownCommit => {
            Some(MessagingErrorKind::Transient)
        }
    };
    assert_eq!(kind, expected);
    let status: String = sqlx::query_scalar(
        "SELECT status FROM rss_transactional_messaging.outbox WHERE message_id=$1",
    )
    .bind(name)
    .fetch_one(owner)
    .await?;
    assert_eq!(
        status,
        if matches!(mode, Mode::Release | Mode::UnknownCommit) {
            "published"
        } else {
            "publishing"
        }
    );
    if matches!(
        mode,
        Mode::OtherLock | Mode::UnknownCommit | Mode::RollbackFailed
    ) {
        let attempts: i64 = sqlx::query_scalar(
            "SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM public.settle_seen",
        )
        .fetch_one(owner)
        .await?;
        assert_eq!(attempts, 1);
    }
    // Isolate the next scenario from this deliberately expired retained claim.
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='resolved',lease_token=NULL,lease_until=NULL WHERE message_id=$1 AND status='publishing'").bind(name).execute(owner).await?;
    Ok(())
}
