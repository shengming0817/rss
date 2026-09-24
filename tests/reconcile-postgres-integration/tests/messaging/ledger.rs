use super::*;
use rss_ledger::{AppendRequest, Authenticator, ChainId, KeyId, LedgerId, RecordId};
use rss_transactional_messaging::{policy::OperationDeadline, transaction::LocalTxAttempt};
use tokio::sync::Notify;

pub(super) fn auth() -> anyhow::Result<Arc<Authenticator>> {
    Ok(Arc::new(Authenticator::new(
        KeyId::parse("composition-fixture")?,
        vec![42; 32],
    )?))
}
pub(super) fn request(chain: &str, id: &str) -> anyhow::Result<AppendRequest> {
    Ok(AppendRequest::new(
        LedgerId::new(TenantId::parse(TENANT)?, ChainId::parse(chain)?),
        RecordId::parse(id)?,
        id.as_bytes().to_vec(),
    )?)
}
pub(super) async fn install(owner: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE ROLE composition_ledger_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; GRANT CREATE ON DATABASE rss_test TO composition_ledger_owner;").execute(owner).await?;
    let mut tx = owner.begin().await?;
    sqlx::query("SET LOCAL ROLE composition_ledger_owner")
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql(rss_ledger_postgres::MIGRATION_SQL)
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_ledger TO reconcile_runtime; GRANT SELECT ON rss_ledger.heads,rss_ledger.entries TO reconcile_runtime; GRANT EXECUTE ON FUNCTION rss_ledger.prepare_append(uuid,text,text,smallint),rss_ledger.insert_entry(uuid,text,text,bigint,bytea,bytea,bytea,text,smallint) TO reconcile_runtime;").execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
pub(super) async fn verify(owner: &PgPool, chain: &str, committed: bool) -> anyhow::Result<()> {
    let counts: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM rss_ledger.heads WHERE chain_id=$1),(SELECT count(*) FROM rss_ledger.entries WHERE chain_id=$1)")
        .bind(chain).fetch_one(owner).await?;
    assert_eq!(counts, (i64::from(committed), i64::from(committed)));
    Ok(())
}
pub(super) async fn competition(
    store: &PgStore,
    owner: &PgPool,
    runtime: &Arc<PgRuntime>,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    for timed_out in [false, true] {
        competing_pair(store, owner, runtime, control, timed_out).await?;
    }
    Ok(())
}
async fn competing_pair(
    store: &PgStore,
    owner: &PgPool,
    runtime: &Arc<PgRuntime>,
    control: &Control<'_, Clock>,
    timed_out: bool,
) -> anyhow::Result<()> {
    let chain = format!("ordered-competition-{timed_out}");
    let target = target(&chain, TENANT)?;
    store.wake(&target, control).await?;
    let claim = Arc::new(claim(store, &target, Duration::from_secs(10), control).await?);
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let first = tokio::spawn(guarded(
        runtime.clone(),
        claim.clone(),
        request(&chain, "first")?,
        Some((entered.clone(), release.clone())),
        Duration::from_secs(5),
    ));
    tokio::time::timeout(Duration::from_secs(2), entered.notified()).await?;
    let second = tokio::spawn(guarded(
        runtime.clone(),
        claim,
        request(&chain, "second")?,
        None,
        if timed_out {
            Duration::from_millis(500)
        } else {
            Duration::from_secs(5)
        },
    ));
    // Observe the real prepare_append row-lock wait while the first claim is also held.
    wait_for_ledger(owner).await?;
    if timed_out {
        let status = tokio::time::timeout(Duration::from_secs(2), second).await???;
        // The owner can conservatively report CommitUnknown at its cutoff. Never
        // turn that result into rollback proof; check durable state separately below.
        assert!(
            matches!(status, "rolled-back" | "rollback-failed" | "unknown"),
            "timeout outcome: {status}"
        );
        release.notify_one();
    } else {
        release.notify_one();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), second).await???,
            "committed"
        );
    }
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), first).await???,
        "committed"
    );
    verify_competition(owner, &chain, timed_out).await
}
async fn verify_competition(owner: &PgPool, chain: &str, timed_out: bool) -> anyhow::Result<()> {
    let (seq, entries): (i64, i64) = sqlx::query_as("SELECT (SELECT seq FROM rss_ledger.heads WHERE chain_id=$1),(SELECT count(*) FROM rss_ledger.entries WHERE chain_id=$1)").bind(chain).fetch_one(owner).await?;
    assert_eq!((seq, entries), if timed_out { (0, 1) } else { (1, 2) });
    let state: String =
        sqlx::query_scalar("SELECT result FROM rss_reconcile.targets WHERE reconciler=$1")
            .bind(chain)
            .fetch_one(owner)
            .await?;
    assert_eq!(state, "applied");
    Ok(())
}
async fn wait_for_ledger(owner: &PgPool) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='reconcile_runtime' AND wait_event_type='Lock' AND query LIKE '%rss_ledger.prepare_append%')").fetch_one(owner).await?;
            if blocked { return Ok::<_, sqlx::Error>(()); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await??;
    Ok(())
}
async fn guarded(
    runtime: Arc<PgRuntime>,
    claim: Arc<PgClaim>,
    request: AppendRequest,
    hold: Option<(Arc<Notify>, Arc<Notify>)>,
    budget: Duration,
) -> anyhow::Result<&'static str> {
    let result: LocalTxAttempt<(), PgError> = runtime
        .local_tx_with_context(
            TenantId::parse(TENANT)?,
            OperationDeadline::from_remaining(budget),
            (claim, request, hold, auth()?),
            |(claim, request, hold, auth), tx| {
                Box::pin(async move {
                    rss_ledger_postgres::lock_head_in(tx, auth.clone(), request.ledger())
                        .await
                        .map_err(PgError::from)?;
                    rss_reconcile_postgres::messaging::protect_in(
                        tx,
                        claim.as_ref(),
                        (request, hold, auth),
                        |(request, hold, auth), tx| {
                            Box::pin(async move {
                                rss_ledger_postgres::append_in(tx, (*auth).clone(), request)
                                    .await
                                    .map_err(PgError::from)?;
                                if let Some((entered, release)) = hold {
                                    entered.notify_one();
                                    release.notified().await;
                                }
                                Ok(())
                            })
                        },
                    )
                    .await
                })
            },
        )
        .await;
    Ok(result.fold(
        |()| "committed",
        |_| "not-started",
        |_| "rolled-back",
        |_| "rollback-failed",
        |_| "unknown",
        |_| "fenced",
    ))
}
