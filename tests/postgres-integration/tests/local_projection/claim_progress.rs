//! Successful but partially consumed windows must preserve the entrance of the sweep.
use super::*;
use rss_request_context::Clock;
use rss_transactional_messaging::observability::{
    TransactionalMessagingEmitter, TransactionalMessagingObservation,
    TransactionalMessagingRelayPhase,
};
use rss_transactional_messaging::outbox::{OutboxRelayStore, OutboxScanProgress};
use rss_transactional_messaging_runtime::relay::{RelayConfig, RelayWorker};
use rss_transactional_messaging_testkit::memory::FakeClock;
use std::collections::HashSet;

struct ClaimTimes(
    FakeClock,
    tokio::sync::mpsc::UnboundedSender<std::time::Instant>,
);
impl TransactionalMessagingEmitter for ClaimTimes {
    fn emit(&self, event: TransactionalMessagingObservation) {
        if let TransactionalMessagingObservation::RelayTick {
            phase: TransactionalMessagingRelayPhase::Claim,
            duration,
        } = event
        {
            let _ = self.1.send(self.0.now() - duration);
        }
    }
}

async fn idle_worker(store: Arc<PgOutboxStore<()>>) -> anyhow::Result<()> {
    let clock = FakeClock::new();
    let origin = clock.now();
    let (tx, mut times) = tokio::sync::mpsc::unbounded_channel();
    let (publisher, _published) = tokio::sync::mpsc::unbounded_channel();
    let worker = RelayWorker::new(
        store,
        Arc::new(scale::Published(publisher)),
        Arc::new(clock.clone()),
        Arc::new(ClaimTimes(clock.clone(), tx)),
        RelayConfig::new(
            32usize.try_into()?,
            32usize.try_into()?,
            Duration::from_secs(30),
            Duration::from_secs(1),
        )?,
    );
    let stop = tokio_util::sync::CancellationToken::new();
    let run = worker.run(crate::execution(tenant(), 1), stop.clone());
    tokio::pin!(run);
    for expected in [0, 30] {
        tokio::select! {
            result=&mut run => anyhow::bail!("early worker termination: {result:?}"),
            stamp=times.recv()=>assert_eq!(stamp,Some(origin+Duration::from_secs(expected))),
            ()=tokio::time::sleep(Duration::from_secs(5))=>anyhow::bail!("PG claim did not complete"),
        }
        if expected == 0 {
            clock.advance(Duration::from_millis(1200))?;
            assert!(futures::poll!(&mut run).is_pending());
            assert!(times.try_recv().is_err());
            clock.advance(Duration::from_millis(28800))?;
        }
    }
    stop.cancel();
    run.await?;
    Ok(())
}

async fn append(f: &Fixture, prefix: &str, first: usize, end: usize) -> anyhow::Result<()> {
    for base in (first..end).step_by(500) {
        let bodies = (base..end.min(base + 500))
            .map(|n| Ok(message(&format!("{prefix}-{n}"), "orders")?.canonical_bytes()))
            .collect::<anyhow::Result<Vec<_>>>()?;
        sqlx::query("SELECT rss_transactional_messaging.append_outbox(body,$2) FROM unnest($1::bytea[]) body")
            .bind(bodies).bind(serde_json::json!({"trace":null,"tenant_authority":null})).execute(&f.owner).await?;
    }
    Ok(())
}

async fn lease_prefix(f: &Fixture, start: usize, end: usize) -> anyhow::Result<()> {
    append(f, "live-prefix", start, end).await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='publishing', retry_after=statement_timestamp()-interval '1 day',lease_until=statement_timestamp()+interval '1 hour',lease_token=gen_random_uuid(),automatic_retry_deadline=statement_timestamp()+interval '1 day' WHERE message_id LIKE 'live-prefix-%' AND status='pending'").execute(&f.owner).await?;
    sqlx::query("ANALYZE rss_transactional_messaging.outbox")
        .execute(&f.owner)
        .await?;
    Ok(())
}

async fn snapshot(f: &Fixture) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar("SELECT md5(string_agg(ROW(seq,status,claim_epoch,claim_lineage,lease_token,lease_until)::text,',' ORDER BY seq)) FROM rss_transactional_messaging.outbox WHERE message_id LIKE 'live-prefix-%'").fetch_one(&f.owner).await?)
}

async fn tail(
    store: &PgOutboxStore<()>,
    expected: &[(usize, usize)],
    count: usize,
) -> anyhow::Result<()> {
    let wanted = (0..count)
        .map(|n| format!("eligible-tail-{n}"))
        .collect::<HashSet<_>>();
    let mut ids = HashSet::new();
    let mut hits = Vec::new();
    let timer = Timer::new();
    let started = timer.now();
    for call in 1..=expected
        .last()
        .ok_or_else(|| anyhow::anyhow!("missing expected hit"))?
        .0
    {
        let batch = store
            .claim_partition_heads(
                crate::execution(tenant(), 1),
                32usize.try_into()?,
                deadline(),
            )
            .await?;
        if batch.is_empty() {
            assert_eq!(batch.scan_progress(), OutboxScanProgress::Continue);
        } else {
            if hits.is_empty() {
                println!(
                    "first eligible claim after {call} calls in {:?}",
                    timer.now() - started
                );
            }
            hits.push((call, batch.len()));
        }
        for claim in batch {
            assert!(
                ids.insert(
                    PgOutboxStore::<()>::message(&claim)
                        .message_id()
                        .as_str()
                        .to_owned()
                )
            );
        }
    }
    assert_eq!(hits, expected);
    assert_eq!(ids, wanted);
    Ok(())
}

async fn reset_tail(f: &Fixture) -> anyhow::Result<()> {
    // Reverse eligibility order relative to source lock order inside the window.
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='pending',lease_token=NULL,lease_until=NULL,retry_after=statement_timestamp()-seq*interval '1 microsecond' WHERE message_id LIKE 'eligible-tail-%'").execute(&f.owner).await?;
    Ok(())
}

pub(super) async fn run(f: &Fixture) -> anyhow::Result<()> {
    let store = Arc::new(PgOutboxStore::<()>::new(
        f.worker.clone(),
        domain()?,
        DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )?,
    )?);
    all_leased(f, store.clone()).await?;
    lease_prefix(f, 128, 10_000).await?;
    scale::install_explain(f).await?;
    scale::explain(f, "10,000 live leases in the current generation").await?;
    let original = snapshot(f).await?;
    current_generation(f, &store).await?;
    mixed_generation(f, store.clone()).await?;
    late_generation(f, &store).await?;
    assert_eq!(snapshot(f).await?, original);
    sqlx::query("DELETE FROM rss_transactional_messaging.outbox WHERE message_id LIKE 'live-prefix-%' OR message_id LIKE 'eligible-tail-%' OR message_id LIKE 'future-history-%'").execute(&f.owner).await?;
    Ok(())
}

async fn all_leased(f: &Fixture, store: Arc<PgOutboxStore<()>>) -> anyhow::Result<()> {
    lease_prefix(f, 0, 128).await?;
    for _ in 0..12 {
        let batch = store
            .claim_partition_heads(
                crate::execution(tenant(), 1),
                32usize.try_into()?,
                deadline(),
            )
            .await?;
        assert!(batch.is_empty());
        assert_eq!(batch.scan_progress(), OutboxScanProgress::Complete);
    }
    let cursors: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.outbox_scan WHERE domain='orders'",
    )
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(cursors, 0);
    idle_worker(store).await
}

async fn mixed_generation(f: &Fixture, store: Arc<PgOutboxStore<()>>) -> anyhow::Result<()> {
    append(f, "future-history", 0, 1).await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='publishing',lease_token=gen_random_uuid(),lease_until=clock_timestamp()+interval '1 hour',retry_after=clock_timestamp()+interval '1 day' WHERE message_id='future-history-0'").execute(&f.owner).await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET claim_lineage=decode(repeat('03',16),'hex') WHERE message_id='future-history-0'").execute(&f.owner).await?;
    reset_tail(f).await?;
    tail(&store, &[(1, 32), (2, 32), (3, 1)], 65).await?;
    idle_worker(store.clone()).await?;
    scale::explain(f, "empty mixed generation with a future retry").await?;
    reset_tail(f).await?;
    // A genuinely due historical source after the live prefix, held by another
    // transaction, keeps the bounded scan active while the 65 unlocked items drain.
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET retry_after=statement_timestamp()-interval '1 hour' WHERE message_id='future-history-0'").execute(&f.owner).await?;
    let mut source_lock = f.owner.begin().await?;
    sqlx::query("SELECT seq FROM rss_transactional_messaging.outbox WHERE message_id='future-history-0' FOR UPDATE").execute(&mut *source_lock).await?;
    contended_progress(f, &store).await?;
    tail(&store, &[(79, 32), (80, 32), (81, 1)], 65).await?;
    source_lock.rollback().await?;
    Ok(())
}

// More distinct generations than the fixed index-probe budget. A due generation
// outside the probe must still be discovered; speculative empty pages are paced.
async fn late_generation(f: &Fixture, store: &PgOutboxStore<()>) -> anyhow::Result<()> {
    append(f, "future-history", 1, 7).await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='publishing',lease_token=gen_random_uuid(),lease_until=statement_timestamp()+interval '1 hour',retry_after=statement_timestamp()+interval '1 day',automatic_retry_deadline=statement_timestamp()+interval '1 day' WHERE message_id LIKE 'future-history-%'").execute(&f.owner).await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET claim_epoch=2+split_part(message_id,'-',3)::bigint, retry_after=CASE WHEN message_id='future-history-6' THEN statement_timestamp()-interval '1 minute' ELSE retry_after END WHERE message_id LIKE 'future-history-%'").execute(&f.owner).await?;
    for call in 1..=81 {
        let batch = store
            .claim_partition_heads(
                crate::execution(tenant(), 1),
                32usize.try_into()?,
                deadline(),
            )
            .await?;
        if batch.is_empty() {
            assert_eq!(batch.scan_progress(), OutboxScanProgress::RetryLater);
        } else {
            assert!(call > 1);
            assert_eq!(batch.len(), 1);
            let claim = batch
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("missing historical claim"))?;
            assert_eq!(
                PgOutboxStore::<()>::message(&claim).message_id().as_str(),
                "future-history-6"
            );
            return Ok(());
        }
    }
    anyhow::bail!("historical head beyond the generation probe was starved")
}

async fn contended_progress(f: &Fixture, store: &PgOutboxStore<()>) -> anyhow::Result<()> {
    let mut held = f.raw_worker.begin().await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('rss-tmsg-claim:'||$1||':orders',0))",
    )
    .bind(tenant().to_string())
    .execute(&mut *held)
    .await?;
    let blocked = store
        .claim_partition_heads(
            crate::execution(tenant(), 1),
            32usize.try_into()?,
            deadline(),
        )
        .await?;
    assert!(blocked.is_empty());
    assert_eq!(blocked.scan_progress(), OutboxScanProgress::RetryLater);
    held.rollback().await?;

    Ok(())
}

async fn current_generation(f: &Fixture, store: &PgOutboxStore<()>) -> anyhow::Result<()> {
    append(f, "eligible-tail", 0, 1).await?;
    tail(store, &[(1, 1)], 1).await?;
    append(f, "eligible-tail", 1, 65).await?;
    reset_tail(f).await?;
    tail(store, &[(1, 32), (2, 32), (3, 1)], 65).await?;
    let empty = store
        .claim_partition_heads(
            crate::execution(tenant(), 1),
            32usize.try_into()?,
            deadline(),
        )
        .await?;
    assert!(empty.is_empty());
    assert_eq!(empty.scan_progress(), OutboxScanProgress::Complete);
    Ok(())
}
