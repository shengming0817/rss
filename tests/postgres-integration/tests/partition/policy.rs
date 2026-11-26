//! Frozen delivery deadlines and persistent retry schedules across a reconnect.
use super::*;

async fn now_us(pool: &PgPool) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(pool)
            .await?,
    )
}
async fn facts(pool: &PgPool, id: &str) -> anyhow::Result<(i64, i64, i32)> {
    Ok(sqlx::query_as("SELECT (extract(epoch FROM automatic_retry_deadline)*1000000)::bigint,
        (extract(epoch FROM retry_after)*1000000)::bigint,retry_count FROM rss_transactional_messaging.outbox WHERE message_id=$1")
        .bind(id).fetch_one(pool).await?)
}
async fn floors(pool: &PgPool) -> anyhow::Result<(i64, i64)> {
    Ok(sqlx::query_as("SELECT (extract(epoch FROM hot_floor_until)*1000000)::bigint,
        (extract(epoch FROM receipt_floor_until)*1000000)::bigint FROM rss_transactional_messaging.policy").fetch_one(pool).await?)
}
async fn claim(store: &PgOutboxStore<()>) -> anyhow::Result<PgOutboxClaim> {
    store
        .claim_partition_heads(
            crate::execution(crate::fixture_tenant(), 1),
            NonZeroUsize::MIN,
            deadline(),
        )
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("expected policy claim"))
}
async fn store(config: PgConfig, domain: &str) -> anyhow::Result<PgOutboxStore<()>> {
    let runtime = PgRuntime::connect(config, Timer::new(), fence_fixture::storage()).await?;
    Ok(PgOutboxStore::new(
        Arc::new(runtime),
        MessagingDomain::parse(domain)?,
        outbox_budget(Duration::from_secs(30)),
    )?
    .with_scan_budget(PgOutboxScanBudget::new(2)?))
}

async fn reject_invalid(owner: &PgPool) -> anyhow::Result<()> {
    for limit in [0, 1025] {
        assert!(PgOutboxScanBudget::new(limit).is_err());
    }
    for change in [
        "UPDATE rss_transactional_messaging.policy SET receipt_retention_seconds=172800",
        "UPDATE rss_transactional_messaging.policy SET retry_max_seconds=0",
        "UPDATE rss_transactional_messaging.policy SET safety_seconds=2147483647",
        "UPDATE rss_transactional_messaging.policy SET automatic_window_seconds=2147483648",
    ] {
        assert!(sqlx::query(change).execute(owner).await.is_err());
    }
    Ok(())
}
async fn seed(raw: &PgPool) -> anyhow::Result<()> {
    for lane in ["policy-first", "policy-second"] {
        let message = ordered(lane, lane, lane);
        let mut tx = sql_tx(raw, message.metadata().tenant_id()).await?;
        sql_prepare(&mut tx, serde_json::json!([[lane, lane]])).await?;
        sql_append(&mut tx, &message).await?;
        tx.commit().await?;
    }
    Ok(())
}
async fn change_policy(owner: &PgPool, before: i64) -> anyhow::Result<()> {
    sqlx::query("UPDATE rss_transactional_messaging.policy SET automatic_window_seconds=75,safety_seconds=5,
        receipt_retention_seconds=90,retry_initial_seconds=3,retry_max_seconds=7").execute(owner).await?;
    let preserved = floors(owner).await?;
    assert!((before..=now_us(owner).await?).contains(&(preserved.0 - 172_800_000_000)));
    assert_eq!(preserved.1 - preserved.0, 432_000_000_000);
    sqlx::query("UPDATE rss_transactional_messaging.policy SET automatic_window_seconds=60,receipt_retention_seconds=80").execute(owner).await?;
    sqlx::query("UPDATE rss_transactional_messaging.policy SET retry_initial_seconds=3")
        .execute(owner)
        .await?;
    assert_eq!(floors(owner).await?, preserved);
    Ok(())
}
async fn first_retry(owner: &PgPool, config: PgConfig) -> anyhow::Result<(i64, i64, i32)> {
    let first = store(config, "policy-first").await?;
    let before = now_us(owner).await?;
    let original = claim(&first).await?;
    let frozen = facts(owner, "policy-first").await?.0;
    assert!((before..=now_us(owner).await?).contains(&(frozen - 86_400_000_000)));
    change_policy(owner, before).await?;
    let before = now_us(owner).await?;
    first
        .settle(original, OutboxSettlement::Retry, deadline())
        .await?;
    let persisted = facts(owner, "policy-first").await?;
    assert_eq!((persisted.0, persisted.2), (frozen, 1));
    assert!((before..=now_us(owner).await?).contains(&(persisted.1 - 3_000_000)));
    Ok(persisted)
}
async fn backoff(owner: &PgPool, first: &PgOutboxStore<()>, frozen: i64) -> anyhow::Result<()> {
    for (attempts, seconds) in [(1, 6_i64), (2, 7), (i32::MAX, 7)] {
        sqlx::query("UPDATE rss_transactional_messaging.outbox SET retry_count=$1,retry_after=clock_timestamp() WHERE message_id='policy-first'")
            .bind(attempts).execute(owner).await?;
        let item = claim(first).await?;
        let before = now_us(owner).await?;
        first
            .settle(item, OutboxSettlement::Retry, deadline())
            .await?;
        let (absolute, retry, count) = facts(owner, "policy-first").await?;
        assert_eq!((absolute, count), (frozen, attempts.saturating_add(1)));
        assert!((before..=now_us(owner).await?).contains(&(retry - seconds * 1_000_000)));
    }
    Ok(())
}
async fn new_window(owner: &PgPool, config: PgConfig) -> anyhow::Result<()> {
    let second = store(config, "policy-second").await?;
    let before = now_us(owner).await?;
    let item = claim(&second).await?;
    assert!(
        (before..=now_us(owner).await?)
            .contains(&(facts(owner, "policy-second").await?.0 - 60_000_000))
    );
    sqlx::query("UPDATE rss_transactional_messaging.policy SET retry_initial_seconds=2147483647,retry_max_seconds=2147483647")
        .execute(owner).await?;
    second
        .settle(item, OutboxSettlement::Retry, deadline())
        .await?;
    let (absolute, retry, count) = facts(owner, "policy-second").await?;
    assert_eq!((retry, count), (absolute, 1));
    Ok(())
}
pub(crate) async fn run(owner: &PgPool, raw: &PgPool, config: PgConfig) -> anyhow::Result<()> {
    reject_invalid(owner).await?;
    seed(raw).await?;
    let persisted = first_retry(owner, config.clone()).await?;
    let first = store(config.clone(), "policy-first").await?;
    assert_eq!(facts(owner, "policy-first").await?, persisted);
    backoff(owner, &first, persisted.0).await?;
    new_window(owner, config).await?;
    sqlx::query("UPDATE rss_transactional_messaging.policy SET automatic_window_seconds=86400,safety_seconds=86400,
        receipt_retention_seconds=604800,retry_initial_seconds=1,retry_max_seconds=3600").execute(owner).await?;
    Ok(())
}
