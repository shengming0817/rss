//! Consumer/RLS evidence for hot partitions, capacity locks and complete drain latency.
use super::*;
use rss_transactional_messaging::outbox::{OutboxRelayStore, OutboxSettlement};
use std::time::Instant;

async fn append(
    f: &Fixture,
    prefix: &str,
    start: usize,
    count: usize,
    partitions: usize,
) -> anyhow::Result<()> {
    for base in (start..start + count).step_by(500) {
        let end = (base + 500).min(start + count);
        let messages = (base..end)
            .map(|n| {
                let partition = if partitions == 0 {
                    None
                } else {
                    Some(PartitionKey::parse(&format!(
                        "{prefix}-partition-{}",
                        n % partitions
                    ))?)
                };
                Ok(PendingMessage::new(message_partition(
                    &format!("{prefix}-{n}"),
                    "orders",
                    partition,
                )?))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let writer = PgOutboxWriter::new(f.producer.clone(), domain()?);
        committed(
            f.producer
                .local_tx_with_context(
                    tenant(),
                    OperationDeadline::from_remaining(Duration::from_secs(60)),
                    (writer, messages),
                    |(writer, messages), tx| {
                        Box::pin(async move {
                            tx.prepare_outbox_partitions(
                                &messages
                                    .iter()
                                    .filter_map(|m| m.partition().cloned())
                                    .collect::<Vec<_>>(),
                            )
                            .await?;
                            for message in messages.drain(..) {
                                writer.append(tx, message).await?;
                            }
                            Ok(())
                        })
                    },
                )
                .await,
        )?;
    }
    Ok(())
}

pub(super) async fn run(f: &Fixture) -> anyhow::Result<()> {
    append(f, "scale-history", 0, 30_000, 100).await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='published' WHERE message_id LIKE 'scale-history-%'").execute(&f.owner).await?;
    append(f, "scale-hot", 0, 1_200, 1).await?;
    append(f, "scale-cold", 0, 3_000, 100).await?;
    install_explain(f).await?;
    let small = explain(f, "1,200 hot / 101 active partitions").await?;
    append(f, "scale-hot", 1_200, 10_800, 1).await?;
    let large = explain(f, "12,000 hot / 101 active partitions").await?;
    assert!(
        large <= small * 2.0 + 100.0,
        "head work must not grow with a tenfold hot backlog: {small} -> {large}"
    );
    sqlx::query("INSERT INTO rss_transactional_messaging.outbox_partitions(tenant_id,domain,partition_key,prepared_by) SELECT $1::uuid,'orders','scale-empty-'||n,pg_current_xact_id() FROM generate_series(1,40000) n")
        .bind(tenant().to_string()).execute(&f.owner).await?;
    let empty = explain(f, "40,000 empty / 101 active partitions").await?;
    assert!(empty <= large * 2.0 + 100.0);
    capacity(f).await?;
    for limit in [32usize, 1] {
        if limit == 1 {
            sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='pending' WHERE message_id LIKE 'scale-hot-%' OR message_id LIKE 'scale-cold-%'").execute(&f.owner).await?;
        }
        drain(f, limit, 15_000).await?;
    }
    append(f, "scale-wide", 0, 1_000, 1_000).await?;
    append(f, "scale-null", 0, 1_000, 0).await?;
    explain(f, "1,000 active / 1,000 unpartitioned").await?;
    drain(f, 32, 2_000).await?;
    Ok(())
}

// A fixed read-only query runs with the exact login scope and effective relay role of claim.
// No generic SQL execution or broader table grants are exposed to the consumer fixture.
async fn install_explain(f: &Fixture) -> anyhow::Result<()> {
    let body: String = sqlx::query_scalar("SELECT prosrc FROM pg_proc WHERE oid='rss_transactional_messaging.outbox_candidates(uuid,text)'::regprocedure").fetch_one(&f.owner).await?;
    let query = format!(
        "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) SELECT src.seq FROM ({}) c JOIN rss_transactional_messaging.outbox src ON src.seq=c.source_seq WHERE c.eligible_at<=clock_timestamp() ORDER BY src.seq FOR UPDATE OF src SKIP LOCKED",
        body.replace("p_tenant", "$1::uuid")
            .replace("p_domain", "$2")
    );
    let ddl = format!(
        "GRANT CREATE ON SCHEMA public TO rss_tmsg_relay; CREATE FUNCTION public.explain_heads(p_tenant uuid,p_domain text) RETURNS json LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $explain$ DECLARE plan json; BEGIN EXECUTE '{}' INTO plan USING p_tenant,p_domain; RETURN plan; END $explain$; ALTER FUNCTION public.explain_heads(uuid,text) OWNER TO rss_tmsg_relay; REVOKE ALL ON FUNCTION public.explain_heads(uuid,text) FROM PUBLIC; GRANT EXECUTE ON FUNCTION public.explain_heads(uuid,text) TO projection_worker; REVOKE CREATE ON SCHEMA public FROM rss_tmsg_relay;",
        query.replace('\'', "''")
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(ddl))
        .execute(&f.owner)
        .await?;
    Ok(())
}
fn examined(plan: &serde_json::Value) -> f64 {
    let own = if plan["Relation Name"] == "outbox" {
        (plan["Actual Rows"].as_f64().unwrap_or(0.0)
            + plan["Rows Removed by Filter"].as_f64().unwrap_or(0.0))
            * plan["Actual Loops"].as_f64().unwrap_or(1.0)
    } else {
        0.0
    };
    own + plan["Plans"]
        .as_array()
        .map_or(0.0, |children| children.iter().map(examined).sum::<f64>())
}
async fn explain(f: &Fixture, label: &str) -> anyhow::Result<f64> {
    sqlx::query("ANALYZE rss_transactional_messaging.outbox")
        .execute(&f.owner)
        .await?;
    let mut tx = f.raw_worker.begin().await?;
    let plan: serde_json::Value =
        sqlx::query_scalar("SELECT public.explain_heads($1::uuid,'orders')")
            .bind(tenant().to_string())
            .fetch_one(&mut *tx)
            .await?;
    tx.rollback().await?;
    let rows = examined(&plan[0]["Plan"]);
    println!("head-plan {label}: examined={rows} {plan}");
    assert!(
        rows < 15_000.0,
        "heads must not inspect every hot successor"
    );
    Ok(rows)
}
async fn capacity(f: &Fixture) -> anyhow::Result<()> {
    let mut first = f.raw_worker.begin().await?;
    let first_rows: Vec<i64> = sqlx::query_scalar(
        "SELECT seq FROM rss_transactional_messaging.claim_outbox($1::uuid,'orders',1,60000)",
    )
    .bind(tenant().to_string())
    .fetch_all(&mut *first)
    .await?;
    assert_eq!(first_rows.len(), 1);
    let mut second = f.raw_worker.begin().await?;
    let others: Vec<i64> = sqlx::query_scalar(
        "SELECT seq FROM rss_transactional_messaging.claim_outbox($1::uuid,'orders',101,60000)",
    )
    .bind(tenant().to_string())
    .fetch_all(&mut *second)
    .await?;
    second.rollback().await?;
    first.rollback().await?;
    assert_eq!(
        others.len(),
        100,
        "limit=1 must lock only its processed head; another worker can claim every other partition"
    );
    assert!(!others.contains(&first_rows[0]));
    Ok(())
}
async fn drain(f: &Fixture, limit: usize, expected: usize) -> anyhow::Result<()> {
    let store = PgOutboxStore::<()>::new(
        f.worker.clone(),
        domain()?,
        DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )?,
    )?;
    let mut seen = std::collections::HashSet::new();
    let mut last = std::collections::HashMap::new();
    let mut cold = 0usize;
    let mut claims = Vec::new();
    let mut wakeups = Vec::new();
    let started = Instant::now();
    loop {
        let at = Instant::now();
        let wake = store.next_wakeup(deadline()).await?;
        wakeups.push(at.elapsed().as_micros());
        let at = Instant::now();
        let batch = store
            .claim_partition_heads(NonZeroUsize::try_from(limit)?, deadline())
            .await?;
        claims.push(at.elapsed().as_micros());
        if batch.is_empty() {
            assert!(!wake.due_now());
            break;
        }
        assert!(wake.due_now());
        for claim in batch {
            let id = PgOutboxStore::<()>::message(&claim)
                .message_id()
                .as_str()
                .to_owned();
            if let Some(partition) = PgOutboxStore::<()>::message(&claim).partition() {
                let ordinal: usize = id
                    .rsplit('-')
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("fixture ordinal"))?
                    .parse()?;
                if let Some(previous) = last.insert(partition.key().as_str().to_owned(), ordinal) {
                    assert!(ordinal > previous, "partition order");
                }
            }
            if id.starts_with("scale-cold-") {
                cold += 1;
                if cold == 3_000 && limit == 32 {
                    assert!(
                        seen.len() < 15_000 - 1,
                        "cold partitions drain while the hot partition still has backlog"
                    );
                }
            }
            assert!(seen.insert(id), "no duplicate settlement");
            store
                .settle(claim, OutboxSettlement::Published(()), deadline())
                .await?;
        }
    }
    assert_eq!(seen.len(), expected);
    println!(
        "drain limit={limit} count={} elapsed_ms={}",
        seen.len(),
        started.elapsed().as_millis()
    );
    distribution("claim", limit, &mut claims);
    distribution("wakeup", limit, &mut wakeups);
    let mut idle = Vec::new();
    for _ in 0..20 {
        let at = Instant::now();
        assert!(!store.next_wakeup(deadline()).await?.due_now());
        idle.push(at.elapsed().as_micros());
    }
    distribution("idle-wakeup", limit, &mut idle);
    Ok(())
}
fn distribution(operation: &str, limit: usize, samples: &mut [u128]) {
    samples.sort_unstable();
    let n = samples.len();
    println!(
        "latency_us operation={operation} limit={limit} n={n} min={} p50={} p95={} p99={} max={}",
        samples[0],
        samples[(n - 1) * 50 / 100],
        samples[(n - 1) * 95 / 100],
        samples[(n - 1) * 99 / 100],
        samples[n - 1]
    );
}
