//! Consumer/RLS evidence for hot partitions, capacity locks and complete drain latency.
use super::*;
use rss_request_context::Clock;
use rss_transactional_messaging::outbox::{OutboxRelayStore, OutboxSettlement};

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
                    crate::execution(tenant(), 1),
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

async fn prepare(f: &Fixture) -> anyhow::Result<()> {
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
    capacity(f).await
}

pub(super) async fn run(f: &Fixture) -> anyhow::Result<()> {
    if std::env::var_os("RSS_PG_WORK_PROFILE_ONLY").is_some() {
        return profile_populations(f).await;
    }
    prepare(f).await?;
    for limit in [32usize, 1] {
        if limit == 1 {
            sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='pending' WHERE message_id LIKE 'scale-hot-%' OR message_id LIKE 'scale-cold-%'").execute(&f.owner).await?;
        }
        drain(f, limit, 15_000).await?;
    }
    append(f, "scale-wide", 0, 1_000, 1_000).await?;
    append(f, "scale-null", 0, 1_000, 0).await?;
    explain(f, "1,000 active / 1,000 unpartitioned").await?;
    if std::env::var_os("RSS_PG_WORK_PROFILE").is_some() {
        nested_profiles(f).await?;
    }
    drain(f, 32, 2_000).await?;
    Ok(())
}

async fn profile_populations(f: &Fixture) -> anyhow::Result<()> {
    install_explain(f).await?;
    append(f, "profile-history", 0, 512, 512).await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='published' WHERE message_id LIKE 'profile-history-%'").execute(&f.owner).await?;
    for (start, count) in [(0, 1000), (1000, 9000)] {
        append(f, "scale-wide", start, count, start + count).await?;
        append(f, "scale-null", start, count, 0).await?;
        println!("claim-profile population={}", 2 * (start + count));
        nested_profiles(f).await?;
    }
    Ok(())
}

// A fixed read-only query runs with the exact login scope and effective relay role of claim.
// No generic SQL execution or broader table grants are exposed to the consumer fixture.
pub(super) async fn install_explain(f: &Fixture) -> anyhow::Result<()> {
    let body: String = sqlx::query_scalar("SELECT prosrc FROM pg_proc WHERE oid='rss_transactional_messaging.outbox_claim_window(uuid,text,timestamptz,bigint,integer,timestamptz,integer)'::regprocedure").fetch_one(&f.owner).await?;
    let query = format!(
        "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) {}",
        body.replace("p_tenant", "$1::uuid")
            .replace("p_domain", "$2")
            .replace("p_at", "'-infinity'::timestamptz")
            .replace("p_seq", "0::bigint")
            .replace("p_lane", "0::integer")
            .replace("p_through", "statement_timestamp()")
            .replace("p_take", "$3::integer")
    );
    let ddl = format!(
        "GRANT CREATE ON SCHEMA public TO rss_tmsg_relay; CREATE FUNCTION public.explain_heads(p_tenant uuid,p_domain text,p_budget integer) RETURNS json LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $explain$ DECLARE plan json; BEGIN EXECUTE '{}' INTO plan USING p_tenant,p_domain,p_budget; RETURN plan; END $explain$; ALTER FUNCTION public.explain_heads(uuid,text,integer) OWNER TO rss_tmsg_relay; REVOKE ALL ON FUNCTION public.explain_heads(uuid,text,integer) FROM PUBLIC; GRANT EXECUTE ON FUNCTION public.explain_heads(uuid,text,integer) TO projection_worker; REVOKE CREATE ON SCHEMA public FROM rss_tmsg_relay;",
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
pub(super) async fn explain(f: &Fixture, label: &str) -> anyhow::Result<f64> {
    sqlx::query("ANALYZE rss_transactional_messaging.outbox")
        .execute(&f.owner)
        .await?;
    let mut tx = f.raw_worker.begin().await?;
    let plan: serde_json::Value =
        sqlx::query_scalar("SELECT public.explain_heads($1::uuid,'orders',64)")
            .bind(tenant().to_string())
            .fetch_one(&mut *tx)
            .await?;
    tx.rollback().await?;
    let rows = examined(&plan[0]["Plan"]);
    println!("head-plan {label}: examined={rows} {plan}");
    assert!(rows < 1024.0, "heads must not inspect every hot successor");
    Ok(rows)
}
async fn capacity(f: &Fixture) -> anyhow::Result<()> {
    let mut first = f.raw_worker.begin().await?;
    let first_rows: Vec<i64> = sqlx::query_scalar(
        "SELECT seq FROM rss_transactional_messaging.claim_outbox($1::uuid,'orders',1,64,60000)",
    )
    .bind(tenant().to_string())
    .fetch_all(&mut *first)
    .await?;
    assert_eq!(first_rows.len(), 1);
    let mut second = f.raw_worker.begin().await?;
    let others: Vec<i64> = sqlx::query_scalar(
        "SELECT seq FROM rss_transactional_messaging.claim_outbox($1::uuid,'orders',101,404,60000)",
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
    let mut progress = Progress::default();
    let timer = Timer::new();
    let mut claims = Vec::new();
    let mut wakeups = Vec::new();
    let mut empty_pages = 0usize;
    let started = timer.now();
    loop {
        let at = timer.now();
        let wake = store
            .next_wakeup(crate::execution(crate::fixture_tenant(), 1), deadline())
            .await?;
        wakeups.push((timer.now() - at).as_micros());
        let at = timer.now();
        let batch = store
            .claim_partition_heads(
                crate::execution(crate::fixture_tenant(), 1),
                NonZeroUsize::try_from(limit)?,
                deadline(),
            )
            .await?;
        claims.push((timer.now() - at).as_micros());
        if batch.is_empty() {
            if wake.due_now() {
                empty_pages += 1;
                anyhow::ensure!(
                    empty_pages <= expected.div_ceil(64) + 2,
                    "drain stalled: claimed={}, empty_pages={empty_pages}, due_now={}",
                    progress.seen.len(),
                    wake.due_now()
                );
                continue;
            }
            break;
        }
        empty_pages = 0;
        assert!(wake.due_now());
        for claim in batch {
            let message = PgOutboxStore::<()>::message(&claim);
            progress.observe(
                message.message_id().as_str(),
                message.partition().map(|p| p.key().as_str()),
                limit,
            )?;
            store
                .settle(claim, OutboxSettlement::Published(()), deadline())
                .await?;
        }
    }
    assert_eq!(progress.seen.len(), expected);
    println!(
        "drain limit={limit} count={} elapsed_ms={}",
        progress.seen.len(),
        (timer.now() - started).as_millis()
    );
    distribution("claim", limit, &mut claims);
    distribution("wakeup", limit, &mut wakeups);
    idle_latency(&store, limit).await
}
async fn idle_latency(store: &PgOutboxStore<()>, limit: usize) -> anyhow::Result<()> {
    let timer = Timer::new();
    let mut idle = Vec::new();
    for _ in 0..20 {
        let at = timer.now();
        assert!(
            !store
                .next_wakeup(crate::execution(crate::fixture_tenant(), 1), deadline())
                .await?
                .due_now()
        );
        idle.push((timer.now() - at).as_micros());
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

#[derive(Default)]
struct Progress {
    seen: std::collections::HashSet<String>,
    last: std::collections::HashMap<String, usize>,
    cold: usize,
}
impl Progress {
    fn observe(&mut self, id: &str, partition: Option<&str>, limit: usize) -> anyhow::Result<()> {
        if let Some(partition) = partition {
            let ordinal: usize = id
                .rsplit('-')
                .next()
                .ok_or_else(|| anyhow::anyhow!("fixture ordinal"))?
                .parse()?;
            if let Some(previous) = self.last.insert(partition.to_owned(), ordinal) {
                assert!(ordinal > previous, "partition order");
            }
        }
        if id.starts_with("scale-cold-") {
            self.cold += 1;
            if self.cold == 3_000 && limit == 32 {
                assert!(
                    self.seen.len() < 15_000 - 1,
                    "cold partitions drain while the hot partition still has backlog"
                );
            }
        }
        assert!(self.seen.insert(id.to_owned()), "no duplicate settlement");
        Ok(())
    }
}

async fn scan_matrix(f: &Fixture) -> anyhow::Result<()> {
    for (capacity, scan) in [(4_i32, 2_i32), (4, 8), (1, 8)] {
        let mut tx = f.raw_worker.begin().await?;
        let plan: serde_json::Value =
            sqlx::query_scalar("SELECT public.explain_heads($1::uuid,'orders',$2)")
                .bind(tenant().to_string())
                .bind(scan)
                .fetch_one(&mut *tx)
                .await?;
        let root = &plan[0]["Plan"];
        assert_eq!(root["Actual Rows"].as_i64(), Some(i64::from(scan)));
        let timer = Timer::new();
        let started = timer.now();
        let rows: Vec<i64> = sqlx::query_scalar("SELECT seq FROM rss_transactional_messaging.claim_outbox($1::uuid,'orders',$2,$3,60000)")
            .bind(tenant().to_string()).bind(capacity).bind(scan).fetch_all(&mut *tx).await?;
        assert_eq!(rows.len(), capacity.min(scan) as usize);
        println!(
            "first claim limit={capacity} budget={scan} elapsed={:?} examined={} shared_hits={} shared_reads={}",
            timer.now() - started,
            examined(root),
            root["Shared Hit Blocks"],
            root["Shared Read Blocks"]
        );
        tx.rollback().await?;
    }
    Ok(())
}

#[allow(
    clippy::cognitive_complexity,
    reason = "The lock window, arrivals and revisit assertions form one sequential provider scenario."
)]
pub(super) async fn bounded_windows(f: &Fixture) -> anyhow::Result<()> {
    for _ in 0..3 {
        let empty: Vec<i64> = sqlx::query_scalar(
            "SELECT seq FROM rss_transactional_messaging.claim_outbox($1::uuid,'orders',1,64,60000)",
        )
        .bind(tenant().to_string())
        .fetch_all(&f.raw_worker)
        .await?;
        assert!(empty.is_empty());
        let cursors: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM rss_transactional_messaging.outbox_scan WHERE domain='orders'",
        )
        .fetch_one(&f.owner)
        .await?;
        assert_eq!(
            cursors, 0,
            "idle scans must not create durable cursor versions"
        );
    }
    append(f, "window", 0, 258, 0).await?;
    scan_matrix(f).await?;
    // One projection permit can drive a full, independently sized scan window.
    let runtime = Arc::new(
        PgRuntime::connect_consumer(
            f.config.clone().with_pool_limits(0, 33),
            Timer::new(),
            fence_fixture::storage(),
        )
        .await?,
    );
    let projection = Fixture::projection_on(
        runtime.clone(),
        Effect {
            gate: None,
            reject: false,
            fail: false,
        },
    )
    .await?;
    let projection = Arc::into_inner(projection)
        .ok_or_else(|| anyhow::anyhow!("fixture owns its projection"))?
        .with_scan_budget(PgOutboxScanBudget::new(128)?);
    let validator = Validator;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET retry_after=statement_timestamp()-interval '1 day' WHERE message_id LIKE 'window-%'").execute(&f.owner).await?;
    let mut held = f.owner.begin().await?;
    let locked:Vec<i64>=sqlx::query_scalar("SELECT seq FROM rss_transactional_messaging.outbox WHERE message_id LIKE 'window-%' ORDER BY seq LIMIT 256 FOR UPDATE")
        .fetch_all(&mut *held).await?;
    for page in 1..=2 {
        let batch = projection
            .project_batch(
                crate::execution(tenant(), 1),
                &validator,
                NonZeroUsize::MIN,
                deadline(),
                Duration::from_secs(5),
            )
            .await?;
        assert_eq!(
            batch.scan_progress(),
            rss_transactional_messaging::outbox::OutboxScanProgress::Continue
        );
        let cursor: i64 = sqlx::query_scalar(
            "SELECT source_seq FROM rss_transactional_messaging.outbox_scan WHERE domain='orders'",
        )
        .fetch_one(&f.owner)
        .await?;
        assert_eq!(cursor, locked[page * 128 - 1]);
        let rows = futures::StreamExt::collect::<Vec<_>>(batch).await;
        assert!(
            rows.is_empty(),
            "each locked window is a bounded empty page"
        );
    }
    let mut claim = f.raw_worker.begin().await?;
    let rows: Vec<i64> = sqlx::query_scalar(
        "SELECT seq FROM rss_transactional_messaging.claim_outbox($1::uuid,'orders',1,64,60000)",
    )
    .bind(tenant().to_string())
    .fetch_all(&mut *claim)
    .await?;
    assert_eq!(rows.len(), 1, "third call reaches the unlocked suffix");
    assert!(!locked.contains(&rows[0]));
    let unlocked:Vec<i64>=sqlx::query_scalar("SELECT seq FROM rss_transactional_messaging.outbox WHERE message_id LIKE 'window-%' AND seq<>ALL($1) FOR UPDATE SKIP LOCKED")
        .bind(&locked).fetch_all(&mut *held).await?;
    assert_eq!(unlocked.len(), 1, "lookahead is not locked");
    claim.rollback().await?;
    held.rollback().await?;
    let mut revisited = false;
    for n in 0..10 {
        append(f, "arrival", n, 1, 0).await?;
        let rows: Vec<i64> = sqlx::query_scalar(
            "SELECT seq FROM rss_transactional_messaging.claim_outbox($1::uuid,'orders',1,64,60000)",
        )
        .bind(tenant().to_string())
        .fetch_all(&f.raw_worker)
        .await?;
        revisited |= rows.iter().any(|id| locked.contains(id));
        if revisited {
            break;
        }
    }
    assert!(
        revisited,
        "a frozen sweep revisits unlocked prefixes despite continuous arrivals"
    );
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='published',lease_token=NULL,lease_until=NULL WHERE message_id LIKE 'window-%' OR message_id LIKE 'arrival-%'").execute(&f.owner).await?;
    drop(projection);
    runtime.close().await;
    Ok(())
}

pub(super) struct Published(pub(super) tokio::sync::mpsc::UnboundedSender<String>);
impl rss_transactional_messaging::transport::Publisher<Vec<u8>> for Published {
    type Receipt = ();
    async fn publish(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> rss_transactional_messaging::transport::PublishOutcome<()> {
        let _ = self.0.send(message.id().as_str().to_owned());
        rss_transactional_messaging::transport::PublishOutcome::Confirmed(())
    }
}
struct Quiet;
impl rss_transactional_messaging::observability::TransactionalMessagingEmitter for Quiet {
    fn emit(
        &self,
        _: rss_transactional_messaging::observability::TransactionalMessagingObservation,
    ) {
    }
}

pub(super) async fn worker_continuation(f: &Fixture) -> anyhow::Result<()> {
    first_publication(f, "resume-lease", 64, false).await?;
    first_publication(f, "resume-locked", 130, true).await?;
    finish_retired_sweep(f).await
}

async fn first_publication(
    f: &Fixture,
    prefix: &str,
    count: usize,
    lock_prefix: bool,
) -> anyhow::Result<()> {
    use rss_transactional_messaging_runtime::relay::{RelayConfig, RelayWorker};
    append(f, prefix, 0, count, 0).await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET retry_after=clock_timestamp()-interval '2 days' WHERE message_id LIKE $1").bind(format!("{prefix}-%")).execute(&f.owner).await?;
    let mut held = f.owner.begin().await?;
    if lock_prefix {
        sqlx::query("SELECT seq FROM rss_transactional_messaging.outbox WHERE message_id LIKE $1 ORDER BY seq LIMIT 128 FOR UPDATE").bind(format!("{prefix}-%")).fetch_all(&mut *held).await?;
    } else {
        sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='publishing',lease_token=gen_random_uuid(),lease_until=clock_timestamp()-interval '1 day',automatic_retry_deadline=clock_timestamp()+interval '1 day' WHERE message_id LIKE $1").bind(format!("{prefix}-%")).execute(&f.owner).await?;
    }
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
    let config = RelayConfig::new(
        NonZeroUsize::MIN,
        NonZeroUsize::MIN,
        Duration::from_secs(30),
        Duration::from_secs(1),
    )?;
    let (sent, mut received) = tokio::sync::mpsc::unbounded_channel();
    let worker = RelayWorker::new(
        store,
        Arc::new(Published(sent)),
        Arc::new(Timer::new()),
        Arc::new(Quiet),
        config,
    );
    let stop = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(worker.run(crate::execution(tenant(), 1), stop.clone()));
    let first = tokio::time::timeout(Duration::from_secs(3), received.recv()).await;
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), task).await???;
    held.rollback().await?;
    let id = first?.ok_or_else(|| anyhow::anyhow!("worker stopped without publication"))?;
    assert!(id.starts_with(prefix));
    if lock_prefix {
        assert!(id.ends_with("-128") || id.ends_with("-129"));
    }
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='published',lease_token=NULL,lease_until=NULL WHERE message_id LIKE $1").bind(format!("{prefix}-%")).execute(&f.owner).await?;
    Ok(())
}

async fn finish_retired_sweep(f: &Fixture) -> anyhow::Result<()> {
    // The worker stopped on its first publication. The fixture then explicitly retired
    // its remaining sources. Finish any frozen sweep before handing the domain back.
    for _ in 0..2 {
        let mut tx = f.raw_worker.begin().await?;
        let rows: Vec<i64> = sqlx::query_scalar(
            "SELECT seq FROM rss_transactional_messaging.claim_outbox($1::uuid,'orders',32,128,60000)",
        )
        .bind(tenant().to_string())
        .fetch_all(&mut *tx)
        .await?;
        assert!(rows.is_empty());
        let progress: String =
            sqlx::query_scalar("SELECT current_setting('rss.outbox_scan_progress')")
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        if progress == "complete" {
            return Ok(());
        }
        assert_eq!(progress, "retry_later");
    }
    anyhow::bail!("retired fixture did not finish its sweep")
}

async fn nested_profiles(f: &Fixture) -> anyhow::Result<()> {
    use sqlx::Connection as _;
    let _ = tracing_subscriber::fmt()
        .with_env_filter("sqlx::postgres::notice=info")
        .with_ansi(false)
        .try_init();
    for scenario in ["wide", "leases-dr"] {
        if scenario == "leases-dr" {
            sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='publishing',lease_token=gen_random_uuid(),lease_until=clock_timestamp()+interval '1 minute',automatic_retry_deadline=clock_timestamp()+interval '1 day',retry_after=clock_timestamp()-interval '1 hour' WHERE seq IN (SELECT seq FROM rss_transactional_messaging.outbox WHERE message_id LIKE 'scale-null-%' ORDER BY seq LIMIT 192)").execute(&f.owner).await?;
            sqlx::query("UPDATE rss_transactional_messaging.outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE seq IN (SELECT seq FROM rss_transactional_messaging.outbox WHERE status='publishing' ORDER BY seq LIMIT 64)").execute(&f.owner).await?;
            sqlx::query("UPDATE rss_transactional_messaging.outbox SET claim_epoch=0 WHERE seq IN (SELECT seq FROM rss_transactional_messaging.outbox WHERE status='publishing' ORDER BY seq OFFSET 128 LIMIT 64)").execute(&f.owner).await?;
            sqlx::query("UPDATE rss_transactional_messaging.outbox SET automatic_retry_deadline=clock_timestamp()+interval '1 day' WHERE status='published'").execute(&f.owner).await?;
            sqlx::query("INSERT INTO rss_transactional_messaging.dr_plans(tenant_id,operation_id,request_digest,lineage,epoch,kind,evidence) VALUES($1::uuid,'00000000-0000-0000-0000-000000003281',sha256('profile'::bytea),decode(repeat('02',16),'hex'),1,'database','{}')").bind(tenant().to_string()).execute(&f.owner).await?;
            sqlx::query("INSERT INTO rss_transactional_messaging.dr_members(tenant_id,operation_id,ordinal,message_id,consumer_group,fingerprint,outbox_seq,status) SELECT tenant_id,'00000000-0000-0000-0000-000000003281',(row_number() OVER(ORDER BY seq)-1)::integer,message_id,'',fingerprint,seq,'pending' FROM rss_transactional_messaging.outbox WHERE status='published' AND payload IS NOT NULL ORDER BY seq LIMIT 512").execute(&f.owner).await?;
            explain(f, "512 current DR / mixed leases").await?;
        }
        for scan in [64_i32, 128] {
            for limit in [1, 32] {
                let mut plain =
                    sqlx::PgConnection::connect_with(f.owner.connect_options().as_ref()).await?;
                sqlx::query("SET SESSION AUTHORIZATION projection_worker")
                    .execute(&mut plain)
                    .await?;
                let timer = Timer::new();
                let mut latency = Vec::new();
                for attempt in 0..11 {
                    let at = timer.now();
                    let mut tx = plain.begin().await?;
                    let rows:Vec<i64>=sqlx::query_scalar("SELECT seq FROM rss_transactional_messaging.claim_outbox($1::uuid,'orders',$2,$3,60000)").bind(tenant().to_string()).bind(limit).bind(scan).fetch_all(&mut *tx).await?;
                    assert_eq!(rows.len(), limit as usize);
                    tx.rollback().await?;
                    if attempt == 0 {
                        println!(
                            "first claim scan={scan} limit={limit} elapsed_us={}",
                            (timer.now() - at).as_micros()
                        );
                    } else {
                        latency.push((timer.now() - at).as_micros());
                    }
                }
                distribution(
                    &format!("claim-transaction-{scan}-{scenario}"),
                    limit as usize,
                    &mut latency,
                );
                plain.close().await?;
                let mut c =
                    sqlx::PgConnection::connect_with(f.owner.connect_options().as_ref()).await?;
                sqlx::raw_sql("LOAD 'auto_explain'; SET auto_explain.log_min_duration=0; SET auto_explain.log_nested_statements=on; SET auto_explain.log_analyze=on; SET auto_explain.log_buffers=on; SET auto_explain.log_timing=off; SET auto_explain.log_format=json; SET auto_explain.log_level=notice; SET SESSION AUTHORIZATION projection_worker;").execute(&mut c).await?;
                println!("claim-profile scan_budget={scan} scenario={scenario} limit={limit}");
                let mut tx = c.begin().await?;
                let rows:Vec<i64>=sqlx::query_scalar("SELECT seq FROM rss_transactional_messaging.claim_outbox($1::uuid,'orders',$2,$3,60000)").bind(tenant().to_string()).bind(limit).bind(scan).fetch_all(&mut *tx).await?;
                assert_eq!(rows.len(), limit as usize);
                tx.rollback().await?;
                c.close().await?;
            }
        }
    }
    sqlx::query("DELETE FROM rss_transactional_messaging.dr_members WHERE operation_id='00000000-0000-0000-0000-000000003281'").execute(&f.owner).await?;
    sqlx::query("DELETE FROM rss_transactional_messaging.dr_plans WHERE operation_id='00000000-0000-0000-0000-000000003281'").execute(&f.owner).await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='pending',lease_token=NULL,lease_until=NULL,claim_epoch=1,retry_after=clock_timestamp() WHERE message_id LIKE 'scale-null-%' AND status='publishing'").execute(&f.owner).await?;
    Ok(())
}
