//! INVARIANT: OUTBOX-PARTITION-ORDER-01 — public Rust and independent SQL callers.
mod wire_contract;
use super::{Timer, binding, deadline, fence_fixture, message, outbox_budget};
use rss_request_context::TenantId;
use rss_transactional_messaging::{inbox::*, message::*, outbox::*, policy::*, transaction::*};
use rss_transactional_messaging_postgres::*;
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};

fn ordered(id: &str, domain: &str, key: &str) -> MessageEnvelope<Vec<u8>> {
    ordered_in(message(id).metadata().tenant_id(), id, domain, key)
}

fn ordered_in(tenant: TenantId, id: &str, domain: &str, key: &str) -> MessageEnvelope<Vec<u8>> {
    let template = message(id);
    let m = template.metadata();
    MessageEnvelope::new(
        template.id().clone(),
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                m.occurred_at(),
                MessagingDomain::parse(domain).expect("domain"),
                m.route().clone(),
                m.contract().clone(),
            ),
            MessageMetadataExtensions::new(
                None,
                Some(PartitionKey::parse(key).expect("partition")),
                None,
                Default::default(),
            ),
        ),
        template.payload().clone(),
    )
}

// Independent SQL-client implementation of the public core byte contract (no adapter codec).
fn frames(message: &MessageEnvelope<Vec<u8>>) -> Vec<(u8, Vec<u8>)> {
    let m = message.metadata();
    let mut fields = vec![
        (0, b"rss-transactional-message-v1".to_vec()),
        (1, message.id().as_str().as_bytes().to_vec()),
        (2, m.tenant_id().octets().to_vec()),
        (3, m.occurred_at().unix_seconds().to_be_bytes().to_vec()),
    ];
    optional_frame(&mut fields, 4, m.correlation());
    fields.extend([
        (5, m.domain().as_str().as_bytes().to_vec()),
        (6, m.route().as_str().as_bytes().to_vec()),
        (7, m.contract().id().as_str().as_bytes().to_vec()),
        (8, m.contract().version().major().to_be_bytes().to_vec()),
        (9, m.contract().schema_digest().as_str().as_bytes().to_vec()),
        (10, vec![u8::from(m.partition().is_some())]),
    ]);
    if let Some(partition) = m.partition() {
        fields.extend([
            (11, partition.tenant_id().octets().to_vec()),
            (12, partition.domain().as_str().as_bytes().to_vec()),
            (13, partition.key().as_str().as_bytes().to_vec()),
        ]);
    }
    optional_frame(&mut fields, 14, m.causation().map(MessageId::as_str));
    let attributes = m.attributes().collect::<Vec<_>>();
    fields.push((
        15,
        u64::try_from(attributes.len())
            .expect("count")
            .to_be_bytes()
            .to_vec(),
    ));
    for (key, value) in attributes {
        fields.extend([
            (16, key.as_bytes().to_vec()),
            (17, value.as_bytes().to_vec()),
        ]);
    }
    fields.push((18, message.payload().clone()));
    fields
}

fn optional_frame(fields: &mut Vec<(u8, Vec<u8>)>, tag: u8, value: Option<&str>) {
    fields.push((tag, vec![u8::from(value.is_some())]));
    if let Some(value) = value {
        fields.push((tag, value.as_bytes().to_vec()));
    }
}

fn wire(fields: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut output = Vec::new();
    for (tag, bytes) in fields {
        output.push(*tag);
        output.extend(
            u64::try_from(bytes.len())
                .expect("frame size")
                .to_be_bytes(),
        );
        output.extend(bytes);
    }
    output
}

fn transport(message: &MessageEnvelope<Vec<u8>>) -> serde_json::Value {
    serde_json::json!({"trace":message.transport_context().trace(),"tenant_authority":message.transport_context().tenant_authority()})
}

async fn sql_tx(pool: &PgPool, tenant: TenantId) -> anyhow::Result<Transaction<'static, Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('rss.storage_target','01010101010101010101010101010101',true),set_config('rss.storage_lineage','02020202020202020202020202020202',true),set_config('rss.execution_epoch','1',true),set_config('statement_timeout','3s',true)")
        .bind(tenant.to_string()).execute(&mut *tx).await?;
    Ok(tx)
}

async fn sql_prepare(
    connection: &mut PgConnection,
    pairs: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT rss_transactional_messaging.prepare_outbox_partitions($1)")
        .bind(pairs)
        .execute(connection)
        .await
        .map(|_| ())
}

async fn sql_append(
    connection: &mut PgConnection,
    message: &MessageEnvelope<Vec<u8>>,
) -> Result<String, sqlx::Error> {
    let encoded = wire(&frames(message));
    assert_eq!(
        encoded,
        message.canonical_bytes(),
        "independent SQL encoder agrees with core"
    );
    sqlx::query_scalar("SELECT rss_transactional_messaging.append_outbox($1,$2)")
        .bind(encoded)
        .bind(transport(message))
        .fetch_one(connection)
        .await
}

fn code(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(|error| error.code())
        .map(|code| code.into_owned())
}

async fn wait_lock(owner: &PgPool, pid: i32) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')")
                .bind(pid).fetch_one(owner).await?;
            if waiting { return Ok::<_, sqlx::Error>(()); }
            tokio::task::yield_now().await;
        }
    }).await??;
    Ok(())
}

pub(super) async fn run(
    runtime: Arc<PgRuntime>,
    owner: &PgPool,
    raw: &PgPool,
    config: PgConfig,
) -> anyhow::Result<()> {
    Box::pin(sql_digest_integrity(raw)).await?;
    Box::pin(wire_contract::run(runtime.clone(), raw)).await?;
    Box::pin(sql_protocol(raw)).await?;
    Box::pin(rollback_and_independence(owner, raw)).await?;
    Box::pin(opposite_declarations(owner, raw)).await?;
    Box::pin(ignored_errors(runtime.clone(), owner)).await?;
    Box::pin(ignored_conflict(runtime.clone(), owner)).await?;
    Box::pin(ignored_foreign_partition(runtime.clone(), owner)).await?;
    Box::pin(cancelled_preparation(runtime.clone(), owner, raw)).await?;
    Box::pin(timed_out_preparation(runtime.clone(), owner, raw)).await?;
    Box::pin(rejected_effect(runtime.clone(), owner)).await?;
    Box::pin(cached_row_ids(runtime.clone(), owner, raw)).await?;
    Box::pin(permission_drift(owner, config)).await?;
    Ok(())
}

#[allow(clippy::cognitive_complexity)] // reason: real SQL protocol cases keep rejected statements adjacent to rollback and error-code evidence.
async fn sql_protocol(raw: &PgPool) -> anyhow::Result<()> {
    let tenant = message("sql").metadata().tenant_id();
    let item = ordered("sql-item", "sql-protocol", "one");
    let mut tx = sql_tx(raw, tenant).await?;
    assert_eq!(
        code(
            &sql_append(&mut tx, &item)
                .await
                .expect_err("declaration required")
        )
        .as_deref(),
        Some("PZ002")
    );
    tx.rollback().await?;
    for pairs in [
        serde_json::json!([null]),
        serde_json::json!([["ok", null]]),
        serde_json::json!([["bad space", "one"]]),
        serde_json::json!([["ok", "\n"]]),
        serde_json::json!([["a".repeat(256), "one"]]),
        serde_json::json!([["ok", "a".repeat(256)]]),
    ] {
        let mut tx = sql_tx(raw, tenant).await?;
        assert_eq!(
            code(
                &sql_prepare(&mut tx, pairs)
                    .await
                    .expect_err("invalid identity")
            )
            .as_deref(),
            Some("22023")
        );
        tx.rollback().await?;
    }
    let mut tx = sql_tx(raw, tenant).await?;
    sql_prepare(
        &mut tx,
        serde_json::json!([["sql-protocol", "one"], ["sql-protocol", "one"]]),
    )
    .await?;
    assert_eq!(sql_append(&mut tx, &item).await?, "inserted");
    assert_eq!(sql_append(&mut tx, &item).await?, "already_present");
    tx.commit().await?;
    let mut tx = sql_tx(raw, tenant).await?;
    sql_prepare(&mut tx, serde_json::json!([["sql-protocol", "one"]])).await?;
    let conflict = MessageEnvelope::new(item.id().clone(), item.metadata().clone(), vec![9]);
    assert_eq!(sql_append(&mut tx, &conflict).await?, "conflict");
    tx.rollback().await?;
    for pairs in [
        serde_json::json!([["sql-protocol", "one"]]),
        serde_json::json!([["sql-protocol", "two"]]),
    ] {
        let mut tx = sql_tx(raw, tenant).await?;
        sql_prepare(&mut tx, serde_json::json!([["sql-protocol", "one"]])).await?;
        assert_eq!(
            code(
                &sql_prepare(&mut tx, pairs)
                    .await
                    .expect_err("cannot redeclare or extend")
            )
            .as_deref(),
            Some("PZ002")
        );
        tx.rollback().await?;
    }
    let mut tx = sql_tx(raw, tenant).await?;
    sqlx::query("SAVEPOINT cancelled_preparation")
        .execute(&mut *tx)
        .await?;
    sql_prepare(&mut tx, serde_json::json!([["sql-protocol", "one"]])).await?;
    sqlx::query("ROLLBACK TO SAVEPOINT cancelled_preparation")
        .execute(&mut *tx)
        .await?;
    assert_eq!(
        code(
            &sql_append(&mut tx, &item)
                .await
                .expect_err("rolled-back proof is not reusable")
        )
        .as_deref(),
        Some("PZ002")
    );
    tx.rollback().await?;
    let mut tx = sql_tx(raw, tenant).await?;
    sql_prepare(&mut tx, serde_json::json!([["sql-protocol", "one"]])).await?;
    assert_eq!(
        code(
            &sql_append(&mut tx, &ordered("outside-set", "sql-protocol", "two"))
                .await
                .expect_err("partition outside declared set")
        )
        .as_deref(),
        Some("PZ002")
    );
    tx.rollback().await?;
    // The longest accepted domain and a non-ASCII partition use the same identity rules as Rust.
    let item = ordered("long-domain", &"a".repeat(255), "分区");
    let mut tx = sql_tx(raw, tenant).await?;
    sql_prepare(
        &mut tx,
        serde_json::json!([[item.metadata().domain().as_str(), "分区"]]),
    )
    .await?;
    assert_eq!(sql_append(&mut tx, &item).await?, "inserted");
    tx.rollback().await?;
    for statement in [
        "INSERT INTO rss_transactional_messaging.outbox DEFAULT VALUES",
        "UPDATE rss_transactional_messaging.outbox SET partition_seq=1",
        "UPDATE rss_transactional_messaging.outbox_partitions SET prepared_by=pg_current_xact_id()",
        "SELECT nextval('rss_transactional_messaging.outbox_seq_seq')",
    ] {
        let mut tx = sql_tx(raw, tenant).await?;
        let error = sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&mut *tx)
            .await
            .expect_err("direct authority denied");
        assert_eq!(code(&error).as_deref(), Some("42501"));
        tx.rollback().await?;
    }
    // Projection identities cannot be forged: the obsolete multi-identity signature is gone.
    let mut tx = sql_tx(raw, tenant).await?;
    let error = sqlx::query("SELECT rss_transactional_messaging.append_outbox('id'::text,'domain'::text,NULL::text,'{}'::jsonb,decode(repeat('00',32),'hex'))")
        .execute(&mut *tx).await.expect_err("unverified digest API removed");
    assert_eq!(code(&error).as_deref(), Some("42883"));
    tx.rollback().await?;
    Ok(())
}

#[allow(clippy::cognitive_complexity)] // reason: one held transaction proves three independence axes and the rollback handoff.
async fn rollback_and_independence(owner: &PgPool, raw: &PgPool) -> anyhow::Result<()> {
    let tenant = message("sql").metadata().tenant_id();
    let mut first = sql_tx(raw, tenant).await?;
    sql_prepare(&mut first, serde_json::json!([["rollback-order", "one"]])).await?;
    sql_append(
        &mut first,
        &ordered("rollback-first", "rollback-order", "one"),
    )
    .await?;
    // Different domain and different key can each advance while the first partition is locked.
    let mut second = sql_tx(raw, tenant).await?;
    sql_prepare(
        &mut second,
        serde_json::json!([["rollback-order", "two"], ["other-domain", "one"]]),
    )
    .await?;
    sql_append(
        &mut second,
        &ordered("independent-key", "rollback-order", "two"),
    )
    .await?;
    sql_append(
        &mut second,
        &ordered("independent-domain", "other-domain", "one"),
    )
    .await?;
    second.commit().await?;
    let other = TenantId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")?;
    let mut independent = sql_tx(raw, other).await?;
    sql_prepare(
        &mut independent,
        serde_json::json!([["rollback-order", "one"]]),
    )
    .await?;
    sql_append(
        &mut independent,
        &ordered_in(other, "independent-tenant", "rollback-order", "one"),
    )
    .await?;
    independent.commit().await?;
    let mut second = sql_tx(raw, tenant).await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *second)
        .await?;
    let waiting = async {
        sql_prepare(&mut second, serde_json::json!([["rollback-order", "one"]])).await?;
        sql_append(
            &mut second,
            &ordered("rollback-successor", "rollback-order", "one"),
        )
        .await?;
        second.commit().await
    };
    let release = async {
        let observed = wait_lock(owner, pid).await;
        first.rollback().await?;
        observed
    };
    let (written, released) = tokio::join!(waiting, release);
    written?;
    released?;
    let rows: Vec<(String,i64)> = sqlx::query_as("SELECT message_id,partition_seq FROM rss_transactional_messaging.outbox WHERE domain='rollback-order' AND partition_key='one' AND message_id<>'independent-tenant'").fetch_all(owner).await?;
    assert_eq!(rows, vec![("rollback-successor".into(), 1)]);
    Ok(())
}

async fn opposite_declarations(owner: &PgPool, raw: &PgPool) -> anyhow::Result<()> {
    let tenant = message("sql").metadata().tenant_id();
    // Pause the first declaration at its second canonical key. A reverse-order
    // implementation lets the contender take that first key and creates a cycle.
    let mut blocker = sql_tx(owner, tenant).await?;
    sql_prepare(&mut blocker, serde_json::json!([["multi-order", "z"]])).await?;
    let mut first = sql_tx(raw, tenant).await?;
    let first_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *first)
        .await?;
    let first = tokio::spawn(async move {
        sql_prepare(
            &mut first,
            serde_json::json!([["multi-order", "z"], ["multi-order", "a"]]),
        )
        .await?;
        sql_append(&mut first, &ordered("multi-first", "multi-order", "a")).await?;
        first.commit().await
    });
    wait_lock(owner, first_pid).await?;
    let mut second = sql_tx(raw, tenant).await?;
    let second_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *second)
        .await?;
    let second = tokio::spawn(async move {
        sql_prepare(
            &mut second,
            serde_json::json!([["multi-order", "a"], ["multi-order", "z"]]),
        )
        .await?;
        sql_append(&mut second, &ordered("multi-second", "multi-order", "a")).await?;
        second.commit().await
    });
    let observed = wait_lock(owner, second_pid).await;
    blocker.rollback().await?;
    first.await??;
    second.await??;
    observed?;
    let rows: Vec<(String,i64)> = sqlx::query_as("SELECT message_id,partition_seq FROM rss_transactional_messaging.outbox WHERE domain='multi-order' ORDER BY partition_seq").fetch_all(owner).await?;
    assert_eq!(
        rows,
        vec![("multi-first".into(), 1), ("multi-second".into(), 2)]
    );
    Ok(())
}

async fn ignored_errors(runtime: Arc<PgRuntime>, owner: &PgPool) -> anyhow::Result<()> {
    let tenant = message("ignored-error").metadata().tenant_id();
    let writer = PgOutboxWriter::new(runtime.clone(), MessagingDomain::parse("ignored-error")?);
    let outcome = runtime.local_tx(tenant,deadline(),move |tx| Box::pin(async move {
        tx.with_connection(|c| Box::pin(async {
            sqlx::query("INSERT INTO public.business_effects VALUES(current_setting('rss.tenant_id')::uuid,'ignored-partition-error')").execute(c).await.map(|_| ())
        })).await?;
        assert!(writer.append(tx,PendingMessage::new(ordered("ignored-error","ignored-error","one"))).await.is_err());
        Ok(())
    })).await;
    assert!(outcome.fold(
        |_| false,
        |_| false,
        |_| true,
        |_| false,
        |_| false,
        |_| false
    ));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.business_effects WHERE id='ignored-partition-error'",
    )
    .fetch_one(owner)
    .await?;
    assert_eq!(count, 0);
    Ok(())
}

async fn cancelled_preparation(
    runtime: Arc<PgRuntime>,
    owner: &PgPool,
    raw: &PgPool,
) -> anyhow::Result<()> {
    let tenant = message("cancel").metadata().tenant_id();
    let mut blocker = sql_tx(raw, tenant).await?;
    sql_prepare(&mut blocker, serde_json::json!([["cancel-order", "z"]])).await?;
    let (send, receive) = tokio::sync::oneshot::channel();
    let (cancelled, acknowledgment) = tokio::sync::oneshot::channel();
    let cancel = Arc::new(tokio::sync::Notify::new());
    let signal = cancel.clone();
    let operation = runtime.local_tx(tenant,deadline(),move |tx| Box::pin(async move {
        let pid: i32 = tx.with_connection(|c|Box::pin(sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(c))).await?;
        let _ = send.send(pid);
        let partitions: Vec<_> = ["a","z"].into_iter().map(|key| ordered("cancel","cancel-order",key).metadata().partition().expect("partition").clone()).collect();
        tokio::select! {
            result = tx.prepare_outbox_partitions(&partitions) => { result?; return Err(PgError::InvalidConnectionConfig); }
            () = signal.notified() => {}
        }
        let _ = cancelled.send(());
        Ok(()) // The owner must still roll back after the admission future was dropped.
    }));
    let release = async {
        let observed = wait_lock(owner, receive.await?).await;
        cancel.notify_one();
        acknowledgment.await?;
        blocker.rollback().await?;
        observed
    };
    let (outcome, released) = tokio::join!(operation, release);
    released?;
    assert!(outcome.fold(
        |_| false,
        |_| false,
        |_| true,
        |_| false,
        |_| false,
        |_| false
    ));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox_partitions WHERE domain='cancel-order' AND partition_key='a'").fetch_one(owner).await?;
    assert_eq!(count, 0);
    Ok(())
}

struct RejectedAppend(PgOutboxWriter);
impl PgConsumerEffect<Vec<u8>> for RejectedAppend {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        _: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        let item = ordered("rejected-outbox", "rejected-outbox", "one");
        tx.prepare_outbox_partitions(
            &item
                .metadata()
                .partition()
                .cloned()
                .into_iter()
                .collect::<Vec<_>>(),
        )
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
        self.0
            .append(tx, PendingMessage::new(item))
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        Ok(TerminalDisposition::Rejected(RejectKind::Permanent))
    }
}

async fn rejected_effect(runtime: Arc<PgRuntime>, owner: &PgPool) -> anyhow::Result<()> {
    let item = message("rejected-outbox-input");
    let verified = binding(&item);
    let inbox = PgInboxStore::new(
        runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))?,
    )?;
    let IdempotencyDisposition::Acquired(claim) =
        inbox.claim(verified.identity(), deadline()).await?
    else {
        anyhow::bail!("fresh inbox");
    };
    let effect = RejectedAppend(PgOutboxWriter::new(
        runtime.clone(),
        MessagingDomain::parse("rejected-outbox")?,
    ));
    let outcome = PgConsumerTx::receipt_only(runtime, effect)
        .execute(&claim, &item, verified.receipt_intent(), deadline())
        .await;
    assert_eq!(outcome.status(),rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus::Committed);
    assert!(
        inbox
            .read_terminal(verified.identity(), deadline())
            .await?
            .is_some()
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox_partitions WHERE domain='rejected-outbox'").fetch_one(owner).await?;
    assert_eq!(count, 0);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id='rejected-outbox'").fetch_one(owner).await?;
    assert_eq!(count, 0);
    Ok(())
}

async fn cached_row_ids(
    runtime: Arc<PgRuntime>,
    owner: &PgPool,
    raw: &PgPool,
) -> anyhow::Result<()> {
    sqlx::query("ALTER SEQUENCE rss_transactional_messaging.outbox_seq_seq CACHE 10")
        .execute(owner)
        .await?;
    let result = cached_order(runtime, owner, raw).await;
    sqlx::query("ALTER SEQUENCE rss_transactional_messaging.outbox_seq_seq CACHE 1")
        .execute(owner)
        .await?;
    result
}

#[allow(clippy::cognitive_complexity)] // reason: the ordered connection/cache protocol and resulting claims form one indivisible regression scenario.
async fn cached_order(runtime: Arc<PgRuntime>, owner: &PgPool, raw: &PgPool) -> anyhow::Result<()> {
    let tenant = message("cached").metadata().tenant_id();
    // Two fresh dedicated connections make sequence cache reservation order deterministic.
    let options = (*raw.connect_options()).clone();
    use sqlx::Connection;
    let mut first = sqlx::PgConnection::connect_with(&options).await?;
    let mut second = sqlx::PgConnection::connect_with(&options).await?;
    // Reuse the bounded tenant setup SQL from fixture-owned transactions on the dedicated leases.
    let settings = "BEGIN; SELECT set_config('rss.tenant_id','f47ac10b-58cc-4372-a567-0e02b2c3d479',true),set_config('rss.storage_target','01010101010101010101010101010101',true),set_config('rss.storage_lineage','02020202020202020202020202020202',true),set_config('rss.execution_epoch','1',true),set_config('statement_timeout','3s',true);";
    sqlx::raw_sql(settings).execute(&mut first).await?;
    sql_prepare(
        &mut first,
        serde_json::json!([["cache-reservation", "one"]]),
    )
    .await?;
    sql_append(
        &mut first,
        &ordered("cache-reserve", "cache-reservation", "one"),
    )
    .await?;
    sqlx::query("COMMIT").execute(&mut first).await?;
    sqlx::raw_sql(settings).execute(&mut second).await?;
    sql_prepare(&mut second, serde_json::json!([["cache-order", "one"]])).await?;
    sql_append(&mut second, &ordered("cache-first", "cache-order", "one")).await?;
    sqlx::query("COMMIT").execute(&mut second).await?;
    sqlx::raw_sql(settings).execute(&mut first).await?;
    sql_prepare(&mut first, serde_json::json!([["cache-order", "one"]])).await?;
    sql_append(&mut first, &ordered("cache-second", "cache-order", "one")).await?;
    sqlx::query("COMMIT").execute(&mut first).await?;
    first.close().await?;
    second.close().await?;
    let ids: Vec<(i64,i64)> = sqlx::query_as("SELECT seq,partition_seq FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain='cache-order' ORDER BY partition_seq").bind(tenant.to_string()).fetch_all(owner).await?;
    assert_eq!(ids.len(), 2);
    assert!(
        ids[0].0 > ids[1].0,
        "physical row IDs must be reversed for this proof"
    );
    let store = PgOutboxStore::<()>::new(
        runtime,
        MessagingDomain::parse("cache-order")?,
        outbox_budget(Duration::from_secs(30)),
    )?;
    for id in ["cache-first", "cache-second"] {
        let claim = store
            .claim_partition_heads(NonZeroUsize::MIN, deadline())
            .await?
            .into_iter()
            .next()
            .expect("head");
        assert_eq!(
            PgOutboxStore::<()>::message(&claim).message_id().as_str(),
            id
        );
        store
            .settle(claim, OutboxSettlement::Published(()), deadline())
            .await?;
    }
    Ok(())
}

#[allow(clippy::cognitive_complexity)] // reason: reversible catalog drift cases preserve restore-before-assert for every incompatible shape.
async fn permission_drift(owner: &PgPool, config: PgConfig) -> anyhow::Result<()> {
    let mut tx = owner.begin().await?;
    let error = sqlx::raw_sql(OUTBOX_MESSAGE_UPGRADE_SQL)
        .execute(&mut *tx)
        .await
        .expect_err("unverified historical rows cannot be backfilled");
    assert_eq!(code(&error).as_deref(), Some("23514"));
    tx.rollback().await?;

    for (grant, revoke) in [
        (
            "GRANT INSERT ON rss_transactional_messaging.outbox TO tmsg_runtime",
            "REVOKE INSERT ON rss_transactional_messaging.outbox FROM tmsg_runtime",
        ),
        (
            "GRANT UPDATE(prepared_by) ON rss_transactional_messaging.outbox_partitions TO tmsg_runtime",
            "REVOKE UPDATE(prepared_by) ON rss_transactional_messaging.outbox_partitions FROM tmsg_runtime",
        ),
        (
            "GRANT USAGE ON SEQUENCE rss_transactional_messaging.outbox_seq_seq TO tmsg_runtime",
            "REVOKE USAGE ON SEQUENCE rss_transactional_messaging.outbox_seq_seq FROM tmsg_runtime",
        ),
    ] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(grant))
            .execute(owner)
            .await?;
        let result =
            PgRuntime::connect(config.clone(), Timer::new(), fence_fixture::binding()).await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(revoke))
            .execute(owner)
            .await?;
        assert!(matches!(
            result,
            Err(PgError::IncompatibleStorageContract(
                PgStorageContractFailure::RuntimeAcl
            ))
        ));
    }
    for (change, restore, expected) in [
        (
            "GRANT EXECUTE ON FUNCTION rss_transactional_messaging.decode_outbox_message(bytea) TO tmsg_runtime",
            "REVOKE EXECUTE ON FUNCTION rss_transactional_messaging.decode_outbox_message(bytea) FROM tmsg_runtime",
            PgStorageContractFailure::Functions,
        ),
        (
            "ALTER FUNCTION rss_transactional_messaging.read_outbox_frame(bytea,integer,integer) SECURITY DEFINER",
            "ALTER FUNCTION rss_transactional_messaging.read_outbox_frame(bytea,integer,integer) SECURITY INVOKER",
            PgStorageContractFailure::Functions,
        ),
        (
            "CREATE FUNCTION rss_transactional_messaging.append_outbox(text,text,text,jsonb,bytea) RETURNS text LANGUAGE sql AS 'SELECT NULL::text'",
            "DROP FUNCTION rss_transactional_messaging.append_outbox(text,text,text,jsonb,bytea)",
            PgStorageContractFailure::Functions,
        ),
        (
            "ALTER TABLE rss_transactional_messaging.outbox_partitions ALTER COLUMN prepared_by DROP NOT NULL",
            "ALTER TABLE rss_transactional_messaging.outbox_partitions ALTER COLUMN prepared_by SET NOT NULL",
            PgStorageContractFailure::Columns,
        ),
        (
            "ALTER TABLE rss_transactional_messaging.outbox_partitions DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE rss_transactional_messaging.outbox_partitions ENABLE ROW LEVEL SECURITY",
            PgStorageContractFailure::RuntimeAcl,
        ),
        (
            "ALTER FUNCTION rss_transactional_messaging.append_outbox(bytea,jsonb) SECURITY INVOKER",
            "ALTER FUNCTION rss_transactional_messaging.append_outbox(bytea,jsonb) SECURITY DEFINER",
            PgStorageContractFailure::Functions,
        ),
    ] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(change))
            .execute(owner)
            .await?;
        let result =
            PgRuntime::connect(config.clone(), Timer::new(), fence_fixture::binding()).await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(restore))
            .execute(owner)
            .await?;
        assert!(
            matches!(result,Err(PgError::IncompatibleStorageContract(actual)) if actual==expected)
        );
    }
    Ok(())
}

async fn timed_out_preparation(
    runtime: Arc<PgRuntime>,
    owner: &PgPool,
    raw: &PgPool,
) -> anyhow::Result<()> {
    let tenant = message("timeout").metadata().tenant_id();
    let mut blocker = sql_tx(raw, tenant).await?;
    sql_prepare(&mut blocker, serde_json::json!([["timeout-order", "z"]])).await?;
    let outcome = runtime
        .local_tx(tenant, deadline(), |tx| {
            Box::pin(async move {
                tx.with_connection(|c| {
                    Box::pin(async {
                        sqlx::query("SET LOCAL lock_timeout='25ms'")
                            .execute(c)
                            .await
                            .map(|_| ())
                    })
                })
                .await?;
                let partitions: Vec<_> = ["a", "z"]
                    .into_iter()
                    .map(|key| {
                        ordered("timeout", "timeout-order", key)
                            .metadata()
                            .partition()
                            .expect("partition")
                            .clone()
                    })
                    .collect();
                tx.prepare_outbox_partitions(&partitions).await
            })
        })
        .await;
    blocker.rollback().await?;
    assert!(outcome.fold(
        |_| false,
        |_| false,
        |error| error.kind() == rss_transactional_messaging::error::MessagingErrorKind::Transient,
        |_| false,
        |_| false,
        |_| false
    ));
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox_partitions WHERE domain='timeout-order'").fetch_one(owner).await?;
    assert_eq!(count, 0);
    Ok(())
}

async fn ignored_conflict(runtime: Arc<PgRuntime>, owner: &PgPool) -> anyhow::Result<()> {
    let tenant = message("ignored-conflict").metadata().tenant_id();
    let first = ordered("ignored-conflict", "ignored-conflict", "one");
    let conflict = MessageEnvelope::new(first.id().clone(), first.metadata().clone(), vec![9]);
    let writer = PgOutboxWriter::new(runtime.clone(), MessagingDomain::parse("ignored-conflict")?);
    runtime
        .local_tx(tenant, deadline(), move |tx| {
            Box::pin(async move {
                tx.prepare_outbox_partitions(
                    &first
                        .metadata()
                        .partition()
                        .cloned()
                        .into_iter()
                        .collect::<Vec<_>>(),
                )
                .await?;
                writer
                    .append(tx, PendingMessage::new(first))
                    .await
                    .map_err(Into::into)
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    let writer = PgOutboxWriter::new(runtime.clone(), MessagingDomain::parse("ignored-conflict")?);
    let result=runtime.local_tx(tenant,deadline(),move |tx|Box::pin(async move {
        tx.prepare_outbox_partitions(&conflict.metadata().partition().cloned().into_iter().collect::<Vec<_>>()).await?;
        tx.with_connection(|c|Box::pin(async {sqlx::query("INSERT INTO public.business_effects VALUES(current_setting('rss.tenant_id')::uuid,'ignored-conflict-effect')").execute(c).await.map(|_|())})).await?;
        assert_eq!(writer.append(tx,PendingMessage::new(conflict)).await.expect_err("fingerprint conflict").kind(),rss_transactional_messaging::error::MessagingErrorKind::Conflict);
        Ok(())
    })).await;
    assert!(
        result.fold(
            |_| false,
            |_| false,
            |_| true,
            |_| false,
            |_| false,
            |_| false
        ),
        "swallowed fingerprint conflict must roll back the transaction"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.business_effects WHERE id='ignored-conflict-effect'",
    )
    .fetch_one(owner)
    .await?;
    assert_eq!(count, 0);
    Ok(())
}

async fn ignored_foreign_partition(runtime: Arc<PgRuntime>, owner: &PgPool) -> anyhow::Result<()> {
    let tenant = message("foreign-partition").metadata().tenant_id();
    let other = TenantId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")?;
    let partition = ordered_in(other, "foreign-partition", "foreign-partition", "one")
        .metadata()
        .partition()
        .expect("partition")
        .clone();
    let result=runtime.local_tx(tenant,deadline(),move |tx|Box::pin(async move {
        tx.with_connection(|c|Box::pin(async {sqlx::query("INSERT INTO public.business_effects VALUES(current_setting('rss.tenant_id')::uuid,'ignored-foreign-partition')").execute(c).await.map(|_|())})).await?;
        assert!(tx.prepare_outbox_partitions(&[partition]).await.is_err());
        Ok(())
    })).await;
    assert!(result.fold(
        |_| false,
        |_| false,
        |_| true,
        |_| false,
        |_| false,
        |_| false
    ));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.business_effects WHERE id='ignored-foreign-partition'",
    )
    .fetch_one(owner)
    .await?;
    assert_eq!(count, 0);
    Ok(())
}

async fn sql_digest_integrity(raw: &PgPool) -> anyhow::Result<()> {
    let item = ordered("digest-integrity", "sql-integrity", "one");
    let mut tx = sql_tx(raw, item.metadata().tenant_id()).await?;
    sql_prepare(&mut tx, serde_json::json!([["sql-integrity", "one"]])).await?;
    assert_eq!(sql_append(&mut tx, &item).await?, "inserted");
    let mut altered = frames(&item);
    altered.last_mut().expect("payload").1 = vec![99];
    let outcome: String =
        sqlx::query_scalar("SELECT rss_transactional_messaging.append_outbox($1,$2)")
            .bind(wire(&altered))
            .bind(transport(&item))
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(
        outcome, "conflict",
        "different authored facts cannot reuse an unverified digest"
    );
    tx.rollback().await?;
    Ok(())
}
