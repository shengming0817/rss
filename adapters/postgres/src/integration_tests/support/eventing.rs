use super::*;

pub(in super::super) use std::collections::{BTreeMap, HashMap};

pub(in super::super) use std::sync::atomic::{AtomicU32, Ordering};

pub(in super::super) use std::sync::{Arc, Mutex};

pub(in super::super) use consistency::{
    BacklogMetricSample, BacklogSample, Disposition, EngineErrorKind, EventEntry, EventTopic,
    HandleResult, OutboxAppendOutcome, OutboxBacklog, OutboxFactIdentity, OutboxRelay,
    RetentionSweeper,
};

pub(in super::super) use diport::{
    AckAction, Acker, DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, Delivery,
    DeliveryStream, DynAcker, DynDeadLetterStore, DynPublisher, EnvelopeMetadata, KEY_ACTOR,
    KEY_CORRELATION, KEY_OCCURRED_AT, KEY_PRINCIPAL, KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION,
    KEY_SUBJECT_ID, KEY_TENANT_AUTHORITY, KEY_TENANT_ID, KEY_TRACE, Message, OutboxEmitErrorKind,
    PublishRequest, Publisher, PublisherError,
};

pub(in super::super) use eventexec::{
    ConsumerMeta, LeaseConfig, MAX_REDELIVERY, RelayBudget, TenantAuthority,
    TenantAuthorityBinding, run_consumer_ackable,
};

pub(in super::super) use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};

pub(in super::super) use testkit::eventing_conformance as eventconf;

pub(in super::super) use crate::dead_letter_payload::tests::test_protector;

pub(in super::super) use crate::outbox::{
    MAX_PUBLISH_ATTEMPTS, OutboxAppendError, OutboxEnvelope, OutboxMetadata, PgClaimedOutboxEntry,
    PgOutbox, STATUS_PUBLISHED, append_outbox, append_outbox_with_projection,
};

pub(in super::super) use crate::outbox_cdc::append_outbox_log;

pub(in super::super) static OUTBOX_SWEEP_TEST_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

pub(in super::super) fn test_append_error(_: OutboxAppendError) -> sqlx::Error {
    sqlx::Error::Protocol("outbox append test failed".to_string())
}

pub(in super::super) fn eventing_test_db(
    store: &PgStore,
) -> crate::cotx::TenantDb<crate::cotx::ServingWriteLane> {
    crate::cotx::TenantDb::<crate::cotx::ServingWriteLane>::from_unverified_for_test(store)
}

/// setup 阶段：应用 migration（含 outbox 表）。**不**全表 DELETE——每个 outbox 用例按唯一 `event_id`
/// （[`unique_event_id`]）+ 唯一 domain 命名空间自隔离断言（`WHERE event_id = $1` / domain-scoped 查询用各自
/// 专属 domain），故无需净表起点。去掉全表清后用例 correct-by-construction：在并发执行下亦互不污染——既覆盖
/// 官方串行 lane（`cargo nextest run --profile integration`，`.config/nextest.toml` `integration` test-group
/// `max-threads=1`），也覆盖直接 `cargo test -p postgres --features integration`（libtest 并行、绕过 nextest
/// 串行组）这条残留路径，隔离不再依赖调度器串行（#1194；nextest 串行组保留作 defense-in-depth）。
pub(in super::super) async fn setup_outbox(
    store: &PgStore,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    store.run_migrations().await?;
    store
        .register_projection_input_bindings(
            TEST_PROJECTION_INPUT_GENERATION,
            TEST_PROJECTION_INPUTS,
        )
        .await?;
    Ok(())
}

pub(in super::super) async fn register_generated_projection_input_catalog(
    store: &PgStore,
) -> TestResult {
    #[cfg(feature = "test-support")]
    {
        let plan = eventexec::WorkflowRuntimePlan::generated_projection_capture_fixture();
        let capture = crate::projection_events::ProjectionCaptureRegistration::from_capture(
            plan.projection_capture(),
        )
        .ok_or_else(|| std::io::Error::other("generated capture fixture was unexpectedly empty"))?;
        store.register_projection_capture(&capture).await?;
        store
            .validate_projection_capture_registration(&capture)
            .await?;
        Ok(())
    }

    #[cfg(not(feature = "test-support"))]
    {
        for binding in generated::event::PROJECTION_INPUTS {
            let definition = generated::event::PROJECTION_DEFINITIONS
                .iter()
                .find(|definition| definition.contract_id() == binding.projection_id())
                .ok_or_else(|| {
                    std::io::Error::other("generated projection input lacks definition")
                })?;
            sqlx::query(
                "SELECT public.rss_register_projection_input_binding(\
                 $1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(generated::event::PROJECTION_INPUT_GENERATION)
            .bind(binding.projection_id())
            .bind(definition.version())
            .bind(definition.schema_hash())
            .bind(binding.domain())
            .bind(binding.contract_id())
            .bind(binding.version())
            .bind(binding.schema_hash())
            .bind(binding.topic())
            .execute(&store.pool)
            .await?;
        }
        Ok(())
    }
}

pub(in super::super) async fn append_generated_projection_source_event(
    store: &PgStore,
    app: &PgStore,
    binding: vocab::ProjectionInputBinding,
    event_id: &str,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    append_generated_projection_source_event_for_tenant(
        store,
        app,
        binding,
        event_id,
        test_tenant(),
    )
    .await
}

pub(in super::super) async fn prepare_generated_projection_source_outbox_event(
    store: &PgStore,
    binding: vocab::ProjectionInputBinding,
    event_id: &str,
    tenant: vocab::TenantId,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    prepare_generated_projection_source_outbox_event_with_payload(
        store,
        binding,
        event_id,
        tenant,
        binding.projection_id().as_bytes(),
    )
    .await
}

pub(in super::super) async fn prepare_generated_projection_source_outbox_event_with_payload(
    store: &PgStore,
    binding: vocab::ProjectionInputBinding,
    event_id: &str,
    tenant: vocab::TenantId,
    payload: &[u8],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let entry = EventEntry::new(
        EventTopic::parse(binding.topic())?,
        IdemKey::parse(event_id)?,
        reviewed_payload(payload),
    );
    let env = OutboxEnvelope::new(
        binding.domain().to_owned(),
        binding.contract_id().to_owned(),
        OutboxMetadata::new(
            0,
            tenant,
            vocab::ContractBinding::from_static(
                binding.domain(),
                binding.contract_id(),
                binding.version(),
                binding.schema_hash(),
            ),
        ),
    );
    let metadata = env.metadata_json();
    eventing_test_db(store)
        .test_write(
            integration_tenant_scope(tenant),
            move |cap| {
                let entry = entry.clone();
                let env = env.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            },
            std::convert::identity,
        )
        .await?;
    Ok(metadata)
}

pub(in super::super) async fn append_generated_projection_source_event_for_tenant(
    store: &PgStore,
    app: &PgStore,
    binding: vocab::ProjectionInputBinding,
    event_id: &str,
    tenant: vocab::TenantId,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    append_generated_projection_source_event_with_payload_for_tenant(
        store,
        app,
        binding,
        event_id,
        tenant,
        binding.projection_id().as_bytes(),
    )
    .await
}

pub(in super::super) async fn append_generated_projection_source_event_with_payload_for_tenant(
    store: &PgStore,
    app: &PgStore,
    binding: vocab::ProjectionInputBinding,
    event_id: &str,
    tenant: vocab::TenantId,
    payload: &[u8],
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let metadata = prepare_generated_projection_source_outbox_event_with_payload(
        store, binding, event_id, tenant, payload,
    )
    .await?;

    let mut tx = app.pool.begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let (lsn,): (i64,) = sqlx::query_as(
        "SELECT public.rss_append_projection_event(\
         $1, $2, $1, $3, $4, NULL, $5, $6, $7, $8::jsonb, NULL, NULL)",
    )
    .bind(event_id)
    .bind(binding.domain())
    .bind(binding.topic())
    .bind(payload)
    .bind(binding.contract_id())
    .bind(binding.version())
    .bind(binding.schema_hash())
    .bind(metadata)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(lsn)
}

pub(in super::super) async fn projection_source_high_water(
    operator: &crate::pool::VerifiedPgProjectionOperatorStore,
    pool: &sqlx::PgPool,
    scope: &eventexec::ProjectionSourceScope,
) -> Result<Option<i64>, sqlx::Error> {
    let (capability_first, capability_second) = issue_projection_source_capability(
        operator,
        scope.tenant().as_uuid(),
        scope.projection().as_str(),
        scope.definition_version(),
        scope.definition_schema_digest(),
        scope.input_generation(),
    )
    .await?;
    sqlx::query_scalar(
        "SELECT public.rss_projection_source_high_water_scoped(\
         $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)",
    )
    .bind(&capability_first)
    .bind(&capability_second)
    .bind(scope.tenant().to_string())
    .bind(scope.projection().as_str())
    .bind(scope.definition_version())
    .bind(scope.definition_schema_digest())
    .bind(scope.input_generation())
    .fetch_one(pool)
    .await
}

pub(in super::super) async fn issue_projection_source_capability(
    operator: &crate::pool::VerifiedPgProjectionOperatorStore,
    tenant: uuid::Uuid,
    projection: &str,
    definition_version: &str,
    definition_digest: &str,
    generation: &str,
) -> Result<(String, String), sqlx::Error> {
    sqlx::query_as(
        "SELECT capability_first::text, capability_second::text \
         FROM public.rss_projection_operator_issue_source_capability(\
         $1::uuid, $2, $3, $4, $5)",
    )
    .bind(tenant.to_string())
    .bind(projection)
    .bind(definition_version)
    .bind(definition_digest)
    .bind(generation)
    .fetch_one(&operator.store_arc().pool)
    .await
}

pub(in super::super) fn projection_high_water_plan_shared_blocks(
    plan: &serde_json::Value,
) -> Option<u64> {
    let root = plan.get(0)?.get("Plan")?;
    ["Shared Hit Blocks", "Shared Read Blocks"]
        .into_iter()
        .try_fold(0_u64, |total, key| {
            root.get(key)
                .and_then(serde_json::Value::as_u64)
                .map(|blocks| total.saturating_add(blocks))
        })
}

pub(in super::super) fn assert_database_sqlstate(
    error: &sqlx::Error,
    expected: &str,
    context: &str,
) {
    let sqlstate = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|code| code.into_owned());
    assert_eq!(
        sqlstate.as_deref(),
        Some(expected),
        "{context} returned the wrong SQLSTATE: {error}"
    );
}

#[derive(Default)]
pub(in super::super) struct RecordingProjectionTargetStore {
    pub(in super::super) applied: std::sync::Mutex<Vec<(String, u64)>>,
}

impl RecordingProjectionTargetStore {
    pub(in super::super) fn applied(&self) -> Vec<(String, u64)> {
        self.applied
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl eventexec::ProjectionTargetStore for RecordingProjectionTargetStore {
    fn apply<'a>(
        &'a self,
        input: &'a eventexec::ValidatedProjectionApply,
    ) -> BoxFuture<
        'a,
        Result<eventexec::ProjectionTargetStoreOutcome, eventexec::ProjectionTargetStoreError>,
    > {
        Box::pin(async move {
            self.applied
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((input.key().event_id().to_owned(), input.lsn().get()));
            Ok(eventexec::ProjectionTargetStoreOutcome::Applied)
        })
    }
}

/// 测试专用 terminal fixture：状态、对应终态时间与 updated_at 必须在同一 UPDATE 中保持一致。
pub(in super::super) async fn set_outbox_terminal_for_test(
    store: &PgStore,
    event_id: &str,
    status: &str,
    age_seconds: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE outbox
        SET status = $1,
            lease_token = CASE
                WHEN $1 = 'publishing' THEN gen_random_uuid()
                ELSE NULL
            END,
            lease_until = CASE
                WHEN $1 = 'publishing' THEN now() + interval '60 seconds'
                ELSE NULL
            END,
            automatic_retry_deadline = CASE
                WHEN $1 IN ('publishing', 'published', 'dlx') THEN
                    COALESCE(automatic_retry_deadline, now() + interval '24 hours')
                ELSE automatic_retry_deadline
            END,
            same_id_redrive_deadline = CASE
                WHEN $1 = 'dlx' THEN
                    COALESCE(same_id_redrive_deadline, now() + interval '24 hours')
                ELSE same_id_redrive_deadline
            END,
            published_at = CASE
                WHEN $1 = 'published' THEN now() - make_interval(secs => $2::double precision)
                ELSE NULL
            END,
            dlx_at = CASE
                WHEN $1 = 'dlx' THEN now() - make_interval(secs => $2::double precision)
                ELSE NULL
            END,
            created_at = now() - make_interval(secs => $2::double precision),
            updated_at = now() - make_interval(secs => $2::double precision)
        WHERE event_id = $3
        "#,
    )
    .bind(status)
    .bind(age_seconds)
    .bind(event_id)
    .execute(&store.pool)
    .await?;
    Ok(())
}

/// 产生唯一 event_id（防并发测试冲突）。
#[allow(clippy::disallowed_methods)]
// reason: SystemTime::now() 仅用于测试隔离产生唯一 id，非时钟注入场景；item-level carve-out（error-handling.md §Carve-out）。
pub(in super::super) fn unique_event_id(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{prefix}-{nanos}-{}", uuid_like())
}

/// 简单递增计数器生成伪唯一后缀（不引 uuid crate）。
pub(in super::super) fn uuid_like() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    format!("{:x}", CTR.fetch_add(1, Ordering::Relaxed))
}

/// 产生唯一 domain（防 **domain-scoped 聚合断言**被跨轮 / 并发旧行污染）——与 [`unique_event_id`] 同源唯一性。
///
/// INVARIANT：按 domain 聚合且断言**精确 depth/计数**的用例（t16–t19 的 `sample_backlog`）必须用 **per-run 唯一**
/// domain。`outbox.event_id` UNIQUE + `ON CONFLICT (event_id) DO NOTHING` 只隔离**单行** `WHERE event_id` 查询；
/// 对 `sample_backlog(domain)` 这种**按 domain 聚合**的查询不够——外部持久库重复跑时，上一轮同 domain 旧行会被
/// 计入，使精确 depth 累加而 flaky（#1194 review F1）。去全表 DELETE 后唯一隔离手段即「event_id + domain 双唯一」。
pub(in super::super) fn unique_domain(prefix: &str) -> String {
    unique_event_id(prefix).replace('-', "_")
}

/// 构造测试用 EventEntry + Envelope。
pub(in super::super) fn make_entry(event_id: &str) -> EventEntry {
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 构造已知合法值，item-level carve-out（error-handling.md §Carve-out）。
    EventEntry::new(
        EventTopic::parse("test.event").unwrap(),
        IdemKey::parse(event_id).unwrap(),
        reviewed_payload(b"payload"),
    )
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn generated_entry<P: serde::Serialize>(
    fact: vocab::EventFactBinding,
    payload: &P,
    idempotency_key: IdemKey,
) -> Result<EventEntry, serde_json::Error> {
    Ok(EventEntry::new(
        EventTopic::parse(fact.topic()).unwrap(),
        idempotency_key,
        reviewed_payload(&serde_json::to_vec(payload)?),
    ))
}

/// Re-author an encoded fixture through the sealed generated contract before it reaches a
/// production provider port. This keeps integration tests able to vary envelope scope and durable
/// metadata without granting ordinary `EventEntry` values a production conversion path.
pub(in super::super) async fn reviewed_generated_event<C>(
    entry: EventEntry,
    envelope: OutboxEnvelopeParts,
) -> Result<eventexec::event::ReviewedEvent, TestError>
where
    C: generated::event::EventContract,
    C::Payload: serde::de::DeserializeOwned + Send + Sync,
{
    if entry.topic().as_str() != C::FACT.topic() || envelope.contract() != &C::SPEC.contract() {
        return Err("fixture topic or contract does not match its generated event contract".into());
    }
    let payload = serde_json::from_slice::<C::Payload>(entry.payload())?;
    let idempotency_key = entry.idem_key().clone();
    let (_contract, tenant, subject_id, actor, partition_key, causation_id) = envelope.into_parts();
    if partition_key.is_some() || causation_id.is_some() {
        return Err("fixture cannot override generated transport coordinates after review".into());
    }
    let reviewed = generated::event::EventEmit::emit::<C>(
        &eventexec::event::GeneratedEventEncoder,
        &payload,
        tenant,
        subject_id,
        actor,
        idempotency_key,
    )
    .await?;
    Ok(reviewed)
}

pub(in super::super) async fn reviewed_session_event(
    event_id: &str,
    tenant: vocab::TenantId,
    envelope_subject: &str,
    actor: diport::OutboxActor,
    session_id: &str,
) -> Result<eventexec::event::ReviewedEvent, TestError> {
    Ok(generated::event::identity_v1::session_created::emit(
        &eventexec::event::GeneratedEventEncoder,
        generated::event::identity_v1::session_created::IdentitySessionCreatedPayload {
            session_id: session_id.to_owned(),
            subject: uuid::Uuid::from_u128(0x51),
            tenant_id: tenant.to_string(),
            occurred_at: expected_occurred_at(),
        },
        tenant,
        subject_id(envelope_subject),
        actor,
        IdemKey::parse(event_id)?,
    )
    .await?)
}

pub(in super::super) async fn claimed_entry_for_event(
    store: &PgStore,
    event_id: &str,
) -> Result<PgClaimedOutboxEntry, String> {
    let domain: String = sqlx::query_scalar("SELECT domain FROM outbox WHERE event_id = $1")
        .bind(event_id)
        .fetch_one(&store.pool)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let outbox = make_pg_outbox_for_domain(
        store,
        &domain,
        RecordingPublisher {
            result: || Ok(()),
            calls: Arc::new(Mutex::new(0)),
        },
    );
    outbox
        .claim_batch(10_000)
        .await
        .map_err(|e| format!("{e:?}"))?
        .into_iter()
        .find(|entry| entry.idem_key().as_str() == event_id)
        .ok_or_else(|| format!("claim_batch did not return event {event_id}"))
}

pub(in super::super) async fn claim_entry_for_relay(
    outbox: &PgOutbox,
    event_id: &str,
) -> Result<PgClaimedOutboxEntry, String> {
    outbox
        .claim_batch(10_000)
        .await
        .map_err(|error| format!("{error:?}"))?
        .into_iter()
        .find(|entry| entry.idem_key().as_str() == event_id)
        .ok_or_else(|| format!("provider-bound claim did not return event {event_id}"))
}

pub(in super::super) fn summarize_backlog(samples: &[BacklogMetricSample]) -> BacklogSample {
    let depth = samples.iter().map(|s| s.sample().depth()).sum();
    let oldest_age_seconds = samples
        .iter()
        .map(|s| s.sample().oldest_age_seconds())
        .max()
        .unwrap_or(0);
    BacklogSample::new(depth, oldest_age_seconds)
}

pub(in super::super) fn active_backlog(
    observation: BacklogObservation,
) -> Result<Vec<BacklogMetricSample>, TestError> {
    match observation {
        BacklogObservation::Active(samples) => Ok(samples),
        BacklogObservation::Standby => {
            Err(std::io::Error::other("postgres backlog provider cannot be standby").into())
        }
    }
}

/// 测试用简化 envelope（占位 `occurred_at=0`）：仅供原子性 / relay 路径验证（T1–T2 等直调 `append_outbox`
/// 的用例，不断言 occurred_at 值）。`occurred_at` 构造期必填（#262 F1），此处取占位 0；envelope occurred_at 的
/// 生产注入路径（从注入 Clock）由 t10（`PgEmitter`）/ t11（`PgAuthGrantLifecycle`）/ config co-tx 专门覆盖（#1129）。
pub(in super::super) fn make_envelope(domain: &str, event_id: &str) -> OutboxEnvelope {
    OutboxEnvelope::new(
        domain.to_string(),
        "contract-1".to_string(),
        OutboxMetadata::new(0, test_tenant(), test_contract())
            .with_subject_id(subject_id(event_id)),
    )
}

/// 构造测试 envelope（routing domain + contract_id；metadata 带标准 schema header，仅占位 `occurred_at=0`）——去重 `OutboxEnvelope::new` 内联重复。
pub(in super::super) fn make_test_env(domain: &str, contract_id: &str) -> OutboxEnvelope {
    OutboxEnvelope::new(
        domain.to_string(),
        contract_id.to_string(),
        OutboxMetadata::new(0, test_tenant(), test_contract()),
    )
}

pub(in super::super) fn make_test_env_with_contract_metadata(
    domain: &str,
    contract_id: &str,
    metadata_contract: vocab::ContractBinding,
) -> OutboxEnvelope {
    OutboxEnvelope::new(
        domain.to_string(),
        contract_id.to_string(),
        OutboxMetadata::new(0, test_tenant(), metadata_contract),
    )
}

/// 构造指定租户的测试 envelope，用于跨租 outbox partition/RLS 用例。
pub(in super::super) fn make_test_env_for_tenant(
    domain: &str,
    contract_id: &str,
    tenant: vocab::TenantId,
) -> OutboxEnvelope {
    OutboxEnvelope::new(
        domain.to_string(),
        contract_id.to_string(),
        OutboxMetadata::new(0, tenant, test_contract()),
    )
}

pub(in super::super) struct SeedFactSnapshot {
    pub(in super::super) payload: Vec<u8>,
    pub(in super::super) fingerprint: Vec<u8>,
}

pub(in super::super) async fn seed_conflicting_outbox_fact(
    store: &PgStore,
    tenant: vocab::TenantId,
    event_id: &str,
) -> Result<SeedFactSnapshot, TestError> {
    let entry = EventEntry::new(
        EventTopic::parse("test.event")?,
        IdemKey::parse(event_id)?,
        reviewed_payload(b"preexisting-conflicting-fact"),
    );
    let env = OutboxEnvelope::new(
        "test".to_string(),
        "test.contract".to_string(),
        OutboxMetadata::new(0, tenant, test_contract())
            .with_subject_id(subject_id("conflict-seed")),
    );
    let outcome = eventing_test_db(store)
        .test_write(
            integration_tenant_scope(tenant),
            |cap| Box::pin(async move { append_outbox(cap, &entry, &env).await }),
            OutboxAppendError::from,
        )
        .await?;
    assert_eq!(outcome, OutboxAppendOutcome::Inserted);
    let (payload, fingerprint): (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT payload, fact_fingerprint FROM outbox WHERE event_id = $1")
            .bind(event_id)
            .fetch_one(&store.pool)
            .await?;
    Ok(SeedFactSnapshot {
        payload,
        fingerprint,
    })
}

pub(in super::super) async fn assert_seed_fact_unchanged(
    store: &PgStore,
    event_id: &str,
    expected: &SeedFactSnapshot,
) -> Result<(), TestError> {
    let rows: Vec<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT payload, fact_fingerprint FROM outbox WHERE event_id = $1")
            .bind(event_id)
            .fetch_all(&store.pool)
            .await?;
    assert_eq!(rows.len(), 1, "seed fact must remain the sole event row");
    assert_eq!(rows[0].0, expected.payload);
    assert_eq!(rows[0].1, expected.fingerprint);
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in super::super) struct OutboxFactGoldenFixture {
    pub(in super::super) schema_version: u32,
    pub(in super::super) cases: Vec<OutboxFactGoldenCase>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in super::super) struct OutboxFactGoldenCase {
    pub(in super::super) label: String,
    pub(in super::super) event_id: String,
    pub(in super::super) tenant_id: String,
    pub(in super::super) domain: String,
    pub(in super::super) topic: String,
    pub(in super::super) contract_id: String,
    pub(in super::super) contract_version: String,
    pub(in super::super) schema_hash: String,
    pub(in super::super) payload: Vec<u8>,
    pub(in super::super) partition_key: Option<String>,
    pub(in super::super) causation_id: Option<String>,
    pub(in super::super) metadata: serde_json::Value,
    pub(in super::super) expected_digest: [u8; 32],
}

pub(in super::super) struct ProjectionHighWaterFixture {
    pub(in super::super) _pg: testkit::PgFixture,
    pub(in super::super) owner: PgStore,
    pub(in super::super) app: PgStore,
    pub(in super::super) operator_store: crate::pool::VerifiedPgProjectionOperatorStore,
    pub(in super::super) source_store: crate::pool::VerifiedPgProjectionSourceReadStore,
    pub(in super::super) tenant: vocab::TenantId,
    pub(in super::super) other_tenant: vocab::TenantId,
    pub(in super::super) binding: vocab::ProjectionInputBinding,
    pub(in super::super) scope: eventexec::ProjectionSourceScope,
    pub(in super::super) other_tenant_scope: eventexec::ProjectionSourceScope,
}

pub(in super::super) static MULTI_BINDING_HIGH_WATER_INPUTS: &[vocab::ProjectionInputBinding] = &[
    vocab::ProjectionInputBinding::from_static(
        "test.multi-binding-projection",
        "multi-a",
        "projection.multi-a",
        "v1",
        TEST_SCHEMA_HASH,
        "test.multi-a",
    ),
    vocab::ProjectionInputBinding::from_static(
        "test.multi-binding-projection",
        "multi-b",
        "projection.multi-b",
        "v1",
        TEST_SCHEMA_HASH,
        "test.multi-b",
    ),
];

impl ProjectionHighWaterFixture {
    pub(in super::super) async fn setup() -> Result<Self, TestError> {
        let (pg, owner) = connect_pg().await?;
        provision_runtime_logins(pg.params()).await?;
        setup_outbox(&owner).await?;
        register_generated_projection_input_catalog(&owner).await?;
        let app = connect_pg_rss_app_role(&pg, &owner).await?;
        let operator_store = crate::PgStore::connect_verified_projection_operator(
            &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
                pg.params(),
                TEST_PROJECTION_OPERATOR_ROLE,
                TEST_PROJECTION_OPERATOR_PASSWORD,
            )),
        )
        .await?;
        let source_store = crate::PgStore::connect_verified_projection_source_read(
            &crate::PgProjectionSourceReadConfig::new(runtime_pg_config(
                pg.params(),
                TEST_PROJECTION_READER_ROLE,
                TEST_PROJECTION_READER_PASSWORD,
            )),
        )
        .await?;
        let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let other_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let binding = *generated::event::PROJECTION_INPUTS
            .first()
            .ok_or_else(|| std::io::Error::other("generated Projection input fixture is empty"))?;
        let projection = eventexec::ProjectionId::parse(binding.projection_id())?;
        let scope = eventexec::WorkflowRuntimePlan::generated_projection_source_scope_fixture(
            &projection,
            tenant,
        )
        .ok_or_else(|| std::io::Error::other("generated registry did not mint source scope"))?;
        let other_tenant_scope =
            eventexec::WorkflowRuntimePlan::generated_projection_source_scope_fixture(
                &projection,
                other_tenant,
            )
            .ok_or_else(|| std::io::Error::other("generated registry did not mint source scope"))?;
        Ok(Self {
            _pg: pg,
            owner,
            app,
            operator_store,
            source_store,
            tenant,
            other_tenant,
            binding,
            scope,
            other_tenant_scope,
        })
    }

    pub(in super::super) fn source_reader(
        &self,
    ) -> crate::projection_events::PgProjectionSourceReader {
        crate::projection_events::PgProjectionSourceReader::new(
            &self.operator_store,
            &self.source_store,
            self.scope.clone(),
        )
    }

    pub(in super::super) fn foreign_binding(
        &self,
    ) -> Result<vocab::ProjectionInputBinding, TestError> {
        generated::event::PROJECTION_INPUTS
            .iter()
            .copied()
            .find(|candidate| candidate.projection_id() != self.binding.projection_id())
            .ok_or_else(|| {
                std::io::Error::other("cross-projection fixture requires two generated projections")
                    .into()
            })
    }

    pub(in super::super) async fn shutdown(self) -> TestResult {
        self.source_store.store_arc().shutdown().await?;
        self.operator_store.store_arc().shutdown().await?;
        self.app.shutdown().await?;
        self.owner.shutdown().await?;
        Ok(())
    }
}

pub(in super::super) async fn append_projection_high_water_fixture_event(
    fixture: &ProjectionHighWaterFixture,
    label: &str,
) -> Result<(String, i64), TestError> {
    let event_id = unique_event_id(label);
    let lsn = append_generated_projection_source_event_for_tenant(
        &fixture.owner,
        &fixture.app,
        fixture.binding,
        &event_id,
        fixture.tenant,
    )
    .await?;
    Ok((event_id, lsn))
}

pub(in super::super) async fn projection_record_from_journal(
    owner: &PgStore,
    tenant: vocab::TenantId,
    lsn: i64,
) -> Result<consistency::ProjectionEventRecord, TestError> {
    let (
        event_id,
        domain,
        event_type,
        payload,
        contract_id,
        contract_version,
        schema_hash,
        sqlx::types::Json(metadata),
        partition_key,
        causation_id,
    ): (
        String,
        String,
        String,
        Vec<u8>,
        String,
        String,
        String,
        sqlx::types::Json<serde_json::Value>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT event_id, domain, event_type, payload, contract_id, contract_version, \
         schema_hash, metadata, partition_key, causation_id \
         FROM public.projection_events WHERE id = $1",
    )
    .bind(lsn)
    .fetch_one(&owner.pool)
    .await?;
    Ok(consistency::ProjectionEventRecord::with_metadata(
        consistency::Lsn::new(u64::try_from(lsn)?),
        consistency::EventTopic::parse(&event_type)?,
        payload,
        consistency::ProjectionEventMetadata::new(
            tenant,
            event_id,
            domain,
            contract_id,
            contract_version,
            schema_hash,
            metadata,
            partition_key,
            causation_id,
        ),
    ))
}

#[derive(Debug, sqlx::FromRow)]
pub(in super::super) struct ProjectionSwapSqlRow {
    pub(in super::super) outcome: String,
    pub(in super::super) reason: Option<String>,
    pub(in super::super) previous_generation: Option<String>,
    pub(in super::super) active_generation: Option<String>,
    pub(in super::super) result_token: Option<i64>,
    pub(in super::super) promoted_high_water_lsn: Option<i64>,
}

pub(in super::super) async fn projection_operator_swap_once(
    pool: &sqlx::PgPool,
    tenant: &str,
    target_generation: &str,
    expected_generation: Option<&str>,
    expected_token: Option<i64>,
) -> Result<ProjectionSwapSqlRow, sqlx::Error> {
    let definition = generated::projection::settings_v3::CONTRACT;
    sqlx::query_as(
        "SELECT outcome, reason, previous_generation, active_generation, \
                result_token, promoted_high_water_lsn \
         FROM public.rss_projection_operator_swap_active(\
             $1::uuid, $2, $3, $4::bigint, $5, $6, $7\
         )",
    )
    .bind(tenant)
    .bind(target_generation)
    .bind(expected_generation)
    .bind(expected_token)
    .bind(definition.version())
    .bind(definition.schema_hash())
    .bind(generated::event::PROJECTION_INPUT_GENERATION)
    .fetch_one(pool)
    .await
}

pub(in super::super) async fn projection_operator_swap_call(
    pool: sqlx::PgPool,
    barrier: Arc<tokio::sync::Barrier>,
    tenant: String,
    target_generation: String,
    expected_generation: Option<String>,
    expected_token: Option<i64>,
) -> Result<ProjectionSwapSqlRow, sqlx::Error> {
    barrier.wait().await;
    projection_operator_swap_once(
        &pool,
        &tenant,
        &target_generation,
        expected_generation.as_deref(),
        expected_token,
    )
    .await
}

pub(in super::super) struct CountingPgActiveProjectionResolver {
    pub(in super::super) inner: crate::PgActiveProjectionResolver,
    pub(in super::super) calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl settings::ports::ActiveProjectionResolver for CountingPgActiveProjectionResolver {
    async fn resolve(
        &self,
        scope: settings::ports::TenantRepoScope,
    ) -> Result<
        settings::ports::ActiveProjectionSelection,
        settings::ports::ActiveProjectionResolveError,
    > {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        settings::ports::ActiveProjectionResolver::resolve(&self.inner, scope).await
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum SwapRejectionFixture {
    SourceMissing,
    CheckpointMissing,
    CheckpointStale,
    CheckpointAhead,
    GenerationMissing,
    DefinitionMismatch,
    InputGenerationMismatch,
    GenerationHighWaterMismatch,
    TargetQuarantined,
}

impl SwapRejectionFixture {
    pub(in super::super) const ALL: [Self; 9] = [
        Self::SourceMissing,
        Self::CheckpointMissing,
        Self::CheckpointStale,
        Self::CheckpointAhead,
        Self::GenerationMissing,
        Self::DefinitionMismatch,
        Self::InputGenerationMismatch,
        Self::GenerationHighWaterMismatch,
        Self::TargetQuarantined,
    ];

    pub(in super::super) const fn reason(self) -> &'static str {
        match self {
            Self::SourceMissing => "source_missing",
            Self::CheckpointMissing => "checkpoint_missing",
            Self::CheckpointStale => "checkpoint_stale",
            Self::CheckpointAhead => "checkpoint_ahead",
            Self::GenerationMissing => "generation_missing",
            Self::DefinitionMismatch => "definition_mismatch",
            Self::InputGenerationMismatch => "input_generation_mismatch",
            Self::GenerationHighWaterMismatch => "generation_high_water_mismatch",
            Self::TargetQuarantined => "target_quarantined",
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
pub(in super::super) struct SwapRejectionStateRow {
    pub(in super::super) generation: String,
    pub(in super::super) promoted_high_water_lsn: i64,
    pub(in super::super) token: i64,
    pub(in super::super) candidate_generations: i64,
    pub(in super::super) candidate_rows: i64,
    pub(in super::super) candidate_receipts: i64,
    pub(in super::super) candidate_checkpoints: i64,
    pub(in super::super) candidate_quarantines: i64,
    pub(in super::super) source_events: i64,
}

#[derive(Debug)]
pub(in super::super) struct TestMac;

impl MacVerifier for TestMac {
    fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
        let mut tag = Vec::from(key.as_bytes());
        tag.extend_from_slice(message);
        Mac::from_bytes(tag)
    }

    fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
        self.sign(key, algorithm, message).as_bytes() == tag.as_bytes()
    }
}

#[allow(clippy::expect_used)]
pub(in super::super) fn test_tenant_authority() -> Arc<TenantAuthority> {
    Arc::new(
        TenantAuthority::new(
            Arc::new(TestMac),
            MacKey::from_bytes(vec![0x42; 32]),
            3600,
            60,
            Arc::new(|| 1_700_000_000),
        )
        .expect("valid test tenant authority"),
    )
}

pub(in super::super) fn test_dlx_payload_protector() -> crate::DlxPayloadProtector {
    test_protector()
}

/// Fake publisher：记录调用次数，返回可控 Result。
pub(in super::super) struct RecordingPublisher {
    pub(in super::super) result: fn() -> Result<(), PublisherError>,
    pub(in super::super) calls: Arc<Mutex<u32>>,
}

/// 首投返回 Ambiguous、第二投成功，并记录两次 broker-visible event ID。
pub(in super::super) struct AmbiguousOncePublisher {
    pub(in super::super) attempts: AtomicU32,
    pub(in super::super) message_ids: Arc<Mutex<Vec<String>>>,
}

impl AmbiguousOncePublisher {
    pub(in super::super) fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
        let message_ids = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                attempts: AtomicU32::new(0),
                message_ids: Arc::clone(&message_ids),
            },
            message_ids,
        )
    }
}

impl Publisher for AmbiguousOncePublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
        self.message_ids
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(request.event_id().as_str().to_string());
        if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(PublisherError::ambiguous(std::io::Error::other(
                "fake ambiguous publish outcome",
            )))
        } else {
            Ok(())
        }
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        Ok(())
    }
}

/// 首次 publish 在测试控制器持有 outbox 行锁后才返回；后续 publish 立即成功。
/// 由此把真实 relay 稳定停在 settle SQL，而不依赖猜测调度时序。
pub(in super::super) struct SettleLockPublisher {
    pub(in super::super) calls: Arc<AtomicU32>,
    pub(in super::super) first_publish_started: Arc<tokio::sync::Notify>,
    pub(in super::super) release_first_publish: Arc<tokio::sync::Notify>,
    pub(in super::super) result: fn() -> Result<(), PublisherError>,
}

pub(in super::super) struct SettleLockPublisherControl {
    pub(in super::super) calls: Arc<AtomicU32>,
    pub(in super::super) first_publish_started: Arc<tokio::sync::Notify>,
    pub(in super::super) release_first_publish: Arc<tokio::sync::Notify>,
}

impl SettleLockPublisher {
    pub(in super::super) fn new() -> (Self, SettleLockPublisherControl) {
        Self::with_result(|| Ok(()))
    }

    pub(in super::super) fn always_transient() -> (Self, SettleLockPublisherControl) {
        Self::with_result(|| {
            Err(PublisherError::transient(std::io::Error::other(
                "fake transient publish error",
            )))
        })
    }

    pub(in super::super) fn always_permanent() -> (Self, SettleLockPublisherControl) {
        Self::with_result(|| {
            Err(PublisherError::permanent(std::io::Error::other(
                "fake permanent publish error",
            )))
        })
    }

    pub(in super::super) fn with_result(
        result: fn() -> Result<(), PublisherError>,
    ) -> (Self, SettleLockPublisherControl) {
        let calls = Arc::new(AtomicU32::new(0));
        let first_publish_started = Arc::new(tokio::sync::Notify::new());
        let release_first_publish = Arc::new(tokio::sync::Notify::new());
        (
            Self {
                calls: Arc::clone(&calls),
                first_publish_started: Arc::clone(&first_publish_started),
                release_first_publish: Arc::clone(&release_first_publish),
                result,
            },
            SettleLockPublisherControl {
                calls,
                first_publish_started,
                release_first_publish,
            },
        )
    }
}

impl Publisher for SettleLockPublisher {
    async fn publish(&self, _request: PublishRequest) -> Result<(), PublisherError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first_publish_started.notify_one();
            self.release_first_publish.notified().await;
        }
        (self.result)()
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        Ok(())
    }
}

impl RecordingPublisher {
    pub(in super::super) fn always_ok() -> (Self, Arc<Mutex<u32>>) {
        let calls = Arc::new(Mutex::new(0u32));
        (
            Self {
                result: || Ok(()),
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }

    pub(in super::super) fn always_transient() -> (Self, Arc<Mutex<u32>>) {
        let calls = Arc::new(Mutex::new(0u32));
        (
            Self {
                result: || {
                    Err(PublisherError::transient(std::io::Error::other(
                        "fake transient publish error",
                    )))
                },
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }

    pub(in super::super) fn always_permanent() -> (Self, Arc<Mutex<u32>>) {
        let calls = Arc::new(Mutex::new(0u32));
        (
            Self {
                result: || {
                    Err(PublisherError::permanent(std::io::Error::other(
                        "fake permanent publish error",
                    )))
                },
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }
}

impl Publisher for RecordingPublisher {
    async fn publish(&self, _request: PublishRequest) -> Result<(), PublisherError> {
        #[allow(clippy::unwrap_used)]
        // reason: 测试内部 Mutex 不存在 poisoning 来源（无 panic 在 lock 持有期间），item-level carve-out。
        {
            *self.calls.lock().unwrap() += 1;
        }
        (self.result)()
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        Ok(())
    }
}

pub(in super::super) fn make_pg_outbox(
    store: &PgStore,
    pub_result_fn: fn() -> Result<(), PublisherError>,
) -> PgOutbox {
    // 临时构造 RecordingPublisher（calls 丢弃；调用方只需验证 DB 状态时用这个）
    let pub_ = RecordingPublisher {
        result: pub_result_fn,
        calls: Arc::new(Mutex::new(0)),
    };
    make_pg_outbox_with_publisher(store, pub_)
}

#[allow(clippy::expect_used)]
pub(in super::super) fn test_relay_budget() -> RelayBudget {
    RelayBudget::new(
        Duration::from_secs(60),
        Duration::from_secs(40),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .expect("test relay budget must be valid")
}

pub(in super::super) async fn set_test_relay_budget_policy(
    store: &PgStore,
    budget: RelayBudget,
) -> TestResult {
    let affected = sqlx::query(
        r#"
        UPDATE event_delivery_policy
        SET relay_lease_ttl_ms = $1,
            relay_publish_timeout_ms = $2,
            relay_settle_timeout_ms = $3,
            relay_safety_margin_ms = $4
        WHERE singleton
        "#,
    )
    .bind(budget.lease_ttl_millis())
    .bind(budget.publish_timeout_millis())
    .bind(budget.settle_timeout_millis())
    .bind(budget.safety_margin_millis())
    .execute(&store.pool)
    .await?
    .rows_affected();
    assert_eq!(affected, 1, "test relay policy singleton must exist");
    Ok(())
}

#[allow(clippy::expect_used)]
pub(in super::super) fn test_relay_lease_ttl_seconds() -> i64 {
    i64::try_from(test_relay_budget().lease_ttl().as_secs())
        .expect("test lease ttl must fit signed seconds")
}

pub(in super::super) fn make_pg_outbox_with_publisher(
    store: &PgStore,
    publisher: impl Publisher + Sync + 'static,
) -> PgOutbox {
    make_pg_outbox_for_domain(store, "identity", publisher)
}

#[allow(clippy::expect_used)]
// reason: integration fixtures pass domain strings already validated by make_test_env/unique_domain.
pub(in super::super) fn make_pg_outbox_for_domain(
    store: &PgStore,
    domain: &str,
    publisher: impl Publisher + Sync + 'static,
) -> PgOutbox {
    make_pg_outbox_for_domain_with_budget(store, domain, publisher, test_relay_budget())
}

#[allow(clippy::expect_used)]
pub(in super::super) fn make_pg_outbox_for_domain_with_budget(
    store: &PgStore,
    domain: &str,
    publisher: impl Publisher + Sync + 'static,
    relay_budget: RelayBudget,
) -> PgOutbox {
    PgOutbox::from_unverified_for_test(
        store,
        vocab::DomainName::parse(domain).expect("valid test outbox domain"),
        DynPublisher::new_box(publisher),
        relay_budget,
        test_tenant_authority(),
        test_dlx_payload_protector(),
    )
}

/// Conformance publisher：记录 broker-visible message_id，并按脚本返回 publish 结果。
pub(in super::super) struct ConformancePublisher {
    pub(in super::super) mode: Arc<Mutex<eventconf::PublishMode>>,
    pub(in super::super) messages: Arc<Mutex<Vec<String>>>,
}

pub(in super::super) struct ConformancePublisherState {
    pub(in super::super) mode: Arc<Mutex<eventconf::PublishMode>>,
    pub(in super::super) messages: Arc<Mutex<Vec<String>>>,
}

impl ConformancePublisher {
    pub(in super::super) fn new() -> (Self, ConformancePublisherState) {
        let mode = Arc::new(Mutex::new(eventconf::PublishMode::Ok));
        let messages = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                mode: Arc::clone(&mode),
                messages: Arc::clone(&messages),
            },
            ConformancePublisherState { mode, messages },
        )
    }
}

impl Publisher for ConformancePublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request.event_id().as_str().to_string());
        let mode = *self.mode.lock().unwrap_or_else(|e| e.into_inner());
        match mode {
            eventconf::PublishMode::Ok => Ok(()),
            eventconf::PublishMode::Transient => Err(PublisherError::transient(
                std::io::Error::other("eventing conformance transient publish"),
            )),
            eventconf::PublishMode::Permanent => Err(PublisherError::permanent(
                std::io::Error::other("eventing conformance permanent publish"),
            )),
            eventconf::PublishMode::Ambiguous => Err(PublisherError::ambiguous(
                std::io::Error::other("eventing conformance ambiguous publish"),
            )),
        }
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        Ok(())
    }
}

pub(in super::super) struct CapturedPublishRequestPublisher {
    pub(in super::super) requests: Arc<Mutex<Vec<PublishRequest>>>,
}

impl CapturedPublishRequestPublisher {
    pub(in super::super) fn new() -> (Self, Arc<Mutex<Vec<PublishRequest>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                requests: Arc::clone(&requests),
            },
            requests,
        )
    }
}

impl Publisher for CapturedPublishRequestPublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request);
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(in super::super) struct CommonBrokerEnvelope {
    pub(in super::super) event_id: String,
    pub(in super::super) key: String,
    pub(in super::super) topic: String,
    pub(in super::super) payload: Vec<u8>,
    pub(in super::super) headers: BTreeMap<String, String>,
}

pub(in super::super) fn common_transport_headers(
    metadata: &EnvelopeMetadata,
) -> BTreeMap<String, String> {
    metadata
        .iter_transport_headers()
        .filter(|(key, _)| *key != KEY_TENANT_AUTHORITY)
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

pub(in super::super) fn assert_no_persisted_only_broker_headers(
    headers: &BTreeMap<String, String>,
) {
    for key in [
        KEY_TENANT_AUTHORITY,
        KEY_SUBJECT_ID,
        KEY_ACTOR,
        KEY_PRINCIPAL,
        "causation_id",
        "aggregate_id",
        "contract_id",
    ] {
        assert!(
            !headers.contains_key(key),
            "broker common envelope must not leak persisted-only header {key}"
        );
    }
}

pub(in super::super) fn relay_common_envelope(request: &PublishRequest) -> CommonBrokerEnvelope {
    assert!(
        request.metadata().get(KEY_TENANT_AUTHORITY).is_some(),
        "tenantAuthority is relay-only and must be signed before exclusion"
    );
    let headers = common_transport_headers(request.metadata());
    assert_no_persisted_only_broker_headers(&headers);
    CommonBrokerEnvelope {
        event_id: request.event_id().as_str().to_string(),
        key: request.event_id().as_str().to_string(),
        topic: request.topic().as_str().to_string(),
        payload: request.payload().to_vec(),
        headers,
    }
}

#[derive(Debug)]
pub(in super::super) struct DebeziumModeledOutboxLog {
    pub(in super::super) event_id: String,
    pub(in super::super) topic: String,
    pub(in super::super) payload: Vec<u8>,
    pub(in super::super) tenant_id: String,
    pub(in super::super) contract_version: String,
    pub(in super::super) schema_hash: String,
    pub(in super::super) occurred_at: String,
    pub(in super::super) aggregate_id: String,
    pub(in super::super) contract_id: String,
    pub(in super::super) metadata: serde_json::Value,
}

impl DebeziumModeledOutboxLog {
    pub(in super::super) fn common_envelope(&self) -> CommonBrokerEnvelope {
        let headers = BTreeMap::from([
            (KEY_TENANT_ID.to_string(), self.tenant_id.clone()),
            (
                KEY_SCHEMA_VERSION.to_string(),
                self.contract_version.clone(),
            ),
            (KEY_SCHEMA_HASH.to_string(), self.schema_hash.clone()),
            (KEY_OCCURRED_AT.to_string(), self.occurred_at.clone()),
        ]);
        assert_no_persisted_only_broker_headers(&headers);
        CommonBrokerEnvelope {
            event_id: self.event_id.clone(),
            key: self.event_id.clone(),
            topic: self.topic.clone(),
            payload: self.payload.clone(),
            headers,
        }
    }
}

pub(in super::super) async fn modeled_debezium_eventrouter_outbox_log(
    store: &PgStore,
    event_id: &str,
) -> Result<DebeziumModeledOutboxLog, sqlx::Error> {
    let row: (
        String,
        String,
        Vec<u8>,
        String,
        String,
        String,
        String,
        String,
        String,
        serde_json::Value,
    ) = sqlx::query_as(
        r#"
        SELECT event_id, topic, payload, tenant_id::text, contract_version, schema_hash,
               occurred_at, aggregate_id, contract_id, metadata
        FROM outbox_log
        WHERE event_id = $1
        "#,
    )
    .bind(event_id)
    .fetch_one(&store.pool)
    .await?;
    Ok(DebeziumModeledOutboxLog {
        event_id: row.0,
        topic: row.1,
        payload: row.2,
        tenant_id: row.3,
        contract_version: row.4,
        schema_hash: row.5,
        occurred_at: row.6,
        aggregate_id: row.7,
        contract_id: row.8,
        metadata: row.9,
    })
}

pub(in super::super) async fn conf_seed_pending(
    store: &PgStore,
    event_id: String,
    domain: String,
) -> Result<(), String> {
    eventing_test_db(store)
        .test_write(
            integration_tenant_scope(test_tenant()),
            move |cap| {
                let entry = make_entry(&event_id);
                let env = make_test_env(&domain, "eventing-conf");
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            },
            std::convert::identity,
        )
        .await
        .map_err(|e| format!("{e:?}"))
}

pub(in super::super) async fn conf_relay(
    store: &PgStore,
    outbox: &PgOutbox,
    publisher_mode: &Mutex<eventconf::PublishMode>,
    messages: &Mutex<Vec<String>>,
    claims: &Mutex<HashMap<String, PgClaimedOutboxEntry>>,
    event_id: String,
    mode: eventconf::PublishMode,
) -> Result<eventconf::RelayObservation, String> {
    *publisher_mode
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = mode;
    messages
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
    let cached = claims
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(&event_id);
    let claimed = match cached {
        Some(claimed) => claimed,
        None => {
            // Conformance retries immediately; make only the target test row eligible again while
            // preserving the production retry predicate and typed claim path.
            sqlx::query(
                "UPDATE outbox SET retry_after = clock_timestamp() - interval '1 microsecond' \
                 WHERE event_id = $1 AND status = 'pending' AND retry_after IS NOT NULL",
            )
            .bind(&event_id)
            .execute(&store.pool)
            .await
            .map_err(|error| format!("{error:?}"))?;
            claim_entry_for_relay(outbox, &event_id).await?
        }
    };
    let disposition = outbox.relay(claimed).await.map_err(|e| format!("{e:?}"))?;
    let messages = messages.lock().unwrap_or_else(|e| e.into_inner());
    let message_id = messages.last().cloned();
    let publish_count = messages.len() as u64;
    Ok(eventconf::RelayObservation {
        disposition: match disposition {
            Disposition::Ack => eventconf::RelayDisposition::Ack,
            Disposition::Requeue => eventconf::RelayDisposition::Requeue,
            Disposition::Reject => eventconf::RelayDisposition::Reject,
            _ => {
                return Err("unknown relay disposition".to_string());
            }
        },
        message_id,
        publish_count,
    })
}

pub(in super::super) async fn conf_claim_batch(
    outbox: &PgOutbox,
    claims: &Mutex<HashMap<String, PgClaimedOutboxEntry>>,
    _domain: String,
) -> Result<Vec<String>, String> {
    outbox
        .claim_batch(100)
        .await
        .map(|entries| {
            let mut claims = claims.lock().unwrap_or_else(|error| error.into_inner());
            entries
                .into_iter()
                .map(|entry| {
                    let event_id = entry.idem_key().as_str().to_string();
                    claims.insert(event_id.clone(), entry);
                    event_id
                })
                .collect()
        })
        .map_err(|e| format!("{e:?}"))
}

pub(in super::super) async fn conf_outbox_state(
    store: &PgStore,
    event_id: String,
) -> Result<eventconf::OutboxState, String> {
    let row: Option<(String, i32, bool)> = sqlx::query_as(
        "SELECT status, retry_count, retry_after IS NOT NULL FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_optional(&store.pool)
    .await
    .map_err(|e| format!("{e:?}"))?;
    let dlx_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM dead_letter WHERE message_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await
            .map_err(|e| format!("{e:?}"))?;
    Ok(match row {
        Some((status, retry_count, retry_after_set)) => eventconf::OutboxState {
            exists: true,
            status: conf_outbox_status(&status)?,
            retry_count: i64::from(retry_count),
            retry_after_set,
            dlx_count: dlx_count.0 as u64,
        },
        None => eventconf::OutboxState {
            exists: false,
            status: eventconf::OutboxStatus::Absent,
            retry_count: 0,
            retry_after_set: false,
            dlx_count: dlx_count.0 as u64,
        },
    })
}

pub(in super::super) fn conf_outbox_status(
    status: &str,
) -> Result<eventconf::OutboxStatus, String> {
    match status {
        crate::outbox::STATUS_PENDING => Ok(eventconf::OutboxStatus::Pending),
        crate::outbox::STATUS_PUBLISHING => Ok(eventconf::OutboxStatus::Publishing),
        crate::outbox::STATUS_PUBLISHED => Ok(eventconf::OutboxStatus::Published),
        "dlx" => Ok(eventconf::OutboxStatus::Dlx),
        other => Err(format!("unknown outbox status {other:?}")),
    }
}

pub(in super::super) async fn conf_backdate_publishing(
    store: &PgStore,
    event_id: String,
) -> Result<(), String> {
    sqlx::query(
        "UPDATE outbox \
         SET status='publishing', lease_token = gen_random_uuid(), \
             automatic_retry_deadline = COALESCE(automatic_retry_deadline, now() + interval '24 hours'), \
             created_at = now() - make_interval(secs => $1), \
             updated_at = now() - make_interval(secs => $1), \
             lease_until = now() - interval '10 seconds' \
         WHERE event_id = $2",
    )
    .bind(test_relay_lease_ttl_seconds() + 10)
    .bind(&event_id)
    .execute(&store.pool)
    .await
    .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

pub(in super::super) async fn conf_sample_backlog(
    store: &PgStore,
    domain: String,
) -> Result<eventconf::BacklogSample, String> {
    let outbox = make_pg_outbox(store, || Ok(()));
    outbox
        .sample_backlog(&domain)
        .await
        .and_then(|observation| match observation {
            BacklogObservation::Active(samples) => Ok(samples),
            BacklogObservation::Standby => Err(consistency::EngineError::new(
                consistency::EngineErrorKind::Invariant,
            )),
        })
        .map(|samples| {
            let summary = summarize_backlog(&samples);
            eventconf::BacklogSample {
                depth: summary.depth(),
                oldest_age_seconds: summary.oldest_age_seconds(),
            }
        })
        .map_err(|e| format!("{e:?}"))
}

pub(in super::super) async fn conf_sweep_outbox(
    store: &PgStore,
    retain_seconds: u64,
) -> Result<u64, String> {
    let outbox = make_pg_outbox(store, || Ok(()));
    outbox
        .sweep(retain_seconds)
        .await
        .map_err(|e| format!("{e:?}"))
}

pub(in super::super) async fn conf_seed_terminal(
    store: &PgStore,
    event_id: String,
    domain: String,
    status: eventconf::TerminalStatus,
) -> Result<(), String> {
    conf_seed_pending(store, event_id.clone(), domain).await?;
    let status = match status {
        eventconf::TerminalStatus::PublishedOld => "published",
        eventconf::TerminalStatus::DlxOld => "dlx",
        _ => "dlx",
    };
    set_outbox_terminal_for_test(store, &event_id, status, 7200)
        .await
        .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

pub(in super::super) fn conf_lease_for(
    leases: &Arc<Mutex<HashMap<String, LeaseToken>>>,
    alias: String,
) -> LeaseToken {
    let mut guard = leases.lock().unwrap_or_else(|e| e.into_inner());
    guard.entry(alias).or_insert_with(LeaseToken::mint).clone()
}

pub(in super::super) async fn conf_try_claim(
    store: &PgStore,
    leases: &Arc<Mutex<HashMap<String, LeaseToken>>>,
    key: String,
    group: String,
    lease_alias: String,
) -> Result<eventconf::InboxSeen, String> {
    let key = IdemKey::parse(&key).map_err(|e| format!("{e:?}"))?;
    let ctx = test_inbox_ctx(&group);
    let lease = conf_lease_for(leases, lease_alias);
    store
        .inbox()
        .try_claim(&ctx, &key, &lease)
        .await
        .map(|seen| match seen {
            SeenState::Fresh => eventconf::InboxSeen::Fresh,
            SeenState::InProgress => eventconf::InboxSeen::InProgress,
            SeenState::Duplicate => eventconf::InboxSeen::Duplicate,
        })
        .map_err(|e| format!("{e:?}"))
}

pub(in super::super) async fn conf_extend(
    store: &PgStore,
    leases: &Arc<Mutex<HashMap<String, LeaseToken>>>,
    key: String,
    group: String,
    lease_alias: String,
) -> Result<eventconf::LeaseOutcome, String> {
    let key = IdemKey::parse(&key).map_err(|e| format!("{e:?}"))?;
    let ctx = test_inbox_ctx(&group);
    let lease = conf_lease_for(leases, lease_alias);
    store
        .inbox()
        .extend(&ctx, &key, &lease)
        .await
        .map(|outcome| match outcome {
            consistency::LeaseOutcome::Held => eventconf::LeaseOutcome::Held,
            consistency::LeaseOutcome::Lost => eventconf::LeaseOutcome::Lost,
            _ => eventconf::LeaseOutcome::Lost,
        })
        .map_err(|e| format!("{e:?}"))
}

pub(in super::super) async fn conf_commit(
    store: &PgStore,
    leases: &Arc<Mutex<HashMap<String, LeaseToken>>>,
    key: String,
    group: String,
    lease_alias: String,
) -> Result<eventconf::LeaseOutcome, String> {
    let key = IdemKey::parse(&key).map_err(|e| format!("{e:?}"))?;
    let ctx = test_inbox_ctx(&group);
    let lease = conf_lease_for(leases, lease_alias);
    store
        .inbox()
        .commit(&ctx, &key, &lease)
        .await
        .map(|outcome| match outcome {
            consistency::LeaseOutcome::Held => eventconf::LeaseOutcome::Held,
            consistency::LeaseOutcome::Lost => eventconf::LeaseOutcome::Lost,
            _ => eventconf::LeaseOutcome::Lost,
        })
        .map_err(|e| format!("{e:?}"))
}

pub(in super::super) async fn conf_release(
    store: &PgStore,
    leases: &Arc<Mutex<HashMap<String, LeaseToken>>>,
    key: String,
    group: String,
    lease_alias: String,
) -> Result<(), String> {
    let key = IdemKey::parse(&key).map_err(|e| format!("{e:?}"))?;
    let ctx = test_inbox_ctx(&group);
    let lease = conf_lease_for(leases, lease_alias);
    store
        .inbox()
        .release(&ctx, &key, &lease)
        .await
        .map_err(|e| format!("{e:?}"))
}

pub(in super::super) async fn conf_backdate_claim(
    store: &PgStore,
    key: String,
    group: String,
) -> Result<(), String> {
    let ctx = test_inbox_ctx(&group);
    sqlx::query(
        "UPDATE inbox_receipts \
         SET claimed_at = now() - make_interval(secs => $1) \
         WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
    )
    .bind(crate::inbox::INBOX_LEASE_TTL_SECONDS + 10)
    .bind(ctx.tenant_id().to_string())
    .bind(&key)
    .bind(&group)
    .execute(&store.pool)
    .await
    .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

pub(in super::super) struct ConformanceAcker {
    pub(in super::super) actions: Mutex<Vec<AckAction>>,
}

impl ConformanceAcker {
    pub(in super::super) fn new() -> (Arc<Self>, Box<DynAcker<'static>>) {
        let acker = Arc::new(Self {
            actions: Mutex::new(Vec::new()),
        });
        struct ArcAcker(Arc<ConformanceAcker>);
        impl Acker for ArcAcker {
            async fn settle(&self, action: AckAction) -> Result<(), diport::AckError> {
                self.0
                    .actions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(action);
                Ok(())
            }
        }
        (Arc::clone(&acker), DynAcker::new_box(ArcAcker(acker)))
    }

    pub(in super::super) fn exactly_one_action(&self) -> Result<AckAction, String> {
        let actions = self.actions.lock().unwrap_or_else(|e| e.into_inner());
        match actions.as_slice() {
            [action] => Ok(*action),
            [] => Err("missing settle action".to_string()),
            many => Err(format!(
                "expected exactly one settle action, got {}",
                many.len()
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in super::super) struct CommitAckAtSettle {
    pub(in super::super) committed: bool,
    pub(in super::super) action: AckAction,
}

pub(in super::super) struct CommitObservingAcker {
    pub(in super::super) pool: sqlx::PgPool,
    pub(in super::super) event_id: String,
    pub(in super::super) consumer_group: String,
    pub(in super::super) observations: Arc<Mutex<Vec<CommitAckAtSettle>>>,
}

impl CommitObservingAcker {
    pub(in super::super) fn observe(
        store: &PgStore,
        event_id: String,
        consumer_group: String,
    ) -> (Arc<Mutex<Vec<CommitAckAtSettle>>>, Box<DynAcker<'static>>) {
        let observations = Arc::new(Mutex::new(Vec::new()));
        let acker = Self {
            pool: store.pool.clone(),
            event_id,
            consumer_group,
            observations: Arc::clone(&observations),
        };
        (observations, DynAcker::new_box(acker))
    }
}

impl Acker for CommitObservingAcker {
    async fn settle(&self, action: AckAction) -> Result<(), diport::AckError> {
        let committed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM inbox_receipts \
             WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3 \
             AND status = 'done')",
        )
        .bind(test_tenant().to_string())
        .bind(&self.event_id)
        .bind(&self.consumer_group)
        .fetch_one(&self.pool)
        .await
        .map_err(diport::AckError::new)?;
        self.observations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(CommitAckAtSettle { committed, action });
        Ok(())
    }
}

pub(in super::super) struct FailingDlx {
    pub(in super::super) captured: Arc<Mutex<Option<DeadLetterRecord>>>,
}

impl FailingDlx {
    pub(in super::super) fn new(captured: Arc<Mutex<Option<DeadLetterRecord>>>) -> Self {
        Self { captured }
    }
}

impl DeadLetterStore for FailingDlx {
    async fn write_dead_letter(
        &self,
        record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        *self.captured.lock().unwrap_or_else(|e| e.into_inner()) = Some(record);
        Err(DeadLetterStoreError::new(std::io::Error::other(
            "eventing conformance dlx failure",
        )))
    }

    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
        Ok(())
    }
}

#[allow(clippy::expect_used)]
pub(in super::super) fn conf_consumer_metadata(event_id: &str) -> EnvelopeMetadata {
    let authority = test_tenant_authority();
    let tenant = test_tenant();
    let token = authority
        .sign(TenantAuthorityBinding::new(
            tenant,
            "eventing-conf-consumer-domain",
            "eventing-conf-consumer-contract",
            "eventing.conf.consumer",
            event_id,
        ))
        .expect("tenant authority test signing cannot fail");
    let mut metadata = EnvelopeMetadata::empty();
    metadata.insert_wire_pair(KEY_TENANT_ID, COTX_TENANT_A);
    metadata.insert_wire_pair(KEY_TENANT_AUTHORITY, token);
    metadata.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
    metadata.insert_wire_pair(KEY_SCHEMA_HASH, TEST_SCHEMA_HASH);
    metadata
}

pub(in super::super) fn conf_delivery_stream(
    event_id: &str,
) -> (DeliveryStream, Arc<ConformanceAcker>) {
    let (acker, boxed) = ConformanceAcker::new();
    let message = Message::new_with_metadata(
        event_id,
        b"eventing-conformance-payload".to_vec(),
        conf_consumer_metadata(event_id),
    );
    (
        Box::pin(futures::stream::iter(vec![Delivery::new(message, boxed)])),
        acker,
    )
}

pub(in super::super) fn conf_consumer_meta(group: &str) -> ConsumerMeta {
    ConsumerMeta::new(
        "eventing-conf-consumer-domain",
        "eventing-conf-consumer-domain",
        "eventing-conf-consumer-contract",
        "eventing.conf.consumer",
        group,
        test_tenant_authority(),
    )
    .with_expected_schema("v1", TEST_SCHEMA_HASH)
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn conf_consumer_ctx(group: &str) -> InboxReceiptContext {
    InboxReceiptContext::new(
        test_tenant(),
        ConsumerGroup::parse(group).unwrap(),
        "eventing-conf-consumer-domain",
        "eventing.conf.consumer",
        "eventing-conf-consumer-contract",
        "v1",
        TEST_SCHEMA_HASH,
        None,
        None,
    )
    .unwrap()
}

pub(in super::super) fn conf_expected_dlx() -> eventconf::DlxFields {
    eventconf::DlxFields {
        source_kind: "consumer".to_string(),
        domain: "eventing-conf-consumer-domain".to_string(),
        contract_id: "eventing-conf-consumer-contract".to_string(),
        topic: "eventing.conf.consumer".to_string(),
        num_attempts: MAX_REDELIVERY,
    }
}

pub(in super::super) fn conf_lease_cfg() -> LeaseConfig {
    LeaseConfig::from_ttl(std::time::Duration::from_secs(
        crate::inbox::INBOX_LEASE_TTL_SECONDS as u64,
    ))
}

pub(in super::super) fn conf_requeue_handler(
    calls: Arc<AtomicU32>,
) -> impl Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync {
    move |_message| {
        let calls = Arc::clone(&calls);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::Relaxed);
            HandleResult::requeue(consistency::EngineError::new(
                consistency::EngineErrorKind::Transient,
            ))
        })
    }
}

pub(in super::super) fn conf_ack_handler(
    calls: Arc<AtomicU32>,
) -> impl Fn(Message) -> futures::future::BoxFuture<'static, HandleResult> + Send + Sync {
    move |_message| {
        let calls = Arc::clone(&calls);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::Relaxed);
            HandleResult::ack()
        })
    }
}

pub(in super::super) fn action_to_settle(
    action: AckAction,
) -> Result<eventconf::SettleAction, String> {
    match action {
        AckAction::Ack => Ok(eventconf::SettleAction::Ack),
        AckAction::Requeue => Ok(eventconf::SettleAction::Requeue),
        AckAction::Reject => Ok(eventconf::SettleAction::Reject),
        _ => Err("unknown ack action".to_string()),
    }
}

pub(in super::super) fn conf_settle_action(
    acker: &ConformanceAcker,
) -> Result<eventconf::SettleAction, String> {
    action_to_settle(acker.exactly_one_action()?)
}

pub(in super::super) fn conf_dlx_fields_from_record(
    record: &DeadLetterRecord,
) -> eventconf::DlxFields {
    eventconf::DlxFields {
        source_kind: record.source().as_str().to_string(),
        domain: record.producer_domain().to_string(),
        contract_id: record.contract_id().to_string(),
        topic: record.topic().to_string(),
        num_attempts: record.num_attempts(),
    }
}

pub(in super::super) async fn conf_inbox_status(
    store: &PgStore,
    event_id: &str,
    group: &str,
) -> Result<Option<String>, String> {
    let ctx = test_inbox_ctx(group);
    sqlx::query_as::<_, (String,)>(
        "SELECT status FROM inbox_receipts WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
    )
    .bind(ctx.tenant_id().to_string())
    .bind(event_id)
    .bind(group)
    .fetch_optional(&store.pool)
    .await
    .map(|row| row.map(|(status,)| status))
    .map_err(|e| format!("{e:?}"))
}

pub(in super::super) async fn conf_dlx_fields(
    store: &PgStore,
    event_id: &str,
) -> Result<(u64, eventconf::DlxFields), String> {
    let row: Option<(String, String, String, String, i32)> = sqlx::query_as(
        "SELECT source_kind, producer_domain, contract_id, topic, num_attempts \
         FROM dead_letter WHERE message_id = $1 ORDER BY last_attempt_at DESC LIMIT 1",
    )
    .bind(event_id)
    .fetch_optional(&store.pool)
    .await
    .map_err(|e| format!("{e:?}"))?;
    let Some((source_kind, domain, contract_id, topic, num_attempts)) = row else {
        return Ok((
            0,
            eventconf::DlxFields {
                source_kind: String::new(),
                domain: String::new(),
                contract_id: String::new(),
                topic: String::new(),
                num_attempts: 0,
            },
        ));
    };
    Ok((
        1,
        eventconf::DlxFields {
            source_kind,
            domain,
            contract_id,
            topic,
            num_attempts: u32::try_from(num_attempts).unwrap_or(0),
        },
    ))
}

pub(in super::super) async fn conf_duplicate_delivery(
    store: &PgStore,
    event_id: String,
    group: String,
) -> Result<eventconf::ConsumerObservation, String> {
    let key = IdemKey::parse(&event_id).map_err(|e| format!("{e:?}"))?;
    let meta = conf_consumer_meta(&group);
    let ctx = conf_consumer_ctx(&group);
    let lease = LeaseToken::mint();
    let inbox = store.inbox();
    inbox
        .try_claim(&ctx, &key, &lease)
        .await
        .map_err(|e| format!("{e:?}"))?;
    inbox
        .commit(&ctx, &key, &lease)
        .await
        .map_err(|e| format!("{e:?}"))?;

    let calls = Arc::new(AtomicU32::new(0));
    let (stream, acker) = conf_delivery_stream(&event_id);
    run_consumer_ackable(
        stream,
        Arc::new(store.inbox()),
        (DynDeadLetterStore::new_box(store.dead_letter(test_dlx_payload_protector()))).as_ref(),
        &(meta),
        &(conf_ack_handler(Arc::clone(&calls))),
        conf_lease_cfg(),
    )
    .await;

    let (_, dlx) = conf_dlx_fields(store, &event_id).await?;
    Ok(eventconf::ConsumerObservation {
        handler_calls: calls.load(Ordering::Relaxed),
        claim_attempts: 1,
        committed: false,
        released: false,
        dlx_count: 0,
        settle: conf_settle_action(&acker)?,
        num_attempts: dlx.num_attempts,
        source_kind: dlx.source_kind,
        domain: dlx.domain,
        contract_id: dlx.contract_id,
        topic: dlx.topic,
    })
}

pub(in super::super) async fn conf_poison_delivery(
    store: &PgStore,
    event_id: String,
    group: String,
) -> Result<eventconf::ConsumerObservation, String> {
    let calls = Arc::new(AtomicU32::new(0));
    let (stream, acker) = conf_delivery_stream(&event_id);
    run_consumer_ackable(
        stream,
        Arc::new(store.inbox()),
        (DynDeadLetterStore::new_box(store.dead_letter(test_dlx_payload_protector()))).as_ref(),
        &(conf_consumer_meta(&group)),
        &(conf_requeue_handler(Arc::clone(&calls))),
        conf_lease_cfg(),
    )
    .await;

    let (dlx_count, dlx) = conf_dlx_fields(store, &event_id).await?;
    let committed = conf_inbox_status(store, &event_id, &group).await? == Some("done".to_string());
    Ok(eventconf::ConsumerObservation {
        handler_calls: calls.load(Ordering::Relaxed),
        claim_attempts: 1,
        committed,
        released: false,
        dlx_count,
        settle: conf_settle_action(&acker)?,
        num_attempts: dlx.num_attempts,
        source_kind: dlx.source_kind,
        domain: dlx.domain,
        contract_id: dlx.contract_id,
        topic: dlx.topic,
    })
}

pub(in super::super) async fn conf_dlx_failure(
    store: &PgStore,
    event_id: String,
    group: String,
) -> Result<eventconf::ConsumerObservation, String> {
    let calls = Arc::new(AtomicU32::new(0));
    let (stream, acker) = conf_delivery_stream(&event_id);
    let captured = Arc::new(Mutex::new(None));
    run_consumer_ackable(
        stream,
        Arc::new(store.inbox()),
        (DynDeadLetterStore::new_box(FailingDlx::new(Arc::clone(&captured)))).as_ref(),
        &(conf_consumer_meta(&group)),
        &(conf_requeue_handler(Arc::clone(&calls))),
        conf_lease_cfg(),
    )
    .await;

    let released = conf_inbox_status(store, &event_id, &group).await?.is_none();
    let captured = captured
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or_else(|| "missing failed dlx write record".to_string())?;
    let dlx = conf_dlx_fields_from_record(&captured);
    Ok(eventconf::ConsumerObservation {
        handler_calls: calls.load(Ordering::Relaxed),
        claim_attempts: 1,
        committed: false,
        released,
        dlx_count: 0,
        settle: conf_settle_action(&acker)?,
        num_attempts: dlx.num_attempts,
        source_kind: dlx.source_kind,
        domain: dlx.domain,
        contract_id: dlx.contract_id,
        topic: dlx.topic,
    })
}

pub(in super::super) async fn conf_malformed_delivery(
    store: &PgStore,
    group: String,
) -> Result<eventconf::ConsumerObservation, String> {
    let calls = Arc::new(AtomicU32::new(0));
    let (stream, acker) = conf_delivery_stream("");
    run_consumer_ackable(
        stream,
        Arc::new(store.inbox()),
        (DynDeadLetterStore::new_box(store.dead_letter(test_dlx_payload_protector()))).as_ref(),
        &(conf_consumer_meta(&group)),
        &(conf_ack_handler(Arc::clone(&calls))),
        conf_lease_cfg(),
    )
    .await;

    let expected = conf_expected_dlx();
    Ok(eventconf::ConsumerObservation {
        handler_calls: calls.load(Ordering::Relaxed),
        claim_attempts: 0,
        committed: false,
        released: false,
        dlx_count: 0,
        settle: conf_settle_action(&acker)?,
        num_attempts: expected.num_attempts,
        source_kind: expected.source_kind,
        domain: expected.domain,
        contract_id: expected.contract_id,
        topic: expected.topic,
    })
}

pub(in super::super) async fn localtx_assert_backend_reused(
    pool: &sqlx::PgPool,
    expected_pid: i32,
    context: &str,
) -> TestResult {
    let mut connection = tokio::time::timeout(Duration::from_secs(1), pool.acquire()).await??;
    let actual_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *connection)
        .await?;
    assert_eq!(
        actual_pid, expected_pid,
        "{context}: safe backend was closed"
    );
    Ok(())
}

pub(in super::super) const LOCALTX_BACKEND_CLOSE_TIMEOUT: Duration = Duration::from_secs(6);

pub(in super::super) async fn localtx_assert_backend_quarantined(
    owner: &PgStore,
    pool: &sqlx::PgPool,
    unsafe_pid: i32,
    context: &str,
) -> TestResult {
    assert!(
        unsafe_pid > 0,
        "{context}: LocalTx attempt did not observe a real backend"
    );
    let mut replacement =
        tokio::time::timeout(LOCALTX_BACKEND_CLOSE_TIMEOUT, pool.acquire()).await??;
    let replacement_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *replacement)
        .await?;
    assert_ne!(
        replacement_pid, unsafe_pid,
        "{context}: unsafe backend was returned to the pool"
    );
    drop(replacement);

    await_try(Duration::from_secs(6), async || {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM pg_stat_activity WHERE pid = $1")
                .bind(unsafe_pid)
                .fetch_one(&owner.pool)
                .await?;
        Ok::<Option<()>, TestError>((count == 0).then_some(()))
    })
    .await
    .map_err(|error| {
        format!("{context}: close_on_drop did not terminate backend {unsafe_pid}: {error}")
    })?;
    Ok(())
}

pub(in super::super) async fn run_localtx_deadline_write<T, F>(
    scoped: &crate::cotx::TenantDb<ServingWriteLane>,
    tenant: vocab::TenantId,
    budget: consistency::LocalTxExecutionBudget,
    write: F,
) -> (Result<T, settings::ports::ConfigRepoError>, usize)
where
    F: for<'c, 'tx> FnOnce(
            &'c mut crate::cotx::eventing::OutboxTx<'tx>,
        ) -> futures::future::BoxFuture<
            'c,
            Result<T, settings::ports::ConfigRepoError>,
        > + Clone
        + Send
        + 'static,
    T: Send,
{
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use generated::http::settings_v2::{LOCAL_TX, ROUTE};

    let observation = observ::LocalTxObservation::new(ROUTE, LOCAL_TX.boundary);
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_for_runner = Arc::clone(&attempts);
    let result = crate::tx_retry::with_localtx_execution_budget_for_test(
        budget,
        crate::tx_retry::run_pg_localtx_retry(
            observation,
            |_attempt, deadline| {
                attempts_for_runner.fetch_add(1, Ordering::SeqCst);
                scoped.test_retry_write(
                    settings::ports::TenantRepoScope::for_test(tenant),
                    deadline,
                    write.clone(),
                    |error| settings::ports::ConfigRepoError::Storage(Box::new(error)),
                )
            },
            crate::tx_retry::classify_config_repo_error,
        ),
    )
    .await;
    (result, attempts.load(Ordering::SeqCst))
}

pub(in super::super) fn localtx_deadline_stage_count(
    handle: &metrics_exporter_prometheus::PrometheusHandle,
    stage: consistency::LocalTxDeadlineStage,
) -> f64 {
    let stage_label = format!("stage=\"{}\"", stage.as_label());
    handle
        .render()
        .lines()
        .filter(|line| {
            line.starts_with("localtx_deadline_exceeded_total{") && line.contains(&stage_label)
        })
        .filter_map(|line| line.split_whitespace().last()?.parse::<f64>().ok())
        .sum()
}

pub(in super::super) fn localtx_final_status_count(
    handle: &metrics_exporter_prometheus::PrometheusHandle,
    status: consistency::LocalTxFinalStatus,
) -> f64 {
    let status_label = format!("final_status=\"{}\"", status.as_label());
    handle
        .render()
        .lines()
        .filter(|line| line.starts_with("localtx_final_total{") && line.contains(&status_label))
        .filter_map(|line| line.split_whitespace().last()?.parse::<f64>().ok())
        .sum()
}

pub(in super::super) fn localtx_final_total(
    handle: &metrics_exporter_prometheus::PrometheusHandle,
) -> f64 {
    consistency::LocalTxFinalStatus::ALL
        .iter()
        .map(|status| localtx_final_status_count(handle, *status))
        .sum()
}

pub(in super::super) async fn seed_outbox_dlx(
    store: &PgStore,
    domain: &str,
    event_id: &str,
) -> TestResult {
    let entry = make_entry(event_id);
    let env = make_test_env(domain, "same-id-window");
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    let (publisher, _) = RecordingPublisher::always_permanent();
    let relay = make_pg_outbox_for_domain(store, domain, publisher);
    let claim = claim_entry_for_relay(&relay, event_id).await?;
    assert_eq!(relay.relay(claim).await?, Disposition::Reject);
    Ok(())
}

pub(in super::super) async fn direct_outbox_redrive(
    pool: sqlx::PgPool,
    tenant: vocab::TenantId,
    event_id: String,
) -> Result<i64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let outcome = sqlx::query_scalar("SELECT rss_outbox_redrive($1, $2::uuid)")
        .bind(event_id)
        .bind(tenant.to_string())
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(outcome)
}

#[derive(Clone, Copy)]
pub(in super::super) enum ForcedPublishedSettlementFailure {
    Expired,
    LostLease,
}

impl ForcedPublishedSettlementFailure {
    pub(in super::super) const fn reason(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::LostLease => "lost_lease",
        }
    }
}

pub(in super::super) async fn assert_published_settlement_failure_metric(
    forced: ForcedPublishedSettlementFailure,
) -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let event_id = unique_event_id(forced.reason());
    let domain = unique_domain(forced.reason());
    let entry = make_entry(&event_id);
    let env = make_test_env(&domain, "settle.typed.failure");
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (publisher, control) = SettleLockPublisher::new();
    let outbox = make_pg_outbox_for_domain(&store, &domain, publisher);
    let mut claim = claim_entry_for_relay(&outbox, &event_id).await?;
    match forced {
        ForcedPublishedSettlementFailure::Expired => {
            assert_published_settlement_expired_metric(&store, &outbox, &event_id, &mut claim)
                .await?;
        }
        ForcedPublishedSettlementFailure::LostLease => {
            assert_published_settlement_lost_lease_metric(
                &store, &outbox, &event_id, claim, &control,
            )
            .await?;
        }
    }
    assert_publishing_state_unchanged(&store, &event_id).await?;
    store.shutdown().await?;
    Ok(())
}

pub(in super::super) async fn assert_published_settlement_expired_metric(
    store: &PgStore,
    outbox: &PgOutbox,
    event_id: &str,
    claim: &mut PgClaimedOutboxEntry,
) -> TestResult {
    let forced_deadline_micros: i64 = sqlx::query_scalar(
        "UPDATE outbox SET lease_until = clock_timestamp() - interval '1 second', \
         updated_at = clock_timestamp() - interval '2 seconds' WHERE event_id = $1 \
         RETURNING (extract(epoch FROM lease_until) * 1000000)::bigint",
    )
    .bind(event_id)
    .fetch_one(&store.pool)
    .await?;
    claim.test_override_lease_deadlines(forced_deadline_micros, Duration::from_secs(5));
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    let outcome = metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(outbox.test_published_settlement_outcome(claim))
        })
    })?;
    assert_eq!(outcome, "expired");
    assert_single_settlement_failure_metric(&metrics_handle.render(), "published", "expired");
    Ok(())
}

pub(in super::super) async fn assert_published_settlement_lost_lease_metric(
    store: &PgStore,
    outbox: &PgOutbox,
    event_id: &str,
    claim: PgClaimedOutboxEntry,
    control: &SettleLockPublisherControl,
) -> TestResult {
    let relay_run = outbox.relay(claim);
    let force_failure = async {
        control.first_publish_started.notified().await;
        sqlx::query("UPDATE outbox SET lease_token = gen_random_uuid() WHERE event_id = $1")
            .bind(event_id)
            .execute(&store.pool)
            .await?;
        control.release_first_publish.notify_one();
        Ok::<(), TestError>(())
    };
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    let (relay_result, force_result) = metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { tokio::join!(relay_run, force_failure) })
        })
    });
    force_result?;
    assert!(matches!(relay_result, Err(error) if error.kind() == EngineErrorKind::Transient));
    assert_single_settlement_failure_metric(&metrics_handle.render(), "published", "lost_lease");
    Ok(())
}

pub(in super::super) async fn assert_publishing_state_unchanged(
    store: &PgStore,
    event_id: &str,
) -> TestResult {
    let state: (String, i32, bool, bool) = sqlx::query_as(
        "SELECT status, retry_count, published_at IS NULL, dlx_at IS NULL \
         FROM outbox WHERE event_id = $1",
    )
    .bind(event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        state,
        (crate::outbox::STATUS_PUBLISHING.to_string(), 0, true, true)
    );
    Ok(())
}

#[derive(Clone, Copy)]
pub(in super::super) enum TimedOutSettlePath {
    Retry,
    OrdinaryDlx,
    SameIdExpiryDlx,
}

impl TimedOutSettlePath {
    pub(in super::super) fn label(self) -> &'static str {
        match self {
            Self::Retry => "retry",
            Self::OrdinaryDlx => "ordinary-dlx",
            Self::SameIdExpiryDlx => "same-id-expiry-dlx",
        }
    }

    pub(in super::super) fn publisher(self) -> (RecordingPublisher, Arc<Mutex<u32>>) {
        match self {
            Self::Retry => RecordingPublisher::always_transient(),
            Self::OrdinaryDlx => RecordingPublisher::always_permanent(),
            Self::SameIdExpiryDlx => RecordingPublisher::always_ok(),
        }
    }

    pub(in super::super) fn expected_publish_calls(self) -> u32 {
        match self {
            Self::Retry | Self::OrdinaryDlx => 2,
            Self::SameIdExpiryDlx => 0,
        }
    }

    pub(in super::super) fn barrier_publisher(
        self,
    ) -> (SettleLockPublisher, SettleLockPublisherControl) {
        match self {
            Self::Retry => SettleLockPublisher::always_transient(),
            Self::OrdinaryDlx => SettleLockPublisher::always_permanent(),
            Self::SameIdExpiryDlx => SettleLockPublisher::new(),
        }
    }

    pub(in super::super) fn operation_label(self) -> &'static str {
        match self {
            Self::Retry => "retry",
            Self::OrdinaryDlx => "dlx",
            Self::SameIdExpiryDlx => "same_id_expiry_dlx",
        }
    }
}

pub(in super::super) type TimedOutSettleSnapshot =
    (String, i32, bool, bool, bool, bool, bool, bool);

pub(in super::super) type ConvergedSettleSnapshot = (String, i32, bool, bool, bool, bool);

pub(in super::super) async fn seed_timed_out_settle_entry(
    store: &PgStore,
    path: TimedOutSettlePath,
) -> Result<(String, String), TestError> {
    let event_id = unique_event_id(path.label());
    let domain = unique_domain(path.label());
    let entry = make_entry(&event_id);
    let env = make_test_env(&domain, "settle.timeout.outcome");
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    Ok((event_id, domain))
}

#[allow(clippy::expect_used)]
pub(in super::super) fn claim_clock_test_budget() -> RelayBudget {
    RelayBudget::new(
        Duration::from_secs(2),
        Duration::from_millis(500),
        Duration::from_millis(250),
        Duration::from_millis(250),
    )
    .expect("claim clock test budget must be valid")
}

pub(in super::super) async fn timed_out_settle_snapshot(
    store: &PgStore,
    event_id: &str,
) -> Result<TimedOutSettleSnapshot, sqlx::Error> {
    sqlx::query_as(
        "SELECT status, retry_count, retry_after IS NULL, lease_token IS NOT NULL, \
                lease_until IS NOT NULL, published_at IS NULL, dlx_at IS NULL, abandoned_at IS NULL \
         FROM outbox WHERE event_id = $1",
    )
    .bind(event_id)
    .fetch_one(&store.pool)
    .await
}

pub(in super::super) async fn dead_letter_count(
    store: &PgStore,
    event_id: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM dead_letter WHERE message_id = $1")
        .bind(event_id)
        .fetch_one(&store.pool)
        .await
}

pub(in super::super) async fn run_with_exhausted_settlement_pool(
    single: &PgStore,
    outbox: &PgOutbox,
    claim: PgClaimedOutboxEntry,
    control: &SettleLockPublisherControl,
) -> Result<
    (
        Result<consistency::Disposition, consistency::EngineError>,
        String,
    ),
    TestError,
> {
    let relay_completed = tokio::sync::Notify::new();
    let relay_run = async {
        let result = outbox.relay(claim).await;
        relay_completed.notify_one();
        result
    };
    let exhaustion = async {
        control.first_publish_started.notified().await;
        let held = single.pool.acquire().await?;
        control.release_first_publish.notify_one();
        relay_completed.notified().await;
        drop(held);
        Ok::<(), TestError>(())
    };
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    let (result, exhaustion_result) = metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { tokio::join!(relay_run, exhaustion) })
        })
    });
    exhaustion_result?;
    Ok((result, metrics_handle.render()))
}

pub(in super::super) struct SettlementPoolWaitFixture {
    pub(in super::super) _pg: testkit::PgFixture,
    pub(in super::super) owner: PgStore,
    pub(in super::super) single: PgStore,
    pub(in super::super) outbox: PgOutbox,
    pub(in super::super) claim: PgClaimedOutboxEntry,
    pub(in super::super) control: SettleLockPublisherControl,
    pub(in super::super) event_id: String,
}

pub(in super::super) async fn settlement_pool_wait_fixture(
    path: TimedOutSettlePath,
) -> Result<SettlementPoolWaitFixture, TestError> {
    let (pg, owner) = connect_pg().await?;
    setup_outbox(&owner).await?;
    let (event_id, domain) = seed_timed_out_settle_entry(&owner, path).await?;
    let budget = RelayBudget::new(
        Duration::from_secs(10),
        Duration::from_secs(2),
        Duration::from_millis(250),
        Duration::from_secs(1),
    )?;
    set_test_relay_budget_policy(&owner, budget).await?;

    let p = pg.params();
    let config = PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_max_connections(1)
    .with_acquire_timeout(Duration::from_secs(5));
    let single = PgStore::connect(&config).await?;
    let (publisher, control) = path.barrier_publisher();
    let outbox = make_pg_outbox_for_domain_with_budget(&single, &domain, publisher, budget);
    let claim = claim_entry_for_relay(&outbox, &event_id).await?;
    Ok(SettlementPoolWaitFixture {
        _pg: pg,
        owner,
        single,
        outbox,
        claim,
        control,
        event_id,
    })
}

pub(in super::super) async fn assert_settle_pool_wait_is_bounded(
    path: TimedOutSettlePath,
) -> TestResult {
    let fixture = settlement_pool_wait_fixture(path).await?;
    let (result, rendered_metrics) = run_with_exhausted_settlement_pool(
        &fixture.single,
        &fixture.outbox,
        fixture.claim,
        &fixture.control,
    )
    .await?;
    assert!(matches!(result, Err(error) if error.kind() == EngineErrorKind::Transient));
    assert_single_settlement_failure_metric(&rendered_metrics, path.operation_label(), "timeout");
    assert_eq!(
        timed_out_settle_snapshot(&fixture.owner, &fixture.event_id).await?,
        (
            crate::outbox::STATUS_PUBLISHING.to_string(),
            0,
            true,
            true,
            true,
            true,
            true,
            true,
        )
    );
    assert_eq!(
        dead_letter_count(&fixture.owner, &fixture.event_id).await?,
        0
    );
    assert_eq!(fixture.control.calls.load(Ordering::SeqCst), 1);

    fixture.single.shutdown().await?;
    fixture.owner.shutdown().await?;
    Ok(())
}

pub(in super::super) fn assert_single_settlement_failure_metric(
    rendered: &str,
    operation: &str,
    reason: &str,
) {
    let samples = rendered
        .lines()
        .filter(|line| line.starts_with("outbox_relay_settlement_failure_total{"))
        .collect::<Vec<_>>();
    assert_eq!(
        samples.len(),
        1,
        "unexpected settlement samples: {rendered}"
    );
    assert!(
        samples[0].contains(&format!(r#"operation="{operation}""#)),
        "{rendered}"
    );
    assert!(
        samples[0].contains(&format!(r#"reason="{reason}""#)),
        "{rendered}"
    );
    assert!(samples[0].ends_with(" 1"), "{rendered}");
    for forbidden in ["event_id=", "lease_token=", "deadline=", "error="] {
        assert!(!samples[0].contains(forbidden), "{rendered}");
    }
}

/// 用真实 `FOR UPDATE` gate 稳定阻塞目标 settle SQL；在持锁事务内使旧 lease capability 失效，
/// 保证解锁后的已取消 SQL 即便到达也只能 CAS miss。
pub(in super::super) async fn assert_locked_settle_timeout(
    store: &PgStore,
    outbox: &PgOutbox,
    claim: PgClaimedOutboxEntry,
    event_id: &str,
    path: TimedOutSettlePath,
    before: &TimedOutSettleSnapshot,
) -> TestResult {
    let mut blocker = store.pool.begin().await?;
    let locked: String =
        sqlx::query_scalar("SELECT event_id FROM outbox WHERE event_id = $1 FOR UPDATE")
            .bind(event_id)
            .fetch_one(&mut *blocker)
            .await?;
    assert_eq!(locked, event_id);

    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    let first_result = metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(outbox.relay(claim))
        })
    });
    assert!(
        matches!(first_result, Err(error) if error.kind() == EngineErrorKind::Transient),
        "{} settle timeout must remain transient",
        path.label()
    );
    let operation = match path {
        TimedOutSettlePath::Retry => "retry",
        TimedOutSettlePath::OrdinaryDlx => "dlx",
        TimedOutSettlePath::SameIdExpiryDlx => "same_id_expiry_dlx",
    };
    assert_single_settlement_failure_metric(&metrics_handle.render(), operation, "timeout");
    assert_eq!(
        timed_out_settle_snapshot(store, event_id).await?,
        *before,
        "{} timeout must not append retry/terminal state",
        path.label()
    );
    assert_eq!(
        dead_letter_count(store, event_id).await?,
        0,
        "{} timeout must not append a durable error",
        path.label()
    );

    sqlx::query(
        "UPDATE outbox SET updated_at = clock_timestamp() - interval '11 seconds', \
         lease_until = clock_timestamp() - interval '1 second' WHERE event_id = $1",
    )
    .bind(event_id)
    .execute(&mut *blocker)
    .await?;
    blocker.commit().await?;
    Ok(())
}

#[allow(clippy::unwrap_used)]
pub(in super::super) async fn assert_timed_out_settle_convergence(
    store: &PgStore,
    outbox: &PgOutbox,
    event_id: &str,
    path: TimedOutSettlePath,
    calls: &Arc<Mutex<u32>>,
) -> TestResult {
    let reclaimed = claim_entry_for_relay(outbox, event_id).await?;
    assert_eq!(reclaimed.idem_key().as_str(), event_id);
    let disposition = outbox.relay(reclaimed).await?;
    let converged: ConvergedSettleSnapshot = sqlx::query_as(
        "SELECT status, retry_count, retry_after IS NOT NULL, lease_token IS NULL, \
                published_at IS NULL, dlx_at IS NOT NULL \
         FROM outbox WHERE event_id = $1",
    )
    .bind(event_id)
    .fetch_one(&store.pool)
    .await?;
    let dead_letters_after = dead_letter_count(store, event_id).await?;

    match path {
        TimedOutSettlePath::Retry => {
            assert_eq!(disposition, Disposition::Requeue);
            assert_eq!(
                converged,
                ("pending".to_string(), 1, true, true, true, false)
            );
            assert_eq!(dead_letters_after, 0);
        }
        TimedOutSettlePath::OrdinaryDlx | TimedOutSettlePath::SameIdExpiryDlx => {
            assert_eq!(disposition, Disposition::Reject);
            assert_eq!(converged, ("dlx".to_string(), 1, false, true, true, true));
            assert_eq!(dead_letters_after, 1, "DLX must be inserted exactly once");
        }
    }
    assert_eq!(*calls.lock().unwrap(), path.expected_publish_calls());
    Ok(())
}

/// timeout 时比较整行状态快照，随后以同一 event ID 重 claim，验证 retry / 普通 DLX / expiry DLX
/// 各自只结算一次。
pub(in super::super) async fn assert_relay_settle_timeout_outcome(
    path: TimedOutSettlePath,
) -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let (event_id, domain) = seed_timed_out_settle_entry(&store, path).await?;

    let budget = RelayBudget::new(
        Duration::from_secs(10),
        Duration::from_secs(2),
        Duration::from_millis(250),
        Duration::from_secs(1),
    )?;
    set_test_relay_budget_policy(&store, budget).await?;
    let (publisher, calls) = path.publisher();
    let outbox = make_pg_outbox_for_domain_with_budget(&store, &domain, publisher, budget);
    let claim = claim_entry_for_relay(&outbox, &event_id).await?;
    if matches!(path, TimedOutSettlePath::SameIdExpiryDlx) {
        sqlx::query(
            "UPDATE outbox SET automatic_retry_deadline = clock_timestamp() - interval '1 second' \
             WHERE event_id = $1",
        )
        .bind(&event_id)
        .execute(&store.pool)
        .await?;
    }

    // retry_after is the durable next-attempt field; relay has no outbox last_error column, and a
    // dead_letter row is the only durable error summary. Both are included in the assertions below.
    let before = timed_out_settle_snapshot(&store, &event_id).await?;
    assert_eq!(
        before,
        (
            crate::outbox::STATUS_PUBLISHING.to_string(),
            0,
            true,
            true,
            true,
            true,
            true,
            true,
        )
    );

    assert_locked_settle_timeout(&store, &outbox, claim, &event_id, path, &before).await?;
    assert_timed_out_settle_convergence(&store, &outbox, &event_id, path, &calls).await?;

    store.shutdown().await?;
    Ok(())
}

/// PgOutboxCdcEmitter::write writes the opt-in append-only CDC table only.
///
/// It must not fallback to relay `outbox`, and duplicate event_id emits remain idempotent.
pub(in super::super) type OutboxCdcEmitterRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Vec<u8>,
    serde_json::Value,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);
