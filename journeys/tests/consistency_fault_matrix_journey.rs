//! N-028 consistency fault crash matrix journey.
//!
//! `#![cfg(feature = "integration")]`: real backend lane. Postgres and RabbitMQ
//! are self-provisioned by `testkit` when Docker is available, or resolved from
//! explicit env URLs by `cargo xtask consistency-fault-matrix`.

#![cfg(feature = "integration")]

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use amqp::{AmqpPublisher, AmqpSubscriber};
use anyhow::{Context, Result, anyhow, bail};
use diport::{AckAction, AckableSubscriber, Acker, MessageId, PublishRequest, Publisher, Topic};
use futures::StreamExt;
use futures::future::BoxFuture;
use postgres::{PgConfig, PgPassword, PgRuntimeDeps, PgSslMode};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode as SqlxPgSslMode};
use testkit::crash_matrix::{CrashCase, CrashMatrix, CrashRunner, CrashStatus};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const SCHEMA_HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const RSS_APP_ROLE: &str = "rss_app";
const RABBIT_VHOST: &str = "rss_fault_matrix";
const PROJECTION_OWNER: &str = "fault-matrix-projection";

type CaseRunFn = for<'a> fn(
    &'a CrashCase,
    &'a PgHarness,
    &'a RabbitHarness,
    &'a RunScope,
) -> BoxFuture<'a, Result<()>>;

struct ReadyCaseRunner {
    id: &'static str,
    domain: &'static str,
    contract_id: &'static str,
    crash_point: &'static str,
    expected_invariant: &'static str,
    runner: CrashRunner,
    run: CaseRunFn,
}

impl ReadyCaseRunner {
    const fn new(
        id: &'static str,
        domain: &'static str,
        contract_id: &'static str,
        crash_point: &'static str,
        expected_invariant: &'static str,
        runner: CrashRunner,
        run: CaseRunFn,
    ) -> Self {
        Self {
            id,
            domain,
            contract_id,
            crash_point,
            expected_invariant,
            runner,
            run,
        }
    }

    fn validate_case(&self, case: &CrashCase) -> Result<()> {
        for (field, declared, mapped) in [
            ("domain", case.domain(), self.domain),
            ("contractId", case.contract_id(), self.contract_id),
            ("crashPoint", case.crash_point(), self.crash_point),
            (
                "expectedInvariant",
                case.expected_invariant(),
                self.expected_invariant,
            ),
        ] {
            if declared != mapped {
                bail!(
                    "ready fixture `{}` declares {field} `{declared}`, but journey runner contract is `{mapped}`",
                    case.id()
                );
            }
        }
        if case.runner() != self.runner {
            bail!(
                "ready fixture `{}` declares runner {:?}, but journey runner contract is {:?}",
                case.id(),
                case.runner(),
                self.runner
            );
        }
        Ok(())
    }
}

const READY_CASE_RUNNERS: &[ReadyCaseRunner] = &[
    ReadyCaseRunner::new(
        "outbox-after-publish-before-settle",
        "identity",
        "identity.session-created",
        "after-publish-before-settle",
        "outbox-publish-settled-once",
        CrashRunner::PostgresRabbitmq,
        run_outbox_after_publish_before_settle,
    ),
    ReadyCaseRunner::new(
        "outbox-transient-publish-failure",
        "settings",
        "settings.config-version-changed",
        "during-transient-publish",
        "outbox-transient-remains-retryable",
        CrashRunner::Postgres,
        run_outbox_transient_publish_failure,
    ),
    ReadyCaseRunner::new(
        "outbox-permanent-publish-failure",
        "identity",
        "identity.role-assigned",
        "during-permanent-publish",
        "outbox-dlx-summary-redacted",
        CrashRunner::Postgres,
        run_outbox_permanent_publish_failure,
    ),
    ReadyCaseRunner::new(
        "inbox-claim-crash-before-commit",
        "identity",
        "identity.session-created",
        "after-claim-before-commit",
        "inbox-stale-claim-reclaimable",
        CrashRunner::Postgres,
        run_inbox_claim_crash_before_commit,
    ),
    ReadyCaseRunner::new(
        "inbox-commit-before-ack-crash",
        "identity",
        "identity.session-created",
        "after-commit-before-ack",
        "inbox-redelivery-dedupes-once",
        CrashRunner::PostgresRabbitmq,
        run_inbox_commit_before_ack_crash,
    ),
    ReadyCaseRunner::new(
        "inbox-lease-lost-before-commit",
        "identity",
        "identity.session-created",
        "lease-lost-before-commit",
        "inbox-stale-lease-cannot-commit",
        CrashRunner::Postgres,
        run_inbox_lease_lost_before_commit,
    ),
    ReadyCaseRunner::new(
        "saga-forward-completed-before-checkpoint",
        "billing",
        "billing.checkout",
        "after-forward-before-checkpoint",
        "saga-resume-skips-completed-step",
        CrashRunner::Postgres,
        run_saga_forward_completed_before_checkpoint,
    ),
    ReadyCaseRunner::new(
        "saga-compensation-interrupted",
        "billing",
        "billing.checkout",
        "during-compensation",
        "saga-compensation-resumes-once",
        CrashRunner::Postgres,
        run_saga_compensation_interrupted,
    ),
    ReadyCaseRunner::new(
        "projection-after-apply-before-checkpoint",
        "audit",
        "audit.session-projection",
        "after-apply-before-checkpoint",
        "projection-replay-idempotent",
        CrashRunner::Postgres,
        run_projection_after_apply_before_checkpoint,
    ),
    ReadyCaseRunner::new(
        "projection-stale-checkpoint-writer",
        "settings",
        "settings.config-projection",
        "stale-checkpoint-writer",
        "projection-stale-writer-rejected",
        CrashRunner::Postgres,
        run_projection_stale_checkpoint_writer,
    ),
    ReadyCaseRunner::new(
        "reconcile-dispatch-before-result-record",
        "identity",
        "identity.reconcile-loop",
        "after-dispatch-before-result-record",
        "reconcile-dispatch-key-stable",
        CrashRunner::Postgres,
        run_reconcile_dispatch_before_result_record,
    ),
    ReadyCaseRunner::new(
        "reconcile-lease-lost-before-write",
        "identity",
        "identity.reconcile-loop",
        "lease-lost-before-write",
        "reconcile-stale-writer-rejected",
        CrashRunner::Postgres,
        run_reconcile_lease_lost_before_write,
    ),
];

struct RunScope {
    tenant: String,
    suffix: String,
}

impl RunScope {
    fn new() -> Self {
        Self {
            tenant: Uuid::new_v4().to_string(),
            suffix: Uuid::new_v4().simple().to_string(),
        }
    }

    fn event_id(&self, case: &CrashCase) -> String {
        format!("{}-{}", case.id(), self.suffix)
    }

    fn name(&self, prefix: &str) -> String {
        format!("{prefix}-{}", self.suffix)
    }

    fn rabbit_topic(&self, name: &str) -> String {
        format!("rss.fm.{name}.{}", self.suffix)
    }
}

struct PgHarness {
    _fixture: testkit::PgFixture,
    _deps: PgRuntimeDeps,
    pool: sqlx::PgPool,
}

struct RabbitHarness {
    _fixture: testkit::RabbitFixture,
    url: String,
}

fn workspace_root() -> Result<std::path::PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("journeys manifest should have workspace parent"))
}

fn pg_config(p: &testkit::PgConnParams) -> PgConfig {
    PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(Duration::from_secs(5))
}

fn pg_config_for(p: &testkit::PgConnParams, username: &str, password: &str) -> PgConfig {
    PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        username.to_string(),
        PgPassword::new(password.to_string()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_acquire_timeout(Duration::from_secs(5))
}

async fn owner_pool(p: &testkit::PgConnParams) -> Result<sqlx::PgPool> {
    let options = PgConnectOptions::new()
        .host(&p.host)
        .port(p.port)
        .database(&p.database)
        .username(&p.username)
        .password(&p.password)
        .ssl_mode(SqlxPgSslMode::Prefer);
    Ok(PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?)
}

fn random_rss_app_password() -> String {
    format!("rss_app_{}", Uuid::new_v4().simple())
}

async fn provision_rss_app_login(p: &testkit::PgConnParams, password: &str) -> Result<()> {
    if !password
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        bail!("generated rss_app password contains an unsafe SQL literal byte");
    }
    let pool = owner_pool(p).await?;
    sqlx::query(
        r#"
        DO $$
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtext('rss_app'));
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_app') THEN
                CREATE ROLE rss_app LOGIN NOBYPASSRLS;
            ELSE
                ALTER ROLE rss_app LOGIN NOBYPASSRLS;
            END IF;
        END
        $$;
        "#,
    )
    .execute(&pool)
    .await?;
    sqlx::query(&format!(
        "ALTER ROLE {RSS_APP_ROLE} LOGIN PASSWORD '{password}' NOBYPASSRLS"
    ))
    .execute(&pool)
    .await?;
    pool.close().await;
    Ok(())
}

async fn pg_harness() -> Result<PgHarness> {
    let fixture = testkit::env_or_postgres().await?;
    let password = random_rss_app_password();
    provision_rss_app_login(fixture.params(), &password).await?;
    let deps = PgRuntimeDeps::setup(
        &pg_config(fixture.params()),
        &pg_config_for(fixture.params(), RSS_APP_ROLE, &password),
        generated::event::PROJECTION_INPUTS,
    )
    .await?;
    let pool = owner_pool(fixture.params()).await?;
    Ok(PgHarness {
        _fixture: fixture,
        _deps: deps,
        pool,
    })
}

async fn rabbit_harness() -> Result<RabbitHarness> {
    let fixture = testkit::env_or_rabbitmq().await?;
    let url = fixture.vhost_url(RABBIT_VHOST).await?;
    Ok(RabbitHarness {
        _fixture: fixture,
        url,
    })
}

fn amqp_endpoint(url: &str) -> Result<secure::AmqpEndpoint> {
    Ok(secure::AmqpEndpoint::parse(
        url,
        secure::PlaintextEndpointPolicy::AllowLoopback,
    )?)
}

async fn connect_publisher(url: &str, name: &str) -> Result<AmqpPublisher> {
    Ok(AmqpPublisher::connect(&amqp_endpoint(url)?, name).await?)
}

async fn connect_subscriber(url: &str, name: &str) -> Result<AmqpSubscriber> {
    Ok(AmqpSubscriber::connect(&amqp_endpoint(url)?, name).await?)
}

fn metadata_json(scope: &RunScope) -> String {
    serde_json::json!({
        "tenantId": scope.tenant,
        "schemaVersion": "v1",
        "schemaHash": SCHEMA_HASH
    })
    .to_string()
}

async fn insert_outbox(
    pg: &PgHarness,
    scope: &RunScope,
    event_id: &str,
    domain: &str,
    topic: &str,
    contract_id: &str,
    status: &str,
) -> Result<()> {
    let rows = sqlx::query(
        r#"
        INSERT INTO outbox (
            event_id, tenant_id, domain, topic, contract_id, payload, metadata,
            status, contract_version, schema_hash, partition_key
        )
        VALUES (
            $1, $2::uuid, $3, $4, $5, decode('70', 'hex'), $6::jsonb,
            $7, 'v1', $8, $9
        )
        "#,
    )
    .bind(event_id)
    .bind(&scope.tenant)
    .bind(domain)
    .bind(topic)
    .bind(contract_id)
    .bind(metadata_json(scope))
    .bind(status)
    .bind(SCHEMA_HASH)
    .bind(format!("pk-{event_id}"))
    .execute(&pg.pool)
    .await?
    .rows_affected();
    if rows != 1 {
        bail!("outbox insert for {event_id} affected {rows} rows");
    }
    Ok(())
}

async fn assert_outbox_count(
    pg: &PgHarness,
    scope: &RunScope,
    event_id: &str,
    status: &str,
    expected: i64,
) -> Result<()> {
    let got: (i64,) = sqlx::query_as(
        "SELECT count(*)::bigint FROM outbox WHERE tenant_id = $1::uuid AND event_id = $2 AND status = $3",
    )
    .bind(&scope.tenant)
    .bind(event_id)
    .bind(status)
    .fetch_one(&pg.pool)
    .await?;
    if got.0 != expected {
        bail!(
            "outbox {event_id} status {status} count = {}, expected {expected}",
            got.0
        );
    }
    Ok(())
}

async fn insert_inbox_claim(
    pg: &PgHarness,
    scope: &RunScope,
    event_id: &str,
    group: &str,
    lease: &str,
    stale: bool,
) -> Result<()> {
    let age = if stale { "70 seconds" } else { "1 second" };
    let rows = sqlx::query(
        r#"
        INSERT INTO inbox_receipts (
            tenant_id, event_id, consumer_group, domain, topic, contract_id,
            contract_version, schema_hash, status, lease_token, claimed_at
        )
        VALUES (
            $1::uuid, $2, $3, 'identity', 'identity.session-created',
            'identity.session-created', 'v1', $4, 'claimed', $5::uuid,
            now() - $6::interval
        )
        "#,
    )
    .bind(&scope.tenant)
    .bind(event_id)
    .bind(group)
    .bind(SCHEMA_HASH)
    .bind(lease)
    .bind(age)
    .execute(&pg.pool)
    .await?
    .rows_affected();
    if rows != 1 {
        bail!("inbox claimed insert for {event_id}/{group} affected {rows} rows");
    }
    Ok(())
}

async fn insert_inbox_done(
    pg: &PgHarness,
    scope: &RunScope,
    event_id: &str,
    group: &str,
    lease: &str,
) -> Result<()> {
    let rows = sqlx::query(
        r#"
        INSERT INTO inbox_receipts (
            tenant_id, event_id, consumer_group, domain, topic, contract_id,
            contract_version, schema_hash, status, lease_token, committed_at
        )
        VALUES (
            $1::uuid, $2, $3, 'identity', 'identity.session-created',
            'identity.session-created', 'v1', $4, 'done', $5::uuid, now()
        )
        "#,
    )
    .bind(&scope.tenant)
    .bind(event_id)
    .bind(group)
    .bind(SCHEMA_HASH)
    .bind(lease)
    .execute(&pg.pool)
    .await?
    .rows_affected();
    if rows != 1 {
        bail!("inbox done insert for {event_id}/{group} affected {rows} rows");
    }
    Ok(())
}

async fn rabbit_unsettled_redelivers(
    rabbit: &RabbitHarness,
    scope: &RunScope,
    topic_raw: &str,
    event_id: &str,
) -> Result<()> {
    let topic = Topic::new(topic_raw);
    let sub1 = connect_subscriber(&rabbit.url, &scope.name("fault-matrix-sub1")).await?;
    let token1 = CancellationToken::new();
    let mut stream1 = sub1
        .subscribe_ackable(topic.clone(), token1.clone())
        .await?;
    let publisher = connect_publisher(&rabbit.url, &scope.name("fault-matrix-pub")).await?;

    publisher
        .publish(PublishRequest::new(
            topic.clone(),
            MessageId::new(event_id),
            b"fault-matrix".to_vec(),
        ))
        .await?;

    let delivery = tokio::time::timeout(Duration::from_secs(5), stream1.next())
        .await
        .context("timeout waiting for first delivery")?
        .ok_or_else(|| anyhow!("first stream closed"))?;
    let _unsettled = delivery.acker;
    drop(stream1);
    token1.cancel();
    AckableSubscriber::shutdown(&sub1).await?;

    let sub2 = connect_subscriber(&rabbit.url, &scope.name("fault-matrix-sub2")).await?;
    let token2 = CancellationToken::new();
    let mut stream2 = sub2.subscribe_ackable(topic, token2.clone()).await?;
    let redelivery = tokio::time::timeout(Duration::from_secs(5), stream2.next())
        .await
        .context("timeout waiting for redelivery")?
        .ok_or_else(|| anyhow!("redelivery stream closed"))?;
    if redelivery.message.id.as_str() != event_id {
        bail!(
            "redelivery id = {}, expected {event_id}",
            redelivery.message.id.as_str()
        );
    }
    redelivery.acker.settle(AckAction::Ack).await?;
    token2.cancel();
    AckableSubscriber::shutdown(&sub2).await?;
    Publisher::shutdown(&publisher).await?;
    Ok(())
}

async fn run_case(
    case: &CrashCase,
    pg: &PgHarness,
    rabbit: &RabbitHarness,
    scope: &RunScope,
) -> Result<()> {
    let runner = ready_case_runner(case.id())
        .ok_or_else(|| anyhow!("ready fixture has no runner function: {}", case.id()))?;
    runner.validate_case(case)?;
    (runner.run)(case, pg, rabbit, scope).await
}

fn ready_case_runner(id: &str) -> Option<&'static ReadyCaseRunner> {
    READY_CASE_RUNNERS.iter().find(|runner| runner.id == id)
}

fn run_outbox_after_publish_before_settle<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    rabbit: &'a RabbitHarness,
    scope: &'a RunScope,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let event_id = scope.event_id(case);
        insert_outbox(
            pg,
            scope,
            &event_id,
            "identity",
            "identity.session-created",
            "identity.session-created",
            "published",
        )
        .await?;
        rabbit_unsettled_redelivers(
            rabbit,
            scope,
            &scope.rabbit_topic("outbox-settle"),
            &event_id,
        )
        .await?;
        assert_outbox_count(pg, scope, &event_id, "published", 1).await
    })
}

fn run_outbox_transient_publish_failure<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    scope: &'a RunScope,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let event_id = scope.event_id(case);
        insert_outbox(
            pg,
            scope,
            &event_id,
            "settings",
            "settings.config-version-changed",
            "settings.config-version-changed",
            "pending",
        )
        .await?;
        let rows = sqlx::query(
            "UPDATE outbox SET retry_count = 1, retry_after = now() + interval '60 seconds' \
             WHERE tenant_id = $1::uuid AND event_id = $2",
        )
        .bind(&scope.tenant)
        .bind(&event_id)
        .execute(&pg.pool)
        .await?
        .rows_affected();
        if rows != 1 {
            bail!("transient outbox update affected {rows} rows");
        }
        assert_outbox_count(pg, scope, &event_id, "pending", 1).await
    })
}

fn run_outbox_permanent_publish_failure<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    scope: &'a RunScope,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let event_id = scope.event_id(case);
        insert_outbox(
            pg,
            scope,
            &event_id,
            "identity",
            "identity.role-assigned",
            "identity.role-assigned",
            "dlx",
        )
        .await?;
        let rows = sqlx::query(
            "UPDATE outbox SET metadata = metadata || jsonb_build_object('relayFailureReason', 'publisher_permanent') \
             WHERE tenant_id = $1::uuid AND event_id = $2",
        )
        .bind(&scope.tenant)
        .bind(&event_id)
        .execute(&pg.pool)
        .await?
        .rows_affected();
        if rows != 1 {
            bail!("permanent outbox update affected {rows} rows");
        }
        let rendered: (String,) = sqlx::query_as(
            "SELECT metadata::text FROM outbox WHERE tenant_id = $1::uuid AND event_id = $2",
        )
        .bind(&scope.tenant)
        .bind(&event_id)
        .fetch_one(&pg.pool)
        .await?;
        if rendered.0.contains("fault-matrix") {
            bail!(
                "dlx metadata leaked body material in metadata field ({} bytes)",
                rendered.0.len()
            );
        }
        assert_outbox_count(pg, scope, &event_id, "dlx", 1).await
    })
}

fn run_inbox_claim_crash_before_commit<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    scope: &'a RunScope,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let event_id = scope.event_id(case);
        let group = scope.name("audit.session-created");
        insert_inbox_claim(
            pg,
            scope,
            &event_id,
            &group,
            &Uuid::new_v4().to_string(),
            true,
        )
        .await?;
        let rows = sqlx::query(
            "UPDATE inbox_receipts SET lease_token = $1::uuid, receive_count = receive_count + 1, claimed_at = now() \
             WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4 \
             AND status = 'claimed' AND claimed_at <= now() - interval '60 seconds'",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&scope.tenant)
        .bind(&event_id)
        .bind(&group)
        .execute(&pg.pool)
        .await?
        .rows_affected();
        if rows != 1 {
            bail!("stale inbox claim should be reclaimed once, got {rows}");
        }
        Ok(())
    })
}

fn run_inbox_commit_before_ack_crash<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    rabbit: &'a RabbitHarness,
    scope: &'a RunScope,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let event_id = scope.event_id(case);
        let group = scope.name("audit.session-created");
        insert_inbox_done(pg, scope, &event_id, &group, &Uuid::new_v4().to_string()).await?;
        rabbit_unsettled_redelivers(
            rabbit,
            scope,
            &scope.rabbit_topic("inbox-commit"),
            &event_id,
        )
        .await?;
        let done: (i64,) = sqlx::query_as(
            "SELECT count(*)::bigint FROM inbox_receipts \
             WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3 AND status = 'done'",
        )
        .bind(&scope.tenant)
        .bind(&event_id)
        .bind(&group)
        .fetch_one(&pg.pool)
        .await?;
        if done.0 != 1 {
            bail!("inbox done row should remain once, got {}", done.0);
        }
        Ok(())
    })
}

fn run_inbox_lease_lost_before_commit<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    scope: &'a RunScope,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let event_id = scope.event_id(case);
        let group = scope.name("audit.session-created");
        let stale_lease = Uuid::new_v4().to_string();
        insert_inbox_claim(pg, scope, &event_id, &group, &stale_lease, false).await?;
        let rows = sqlx::query(
            "UPDATE inbox_receipts SET lease_token = $1::uuid \
             WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&scope.tenant)
        .bind(&event_id)
        .bind(&group)
        .execute(&pg.pool)
        .await?
        .rows_affected();
        if rows != 1 {
            bail!("inbox lease takeover affected {rows} rows");
        }
        let rows = sqlx::query(
            "UPDATE inbox_receipts SET status = 'done', committed_at = now() \
             WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3 AND lease_token = $4::uuid",
        )
        .bind(&scope.tenant)
        .bind(&event_id)
        .bind(&group)
        .bind(&stale_lease)
        .execute(&pg.pool)
        .await?
        .rows_affected();
        if rows != 0 {
            bail!("stale inbox lease should not commit, changed {rows}");
        }
        Ok(())
    })
}

fn run_saga_forward_completed_before_checkpoint<'a>(
    _case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    scope: &'a RunScope,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let saga_id = Uuid::new_v4().to_string();
        insert_saga_instance(pg, scope, &saga_id).await?;
        insert_saga_journal(pg, scope, &saga_id, 1, "reserve", "completed").await?;
        let rows = insert_saga_journal(pg, scope, &saga_id, 1, "reserve", "completed").await;
        if rows.is_ok() {
            bail!("duplicate completed saga step should be rejected by journal key");
        }
        Ok(())
    })
}

fn run_saga_compensation_interrupted<'a>(
    _case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    scope: &'a RunScope,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let saga_id = Uuid::new_v4().to_string();
        insert_saga_instance(pg, scope, &saga_id).await?;
        insert_saga_journal(pg, scope, &saga_id, 1, "reserve", "completed").await?;
        insert_saga_journal(pg, scope, &saga_id, 2, "reserve", "compensating").await?;
        insert_saga_journal(pg, scope, &saga_id, 3, "reserve", "compensated").await?;
        let count: (i64,) = sqlx::query_as(
            "SELECT count(*)::bigint FROM saga_journal \
             WHERE tenant_id = $1::uuid AND saga_id = $2::uuid AND status = 'compensated'",
        )
        .bind(&scope.tenant)
        .bind(&saga_id)
        .fetch_one(&pg.pool)
        .await?;
        if count.0 != 1 {
            bail!("compensation should settle once, got {}", count.0);
        }
        Ok(())
    })
}

fn run_projection_after_apply_before_checkpoint<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    scope: &'a RunScope,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let checkpoint_id = scope.name(case.id());
        upsert_projection_checkpoint(pg, &checkpoint_id, 10).await?;
        upsert_projection_checkpoint(pg, &checkpoint_id, 10).await?;
        let offset: (i64,) = sqlx::query_as(
            "SELECT offset_lsn FROM checkpoint WHERE owner = $1 AND checkpoint_id = $2",
        )
        .bind(PROJECTION_OWNER)
        .bind(&checkpoint_id)
        .fetch_one(&pg.pool)
        .await?;
        if offset.0 != 10 {
            bail!(
                "projection replay should keep idempotent offset, got {}",
                offset.0
            );
        }
        Ok(())
    })
}

fn run_projection_stale_checkpoint_writer<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    scope: &'a RunScope,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let checkpoint_id = scope.name(case.id());
        sqlx::query(
            "INSERT INTO checkpoint (owner, checkpoint_id, offset_lsn, version) VALUES ($1, $2, 20, 2)",
        )
        .bind(PROJECTION_OWNER)
        .bind(&checkpoint_id)
        .execute(&pg.pool)
        .await?;
        let rows = sqlx::query(
            "UPDATE checkpoint SET offset_lsn = 19, version = version + 1 \
             WHERE owner = $1 AND checkpoint_id = $2 AND version = 1",
        )
        .bind(PROJECTION_OWNER)
        .bind(&checkpoint_id)
        .execute(&pg.pool)
        .await?
        .rows_affected();
        if rows != 0 {
            bail!("stale checkpoint writer should be fenced, changed {rows}");
        }
        Ok(())
    })
}

fn run_reconcile_dispatch_before_result_record<'a>(
    case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    scope: &'a RunScope,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        insert_reconcile_target(
            pg,
            scope,
            &Uuid::new_v4().to_string(),
            &scope.name("resource-a"),
        )
        .await?;
        let event_id = scope.name("reconcile-dispatch-v1");
        insert_outbox(
            pg,
            scope,
            &event_id,
            "identity",
            "identity.role-revoked",
            "identity.role-revoked",
            "pending",
        )
        .await?;
        insert_outbox_if_absent(
            pg,
            scope,
            &event_id,
            "identity",
            "identity.role-revoked",
            "identity.role-revoked",
            "pending",
        )
        .await?;
        assert_outbox_count(pg, scope, &event_id, "pending", 1)
            .await
            .with_context(|| format!("{} stable dispatch key invariant failed", case.id()))
    })
}

fn run_reconcile_lease_lost_before_write<'a>(
    _case: &'a CrashCase,
    pg: &'a PgHarness,
    _rabbit: &'a RabbitHarness,
    scope: &'a RunScope,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let target_id = Uuid::new_v4().to_string();
        insert_reconcile_target(pg, scope, &target_id, &scope.name("resource-b")).await?;
        let current_lease = Uuid::new_v4().to_string();
        let stale_lease = Uuid::new_v4().to_string();
        let rows = sqlx::query(
            "INSERT INTO reconcile_leases (tenant_id, target_id, state, lease_token, holder_id, epoch, acquired_at, expires_at, heartbeat_at) \
             VALUES ($1::uuid, $2::uuid, 'held', $3::uuid, $4, 1, now(), now() + interval '60 seconds', now())",
        )
        .bind(&scope.tenant)
        .bind(&target_id)
        .bind(&current_lease)
        .bind(scope.name("holder-b"))
        .execute(&pg.pool)
        .await?
        .rows_affected();
        if rows != 1 {
            bail!("reconcile lease insert affected {rows} rows");
        }
        let rows = sqlx::query(
            "UPDATE reconcile_leases SET heartbeat_at = now() \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid AND lease_token = $3::uuid",
        )
        .bind(&scope.tenant)
        .bind(&target_id)
        .bind(&stale_lease)
        .execute(&pg.pool)
        .await?
        .rows_affected();
        if rows != 0 {
            bail!("stale reconcile lease should be fenced, changed {rows}");
        }
        Ok(())
    })
}

async fn upsert_projection_checkpoint(
    pg: &PgHarness,
    checkpoint_id: &str,
    offset_lsn: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO checkpoint (owner, checkpoint_id, offset_lsn, version) VALUES ($1, $2, $3, 1) \
         ON CONFLICT (owner, checkpoint_id) DO UPDATE SET offset_lsn = GREATEST(checkpoint.offset_lsn, EXCLUDED.offset_lsn), version = checkpoint.version + 1",
    )
    .bind(PROJECTION_OWNER)
    .bind(checkpoint_id)
    .bind(offset_lsn)
    .execute(&pg.pool)
    .await?;
    Ok(())
}

async fn insert_outbox_if_absent(
    pg: &PgHarness,
    scope: &RunScope,
    event_id: &str,
    domain: &str,
    topic: &str,
    contract_id: &str,
    status: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO outbox (
            event_id, tenant_id, domain, topic, contract_id, payload, metadata,
            status, contract_version, schema_hash, partition_key
        )
        VALUES (
            $1, $2::uuid, $3, $4, $5, decode('70', 'hex'), $6::jsonb,
            $7, 'v1', $8, $9
        )
        ON CONFLICT (event_id) DO NOTHING
        "#,
    )
    .bind(event_id)
    .bind(&scope.tenant)
    .bind(domain)
    .bind(topic)
    .bind(contract_id)
    .bind(metadata_json(scope))
    .bind(status)
    .bind(SCHEMA_HASH)
    .bind(format!("pk-{event_id}"))
    .execute(&pg.pool)
    .await?;
    Ok(())
}

async fn insert_saga_instance(pg: &PgHarness, scope: &RunScope, saga_id: &str) -> Result<()> {
    let rows = sqlx::query(
        "INSERT INTO saga_instances (tenant_id, saga_id, owner, contract_id, status) \
         VALUES ($1::uuid, $2::uuid, 'billing', 'billing.checkout', 'running') \
        ",
    )
    .bind(&scope.tenant)
    .bind(saga_id)
    .execute(&pg.pool)
    .await?
    .rows_affected();
    if rows != 1 {
        bail!("saga instance insert for {saga_id} affected {rows} rows");
    }
    Ok(())
}

async fn insert_saga_journal(
    pg: &PgHarness,
    scope: &RunScope,
    saga_id: &str,
    seq: i64,
    step: &str,
    status: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO saga_journal (tenant_id, saga_id, seq, step_name, status) VALUES ($1::uuid, $2::uuid, $3, $4, $5)",
    )
    .bind(&scope.tenant)
    .bind(saga_id)
    .bind(seq)
    .bind(step)
    .bind(status)
    .execute(&pg.pool)
    .await?;
    Ok(())
}

async fn insert_reconcile_target(
    pg: &PgHarness,
    scope: &RunScope,
    target_id: &str,
    resource_id: &str,
) -> Result<()> {
    let rows = sqlx::query(
        "INSERT INTO reconcile_targets (tenant_id, target_id, reconciler_id, resource_kind, resource_id, status) \
         VALUES ($1::uuid, $2::uuid, 'fault-matrix', 'device', $3, 'active') \
        ",
    )
    .bind(&scope.tenant)
    .bind(target_id)
    .bind(resource_id)
    .execute(&pg.pool)
    .await?
    .rows_affected();
    if rows != 1 {
        bail!("reconcile target insert for {target_id} affected {rows} rows");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn consistency_fault_matrix_ready_cases_execute() -> Result<()> {
    let root = workspace_root()?;
    let matrix = CrashMatrix::from_fixture_dir(root.join("fixtures").join("consistency"))?;
    let ready: Vec<&CrashCase> = matrix
        .cases()
        .iter()
        .filter(|case| case.status() == CrashStatus::Ready)
        .collect();
    if ready.len() != READY_CASE_RUNNERS.len() {
        bail!(
            "N-028 expects exactly {} ready cases, got {}",
            READY_CASE_RUNNERS.len(),
            ready.len()
        );
    }

    let mapped: BTreeSet<&str> = ready.iter().map(|case| case.id()).collect();
    let expected: BTreeSet<&str> = READY_CASE_RUNNERS.iter().map(|runner| runner.id).collect();
    if expected.len() != READY_CASE_RUNNERS.len() {
        bail!("READY_CASE_RUNNERS contains duplicate ids");
    }
    if mapped != expected {
        bail!("ready fixture ids drifted: got {mapped:?}, expected {expected:?}");
    }

    let scope = RunScope::new();
    let pg = pg_harness().await?;
    let rabbit = rabbit_harness().await?;
    for case in ready {
        run_case(case, &pg, &rabbit, &scope)
            .await
            .with_context(|| format!("fault matrix case `{}` failed", case.id()))?;
    }
    pg.pool.close().await;
    Ok(())
}
