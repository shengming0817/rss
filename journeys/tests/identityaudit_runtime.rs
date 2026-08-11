//! IdentityAudit executable acceptance over real Postgres, RabbitMQ and Redis providers.

use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result, ensure};
use audit::ports::{
    AuditChainHasher, AuditEntry, AuditOutcome, EntryHash, ResourceRef, actor_kind_from_db,
};
use primitives::MacKey;
use secure::{PasswordHash, RawPassword};
use sqlx::Row as _;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions, PgSslMode};
use testkit::await_try;

#[path = "support/identityaudit_fixture.rs"]
mod identityaudit_fixture;
use identityaudit_fixture::{FixtureProviders, LoginReceipt, RuntimeFixture};

const USER_ID: &str = "00000000-0000-4000-8000-000000000197";
const WAIT_TIMEOUT: Duration = Duration::from_secs(20);

fn assert_no_workflow_readiness_probes(report: &serde_json::Value) -> Result<()> {
    let checks = report
        .get("checks")
        .and_then(serde_json::Value::as_array)
        .context("identityaudit readiness report must contain a checks array")?;
    let names = checks
        .iter()
        .map(|check| {
            check
                .get("name")
                .and_then(serde_json::Value::as_str)
                .context("identityaudit readiness check must contain a string name")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        names
            .iter()
            .all(|name| !name.starts_with("projection") && !name.starts_with("saga")),
        "disabled workflows registered readiness probes: {names:?}"
    );
    Ok(())
}

fn owner_options(params: &testkit::PgConnParams) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(&params.host)
        .port(params.port)
        .database(&params.database)
        .username(&params.username)
        .password(&params.password)
        .ssl_mode(PgSslMode::Prefer)
}

async fn owner_pool(params: &testkit::PgConnParams) -> Result<PgPool> {
    Ok(PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(owner_options(params))
        .await?)
}

async fn seed_login(pool: &PgPool) -> Result<()> {
    let password = PasswordHash::for_test(RawPassword::new(
        identityaudit_fixture::password().to_owned(),
    ))?;
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version) \
         VALUES ($1::uuid, $2::uuid, $3, $4, 1)",
    )
    .bind(identityaudit_fixture::tenant())
    .bind(USER_ID)
    .bind(identityaudit_fixture::username())
    .bind(password.as_str())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO account_security_states \
         (tenant_id, user_id, status, authn_epoch, version, status_changed_at, updated_at) \
         VALUES ($1::uuid, $2::uuid, 'active', 0, 1, now(), now())",
    )
    .bind(identityaudit_fixture::tenant())
    .bind(USER_ID)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn seed_runtime_inventory_grant(pool: &PgPool) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(identityaudit_fixture::tenant())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "SELECT * FROM rss_record_role_revision( \
         'identityaudit-runtime-inventory-reader', \
         'IdentityAudit runtime inventory reader', \
         ARRAY['runtime:inventory:read']::text[], $1::uuid, 'admin')",
    )
    .bind(USER_ID)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO role_bindings (tenant_id, role_id, subject) \
         VALUES ($1::uuid, 'identityaudit-runtime-inventory-reader', $2)",
    )
    .bind(identityaudit_fixture::tenant())
    .bind(USER_ID)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn assert_no_projection_capture(pool: &PgPool) -> Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM projection_events")
        .fetch_one(pool)
        .await?;
    ensure!(
        count == 0,
        "disabled IdentityAudit captured {count} projection events"
    );
    Ok(())
}

async fn wait_for_auth_audit(pool: &PgPool) -> Result<()> {
    await_try(WAIT_TIMEOUT, async || {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM auth_audit_events \
                 WHERE tenant_context = $1::uuid \
                   AND resource_kind = 'http_route' \
                   AND resource_id = 'identity.profile' \
                   AND action = 'httpserve:authz' \
                   AND outcome = 'success'",
        )
        .bind(identityaudit_fixture::tenant())
        .fetch_one(pool)
        .await?;
        Ok::<Option<()>, anyhow::Error>((count == 1).then_some(()))
    })
    .await
    .context("auth audit did not persist within twenty seconds")
}

async fn wait_for_session_created_hash_chain(pool: &PgPool, login: &LoginReceipt) -> Result<()> {
    let session_id = login.session_id().to_owned();
    let rows = await_try(WAIT_TIMEOUT, async || {
        let rows = sqlx::query(
            "SELECT seq, prev_hash, entry_hash, actor::text AS actor, actor_kind, \
                        tenant_id::text AS tenant_id, action, resource_kind, resource_id, outcome, \
                        recorded_at_secs, recorded_at_nanos \
                 FROM audit_entries WHERE tenant_id = $1::uuid ORDER BY seq",
        )
        .bind(identityaudit_fixture::tenant())
        .fetch_all(pool)
        .await?;
        let matched = rows.iter().any(|row| {
            row.try_get::<String, _>("action")
                .is_ok_and(|action| action == "identity:login")
                && row
                    .try_get::<String, _>("resource_kind")
                    .is_ok_and(|kind| kind == "session")
                && row
                    .try_get::<String, _>("resource_id")
                    .is_ok_and(|resource| resource.starts_with("event:") && resource != session_id)
        });
        Ok::<Option<Vec<sqlx::postgres::PgRow>>, anyhow::Error>(matched.then_some(rows))
    })
    .await
    .context("session-created audit chain did not persist within twenty seconds")?;

    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let seq = u64::try_from(row.try_get::<i64, _>("seq")?)?;
        let prev_hash: [u8; 32] = row
            .try_get::<Vec<u8>, _>("prev_hash")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("persisted prev_hash is not 32 bytes"))?;
        let entry_hash: [u8; 32] = row
            .try_get::<Vec<u8>, _>("entry_hash")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("persisted entry_hash is not 32 bytes"))?;
        let actor = uuid::Uuid::parse_str(&row.try_get::<String, _>("actor")?)?;
        let actor_kind_raw = row.try_get::<String, _>("actor_kind")?;
        let actor_kind =
            actor_kind_from_db(&actor_kind_raw).context("persisted audit actor kind is invalid")?;
        let tenant = vocab::TenantId::parse(&row.try_get::<String, _>("tenant_id")?)?;
        let action = vocab::Action::parse(&row.try_get::<String, _>("action")?)?;
        let resource_kind = row.try_get::<String, _>("resource_kind")?;
        let resource_id = row.try_get::<String, _>("resource_id")?;
        let outcome_raw = row.try_get::<String, _>("outcome")?;
        let outcome =
            AuditOutcome::from_db(&outcome_raw).context("persisted audit outcome is invalid")?;
        let seconds = u64::try_from(row.try_get::<i64, _>("recorded_at_secs")?)?;
        let nanos = u32::try_from(row.try_get::<i32, _>("recorded_at_nanos")?)?;
        let recorded_at = SystemTime::UNIX_EPOCH
            .checked_add(Duration::new(seconds, nanos))
            .context("persisted audit timestamp overflow")?;
        entries.push(AuditEntry::hydrate(
            seq,
            EntryHash::new(prev_hash),
            EntryHash::new(entry_hash),
            ids::UserId::new(actor),
            actor_kind,
            tenant,
            action,
            ResourceRef::new(resource_kind, resource_id),
            outcome,
            recorded_at,
        ));
    }
    let hasher = AuditChainHasher::new(
        crypto::RustCryptoMacVerifier,
        MacKey::from_bytes(identityaudit_fixture::audit_chain_key().to_vec()),
    )
    .context("construct journey audit chain hasher")?;
    hasher.verify(&entries)?;
    let session = entries
        .iter()
        .find(|entry| {
            entry.action().as_str() == "identity:login"
                && entry.resource().kind() == "session"
                && entry.resource().id().starts_with("event:")
        })
        .context("session-created audit entry is missing after chain verification")?;
    ensure!(session.action().as_str() == "identity:login");
    ensure!(session.resource().kind() == "session");
    ensure!(session.resource().id() != login.session_id());
    ensure!(session.outcome() == AuditOutcome::Success);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn identityaudit_login_audit_ready_sigterm_drain() -> Result<()> {
    let (postgres, rabbit, redis) = tokio::try_join!(
        testkit::owned_postgres(),
        testkit::env_or_rabbitmq(),
        testkit::env_or_redis(),
    )?;
    let owned = &postgres;
    let logins = identityaudit_fixture::postgres_serving_logins();
    let [writer, reader, audit_admin] = owned
        .resolve_app_roles(
            logins.map(|login| testkit::PgAppRoleSpec::new(login.username(), login.password())),
        )
        .await?;
    let owner = owned.owner_params();
    let pool = owner_pool(owner).await?;
    sqlx::migrate!("../adapters/postgres/migrations")
        .run(&pool)
        .await
        .context("migrate IdentityAudit journey database")?;
    seed_runtime_inventory_grant(&pool).await?;
    let amqp = rabbit.vhost_url("rss_identity").await?;
    let providers = FixtureProviders::new(
        writer.params(),
        reader.params(),
        audit_admin.params(),
        amqp,
        redis.url().to_owned(),
    )?;
    let mut runtime = RuntimeFixture::start(providers).await?;

    runtime.wait_until_ready().await?;
    seed_login(&pool).await?;
    let login = runtime.login().await?;
    wait_for_auth_audit(&pool).await?;
    wait_for_session_created_hash_chain(&pool, &login).await?;
    assert_no_projection_capture(&pool).await?;

    let readiness = runtime.readiness_report().await?;
    assert_no_workflow_readiness_probes(&readiness)?;
    let inventory = runtime.runtime_inventory(&login).await?;
    ensure!(
        inventory.pointer("/data/activatedWorkflows")
            == Some(&serde_json::Value::Array(Vec::new())),
        "identityaudit activated unexpected workflows: {inventory}"
    );
    runtime.send_sigterm()?;
    runtime.wait_for_drain().await?;
    pool.close().await;
    drop((redis, rabbit, postgres));
    Ok(())
}
