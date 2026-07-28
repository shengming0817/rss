//! IdentityAudit executable acceptance over real Postgres, RabbitMQ and Redis providers.

#![cfg(feature = "integration")]

use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result, ensure};
use audit::ports::{
    AuditChainHasher, AuditEntry, AuditOutcome, EntryHash, ResourceRef, actor_kind_from_db,
};
use primitives::MacKey;
use secure::{PasswordHash, RawPassword};
use sqlx::Row as _;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions, PgSslMode};

#[path = "support/identityaudit_fixture.rs"]
mod identityaudit_fixture;
use identityaudit_fixture::{FixtureProviders, LoginReceipt, RuntimeFixture};

const USER_ID: &str = "00000000-0000-4000-8000-000000000197";
const WAIT_TIMEOUT: Duration = Duration::from_secs(20);

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

async fn register_projection_inputs(pool: &PgPool) -> Result<()> {
    for binding in generated::event::PROJECTION_INPUTS {
        sqlx::query("SELECT rss_register_projection_input_binding($1, $2, $3, $4, $5)")
            .bind(generated::event::PROJECTION_INPUT_GENERATION)
            .bind(binding.contract_id())
            .bind(binding.version())
            .bind(binding.schema_hash())
            .bind(binding.topic())
            .execute(pool)
            .await
            .context("register IdentityAudit projection input")?;
    }
    Ok(())
}

async fn wait_for_auth_audit(pool: &PgPool) -> Result<()> {
    tokio::time::timeout(WAIT_TIMEOUT, async {
        loop {
            let count: i64 = sqlx::query_scalar(
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
            if count == 1 {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("auth audit did not persist within twenty seconds")??;
    Ok(())
}

async fn wait_for_session_created_hash_chain(pool: &PgPool, login: &LoginReceipt) -> Result<()> {
    let rows = tokio::time::timeout(WAIT_TIMEOUT, async {
        loop {
            let rows = sqlx::query(
                "SELECT seq, prev_hash, entry_hash, actor::text AS actor, actor_kind, \
                        tenant_id::text AS tenant_id, action, resource_kind, resource_id, outcome, \
                        recorded_at_secs, recorded_at_nanos \
                 FROM audit_entries WHERE tenant_id = $1::uuid ORDER BY seq",
            )
            .bind(identityaudit_fixture::tenant())
            .fetch_all(pool)
            .await?;
            if rows.iter().any(|row| {
                row.try_get::<String, _>("resource_id")
                    .is_ok_and(|resource| resource == login.session_id())
            }) {
                return Ok::<_, anyhow::Error>(rows);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("session-created audit chain did not persist within twenty seconds")??;

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
        .find(|entry| entry.resource().id() == login.session_id())
        .context("session-created audit entry is missing after chain verification")?;
    ensure!(session.action().as_str() == "identity:login");
    ensure!(session.resource().kind() == "session");
    ensure!(session.outcome() == AuditOutcome::Success);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn identityaudit_login_audit_ready_sigterm_drain() -> Result<()> {
    let (postgres, rabbit, redis) = tokio::try_join!(
        testkit::env_or_postgres(),
        testkit::env_or_rabbitmq(),
        testkit::env_or_redis(),
    )?;
    let logins = identityaudit_fixture::postgres_serving_logins();
    let test_logins = logins
        .iter()
        .map(|login| testkit::PostgresTestLogin::new(login.username(), login.password()))
        .collect::<Vec<_>>();
    testkit::provision_postgres_test_logins(postgres.params(), &test_logins).await?;
    let pool = owner_pool(postgres.params()).await?;
    sqlx::migrate!("../adapters/postgres/migrations")
        .run(&pool)
        .await
        .context("migrate IdentityAudit journey database")?;
    register_projection_inputs(&pool).await?;
    let amqp = rabbit.vhost_url("rss_identity").await?;
    let providers = FixtureProviders::new(
        postgres.params().host.clone(),
        postgres.params().port,
        postgres.params().database.clone(),
        amqp,
        redis.url().to_owned(),
    )?;
    let mut runtime = RuntimeFixture::start(providers).await?;

    runtime.wait_until_ready().await?;
    seed_login(&pool).await?;
    let login = runtime.login().await?;
    wait_for_auth_audit(&pool).await?;
    wait_for_session_created_hash_chain(&pool, &login).await?;

    runtime.send_sigterm()?;
    runtime.wait_for_drain().await?;
    pool.close().await;
    drop((redis, rabbit, postgres));
    Ok(())
}
