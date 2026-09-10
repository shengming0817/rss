//! Exact authorized Outbox redrive; archive consumer shares connection and key input.
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    policy::OperationDeadline,
    transaction::LocalTxAttempt,
};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa, PgRecoveryStore};
use rss_transactional_messaging_recovery::protection::{CaptureContext, seal};
use rss_transactional_messaging_recovery::*;
use std::{sync::Arc, time::Duration};
#[derive(serde::Deserialize)]
pub struct Input {
    #[serde(flatten)]
    pub pg: crate::pg::Input,
    pub hot_key: [u8; 32],
    pub cold_key: [u8; 32],
    pub dead_letter: String,
}
pub struct Timer;
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)] // reason: example host supplies monotonic time.
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, d: Deadline) {
        tokio::task::unconstrained(tokio::time::sleep_until(d.instant().into())).await;
    }
}
pub fn deadline() -> anyhow::Result<OperationDeadline> {
    Ok(OperationDeadline::from_cutoff(
        Deadline::from_timeout(&Timer, Duration::from_secs(15))?,
        &Timer,
    ))
}
pub fn config(input: &crate::pg::Input) -> anyhow::Result<PgConfig> {
    Ok(PgConfig::new(
        &input.host,
        input.port,
        &input.database,
        &input.username,
        PgPassword::new(input.password.clone()),
        PgPrivateCa::from_pem(input.pg_ca.as_bytes().to_vec())?,
    ))
}
pub fn binding(input: &crate::pg::Input) -> anyhow::Result<ExecutionBinding> {
    Ok(ExecutionBinding::new(
        StorageIdentity::new([1; 16], [2; 16])?,
        vec![(TenantId::parse(&input.tenant)?, Epoch::new(1)?)],
    )?)
}
pub fn settled<T, E: std::fmt::Display>(value: LocalTxAttempt<T, E>) -> anyhow::Result<T> {
    value.fold(
        Ok,
        |e| Err(anyhow::anyhow!("not started: {e}")),
        |e| Err(anyhow::anyhow!("rolled back: {e}")),
        |e| Err(anyhow::anyhow!("rollback failed: {e}")),
        |e| Err(anyhow::anyhow!("commit unknown: {e}")),
        |e| Err(anyhow::anyhow!("fenced: {e}")),
    )
}
struct Allow(TenantId);
impl Authorizer for Allow {
    async fn authorize(
        &self,
        c: Challenge<'_>,
        _: OperationDeadline,
    ) -> Result<Authorization, Error> {
        if c.tenant() != self.0 {
            return Err(Error::Unauthorized);
        }
        // reason: trusted local example authority, not authentication of arbitrary tenants.
        Ok(c.authorized())
    }
}
pub async fn install(input: Input) -> anyhow::Result<()> {
    let pool = input.pg.pool().await?;
    let mut connection = pool.acquire().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(&input.pg.tenant)
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
        .execute(&mut *connection)
        .await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,$1,$2)")
        .bind([1u8; 16].as_slice())
        .bind([2u8; 16].as_slice())
        .execute(&mut *connection)
        .await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
        .bind(&input.pg.tenant)
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql("SET rss.storage_target='01010101010101010101010101010101'; SET rss.storage_lineage='02020202020202020202020202020202'; SET rss.execution_epoch='1';").execute(&mut *connection).await?;
    // The installer supplies a candidate-encoded dead letter to the archive fixture.
    let tenant = TenantId::parse(&input.pg.tenant)?;
    let pending = crate::sample_message::message(tenant, "archive-example")?;
    let message = pending.envelope();
    let id = DeadLetterId::parse(&input.dead_letter)?;
    let fingerprint = rss_transactional_messaging::message::MessageFingerprint::of(message);
    let context = CaptureContext::from_provider(
        id,
        rss_transactional_messaging::inbox::ConsumerIdentity::new(
            tenant,
            rss_transactional_messaging::inbox::ConsumerGroup::parse("archive")?,
            message.id().clone(),
            message.metadata().contract().clone(),
        ),
        fingerprint,
    );
    let key = crate::ephemeral::EphemeralKey::from_bytes(&input.hot_key, "example-hot")?;
    let capsule = seal(&key, &context, message)?;
    let contract = message.metadata().contract();
    sqlx::query("INSERT INTO rss_transactional_messaging.consumer_dead_letter(tenant_id,id,message_id,consumer_group,contract,contract_version,schema_digest,fingerprint,capsule,reason,created_at) VALUES($1::uuid,$2::uuid,$3,'archive',$4,$5,$6,$7,$8,'rejected_permanent',clock_timestamp()-interval '3 days')")
        .bind(tenant.to_string()).bind(id.to_string()).bind(message.id().as_str()).bind(contract.id().as_str()).bind(contract.version().to_string()).bind(contract.schema_digest().as_str()).bind(fingerprint.as_bytes().as_slice()).bind(capsule.bytes()).execute(&mut *connection).await?;
    drop(connection);
    pool.close().await;
    Ok(())
}
pub async fn run(input: Input) -> anyhow::Result<()> {
    let tenant = TenantId::parse(&input.pg.tenant)?;
    let original_deadline = seed_outbox(&input.pg).await?;
    let key = Arc::new(crate::ephemeral::EphemeralKey::from_bytes(
        &input.hot_key,
        "example-hot",
    )?);
    let store =
        PgRecoveryStore::connect(config(&input.pg)?, Timer, binding(&input.pg)?, key).await?;
    let target = Target::Outbox(rss_transactional_messaging::message::MessageId::parse(
        "redrive-example",
    )?);
    let cutoff = Deadline::from_timeout(&Timer, Duration::from_secs(15))?;
    let query = authorize_query(
        &Allow(tenant),
        Query::inspect(tenant, target.clone()),
        &Timer,
        cutoff,
    )
    .await?;
    let page = store.query(&query, deadline()?).await?;
    let entry = page
        .entries
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("redrive target missing"))?;
    let operation = OperationId::new();
    let request = authorize_mutation(
        &Allow(tenant),
        Mutation::new(tenant, operation, target, entry.version, Action::Redrive)?,
        &Timer,
        cutoff,
    )
    .await?;
    let receipt = settled(store.mutate(&request, deadline()?).await)?;
    anyhow::ensure!(receipt.outcome == Outcome::Redriven, "redrive did not run");
    let retry = settled(store.mutate(&request, deadline()?).await)?;
    anyhow::ensure!(
        receipt.request.digest() == retry.request.digest()
            && receipt.version == retry.version
            && receipt.outcome == retry.outcome,
        "redrive retry changed its receipt"
    );
    store.close().await;
    let pool = input.pg.pool().await?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(&input.pg.tenant)
        .execute(&mut *tx)
        .await?;
    let after:String=sqlx::query_scalar("SELECT automatic_retry_deadline::text FROM rss_transactional_messaging.outbox WHERE message_id='redrive-example'").fetch_one(&mut *tx).await?;
    anyhow::ensure!(
        after == original_deadline,
        "redrive extended the original delivery window"
    );
    tx.commit().await?;
    pool.close().await;
    Ok(())
}

async fn seed_outbox(input: &crate::pg::Input) -> anyhow::Result<String> {
    use rss_transactional_messaging::{message::MessagingDomain, outbox::OutboxWriter};
    use rss_transactional_messaging_postgres::{PgOutboxWriter, PgRuntime};
    let tenant = TenantId::parse(&input.tenant)?;
    let seed_config = PgConfig::new(
        &input.host,
        input.port,
        &input.database,
        "recovery_runtime",
        PgPassword::new(input.password.clone()),
        PgPrivateCa::from_pem(input.pg_ca.as_bytes().to_vec())?,
    );
    let runtime = Arc::new(PgRuntime::connect(seed_config, Timer, binding(input)?).await?);
    let writer = PgOutboxWriter::new(runtime.clone(), MessagingDomain::parse("writer-example")?);
    let message = crate::sample_message::message(tenant, "redrive-example")?;
    let result = runtime
        .local_tx(tenant, deadline()?, move |tx| {
            Box::pin(async move {
                writer
                    .append(tx, message)
                    .await
                    .map(|_| ())
                    .map_err(Into::into)
            })
        })
        .await;
    runtime.close().await;
    settled(result)?;
    // Fixture preparation uses the separately authorized operator; runtime privileges stay narrow.
    let pool = input.pool().await?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(&input.tenant)
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql("SET LOCAL rss.storage_target='01010101010101010101010101010101'; SET LOCAL rss.storage_lineage='02020202020202020202020202020202'; SET LOCAL rss.execution_epoch='1';").execute(&mut *tx).await?;
    let original=sqlx::query_scalar("UPDATE rss_transactional_messaging.outbox SET status='dead_letter', automatic_retry_deadline=clock_timestamp()+interval '1 hour' WHERE message_id='redrive-example' RETURNING automatic_retry_deadline::text").fetch_one(&mut *tx).await?;
    tx.commit().await?;
    pool.close().await;
    Ok(original)
}
