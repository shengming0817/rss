//! Business and Outbox atomicity through only the public write capability and producer ACL.
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    message::{
        AuthoredMessageMetadata, ContractIdentity, MessageEnvelope, MessageId, MessageMetadata,
        MessageMetadataExtensions, MessageRoute, MessagingDomain,
    },
    outbox::{AppendOutcome, OutboxWriter, PendingMessage},
    policy::OperationDeadline,
};
use rss_transactional_messaging_postgres::{
    PgConfig, PgError, PgOutboxWriter, PgPassword, PgPrivateCa, PgRuntime,
};
use std::{sync::Arc, time::Duration};

/// Ephemeral fixture input, not a product configuration or credential format.
#[derive(serde::Deserialize)]
pub struct Input {
    /// Database connection and authorized tenant supplied over stdin.
    #[serde(flatten)]
    pub pg: crate::pg::Input,
    /// Independently provisioned storage target.
    pub target: [u8; 16],
    /// Independently provisioned lineage.
    pub lineage: [u8; 16],
    /// Authorized execution epoch.
    pub epoch: i64,
    /// Isolated message identity prefix.
    pub id: String,
}
struct Timer;
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)] // reason: concrete clock supplies the monotonic source.
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, deadline: Deadline) {
        tokio::task::unconstrained(tokio::time::sleep_until(deadline.instant().into())).await;
    }
}
fn deadline() -> anyhow::Result<OperationDeadline> {
    Ok(OperationDeadline::from_cutoff(
        Deadline::from_timeout(&Timer, Duration::from_secs(10))?,
        &Timer,
    ))
}
fn message(tenant: TenantId, id: &str) -> anyhow::Result<PendingMessage<Vec<u8>>> {
    Ok(PendingMessage::new(MessageEnvelope::new(
        MessageId::parse(id)?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                Timepoint::try_from(1_i64)?,
                MessagingDomain::parse("writer-example")?,
                MessageRoute::parse("created")?,
                ContractIdentity::new(
                    ContractId::parse("example.created")?,
                    ContractVersion::from_major(1)?,
                    SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?,
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        vec![1, 2, 3],
    )))
}

/// Run both commit and rollback, checking persisted business and outbox rows through tenant RLS.
pub async fn run(input: Input) -> anyhow::Result<()> {
    let tenant = TenantId::parse(&input.pg.tenant)?;
    let binding = ExecutionBinding::new(
        StorageIdentity::new(input.target, input.lineage)?,
        vec![(tenant, Epoch::new(input.epoch)?)],
    )?;
    let config = PgConfig::new(
        input.pg.host,
        input.pg.port,
        input.pg.database,
        input.pg.username,
        PgPassword::new(input.pg.password),
        PgPrivateCa::from_pem(input.pg.pg_ca.into_bytes())?,
    );
    let runtime = Arc::new(PgRuntime::connect_producer(config, Timer, binding).await?);
    let result = atomicity(runtime.clone(), tenant, &input.id).await;
    tokio::time::timeout(Duration::from_secs(10), runtime.close()).await?;
    result
}
async fn atomicity(runtime: Arc<PgRuntime>, tenant: TenantId, prefix: &str) -> anyhow::Result<()> {
    for rollback in [false, true] {
        let id = format!("{prefix}-{}", if rollback { "rollback" } else { "commit" });
        let writer =
            PgOutboxWriter::new(runtime.clone(), MessagingDomain::parse("writer-example")?);
        let pending = message(tenant, &id)?;
        let business_id = id.clone();
        let attempt = runtime
            .local_tx(tenant, deadline()?, move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |connection| Box::pin(async move {
                sqlx::query("INSERT INTO public.business_effects(tenant_id,id) VALUES($1::uuid,$2)")
                    .bind(tenant.to_string()).bind(business_id).execute(connection).await?;
                Ok(())
            })).await?;
                    assert_eq!(writer.append(tx, pending).await?, AppendOutcome::Inserted);
                    if rollback {
                        return Err(PgError::from(sqlx::Error::RowNotFound));
                    }
                    Ok(())
                })
            })
            .await;
        let committed = attempt.fold(|()| Ok(true), Err, |_| Ok(false), Err, Err, Err)?;
        anyhow::ensure!(committed != rollback, "unexpected transaction outcome");
        let counts = runtime.local_tx(tenant,deadline()?,move |tx| Box::pin(async move {
            tx.with_connection(move |connection| Box::pin(async move {
                sqlx::query_as::<_,(i64,i64)>("SELECT (SELECT count(*) FROM public.business_effects WHERE id=$1), (SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id=$1)")
                    .bind(id).fetch_one(connection).await
            })).await
        })).await.fold(Ok,Err,Err,Err,Err,Err)?;
        let expected = i64::from(!rollback);
        anyhow::ensure!(
            counts == (expected, expected),
            "business/outbox atomicity mismatch"
        );
    }
    Ok(())
}
