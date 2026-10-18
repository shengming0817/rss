//! One public PG → relay → HTTPS consumer, reused verbatim by independent package proofs.
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    message::*,
    observability::{TransactionalMessagingEmitter, TransactionalMessagingObservation},
    outbox::{OutboxWriter, PendingMessage},
    policy::{DeliveryBudget, OperationDeadline},
};
use rss_transactional_messaging_postgres::{
    PgConfig, PgOutboxStore, PgPassword, PgPrivateCa, PgRuntime,
};
use rss_transactional_messaging_runtime::relay::{RelayBatchLimit, relay_once};
use rss_transactional_messaging_webhook::*;
use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

/// Fixture input is provided over stdin, never command-line arguments or logs.
#[derive(serde::Deserialize)]
pub struct Input {
    #[serde(flatten)]
    pub pg: crate::pg::Input,
    pub endpoint: Endpoint,
    pub id: String,
}
#[derive(Clone, serde::Deserialize)]
pub struct Endpoint {
    pub tenant: String,
    pub url: String,
    pub address: std::net::SocketAddr,
    pub ca: Vec<u8>,
    pub secret: Vec<u8>,
}
impl TargetAuthorizer for Endpoint {
    async fn authorize(
        &self,
        p: &Publication<'_>,
        _: OperationDeadline,
    ) -> Result<AuthorizedTarget, AuthorizationFailure> {
        // This executable example only authorizes a fixed fixture tenant and target.
        // Products replace this lookup with current subscription/resource authorization.
        let tenant = TenantId::parse(&self.tenant).map_err(|_| AuthorizationFailure::Denied)?;
        if p.tenant() != tenant
            || p.target() != &target().map_err(|_| AuthorizationFailure::Denied)?
        {
            return Err(AuthorizationFailure::Denied);
        }
        let network = NetworkAccess::new(
            vec![self.address],
            vec![ipnet::IpNet::from(self.address.ip())],
        )
        .map_err(|_| AuthorizationFailure::Denied)?;
        AuthorizedTarget::new(
            tenant,
            p.target().clone(),
            &self.url,
            network,
            TrustRoots::from_der([self.ca.clone()]).map_err(|_| AuthorizationFailure::Denied)?,
            SigningKeys::new(
                SigningKey::new(self.secret.clone()).map_err(|_| AuthorizationFailure::Denied)?,
                None,
            ),
        )
        .map_err(|_| AuthorizationFailure::Denied)
    }
}
pub struct Timer;
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)] // reason: injected host/test monotonic clock implementation.
    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, d: Deadline) {
        tokio::task::unconstrained(tokio::time::sleep_until(d.instant().into())).await;
    }
}
impl WallClock for Timer {
    fn unix_seconds(&self) -> i64 {
        1700000000
    }
}
pub struct Emitter;
impl TransactionalMessagingEmitter for Emitter {
    fn emit(&self, _: TransactionalMessagingObservation) { /* reason: minimal consumer has no telemetry backend. */
    }
}
pub fn target() -> anyhow::Result<Target> {
    Ok(Target::new(
        TargetId::parse("receiver")?,
        TargetVersion::new(1)?,
    ))
}
pub fn limits() -> anyhow::Result<Limits> {
    Ok(Limits::new(2, 65536, 4, 32, 8192)?)
}
pub fn budget() -> anyhow::Result<DeliveryBudget> {
    Ok(DeliveryBudget::new(
        Duration::from_secs(8),
        Duration::from_secs(2),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )?)
}
pub fn message(tenant: TenantId, id: &str) -> anyhow::Result<PendingMessage<Vec<u8>>> {
    use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
    Ok(pending_message(
        MessageId::parse(id)?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                Timepoint::try_from(1_i64)?,
                MessagingDomain::parse("webhook-example")?,
                MessageRoute::parse("created")?,
                ContractIdentity::new(
                    ContractId::parse("example.created")?,
                    ContractVersion::from_major(1)?,
                    SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?,
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        target()?,
        b"{ \"eventId\": \"business-1\" }\n".to_vec(),
    )?)
}
pub async fn runtime(input: &crate::pg::Input) -> anyhow::Result<Arc<PgRuntime>> {
    let tenant = TenantId::parse(&input.tenant)?;
    Ok(Arc::new(
        PgRuntime::connect(
            PgConfig::new(
                &input.host,
                input.port,
                &input.database,
                &input.username,
                PgPassword::new(&input.password),
                PgPrivateCa::from_pem(input.pg_ca.as_bytes().to_vec())?,
            ),
            Timer,
            // The fixture owns this storage lineage. Real hosts supply their admitted binding.
            ExecutionBinding::new(
                StorageIdentity::new([1; 16], [2; 16])?,
                vec![(tenant, Epoch::new(1)?)],
            )?,
        )
        .await?,
    ))
}
pub async fn run(input: Input) -> anyhow::Result<()> {
    let runtime = runtime(&input.pg).await?;
    let store = Arc::new(PgOutboxStore::<WebhookPublishReceipt>::new(
        runtime.clone(),
        MessagingDomain::parse("webhook-example")?,
        budget()?,
    )?);
    let pending = message(TenantId::parse(&input.pg.tenant)?, &input.id)?;
    let writer = store.clone();
    runtime
        .local_tx(
            TenantId::parse(&input.pg.tenant)?,
            OperationDeadline::from_remaining(Duration::from_secs(5)),
            move |tx| Box::pin(async move { writer.append(tx, pending).await.map_err(Into::into) }),
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    let publisher = WebhookPublisher::new(input.endpoint, Timer, Timer, limits()?);
    let report = relay_once(
        &*store,
        &publisher,
        &Timer,
        &Emitter,
        RelayBatchLimit::new(NonZeroUsize::MIN)?,
    )
    .await?;
    anyhow::ensure!(report.claimed() == 1, "expected one claimed delivery");
    // The fixture independently asserts the received signature and durable published status.
    runtime.close().await;
    Ok(())
}
