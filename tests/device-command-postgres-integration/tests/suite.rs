#[path = "../../../crates/device-command-postgres/examples/compose.rs"]
pub mod compose;
mod crash;
mod scenarios;
use rss_device_command::*;
use rss_device_command_postgres::PgStore;
use rss_request_context::TenantId;
use rss_transactional_messaging::{message::*, outbox::*, policy::*, transaction::LocalTxAttempt};
use rss_transactional_messaging_postgres::{
    PgConfig, PgError, PgOutboxStore, PgPassword, PgPrivateCa, PgRuntime,
};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const OTHER: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d478";
#[derive(Clone)]
struct Timer(Instant);
impl Timer {
    #[allow(clippy::disallowed_methods)]
    // reason: concrete test clock is the injection boundary.
    fn new() -> Self {
        Self(Instant::now())
    }
}
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)]
    // reason: concrete test clock implements the injected monotonic source.
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_elapsed(self.0.elapsed())
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, deadline: AbsoluteDeadline) {
        tokio::time::sleep(deadline.remaining(self)).await;
    }
}
fn budget() -> anyhow::Result<OperationDeadline> {
    let timer = Timer::new();
    Ok(AbsoluteDeadline::from_timeout(&timer, Duration::from_secs(10))?.operation(&timer))
}
fn scope(tenant: &str) -> anyhow::Result<Scope> {
    Ok(Scope::new(
        TenantId::parse(tenant)?,
        DeviceId::parse("550e8400-e29b-41d4-a716-446655440000")?,
    ))
}
fn spec(name: &str, s: Scope, coordinate: Coordinate) -> anyhow::Result<CommandSpec> {
    Ok(CommandSpec::new(
        s,
        CommandId::parse(name)?,
        coordinate,
        StateDigest::from_bytes([7; 32]),
        i64::MAX,
    ))
}
fn message(name: &str, tenant: TenantId) -> anyhow::Result<PendingMessage<Vec<u8>>> {
    message_in_domain(name, tenant, "device-tests")
}
fn message_in_domain(
    name: &str,
    tenant: TenantId,
    domain: &str,
) -> anyhow::Result<PendingMessage<Vec<u8>>> {
    use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
    Ok(PendingMessage::new(MessageEnvelope::new(
        MessageId::parse(&format!("dispatch.{name}"))?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                Timepoint::try_from(1_i64)?,
                MessagingDomain::parse(domain)?,
                MessageRoute::parse("dispatch")?,
                ContractIdentity::new(
                    ContractId::parse("device.dispatch")?,
                    ContractVersion::from_major(1)?,
                    SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?,
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        vec![1, 2, 3],
    )))
}
fn committed<T>(attempt: LocalTxAttempt<T, PgError>) -> anyhow::Result<T> {
    attempt.fold(
        Ok,
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
    )
}
fn status<T>(attempt: LocalTxAttempt<T, PgError>) -> &'static str {
    attempt.fold(
        |_| "committed",
        |_| "not-started",
        |_| "rolled-back",
        |_| "rollback-failed",
        |_| "unknown",
        |_| "fenced",
    )
}
struct Fixture {
    runtime: Arc<PgRuntime>,
    store: Arc<PgStore<()>>,
    outbox: Arc<PgOutboxStore<()>>,
    owner: PgPool,
    config: PgConfig,
}
async fn stores(
    config: PgConfig,
) -> anyhow::Result<(Arc<PgRuntime>, Arc<PgStore<()>>, Arc<PgOutboxStore<()>>)> {
    let runtime = Arc::new(PgRuntime::connect(config, Timer::new()).await?);
    let outbox = Arc::new(PgOutboxStore::new(
        runtime.clone(),
        MessagingDomain::parse("device-tests")?,
        DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )?,
    )?);
    let selected = outbox.clone();
    let store = Arc::new(committed(
        runtime
            .local_tx(TenantId::parse(TENANT)?, budget()?, move |tx| {
                Box::pin(async move { PgStore::new(tx, selected).await })
            })
            .await,
    )?);
    Ok((runtime, store, outbox))
}
async fn setup(fixture: &testkit::PgTlsFixture) -> anyhow::Result<Fixture> {
    let p = fixture.params();
    let owner = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(
            PgConnectOptions::new()
                .host(&p.host)
                .port(p.port)
                .database(&p.database)
                .username(&p.username)
                .password(&p.password)
                .ssl_mode(PgSslMode::VerifyFull)
                .ssl_root_cert_from_pem(fixture.ca_pem().as_bytes().to_vec()),
        )
        .await?;
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; CREATE ROLE device_owner NOLOGIN NOBYPASSRLS; CREATE ROLE device_runtime LOGIN PASSWORD 'fixture-only' NOBYPASSRLS; DO $$ BEGIN EXECUTE format('GRANT CREATE ON DATABASE %I TO device_owner',current_database()); END $$;").execute(&owner).await?;
    sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
        .execute(&owner)
        .await?;
    let mut install = owner.begin().await?;
    sqlx::raw_sql("SET LOCAL ROLE device_owner")
        .execute(&mut *install)
        .await?;
    sqlx::raw_sql(rss_device_command_postgres::MIGRATION_SQL)
        .execute(&mut *install)
        .await?;
    install.commit().await?;
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging,rss_device_command TO device_runtime; GRANT SELECT ON rss_transactional_messaging.policy TO device_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO device_runtime; GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO device_runtime; GRANT USAGE ON ALL SEQUENCES IN SCHEMA rss_transactional_messaging TO device_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_transactional_messaging,rss_device_command TO device_runtime; GRANT SELECT ON ALL TABLES IN SCHEMA rss_device_command TO device_runtime;").execute(&owner).await?;
    let config = PgConfig::new(
        &p.host,
        p.port,
        &p.database,
        "device_runtime",
        PgPassword::new("fixture-only"),
        PgPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?,
    );
    let (runtime, store, outbox) = stores(config.clone()).await?;
    Ok(Fixture {
        runtime,
        store,
        outbox,
        owner,
        config,
    })
}
impl Fixture {
    async fn initialize(&self, s: Scope, coordinate: Coordinate) -> anyhow::Result<()> {
        let store = self.store.clone();
        committed(
            self.runtime
                .local_tx(s.tenant(), budget()?, move |tx| {
                    Box::pin(async move { store.initialize(tx, s, coordinate).await })
                })
                .await,
        )
    }
    async fn queue(&self, name: &str, s: Scope, coordinate: Coordinate) -> anyhow::Result<Command> {
        let spec = spec(name, s, coordinate)?;
        let m = message(name, s.tenant())?;
        let store = self.store.clone();
        committed(
            self.runtime
                .local_tx(s.tenant(), budget()?, move |tx| {
                    Box::pin(async move { store.queue(tx, spec, m).await })
                })
                .await,
        )
    }
    async fn load(&self, name: &str, s: Scope) -> anyhow::Result<Option<Command>> {
        let id = CommandId::parse(name)?;
        let store = self.store.clone();
        committed(
            self.runtime
                .local_tx(s.tenant(), budget()?, move |tx| {
                    Box::pin(async move { store.load(tx, s, &id).await })
                })
                .await,
        )
    }
    async fn report(
        &self,
        name: &str,
        s: Scope,
        coordinate: Coordinate,
        event: DeviceEvent,
    ) -> anyhow::Result<Transition> {
        let input = DeviceReport {
            scope: s,
            command_id: CommandId::parse(name)?,
            coordinate,
            event,
        };
        let store = self.store.clone();
        committed(
            self.runtime
                .local_tx(s.tenant(), budget()?, move |tx| {
                    Box::pin(async move { store.report(tx, &input).await })
                })
                .await,
        )
    }
    async fn recover(&self, s: Scope) -> anyhow::Result<RecoveryPage> {
        let store = self.store.clone();
        let limit = BatchLimit::new(64)?;
        committed(
            self.runtime
                .local_tx(s.tenant(), budget()?, move |tx| {
                    Box::pin(async move { store.recover(tx, s, limit, None).await })
                })
                .await,
        )
    }
    async fn publish(&self) -> anyhow::Result<()> {
        let claims = self
            .outbox
            .claim_partition_heads(std::num::NonZeroUsize::MIN.saturating_add(63), budget()?)
            .await?;
        for claim in claims {
            self.outbox
                .settle(claim, OutboxSettlement::Published(()), budget()?)
                .await?;
        }
        Ok(())
    }
    async fn count(&self, table: &str, id: &str) -> anyhow::Result<i64> {
        // Test-owned closed table selection; no caller SQL interpolation.
        let query = match table {
            "commands" => "SELECT count(*) FROM rss_device_command.commands WHERE command_id=$1",
            _ => "SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id=$1",
        };
        Ok(sqlx::query_scalar(query)
            .bind(id)
            .fetch_one(&self.owner)
            .await?)
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_command_postgres_suite() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(180), async {
        let network = testkit::bridge_network("device-command").await?;
        let postgres = testkit::postgres_tls(
            testkit::NetworkAttachment {
                network: network.name(),
                dns_name: "device-command",
            },
            testkit::PgTlsServerIdentity::MatchingHost,
        )
        .await?;
        let mut fixture = setup(&postgres).await?;
        scenarios::lifecycle(&fixture).await?;
        scenarios::authority_changes(&fixture).await?;
        scenarios::atomicity(&mut fixture).await?;
        scenarios::uncertainty(&mut fixture).await?;
        scenarios::isolation(&fixture).await?;
        scenarios::inbox(&fixture).await?;
        scenarios::bounds(&fixture).await?;
        scenarios::settlement_failures(&fixture).await?;
        scenarios::immutable_facts(&fixture).await?;
        scenarios::authority_rollback(&fixture).await?;
        scenarios::late_controls(&fixture).await?;
        scenarios::delayed_publication_read(&fixture).await?;
        scenarios::catalog_drift(&fixture).await?;
        scenarios::closed_catalog(&fixture).await?;
        scenarios::diagnostic_classes(&fixture).await?;
        scenarios::actual_state_redelivery(&fixture).await?;
        scenarios::permanent_inputs(&fixture).await?;
        crash::recovery(&fixture, &postgres).await?;
        scenarios::full_outbox_states(&fixture).await?;
        scenarios::authority_pages(&fixture).await?;
        scenarios::composition_boundaries(&fixture).await?;
        fixture.runtime.close().await;
        fixture.owner.close().await;
        Ok::<(), anyhow::Error>(())
    })
    .await??;
    Ok(())
}
