//! Public command/outbox composition with explicit publication and device report facts.
pub mod compose;
use rss_device_command::*;
use rss_device_command_postgres::{CallerRoles, PgStore};
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::fence::ExecutionBinding;
use rss_transactional_messaging::{message::*, outbox::*, policy::*, transaction::LocalTxAttempt};
use rss_transactional_messaging_postgres::{
    PgConfig, PgError, PgOutboxStore, PgPassword, PgPrivateCa, PgRuntime,
};
use std::{sync::Arc, time::Duration};
#[derive(Clone)]
struct Timer;
impl Timer {
    #[allow(clippy::disallowed_methods)]
    // reason: concrete test clock is the injection boundary.
    fn new() -> Self {
        Self
    }
}
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)]
    // reason: concrete test clock implements the injected monotonic source.
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, deadline: Deadline) {
        tokio::task::unconstrained(tokio::time::sleep_until(deadline.instant().into())).await;
    }
}
fn budget() -> anyhow::Result<OperationDeadline> {
    let timer = Timer::new();
    Ok(OperationDeadline::from_cutoff(
        Deadline::from_timeout(&timer, Duration::from_secs(10))?,
        &timer,
    ))
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
    message_in_domain(name, tenant, "execution-example")
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
/// Fixture authority is supplied independently of the database being consumed.
#[derive(serde::Deserialize)]
pub struct Input {
    #[serde(flatten)]
    pub pg: crate::pg::Input,
    /// Exact complete caller set supplied by the deployment, including this login.
    pub caller_roles: Vec<String>,
    pub target: [u8; 16],
    pub lineage: [u8; 16],
    pub epoch: i64,
}
pub async fn run(input: Input) -> anyhow::Result<()> {
    use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
    let callers = CallerRoles::new(
        &input
            .caller_roles
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )?;
    let s = scope(&input.pg.tenant)?;
    let authority = ExecutionBinding::new(
        StorageIdentity::new(input.target, input.lineage)?,
        s.tenant(),
        Epoch::new(input.epoch)?,
    );
    let config = PgConfig::new(
        &input.pg.host,
        input.pg.port,
        &input.pg.database,
        &input.pg.username,
        PgPassword::new(input.pg.password),
        PgPrivateCa::from_pem(input.pg.pg_ca.as_bytes().to_vec())?,
    );
    let runtime = Arc::new(PgRuntime::connect(config, Timer::new(), authority.storage()).await?);
    let outbox = Arc::new(PgOutboxStore::new(
        runtime.clone(),
        MessagingDomain::parse("execution-example")?,
        DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )?,
    )?);
    let result = scenario(&runtime, authority, outbox, s, callers).await;
    runtime.close().await;
    result
}
async fn scenario(
    runtime: &PgRuntime,
    binding: ExecutionBinding,
    outbox: Arc<PgOutboxStore<()>>,
    s: Scope,
    callers: CallerRoles,
) -> anyhow::Result<()> {
    let coordinate = Coordinate::new(2, 3)?;
    committed(
        compose::bootstrap(
            runtime,
            binding,
            outbox.clone(),
            s,
            coordinate,
            budget()?,
            callers.clone(),
        )
        .await,
    )?;
    let command = committed(
        compose::enqueue(
            runtime,
            binding,
            outbox.clone(),
            spec("example", s, coordinate)?,
            message("example", s.tenant())?,
            budget()?,
            callers.clone(),
        )
        .await,
    )?;
    anyhow::ensure!(
        command.status() == Status::Queued,
        "command did not start queued"
    );
    let selected = outbox.clone();
    let store = committed(
        runtime
            .local_tx(binding, budget()?, move |tx| {
                Box::pin(async move {
                    PgStore::new(
                        tx,
                        selected,
                        rss_device_command_postgres::CommandClock::Postgres,
                        &callers,
                        BatchLimit::default(),
                    )
                    .await
                })
            })
            .await,
    )?;
    let store = Arc::new(store);
    // A bounded fixture publisher records broker acceptance; this is not proof of device execution.
    let claims = outbox
        .claim_partition_heads(binding, std::num::NonZeroUsize::MIN, budget()?)
        .await?;
    anyhow::ensure!(claims.len() == 1, "atomic command/outbox append missing");
    for claim in claims {
        outbox
            .settle(claim, OutboxSettlement::Published(()), budget()?)
            .await?;
    }
    // The product owns the candidate order and decides how to handle a missing slot.
    let selected = store.clone();
    let ids = [CommandId::parse("missing")?, CommandId::parse("example")?];
    let recovered = committed(
        runtime
            .local_tx_with_context(
                binding,
                budget()?,
                ExactCommandIds::new(&ids)?,
                move |page, tx| Box::pin(async move { selected.recover_exact(tx, s, *page).await }),
            )
            .await,
    )?;
    anyhow::ensure!(
        matches!(recovered.as_slice(), [None, Some(command)] if command.spec().id() == &ids[1] && command.status() == Status::Published),
        "unexpected exact recovery page"
    );
    anyhow::ensure!(
        load(runtime, binding, store.clone(), s, "example")
            .await?
            .status()
            == Status::Published,
        "publication not distinct"
    );
    let received = report(
        runtime,
        binding,
        store.clone(),
        s,
        coordinate,
        DeviceEvent::Received,
    )
    .await?;
    anyhow::ensure!(
        received.command.status() == Status::Received,
        "received not distinct"
    );
    let old = report(
        runtime,
        binding,
        store.clone(),
        s,
        Coordinate::new(1, 1)?,
        DeviceEvent::Received,
    )
    .await;
    anyhow::ensure!(old.is_err(), "old command coordinate accepted");
    anyhow::ensure!(
        load(runtime, binding, store.clone(), s, "example").await? == received.command,
        "stale report changed command"
    );
    let applied = report(
        runtime,
        binding,
        store.clone(),
        s,
        coordinate,
        DeviceEvent::Reported(StateDigest::from_bytes([7; 32])),
    )
    .await?;
    anyhow::ensure!(
        applied.command.status() == Status::Applied,
        "device report did not reach applied"
    );
    handoff(runtime, binding, store.clone(), s, coordinate).await?;
    anyhow::ensure!(
        load(runtime, binding, store, s, "example").await? == applied.command,
        "applied command not persisted"
    );
    Ok(())
}
async fn handoff(
    runtime: &PgRuntime,
    binding: ExecutionBinding,
    store: Arc<PgStore<()>>,
    s: Scope,
    coordinate: Coordinate,
) -> anyhow::Result<()> {
    let pending = spec("handoff", s, coordinate)?;
    let dispatch = message("handoff", s.tenant())?;
    let selected = store.clone();
    committed(
        runtime
            .local_tx(binding, budget()?, move |tx| {
                Box::pin(async move { selected.queue(tx, pending, dispatch).await })
            })
            .await,
    )?;
    committed(
        compose::takeover(
            runtime,
            binding,
            store.clone(),
            s,
            coordinate,
            Coordinate::new(2, 4)?,
            budget()?,
        )
        .await,
    )?;
    anyhow::ensure!(
        load(runtime, binding, store, s, "handoff").await?.status() == Status::Superseded,
        "handoff not persisted"
    );
    Ok(())
}
async fn load(
    runtime: &PgRuntime,
    binding: ExecutionBinding,
    store: Arc<PgStore<()>>,
    s: Scope,
    name: &str,
) -> anyhow::Result<Command> {
    let id = CommandId::parse(name)?;
    committed(
        runtime
            .local_tx(binding, budget()?, move |tx| {
                Box::pin(async move { store.load(tx, s, &id).await })
            })
            .await,
    )?
    .ok_or_else(|| anyhow::anyhow!("missing persisted command"))
}
async fn report(
    runtime: &PgRuntime,
    binding: ExecutionBinding,
    store: Arc<PgStore<()>>,
    scope: Scope,
    coordinate: Coordinate,
    event: DeviceEvent,
) -> anyhow::Result<Transition> {
    let report = DeviceReport {
        scope,
        command_id: CommandId::parse("example")?,
        coordinate,
        event,
    };
    committed(
        runtime
            .local_tx(binding, budget()?, move |tx| {
                Box::pin(async move { store.report(tx, &report).await })
            })
            .await,
    )
}
