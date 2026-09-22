//! Standalone ledger and optional borrowed message transaction, with independently supplied roles.
use rss_ledger::{AppendRequest, Authenticator, ChainId, KeyId, LedgerId, RecordId, Sequence};
use rss_ledger_postgres::{Committed, Control, Error, PgLedger, ReadLimit, Timer};
use rss_request_context::TenantId;
use rss_transactional_messaging::transaction::LocalTxAttempt;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
struct Clock(Instant);
impl Clock {
    #[allow(clippy::disallowed_methods)] // reason: example host supplies the monotonic origin.
    fn new() -> Self {
        Self(Instant::now())
    }
}
impl Timer for Clock {
    #[allow(clippy::disallowed_methods)] // reason: concrete injected example clock.
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, end: Duration) {
        tokio::time::sleep(end.saturating_sub(self.now())).await;
    }
}
#[derive(serde::Deserialize)]
pub struct Input {
    #[serde(flatten)]
    pub pg: crate::pg::Input,
    pub ledger_key_id: String,
    pub ledger_key: [u8; 32],
}
impl Input {
    fn auth(&self) -> anyhow::Result<Authenticator> {
        Ok(Authenticator::new(
            KeyId::parse(&self.ledger_key_id)?,
            self.ledger_key.to_vec(),
        )?)
    }
}
fn request(tenant: TenantId, id: &str) -> anyhow::Result<AppendRequest> {
    Ok(AppendRequest::new(
        LedgerId::new(tenant, ChainId::parse("example")?),
        RecordId::parse(id)?,
        vec![1, 2, 3],
    )?)
}
fn committed<T>(value: LocalTxAttempt<Committed<T>, Error>) -> anyhow::Result<T> {
    value.fold(
        |c| Ok(c.into_value()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
    )
}
pub async fn install(input: crate::pg::Input) -> anyhow::Result<()> {
    let pool = input.pool().await?;
    let mut connection = pool.acquire().await?;
    sqlx::raw_sql("SET ROLE ledger_owner")
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql(rss_ledger_postgres::MIGRATION_SQL)
        .execute(&mut *connection)
        .await?;
    #[cfg(feature = "ledger-messaging")]
    sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
        .execute(&mut *connection)
        .await?;
    drop(connection);
    pool.close().await;
    Ok(())
}
pub async fn run(input: Input) -> anyhow::Result<()> {
    let tenant = TenantId::parse(&input.pg.tenant)?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(40), &cancel);
    let store = PgLedger::new(input.pg.pool().await?, input.auth()?, &control).await?;
    let req = request(tenant, "standalone")?;
    let first = committed(store.append(&req, &control).await)?;
    let replay = committed(store.append(&req, &control).await)?;
    anyhow::ensure!(
        first.inserted() && !replay.inserted() && first.entry() == replay.entry(),
        "ledger idempotency mismatch"
    );
    sqlx_borrow(&input, &req, &control).await?;
    store.close(&control).await?;
    let reopened = PgLedger::new(input.pg.pool().await?, input.auth()?, &control).await?;
    let denied = reopened
        .read_window(
            req.ledger(),
            Sequence::new(0),
            ReadLimit::new(10, 1)?,
            &control,
        )
        .await;
    anyhow::ensure!(
        denied.fold(
            |_| false,
            |_| false,
            |e| matches!(e, Error::ReadBudgetExceeded),
            |_| false,
            |_| false,
            |_| false
        ),
        "encoded byte budget was not rejected with acknowledged rollback"
    );
    let page = committed(
        reopened
            .read_window(
                req.ledger(),
                Sequence::new(0),
                ReadLimit::new(10, 64 * 1024)?,
                &control,
            )
            .await,
    )?;
    anyhow::ensure!(
        input
            .auth()?
            .verify_chain(req.ledger(), page.entries())?
            .count()
            == 1,
        "durable chain missing"
    );
    #[cfg(feature = "ledger-messaging")]
    messaging(&input, &reopened, &control).await?;
    reopened.close(&control).await?;
    Ok(())
}
async fn sqlx_borrow(
    input: &Input,
    request: &AppendRequest,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let pool = input.pg.pool().await?;
    let auth = input.auth()?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(request.ledger().tenant().to_string())
        .execute(&mut *tx)
        .await?;
    let replay =
        rss_ledger_postgres::append_in_transaction(&mut tx, &auth, request, control).await?;
    anyhow::ensure!(!replay.inserted(), "native borrowed replay inserted again");
    let window = rss_ledger_postgres::read_window_in_transaction(
        &mut tx,
        &auth,
        request.ledger(),
        Sequence::new(0),
        ReadLimit::new(1, 4096)?,
        control,
    )
    .await?;
    anyhow::ensure!(
        window.entries().len() == 1 && window.entries()[0].matches(request),
        "native borrowed window differs"
    );
    tx.commit().await?;
    pool.close().await;
    Ok(())
}
#[cfg(feature = "ledger-messaging")]
impl rss_request_context::Clock for Clock {
    fn now(&self) -> Instant {
        self.0 + Timer::now(self)
    }
}
#[cfg(feature = "ledger-messaging")]
impl rss_request_context::ExecutionTimer for Clock {
    async fn sleep_until(&self, d: rss_request_context::Deadline) {
        tokio::task::unconstrained(tokio::time::sleep_until(d.instant().into())).await;
    }
}
#[cfg(feature = "ledger-messaging")]
async fn messaging(
    input: &Input,
    store: &PgLedger,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    use rss_transactional_messaging::{
        fence::{Epoch, ExecutionBinding, StorageIdentity},
        message::MessagingDomain,
        outbox::OutboxWriter,
        policy::OperationDeadline,
    };
    use rss_transactional_messaging_postgres::{
        PgConfig, PgError, PgOutboxWriter, PgPassword, PgPrivateCa, PgRuntime,
    };
    use std::sync::Arc;
    let tenant = TenantId::parse(&input.pg.tenant)?;
    let runtime = Arc::new(
        PgRuntime::connect_producer(
            PgConfig::new(
                &input.pg.host,
                input.pg.port,
                &input.pg.database,
                &input.pg.username,
                PgPassword::new(input.pg.password.clone()),
                PgPrivateCa::from_pem(input.pg.pg_ca.as_bytes().to_vec())?,
            ),
            Clock::new(),
            ExecutionBinding::new(
                StorageIdentity::new([1; 16], [2; 16])?,
                vec![(tenant, Epoch::new(1)?)],
            )?,
        )
        .await?,
    );
    for rollback in [false, true] {
        let id = if rollback { "rollback" } else { "commit" };
        let req = request(tenant, id)?;
        let writing = req.clone();
        let authenticator = Arc::new(input.auth()?);
        let writer =
            PgOutboxWriter::new(runtime.clone(), MessagingDomain::parse("writer-example")?);
        let pending = crate::sample_message::message(tenant, id)?;
        let clock = Clock::new();
        let deadline = OperationDeadline::from_cutoff(
            rss_request_context::Deadline::from_timeout(&clock, Duration::from_secs(10))?,
            &clock,
        );
        let result = runtime
            .local_tx(tenant, deadline, move |tx| {
                Box::pin(async move {
                    tx.prepare_outbox_partitions(
                        &pending.partition().cloned().into_iter().collect::<Vec<_>>(),
                    )
                    .await?;
                    rss_ledger_postgres::append_in(tx, authenticator, &writing).await?;
                    writer.append(tx, pending).await?;
                    if rollback {
                        return Err(PgError::from(sqlx::Error::RowNotFound));
                    }
                    Ok(())
                })
            })
            .await;
        let did_commit = result.fold(|()| Ok(true), Err, |_| Ok(false), Err, Err, Err)?;
        anyhow::ensure!(
            did_commit != rollback,
            "unexpected borrowed transaction settlement"
        );
        anyhow::ensure!(
            committed(store.find(req.ledger(), req.record_id(), control).await)?.is_some()
                != rollback,
            "ledger escaped enclosing transaction"
        );
    }
    runtime.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn runtime_requires_fixture_key_material() -> anyhow::Result<()> {
        let input = serde_json::json!({"host":"localhost","port":5432,"database":"example",
            "username":"runtime","password":"fixture","pg_ca":"ca","tenant":"tenant",
            "ledger_key_id":"random-fixture","ledger_key":vec![9u8;32]});
        assert!(serde_json::from_value::<super::Input>(input.clone()).is_ok());
        for key in ["ledger_key_id", "ledger_key"] {
            let mut missing = input.clone();
            missing
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("fixture input must be an object"))?
                .remove(key);
            assert!(serde_json::from_value::<super::Input>(missing).is_err());
        }
        Ok(())
    }
}
