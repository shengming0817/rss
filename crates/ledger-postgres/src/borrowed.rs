//! Trusted transaction borrowing without transferring settlement or connection ownership.
//! ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.9.0
use crate::{Control, Error, ReadLimit, StagedAppend, Timer, Window, probe, repository};
use rss_ledger::{AppendRequest, Authenticator, LedgerId, Sequence};
use rss_request_context::TenantId;
use rss_transactional_messaging::transaction::LocalTxDeadlineStage;
use sqlx::{PgConnection, Postgres, Transaction};

/// Stage an append in an existing SQLx transaction under its owner's absolute budget.
///
/// Validates the actual connection, role and tenant setting. Does not change settings,
/// acquire a connection or settle the transaction. Propagate errors to the owner; after
/// cancellation the owner must isolate any connection whose settlement is unconfirmed.
pub async fn append_in_transaction<T: Timer>(
    tx: &mut Transaction<'_, Postgres>,
    auth: &Authenticator,
    request: &AppendRequest,
    control: &Control<'_, T>,
) -> Result<StagedAppend, Error> {
    control
        .run_stage(LocalTxDeadlineStage::Operation, append(tx, auth, request))
        .await
}

/// Authenticate a bounded window inside the caller's current transaction snapshot.
///
/// The window can include this transaction's uncommitted appends. It is not commit
/// evidence. Tenant mismatch is an error, including for empty windows. Inherits the
/// caller's isolation level and never changes settings or settles the transaction.
pub async fn read_window_in_transaction<T: Timer>(
    tx: &mut Transaction<'_, Postgres>,
    auth: &Authenticator,
    ledger: &LedgerId,
    start: Sequence,
    limit: ReadLimit,
    control: &Control<'_, T>,
) -> Result<Window, Error> {
    control
        .run_stage(
            LocalTxDeadlineStage::Operation,
            window(tx, auth, ledger, start, limit),
        )
        .await
}

async fn validate(connection: &mut PgConnection, tenant: TenantId) -> Result<(), Error> {
    let setting: Option<String> =
        sqlx::query_scalar("SELECT current_setting('rss.tenant_id',true)")
            .fetch_one(&mut *connection)
            .await?;
    let actual = setting.as_deref().and_then(|s| TenantId::parse(s).ok());
    if actual != Some(tenant) {
        return Err(rss_ledger::Error::ScopeMismatch.into());
    }
    probe::validate_connection(connection).await
}

pub(crate) async fn append(
    connection: &mut PgConnection,
    auth: &Authenticator,
    request: &AppendRequest,
) -> Result<StagedAppend, Error> {
    validate(connection, request.ledger().tenant()).await?;
    repository::append(connection, auth, request).await
}

pub(crate) async fn window(
    connection: &mut PgConnection,
    auth: &Authenticator,
    ledger: &LedgerId,
    start: Sequence,
    limit: ReadLimit,
) -> Result<Window, Error> {
    validate(connection, ledger.tenant()).await?;
    repository::window(connection, auth, ledger, start, limit).await
}
