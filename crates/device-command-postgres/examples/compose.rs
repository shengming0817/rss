//! Copy these functions into an application using its configured runtime and protocol encoder.
use rss_device_command::{
    BatchLimit, Command, CommandId, CommandSpec, Coordinate, DeviceReport, Outcome, Scope, Store,
};
use rss_device_command_postgres::PgStore;
use rss_transactional_messaging::{
    outbox::PendingMessage,
    policy::OperationDeadline,
    transaction::{LocalTxAttempt, TerminalDisposition},
};
use rss_transactional_messaging_postgres::{
    PgConsumerEffect, PgConsumerEffectFailure, PgError, PgOutboxStore, PgRuntime, PgTransaction,
};
use std::sync::Arc;
/// The application supplies an already configured runtime and authenticated command/message.
pub async fn enqueue(
    runtime: &PgRuntime,
    outbox: Arc<PgOutboxStore<()>>,
    spec: CommandSpec,
    message: PendingMessage<Vec<u8>>,
    deadline: OperationDeadline,
) -> LocalTxAttempt<Command, PgError> {
    runtime
        .local_tx(spec.scope().tenant(), deadline, move |tx| {
            Box::pin(async move {
                let store = PgStore::new(tx, outbox).await?;
                store
                    .initialize(tx, spec.scope(), spec.coordinate())
                    .await?;
                store.queue(tx, spec, message).await
            })
        })
        .await
}
/// A bounded page; inspect the full transaction outcome before advancing a page cursor.
pub async fn recover(
    runtime: &PgRuntime,
    store: Arc<PgStore<()>>,
    scope: Scope,
    limit: BatchLimit,
    after: Option<CommandId>,
    deadline: OperationDeadline,
) -> LocalTxAttempt<rss_device_command::RecoveryPage, PgError> {
    runtime
        .local_tx(scope.tenant(), deadline, move |tx| {
            Box::pin(async move { store.recover(tx, scope, limit, after.as_ref()).await })
        })
        .await
}
/// Product-owned authentication and decoding of the current envelope; no fixed report fallback.
pub trait ReportDecoder: Send + Sync {
    /// Bind the actual bytes and authenticated identity to an exact command report.
    fn decode(
        &self,
        message: &rss_transactional_messaging::message::MessageEnvelope<Vec<u8>>,
    ) -> Result<DeviceReport, rss_transactional_messaging::transaction::RejectKind>;
}
/// Reusable consumer always decodes its current message before touching command state.
pub struct ReportEffect<D> {
    /// Validated command repository.
    pub store: Arc<PgStore<()>>,
    /// Required product decoder; protocol and authentication remain outside the library.
    pub decoder: D,
}
impl<D: ReportDecoder> PgConsumerEffect<Vec<u8>> for ReportEffect<D> {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        message: &rss_transactional_messaging::message::MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        use rss_transactional_messaging::{
            error::MessagingErrorKind as Kind, transaction::RejectKind,
        };
        let report = match self.decoder.decode(message) {
            Ok(report) if report.scope.tenant() == message.metadata().tenant_id() => report,
            Ok(_) => return Ok(TerminalDisposition::Rejected(RejectKind::Permanent)),
            Err(reason) => return Ok(TerminalDisposition::Rejected(reason)),
        };
        let transition = match self.store.report(tx, &report).await {
            Ok(value) => value,
            Err(error) => {
                return match error.kind() {
                    Kind::OwnershipLost | Kind::Conflict => {
                        Ok(TerminalDisposition::Rejected(RejectKind::Permanent))
                    }
                    // Storage corruption/configuration failures must not permanently consume valid input.
                    Kind::Transient | Kind::Permanent | Kind::Invariant | Kind::DeadlineElapsed => {
                        Err(PgConsumerEffectFailure::infrastructure(error))
                    }
                };
            }
        };
        if transition.outcome == Outcome::OutOfOrder {
            return Err(PgConsumerEffectFailure::handler_transient(
                std::io::Error::other("command predecessor pending"),
            ));
        }
        Ok(TerminalDisposition::Succeeded)
    }
}
/// Ownership handoff is independent from changing desired generation.
pub async fn takeover(
    runtime: &PgRuntime,
    store: Arc<PgStore<()>>,
    scope: Scope,
    old: Coordinate,
    next: Coordinate,
    deadline: OperationDeadline,
) -> LocalTxAttempt<(), PgError> {
    runtime
        .local_tx(scope.tenant(), deadline, move |tx| {
            Box::pin(async move { store.advance(tx, scope, old, next).await })
        })
        .await
}
pub fn main() {
    println!(
        "Use enqueue/recover/ReportEffect with your configured PgRuntime; see README for installation."
    );
}
