use crate::{Action, AuthorizedMutation, AuthorizedQuery, Error, Page, Receipt};
use rss_transactional_messaging::{
    policy::{ExecutionDeadlines, ExecutionTimer, OperationDeadline},
    transaction::LocalTxAttempt,
};

/// Provider owns tenant isolation, transactional CAS, durable evidence and operation-id uniqueness.
pub trait RecoveryStore: Send + Sync {
    /// Payload-free bounded query under the authorized scope.
    fn query(
        &self,
        request: &AuthorizedQuery,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<Page, Error>> + Send;
    /// Apply and record one mutation atomically. Preserve all transaction settlement states.
    fn mutate(
        &self,
        request: &AuthorizedMutation,
        deadline: OperationDeadline,
    ) -> impl Future<Output = LocalTxAttempt<Receipt, Error>> + Send;
    /// Read an exact operation receipt after checking its complete request digest. Absence does not prove rollback.
    fn receipt(
        &self,
        request: &AuthorizedMutation,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<Option<Receipt>, Error>> + Send;
}
/// Low-cardinality mutation category; no message identity enters observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionKind {
    /// Atomic DR plan application; not broker completion.
    DrApply,
    /// Exact DR termination and epoch advance; not message completion.
    DrTerminate,
    /// New-ID consumer replay.
    Replay,
    /// Same-ID Outbox retry.
    Redrive,
    /// Explicit expiration resolution.
    Resolve,
}
/// Diagnostic-only transaction tags. Mutation results remain canonical `LocalTxAttempt` values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptStatus {
    /// Commit or authoritative receipt readback succeeded.
    Committed,
    /// No mutation was started.
    NotStarted,
    /// Rollback was acknowledged.
    RolledBack,
    /// Rollback acknowledgement was lost.
    RollbackFailed,
    /// Commit may have occurred.
    CommitUnknown,
    /// The execution authority was fenced.
    Fenced,
}
/// Closed, payload-free observation emitted after a recovery attempt.
#[derive(Clone, Copy, Debug)]
pub struct Observation {
    /// Mutation category.
    pub action: ActionKind,
    /// Transaction certainty, preserving unknown commit and failed rollback.
    pub status: AttemptStatus,
    /// Closed error classification, if no committed receipt was established.
    pub error: Option<Error>,
}
/// Caller-owned telemetry; products choose sinks and deployment labels.
pub trait Observer {
    /// Emit a closed recovery observation without target or tenant labels.
    fn observe(&self, observation: Observation);
}
/// Bound a mutation and preserve uncertainty. Never automatically rerun a mutation.
pub async fn execute<S: RecoveryStore, C: ExecutionTimer, O: Observer>(
    store: &S,
    request: &AuthorizedMutation,
    clock: &C,
    deadlines: ExecutionDeadlines,
    observer: &O,
) -> LocalTxAttempt<Receipt, Error> {
    let action = match request.request().action() {
        Action::Replay(_) => ActionKind::Replay,
        Action::Redrive => ActionKind::Redrive,
        Action::Resolve(_) => ActionKind::Resolve,
    };
    crate::completion::execute(
        clock,
        deadlines,
        Error::Deadline,
        |deadline| store.mutate(request, deadline),
        |deadline| store.receipt(request, deadline),
        |status, _, error| {
            observer.observe(Observation {
                action,
                status,
                error,
            })
        },
    )
    .await
}
