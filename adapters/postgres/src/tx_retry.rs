//! Postgres transaction retry classification and boundary metrics.

use std::error::Error;
use std::future::Future;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

#[cfg(feature = "domain-audit")]
use audit::ports::AuditError;
use consistency::{
    LocalTxDeadlineStage, LocalTxExecutionBudget, LocalTxFinalStatus, TxRetryBackoff, TxRetryClass,
    TxRetryFinalStatus, TxRetryPolicy, TxRetryReport, run_tx_retry,
};
#[cfg(feature = "domain-identity")]
use identity::ports::IdentityError;
#[cfg(any(
    feature = "domain-settings",
    feature = "domain-identity",
    feature = "domain-audit"
))]
use observ::LocalTxObservation;
#[cfg(feature = "domain-settings")]
use settings::ports::{ConfigRepoError, SecretRepoError};

use crate::cotx::{LocalTxAttempt, LocalTxRetryError};

/// Absolute monotonic deadlines minted once by the retry runner and shared by every attempt.
///
/// Fields and constructor stay private: callers can copy the token, but cannot reset either
/// deadline or manufacture a fresh budget. The transaction funnel receives the token as a
/// mandatory argument and can only use its stage-specific timeout methods.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LocalTxDeadline {
    operation: tokio::time::Instant,
    final_settlement: tokio::time::Instant,
}

macro_rules! deadline_evidence {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $name {
            _sealed: (),
        }

        impl $name {
            const fn mint() -> Self {
                Self { _sealed: () }
            }
        }
    };
}

deadline_evidence!(LocalTxAcquireDeadline);
deadline_evidence!(LocalTxBeginDeadline);
deadline_evidence!(LocalTxSetupDeadline);
deadline_evidence!(LocalTxOperationDeadline);
deadline_evidence!(LocalTxCommitDeadline);
deadline_evidence!(LocalTxRollbackDeadline);

/// A stage result whose deadline evidence can only be minted by that stage's narrow API.
pub(crate) enum LocalTxStageResult<T, E, D> {
    Complete(T),
    Failed(E),
    Deadline { source: Option<E>, evidence: D },
}

impl LocalTxDeadline {
    #[allow(clippy::disallowed_methods)]
    fn mint(budget: LocalTxExecutionBudget) -> Self {
        let started = tokio::time::Instant::now();
        Self {
            operation: started + budget.operation(),
            final_settlement: started + budget.total(),
        }
    }

    pub(crate) async fn acquire<F, T, E>(
        self,
        future: F,
    ) -> LocalTxStageResult<T, E, LocalTxAcquireDeadline>
    where
        F: Future<Output = Result<T, E>>,
    {
        match self.operation_stage(future).await {
            Ok(Ok(value)) => LocalTxStageResult::Complete(value),
            Ok(Err(error)) => LocalTxStageResult::Failed(error),
            Err(()) => LocalTxStageResult::Deadline {
                source: None,
                evidence: LocalTxAcquireDeadline::mint(),
            },
        }
    }

    pub(crate) async fn begin<F, T, E>(
        self,
        future: F,
    ) -> LocalTxStageResult<T, E, LocalTxBeginDeadline>
    where
        F: Future<Output = Result<T, E>>,
    {
        match self.operation_stage(future).await {
            Ok(Ok(value)) => LocalTxStageResult::Complete(value),
            Ok(Err(error)) => LocalTxStageResult::Failed(error),
            Err(()) => LocalTxStageResult::Deadline {
                source: None,
                evidence: LocalTxBeginDeadline::mint(),
            },
        }
    }

    pub(crate) async fn setup<F, T, E>(
        self,
        future: F,
    ) -> LocalTxStageResult<T, E, LocalTxSetupDeadline>
    where
        F: Future<Output = Result<T, E>>,
        E: Error + 'static,
    {
        match self.operation_stage(future).await {
            Ok(Ok(value)) => LocalTxStageResult::Complete(value),
            Ok(Err(error)) if is_deadline_derived(&error) => LocalTxStageResult::Deadline {
                source: Some(error),
                evidence: LocalTxSetupDeadline::mint(),
            },
            Ok(Err(error)) => LocalTxStageResult::Failed(error),
            Err(()) => LocalTxStageResult::Deadline {
                source: None,
                evidence: LocalTxSetupDeadline::mint(),
            },
        }
    }

    pub(crate) async fn operation<F, T, E>(
        self,
        future: F,
    ) -> LocalTxStageResult<T, E, LocalTxOperationDeadline>
    where
        F: Future<Output = Result<T, E>>,
        E: Error + 'static,
    {
        match self.operation_stage(future).await {
            Ok(Ok(value)) => LocalTxStageResult::Complete(value),
            Ok(Err(error)) if is_deadline_derived(&error) => LocalTxStageResult::Deadline {
                source: Some(error),
                evidence: LocalTxOperationDeadline::mint(),
            },
            Ok(Err(error)) => LocalTxStageResult::Failed(error),
            Err(()) => LocalTxStageResult::Deadline {
                source: None,
                evidence: LocalTxOperationDeadline::mint(),
            },
        }
    }

    pub(crate) async fn commit<F>(
        self,
        future: F,
    ) -> LocalTxStageResult<(), sqlx::Error, LocalTxCommitDeadline>
    where
        F: Future<Output = Result<(), sqlx::Error>>,
    {
        match self.settlement_stage(future).await {
            Ok(Ok(())) => LocalTxStageResult::Complete(()),
            Ok(Err(error)) if is_deadline_derived(&error) => LocalTxStageResult::Deadline {
                source: Some(error),
                evidence: LocalTxCommitDeadline::mint(),
            },
            Ok(Err(error)) => LocalTxStageResult::Failed(error),
            Err(()) => LocalTxStageResult::Deadline {
                source: None,
                evidence: LocalTxCommitDeadline::mint(),
            },
        }
    }

    pub(crate) async fn rollback<F>(
        self,
        future: F,
    ) -> LocalTxStageResult<(), sqlx::Error, LocalTxRollbackDeadline>
    where
        F: Future<Output = Result<(), sqlx::Error>>,
    {
        match self.settlement_stage(future).await {
            Ok(Ok(())) => LocalTxStageResult::Complete(()),
            Ok(Err(error)) if is_deadline_derived(&error) => LocalTxStageResult::Deadline {
                source: Some(error),
                evidence: LocalTxRollbackDeadline::mint(),
            },
            Ok(Err(error)) => LocalTxStageResult::Failed(error),
            Err(()) => LocalTxStageResult::Deadline {
                source: None,
                evidence: LocalTxRollbackDeadline::mint(),
            },
        }
    }

    async fn operation_stage<F: Future>(self, future: F) -> Result<F::Output, ()> {
        #[allow(clippy::disallowed_methods)]
        if tokio::time::Instant::now() >= self.operation {
            return Err(());
        }
        tokio::time::timeout_at(self.operation, future)
            .await
            .map_err(|_| ())
    }

    async fn settlement_stage<F: Future>(self, future: F) -> Result<F::Output, ()> {
        #[allow(clippy::disallowed_methods)]
        if tokio::time::Instant::now() >= self.final_settlement {
            return Err(());
        }
        tokio::time::timeout_at(self.final_settlement, future)
            .await
            .map_err(|_| ())
    }

    /// Server-side operation limits, both strictly inside the client operation deadline.
    pub(crate) fn server_timeout_millis(self) -> (u64, u64) {
        #[allow(clippy::disallowed_methods)]
        let remaining = self
            .operation
            .saturating_duration_since(tokio::time::Instant::now());
        let remaining_millis = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
        let statement_millis = remaining_millis.saturating_sub(2).max(1);
        let lock_millis = statement_millis.min(5_000);
        (statement_millis, lock_millis)
    }

    async fn backoff(self, ceiling: Duration) -> TxRetryBackoff {
        #[cfg(all(test, feature = "integration"))]
        let delay = TEST_LOCALTX_BACKOFF_DELAY
            .try_with(|delay| *delay)
            .unwrap_or_else(|_| full_jitter(ceiling));
        #[cfg(not(all(test, feature = "integration")))]
        let delay = full_jitter(ceiling);
        self.wait_backoff(delay).await
    }

    async fn wait_backoff(self, delay: Duration) -> TxRetryBackoff {
        #[allow(clippy::disallowed_methods)]
        let remaining = self
            .operation
            .saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() || delay >= remaining {
            return TxRetryBackoff::Exhausted;
        }
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        #[allow(clippy::disallowed_methods)]
        if tokio::time::Instant::now() >= self.operation {
            TxRetryBackoff::Exhausted
        } else {
            TxRetryBackoff::Continue
        }
    }
}

fn is_deadline_derived(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(source) = current {
        if matches!(
            source.downcast_ref::<sqlx::Error>(),
            Some(sqlx::Error::Database(database))
                if database.code().as_deref() == Some("57014")
        ) {
            return true;
        }
        current = source.source();
    }
    false
}

#[cfg(all(test, feature = "integration"))]
tokio::task_local! {
    static TEST_LOCALTX_EXECUTION_BUDGET: LocalTxExecutionBudget;
}

#[cfg(all(test, feature = "integration"))]
tokio::task_local! {
    static TEST_LOCALTX_BACKOFF_DELAY: Duration;
}

#[cfg(all(test, feature = "integration"))]
pub(crate) async fn with_localtx_execution_budget_for_test<T>(
    budget: LocalTxExecutionBudget,
    future: impl Future<Output = T>,
) -> T {
    TEST_LOCALTX_EXECUTION_BUDGET.scope(budget, future).await
}

#[cfg(all(test, feature = "integration"))]
pub(crate) async fn with_localtx_backoff_delay_for_test<T>(
    delay: Duration,
    future: impl Future<Output = T>,
) -> T {
    TEST_LOCALTX_BACKOFF_DELAY.scope(delay, future).await
}

#[cfg(test)]
pub(crate) fn localtx_deadline_for_test() -> LocalTxDeadline {
    LocalTxDeadline::mint(LocalTxExecutionBudget::DEFAULT)
}

fn localtx_execution_budget() -> LocalTxExecutionBudget {
    #[cfg(all(test, feature = "integration"))]
    if let Ok(budget) = TEST_LOCALTX_EXECUTION_BUDGET.try_with(|budget| *budget) {
        return budget;
    }
    LocalTxExecutionBudget::DEFAULT
}

/// Closed Postgres retry-routing boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PgTxRetryBoundary {
    #[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
    OutboxProducer,
    #[cfg(feature = "domain-settings")]
    SettingsConfig,
    #[cfg(feature = "domain-settings")]
    SettingsSecret,
    #[cfg(feature = "domain-identity")]
    IdentityCredential,
    #[cfg(feature = "domain-identity")]
    IdentityAuthGrant,
    #[cfg(feature = "domain-identity")]
    IdentityRefresh,
    #[cfg(feature = "domain-audit")]
    AuditAppend,
    #[cfg(feature = "domain-audit")]
    AuditListTenantAppend,
}

impl PgTxRetryBoundary {
    pub(crate) const fn as_label(self) -> &'static str {
        match self {
            #[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
            Self::OutboxProducer => "outbox.producer",
            #[cfg(feature = "domain-settings")]
            Self::SettingsConfig => "settings.config",
            #[cfg(feature = "domain-settings")]
            Self::SettingsSecret => "settings.secret",
            #[cfg(feature = "domain-identity")]
            Self::IdentityCredential => "identity.credential",
            #[cfg(feature = "domain-identity")]
            Self::IdentityAuthGrant => "identity.auth-grant",
            #[cfg(feature = "domain-identity")]
            Self::IdentityRefresh => "identity.refresh",
            #[cfg(feature = "domain-audit")]
            Self::AuditAppend => "audit.append",
            #[cfg(feature = "domain-audit")]
            Self::AuditListTenantAppend => "audit.list-tenant-entries",
        }
    }
}

/// Non-retrying HTTP producer transaction boundary.
#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
pub(crate) const OUTBOX_PRODUCER_BOUNDARY: PgTxRetryBoundary = PgTxRetryBoundary::OutboxProducer;
/// Retry boundary for settings config UoW writes.
#[cfg(feature = "domain-settings")]
pub(crate) const SETTINGS_CONFIG_BOUNDARY: PgTxRetryBoundary = PgTxRetryBoundary::SettingsConfig;
/// Retry boundary for settings secret CAS writes.
#[cfg(feature = "domain-settings")]
pub(crate) const SETTINGS_SECRET_BOUNDARY: PgTxRetryBoundary = PgTxRetryBoundary::SettingsSecret;
/// Retry boundary for identity credential UoW writes.
#[cfg(feature = "domain-identity")]
pub(crate) const IDENTITY_CREDENTIAL_BOUNDARY: PgTxRetryBoundary =
    PgTxRetryBoundary::IdentityCredential;
/// Retry boundary for identity AuthGrant close writes.
#[cfg(feature = "domain-identity")]
pub(crate) const IDENTITY_AUTH_GRANT_BOUNDARY: PgTxRetryBoundary =
    PgTxRetryBoundary::IdentityAuthGrant;
/// Retry boundary for identity refresh-token rotation writes.
#[cfg(feature = "domain-identity")]
pub(crate) const IDENTITY_REFRESH_BOUNDARY: PgTxRetryBoundary = PgTxRetryBoundary::IdentityRefresh;
/// Retry boundary for the durable audit append transaction.
#[cfg(feature = "domain-audit")]
pub(crate) const AUDIT_APPEND_BOUNDARY: PgTxRetryBoundary = PgTxRetryBoundary::AuditAppend;
/// Retry boundary for the route-specific target-tenant auth audit append.
#[cfg(feature = "domain-audit")]
pub(crate) const AUDIT_LIST_TENANT_APPEND_BOUNDARY: PgTxRetryBoundary =
    PgTxRetryBoundary::AuditListTenantAppend;

/// Closed route-marker to Postgres retry-boundary mapping.
///
/// The trait is crate-private, so downstream adapters cannot add arbitrary generated routes.
/// Callers provide only `LocalTxObservation<M>`; the retry boundary is derived from `M` and cannot
/// be independently paired.
pub(crate) trait PgLocalTxOperation {
    const BOUNDARY: PgTxRetryBoundary;
}

/// Closed observation carrier accepted by the Postgres LocalTx retry runner.
///
/// Most operations carry one generated route marker. Auth-grant close additionally admits the
/// refresh route because replay compromise executes the same aggregate transaction while retaining
/// the initiating route's telemetry identity.
pub(crate) trait PgLocalTxObservation {
    fn boundary(&self) -> PgTxRetryBoundary;

    fn record_failed_attempt(
        &self,
        attempt: u32,
        retry_class: TxRetryClass,
        settlement: Option<LocalTxFinalStatus>,
    );

    fn record_deadline_exceeded(&self, stage: LocalTxDeadlineStage);

    fn finish(
        self,
        attempts: u32,
        retry_status: TxRetryFinalStatus,
        settlement: Option<LocalTxFinalStatus>,
    );
}

impl<M> PgLocalTxObservation for LocalTxObservation<M>
where
    M: PgLocalTxOperation,
{
    fn boundary(&self) -> PgTxRetryBoundary {
        M::BOUNDARY
    }

    fn record_failed_attempt(
        &self,
        attempt: u32,
        retry_class: TxRetryClass,
        settlement: Option<LocalTxFinalStatus>,
    ) {
        self.record_failed_attempt(attempt, retry_class, settlement);
    }

    fn record_deadline_exceeded(&self, stage: LocalTxDeadlineStage) {
        self.record_deadline_exceeded(stage);
    }

    fn finish(
        self,
        attempts: u32,
        retry_status: TxRetryFinalStatus,
        settlement: Option<LocalTxFinalStatus>,
    ) {
        self.finish(attempts, retry_status, settlement);
    }
}

#[cfg(feature = "domain-settings")]
impl PgLocalTxOperation for settings::ports::SecretPublishRouteMarker {
    const BOUNDARY: PgTxRetryBoundary = SETTINGS_SECRET_BOUNDARY;
}

#[cfg(feature = "domain-identity")]
impl PgLocalTxOperation for identity::ports::PasswordChangeRouteMarker {
    const BOUNDARY: PgTxRetryBoundary = IDENTITY_CREDENTIAL_BOUNDARY;
}

#[cfg(feature = "domain-identity")]
impl PgLocalTxOperation for identity::ports::AuthGrantCloseRouteMarker {
    const BOUNDARY: PgTxRetryBoundary = IDENTITY_AUTH_GRANT_BOUNDARY;
}

#[cfg(feature = "domain-identity")]
impl PgLocalTxOperation for identity::ports::RefreshRotationRouteMarker {
    const BOUNDARY: PgTxRetryBoundary = IDENTITY_REFRESH_BOUNDARY;
}

#[cfg(feature = "domain-identity")]
impl PgLocalTxObservation for identity::ports::AuthGrantCloseObservation {
    fn boundary(&self) -> PgTxRetryBoundary {
        match self {
            Self::Logout(_) => {
                <identity::ports::AuthGrantCloseRouteMarker as PgLocalTxOperation>::BOUNDARY
            }
            Self::RefreshReplay(_) => {
                <identity::ports::RefreshRotationRouteMarker as PgLocalTxOperation>::BOUNDARY
            }
        }
    }

    fn record_failed_attempt(
        &self,
        attempt: u32,
        retry_class: TxRetryClass,
        settlement: Option<LocalTxFinalStatus>,
    ) {
        match self {
            Self::Logout(observation) => {
                observation.record_failed_attempt(attempt, retry_class, settlement);
            }
            Self::RefreshReplay(observation) => {
                observation.record_failed_attempt(attempt, retry_class, settlement);
            }
        }
    }

    fn record_deadline_exceeded(&self, stage: LocalTxDeadlineStage) {
        match self {
            Self::Logout(observation) => observation.record_deadline_exceeded(stage),
            Self::RefreshReplay(observation) => observation.record_deadline_exceeded(stage),
        }
    }

    fn finish(
        self,
        attempts: u32,
        retry_status: TxRetryFinalStatus,
        settlement: Option<LocalTxFinalStatus>,
    ) {
        match self {
            Self::Logout(observation) => observation.finish(attempts, retry_status, settlement),
            Self::RefreshReplay(observation) => {
                observation.finish(attempts, retry_status, settlement);
            }
        }
    }
}

#[cfg(feature = "domain-audit")]
impl PgLocalTxOperation for audit::ports::AuditListTenantRouteMarker {
    const BOUNDARY: PgTxRetryBoundary = AUDIT_LIST_TENANT_APPEND_BOUNDARY;
}

/// Classify a SQLSTATE code.
pub(crate) fn classify_sqlstate(code: Option<&str>) -> TxRetryClass {
    match code {
        // Serialization failure / deadlock / lock timeout: the whole transaction may be retried.
        Some("40001" | "40P01" | "55P03") => TxRetryClass::Transient,
        // Connection exception family and server shutdown/recovery states.
        Some(
            "08000" | "08001" | "08003" | "08004" | "08006" | "08007" | "57P01" | "57P02" | "57P03",
        ) => TxRetryClass::Transient,
        // Integrity / authorization / syntax / data exceptions are not made correct by retrying.
        Some(_) | None => TxRetryClass::Permanent,
    }
}

/// Classify sqlx errors at the Postgres boundary.
pub(crate) fn classify_sqlx_error(error: &sqlx::Error) -> TxRetryClass {
    match error {
        sqlx::Error::Database(db) => classify_sqlstate(db.code().as_deref()),
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut | sqlx::Error::WorkerCrashed => {
            TxRetryClass::Transient
        }
        sqlx::Error::PoolClosed
        | sqlx::Error::Configuration(_)
        | sqlx::Error::Protocol(_)
        | sqlx::Error::RowNotFound
        | sqlx::Error::TypeNotFound { .. }
        | sqlx::Error::ColumnIndexOutOfBounds { .. }
        | sqlx::Error::ColumnNotFound(_)
        | sqlx::Error::ColumnDecode { .. }
        | sqlx::Error::Decode(_)
        | sqlx::Error::AnyDriverError(_)
        | sqlx::Error::Migrate(_) => TxRetryClass::Permanent,
        _ => TxRetryClass::Permanent,
    }
}

fn classify_source(source: &(dyn Error + Send + Sync + 'static)) -> TxRetryClass {
    source
        .downcast_ref::<sqlx::Error>()
        .map(classify_sqlx_error)
        .unwrap_or(TxRetryClass::Permanent)
}

/// Classify settings repository/UoW errors.
#[cfg(feature = "domain-settings")]
pub(crate) fn classify_config_repo_error(error: &ConfigRepoError) -> TxRetryClass {
    match error {
        ConfigRepoError::VersionConflict => TxRetryClass::Conflict,
        ConfigRepoError::Storage(source) => classify_source(source.as_ref()),
        _ => TxRetryClass::Permanent,
    }
}

/// Classify settings secret repository errors.
#[cfg(feature = "domain-settings")]
pub(crate) fn classify_secret_repo_error(error: &SecretRepoError) -> TxRetryClass {
    match error {
        SecretRepoError::VersionConflict => TxRetryClass::Conflict,
        SecretRepoError::Storage(source) => classify_source(source.as_ref()),
        _ => TxRetryClass::Permanent,
    }
}

/// Classify identity repository/UoW errors.
#[cfg(feature = "domain-identity")]
pub(crate) fn classify_identity_error(error: &IdentityError) -> TxRetryClass {
    match error {
        IdentityError::VersionConflict => TxRetryClass::Conflict,
        IdentityError::Storage(source) => classify_source(source.as_ref()),
        _ => TxRetryClass::Permanent,
    }
}

/// Classify audit repository errors at the Postgres boundary.
#[cfg(feature = "domain-audit")]
pub(crate) fn classify_audit_error(error: &AuditError) -> TxRetryClass {
    match error {
        AuditError::Storage(source) => classify_source(source.as_ref()),
        _ => TxRetryClass::Permanent,
    }
}

/// Run a Postgres UoW under the default retry policy and emit closed-label metrics.
#[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
pub(crate) async fn run_pg_tx_retry<T, E, Op, OpFut, Classify>(
    boundary: PgTxRetryBoundary,
    op: Op,
    classify: Classify,
) -> Result<T, E>
where
    Op: FnMut(u32, LocalTxDeadline) -> OpFut,
    OpFut: Future<Output = LocalTxAttempt<T, E>>,
    Classify: Fn(&E) -> TxRetryClass,
    E: Error + Send + Sync + 'static,
{
    let (result, _, settlement) =
        run_pg_tx_retry_core(boundary, op, classify, |_, _, _, _| {}, |_| {}).await;
    record_settlement(boundary, settlement);
    result
}

/// Run a typed LocalTx Postgres UoW and emit retry and settlement observability.
#[cfg(any(
    feature = "domain-settings",
    feature = "domain-identity",
    feature = "domain-audit"
))]
pub(crate) async fn run_pg_localtx_retry<O, T, E, Op, OpFut, Classify>(
    observation: O,
    op: Op,
    classify: Classify,
) -> Result<T, E>
where
    O: PgLocalTxObservation,
    Op: FnMut(u32, LocalTxDeadline) -> OpFut,
    OpFut: Future<Output = LocalTxAttempt<T, E>>,
    Classify: Fn(&E) -> TxRetryClass,
    E: Error + Send + Sync + 'static,
{
    let boundary = observation.boundary();
    let (result, report, settlement) = run_pg_tx_retry_core(
        boundary,
        op,
        classify,
        |attempt, retry_class, settlement, stages| {
            observation.record_failed_attempt(attempt, retry_class, settlement);
            for stage in stages.into_iter().flatten() {
                observation.record_deadline_exceeded(stage);
            }
        },
        |stage| observation.record_deadline_exceeded(stage),
    )
    .await;
    observation.finish(report.attempts(), report.final_status(), settlement);
    result
}

async fn run_pg_tx_retry_core<T, E, Op, OpFut, Classify, OnFailed, OnDeadline>(
    boundary: PgTxRetryBoundary,
    mut op: Op,
    classify: Classify,
    on_failed: OnFailed,
    on_deadline: OnDeadline,
) -> (Result<T, E>, TxRetryReport, Option<LocalTxFinalStatus>)
where
    Op: FnMut(u32, LocalTxDeadline) -> OpFut,
    OpFut: Future<Output = LocalTxAttempt<T, E>>,
    Classify: Fn(&E) -> TxRetryClass,
    OnFailed: Fn(u32, TxRetryClass, Option<LocalTxFinalStatus>, [Option<LocalTxDeadlineStage>; 2]),
    OnDeadline: Fn(LocalTxDeadlineStage),
    E: Error + Send + Sync + 'static,
{
    let deadline = LocalTxDeadline::mint(localtx_execution_budget());
    let last_settlement = Mutex::new(None);
    let last_reason = Mutex::new("none");
    let backoff_exhausted = AtomicBool::new(false);
    let (result, report) = run_tx_retry(
        TxRetryPolicy::default(),
        |attempt| {
            let future = op(attempt, deadline);
            let last_settlement = &last_settlement;
            let on_failed = &on_failed;
            let classify = &classify;
            async move {
                let attempt_result = future.await;
                let settlement = attempt_result.settlement();
                if let Some(status) = settlement {
                    match last_settlement.lock() {
                        Ok(mut last) => *last = Some(status),
                        Err(poisoned) => *poisoned.into_inner() = Some(status),
                    }
                }
                let result = attempt_result.into_retry_result(classify);
                if let Err(error) = &result {
                    on_failed(attempt, error.class(), settlement, error.deadline_stages());
                }
                result
            }
        },
        |error| {
            let class = error.class();
            let reason = retry_reason(error.error());
            match last_reason.lock() {
                Ok(mut last) => *last = reason,
                Err(poisoned) => *poisoned.into_inner() = reason,
            }
            record_attempt(boundary, class, reason);
            class
        },
        |delay| {
            let backoff_exhausted = &backoff_exhausted;
            async move {
                let outcome = deadline.backoff(delay).await;
                if outcome == TxRetryBackoff::Exhausted {
                    backoff_exhausted.store(true, Ordering::Relaxed);
                }
                outcome
            }
        },
    )
    .await;
    if backoff_exhausted.load(Ordering::Relaxed) {
        on_deadline(LocalTxDeadlineStage::Backoff);
    }
    let reason = match last_reason.into_inner() {
        Ok(reason) => reason,
        Err(poisoned) => poisoned.into_inner(),
    };
    record_final(boundary, report, reason);
    let settlement = match last_settlement.into_inner() {
        Ok(settlement) => settlement,
        Err(poisoned) => poisoned.into_inner(),
    };
    (
        result.map_err(LocalTxRetryError::into_error),
        report,
        settlement,
    )
}

static RETRY_JITTER_SEQUENCE: LazyLock<AtomicU64> = LazyLock::new(|| {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    AtomicU64::new(hasher.finish())
});

fn full_jitter(ceiling: Duration) -> Duration {
    let sample = RETRY_JITTER_SEQUENCE
        .fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed)
        .wrapping_mul(0xbf58_476d_1ce4_e5b9)
        .rotate_left(27);
    full_jitter_from_sample(ceiling, sample)
}

fn full_jitter_from_sample(ceiling: Duration, sample: u64) -> Duration {
    let max_nanos = u64::try_from(ceiling.as_nanos()).unwrap_or(u64::MAX);
    if max_nanos == 0 {
        return Duration::ZERO;
    }
    Duration::from_nanos(sample % max_nanos.saturating_add(1))
}

fn retry_reason(error: &(dyn Error + 'static)) -> &'static str {
    let mut current = Some(error);
    while let Some(source) = current {
        if let Some(error) = source.downcast_ref::<sqlx::Error>() {
            return sqlx_retry_reason(error);
        }
        current = source.source();
    }
    "domain"
}

fn sqlx_retry_reason(error: &sqlx::Error) -> &'static str {
    match error {
        sqlx::Error::Database(database) => match database.code().as_deref() {
            Some("55P03") => "lock_timeout",
            Some("40P01") => "deadlock",
            Some("40001") => "serialization",
            Some(code) if code.starts_with("08") || code.starts_with("57P") => "connection",
            Some(_) => "database",
            None => "database_unknown",
        },
        sqlx::Error::PoolTimedOut => "pool_timeout",
        sqlx::Error::PoolClosed => "pool_closed",
        sqlx::Error::Io(_) | sqlx::Error::WorkerCrashed => "connection",
        sqlx::Error::AnyDriverError(_) => "settlement_wrapper",
        _ => "storage",
    }
}

fn record_attempt(boundary: PgTxRetryBoundary, class: TxRetryClass, reason: &'static str) {
    metrics::counter!(
        "tx_retry_attempts_total",
        "boundary" => boundary.as_label(),
        "class" => class.as_label(),
        "reason" => reason,
    )
    .increment(1);
}

#[derive(Clone, Copy)]
struct SettlementRouting {
    boundary: PgTxRetryBoundary,
    final_status: LocalTxFinalStatus,
}

impl SettlementRouting {
    fn emit(self) {
        let boundary = self.boundary.as_label();
        let final_status = self.final_status.as_label();
        metrics::counter!(
            "tx_settlement_final_total",
            "boundary" => boundary,
            "final_status" => final_status,
        )
        .increment(1);

        if matches!(
            self.final_status,
            LocalTxFinalStatus::CommitUnknown | LocalTxFinalStatus::RollbackFailed
        ) {
            tracing::warn!(
                target: "postgres",
                boundary,
                final_status,
                "transaction completed with an unsafe settlement"
            );
        }
    }
}

pub(crate) fn record_settlement(
    boundary: PgTxRetryBoundary,
    settlement: Option<LocalTxFinalStatus>,
) {
    let Some(final_status) = settlement else {
        return;
    };
    SettlementRouting {
        boundary,
        final_status,
    }
    .emit();
}

fn record_final(boundary: PgTxRetryBoundary, report: TxRetryReport, reason: &'static str) {
    let boundary = boundary.as_label();
    if report.final_status() == TxRetryFinalStatus::Exhausted {
        tracing::warn!(
            target: "postgres",
            boundary,
            attempts = report.attempts(),
            status = report.final_status().as_label(),
            reason,
            "transaction retry budget exhausted"
        );
    }
    metrics::counter!(
        "tx_retry_final_total",
        "boundary" => boundary,
        "status" => report.final_status().as_label(),
        "reason" => reason,
    )
    .increment(1);
    metrics::histogram!(
        "tx_retry_attempts",
        "boundary" => boundary,
        "status" => report.final_status().as_label(),
        "reason" => reason,
    )
    .record(f64::from(report.attempts()));
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "domain-audit")]
    use super::{AUDIT_LIST_TENANT_APPEND_BOUNDARY, PgLocalTxOperation};
    use super::{
        LocalTxDeadline, LocalTxStageResult, classify_sqlstate, classify_sqlx_error, full_jitter,
        full_jitter_from_sample, retry_reason,
    };
    #[cfg(feature = "domain-settings")]
    use super::{SETTINGS_SECRET_BOUNDARY, classify_config_repo_error, classify_secret_repo_error};
    #[cfg(feature = "domain-settings")]
    use crate::cotx::commit_unknown;
    use consistency::{LocalTxExecutionBudget, TxRetryBackoff, TxRetryClass};
    #[cfg(feature = "domain-settings")]
    use settings::ports::{ConfigRepoError, SecretRepoError};
    use sqlx::error::{DatabaseError, ErrorKind};
    use std::borrow::Cow;
    use std::fmt;
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn deadline_token_is_absolute_across_copies_and_keeps_settlement_reserve()
    -> Result<(), consistency::LocalTxExecutionBudgetError> {
        let budget =
            LocalTxExecutionBudget::new(Duration::from_millis(10), Duration::from_millis(2))?;
        let deadline = LocalTxDeadline::mint(budget);
        let copied_for_next_attempt = deadline;
        assert_eq!(deadline.operation, copied_for_next_attempt.operation);
        assert_eq!(
            deadline.final_settlement,
            copied_for_next_attempt.final_settlement
        );

        tokio::time::advance(budget.operation()).await;
        assert!(matches!(
            deadline
                .operation(async { Ok::<(), FakeDeadlineError>(()) })
                .await,
            LocalTxStageResult::Deadline { .. }
        ));
        assert!(matches!(
            deadline.commit(async { Ok(()) }).await,
            LocalTxStageResult::Complete(())
        ));
        Ok(())
    }

    #[allow(clippy::disallowed_methods)]
    // reason: paused Tokio time is the test oracle; production deadlines stay behind LocalTxDeadline.
    #[tokio::test(start_paused = true)]
    async fn deadline_backoff_exhausts_without_sleeping_past_operation_budget()
    -> Result<(), consistency::LocalTxExecutionBudgetError> {
        let budget =
            LocalTxExecutionBudget::new(Duration::from_millis(10), Duration::from_millis(2))?;
        let deadline = LocalTxDeadline::mint(budget);
        tokio::time::advance(Duration::from_millis(7)).await;
        let before = tokio::time::Instant::now();

        assert_eq!(
            deadline.wait_backoff(Duration::from_millis(2)).await,
            TxRetryBackoff::Exhausted
        );
        assert_eq!(tokio::time::Instant::now(), before);
        Ok(())
    }

    #[derive(Debug, thiserror::Error)]
    #[error("deadline test error")]
    struct FakeDeadlineError;

    #[derive(Debug)]
    struct FakeDatabaseError {
        code: &'static str,
    }

    impl fmt::Display for FakeDatabaseError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("fake database error")
        }
    }

    impl std::error::Error for FakeDatabaseError {}

    impl DatabaseError for FakeDatabaseError {
        fn message(&self) -> &str {
            "fake database error"
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.code))
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_server_timeouts_are_inside_operation_deadline_and_lock_is_capped() {
        let deadline = LocalTxDeadline::mint(LocalTxExecutionBudget::DEFAULT);
        let (statement_millis, lock_millis) = deadline.server_timeout_millis();
        assert_eq!((statement_millis, lock_millis), (7_998, 5_000));

        tokio::time::advance(Duration::from_secs(4)).await;
        assert_eq!(deadline.server_timeout_millis(), (3_998, 3_998));

        tokio::time::advance(Duration::from_millis(3_999)).await;
        assert_eq!(
            deadline.server_timeout_millis(),
            (1, 1),
            "sub-3ms residual windows must retain the one millisecond server floor"
        );
    }

    #[cfg(feature = "domain-audit")]
    #[test]
    fn audit_list_tenant_route_maps_to_its_closed_retry_boundary() {
        assert_eq!(
            <audit::ports::AuditListTenantRouteMarker as PgLocalTxOperation>::BOUNDARY,
            AUDIT_LIST_TENANT_APPEND_BOUNDARY
        );
        assert_eq!(
            AUDIT_LIST_TENANT_APPEND_BOUNDARY.as_label(),
            "audit.list-tenant-entries"
        );
    }

    #[cfg(feature = "domain-settings")]
    #[test]
    fn secret_repo_classification_is_closed_and_fail_closed() {
        assert_eq!(SETTINGS_SECRET_BOUNDARY.as_label(), "settings.secret");
        assert_eq!(
            classify_secret_repo_error(&SecretRepoError::VersionConflict),
            TxRetryClass::Conflict
        );
        assert_eq!(
            classify_secret_repo_error(&SecretRepoError::Storage(Box::new(
                sqlx::Error::PoolTimedOut,
            ))),
            TxRetryClass::Transient
        );
        assert_eq!(
            classify_secret_repo_error(&SecretRepoError::Storage(Box::new(std::io::Error::other(
                "opaque storage failure",
            )))),
            TxRetryClass::Permanent
        );
    }

    #[test]
    fn sqlstate_classification_is_closed_and_fail_closed() {
        let cases = [
            (Some("40001"), TxRetryClass::Transient),
            (Some("40P01"), TxRetryClass::Transient),
            (Some("55P03"), TxRetryClass::Transient),
            (Some("08006"), TxRetryClass::Transient),
            (Some("57P03"), TxRetryClass::Transient),
            (Some("23505"), TxRetryClass::Permanent),
            (Some("23503"), TxRetryClass::Permanent),
            (Some("42601"), TxRetryClass::Permanent),
            (Some("99999"), TxRetryClass::Permanent),
            (None, TxRetryClass::Permanent),
        ];
        for (code, expected) in cases {
            assert_eq!(classify_sqlstate(code), expected, "code={code:?}");
        }
    }

    #[test]
    fn sqlx_non_database_errors_are_classified() {
        assert_eq!(
            classify_sqlx_error(&sqlx::Error::PoolTimedOut),
            TxRetryClass::Transient
        );
        assert_eq!(
            classify_sqlx_error(&sqlx::Error::PoolClosed),
            TxRetryClass::Permanent
        );
        assert_eq!(
            classify_sqlx_error(&sqlx::Error::RowNotFound),
            TxRetryClass::Permanent
        );
    }

    #[test]
    fn retry_diagnostics_use_closed_reason_and_full_jitter() {
        let error = sqlx::Error::PoolTimedOut;
        assert_eq!(retry_reason(&error), "pool_timeout");
        let deadline = sqlx::Error::Database(Box::new(FakeDatabaseError { code: "57014" }));
        assert_eq!(
            retry_reason(&deadline),
            "database",
            "typed LocalTx deadline stages are the only deadline signal"
        );

        let ceiling = Duration::from_millis(10);
        for _ in 0..32 {
            assert!(full_jitter(ceiling) <= ceiling);
        }
        assert_eq!(full_jitter(Duration::ZERO), Duration::ZERO);
        assert_eq!(
            full_jitter_from_sample(Duration::from_nanos(10), 12),
            Duration::from_nanos(1)
        );
    }

    #[cfg(feature = "domain-settings")]
    #[test]
    fn commit_unknown_is_not_retryable() {
        let err = commit_unknown(sqlx::Error::PoolTimedOut);
        assert_eq!(classify_sqlx_error(&err), TxRetryClass::Permanent);
        assert_eq!(
            classify_config_repo_error(&ConfigRepoError::Storage(Box::new(err))),
            TxRetryClass::Permanent
        );
    }
}
