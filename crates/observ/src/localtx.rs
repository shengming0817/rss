//! Typed LocalTx metrics and tracing boundary.
//!
//! Dynamic OpenTelemetry attributes are deliberately narrowed here to generated route evidence
//! and closed consistency vocabularies.
//!
//! ref: open-telemetry/opentelemetry-rust opentelemetry/src/metrics/instruments/counter.rs@285dc925f98403ff426acc70968f104dc820d4f2
//!
//! INVARIANT: LOCALTX-OBS-LABELS-01 { level = "Hard", exec = "native-compile", source = "code", native = "`LocalTxObservation<M>` construction requires `HttpRouteBinding<M, LocalTx>` and retains M; private state owns metric names and label keys; LocalTxBoundary, TxRetryClass, and LocalTxFinalStatus provide closed values" }
//! Generated route provenance is separately enforced at Medium by
//! `CONTRACT-BINDING-FUNNEL-01`; this façade does not claim to Hard-seal the public
//! `HttpRouteBinding::from_static` source.

use consistency::{
    LocalTxBoundary, LocalTxDeadlineStage, LocalTxFinalStatus, TxRetryClass, TxRetryFinalStatus,
};
use std::marker::PhantomData;
use tracing::{Level, Span, field};
use vocab::{HttpRouteBinding, http::LocalTx};

/// Closed LocalTx metric identity and purpose, shared by the emitter and proof consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTxMetric {
    RetryAttempts,
    FinalSettlements,
    SettledAttempts,
    DeadlineExceeded,
}

impl LocalTxMetric {
    const ALL: [Self; 4] = [
        Self::RetryAttempts,
        Self::FinalSettlements,
        Self::SettledAttempts,
        Self::DeadlineExceeded,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RetryAttempts => "localtx_retry_attempts_total",
            Self::FinalSettlements => "localtx_final_total",
            Self::SettledAttempts => "localtx_attempts",
            Self::DeadlineExceeded => "localtx_deadline_exceeded_total",
        }
    }

    #[must_use]
    pub const fn purpose(self) -> LocalTxMetricPurpose {
        match self {
            Self::RetryAttempts => LocalTxMetricPurpose::RetryPressureDiagnostic,
            Self::FinalSettlements => LocalTxMetricPurpose::SettlementFinalStatus,
            Self::SettledAttempts => LocalTxMetricPurpose::SettledAttemptCount,
            Self::DeadlineExceeded => LocalTxMetricPurpose::DeadlineDiagnostic,
        }
    }
}

/// Closed proof-report purpose for a LocalTx metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTxMetricPurpose {
    RetryPressureDiagnostic,
    SettlementFinalStatus,
    SettledAttemptCount,
    DeadlineDiagnostic,
}

impl LocalTxMetricPurpose {
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::RetryPressureDiagnostic => "retry-pressure-diagnostic",
            Self::SettlementFinalStatus => "settlement-final-status",
            Self::SettledAttemptCount => "settled-attempt-count",
            Self::DeadlineDiagnostic => "deadline-diagnostic",
        }
    }
}

/// Closed actionable LocalTx alert identity and routing contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTxActionableAlert {
    CommitUnknown,
    RollbackFailed,
}

impl LocalTxActionableAlert {
    const ALL: [Self; 2] = [Self::CommitUnknown, Self::RollbackFailed];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CommitUnknown => "LocalTxCommitUnknown",
            Self::RollbackFailed => "LocalTxRollbackFailed",
        }
    }

    #[must_use]
    pub const fn final_status(self) -> LocalTxFinalStatus {
        match self {
            Self::CommitUnknown => LocalTxFinalStatus::CommitUnknown,
            Self::RollbackFailed => LocalTxFinalStatus::RollbackFailed,
        }
    }

    #[must_use]
    pub const fn metric(self) -> LocalTxMetric {
        LocalTxMetric::FinalSettlements
    }

    #[must_use]
    pub const fn runbook_anchor(self) -> &'static str {
        match self {
            Self::CommitUnknown => "commit-unknown",
            Self::RollbackFailed => "rollback-failed",
        }
    }
}

/// Closed retry-pressure policy classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTxRetryPressureClassification {
    DiagnosticOnly,
}

impl LocalTxRetryPressureClassification {
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        "diagnosticOnly"
    }
}

/// Field-private owner inventory; construction remains confined to this module.
pub struct LocalTxOperationsDescriptor {
    metrics: &'static [LocalTxMetric],
    alerts: &'static [LocalTxActionableAlert],
    retry_metric: LocalTxMetric,
    retry_classification: LocalTxRetryPressureClassification,
    rules_path: &'static str,
    runbook_path: &'static str,
}

impl LocalTxOperationsDescriptor {
    #[must_use]
    pub const fn metrics(&self) -> &'static [LocalTxMetric] {
        self.metrics
    }

    #[must_use]
    pub const fn alerts(&self) -> &'static [LocalTxActionableAlert] {
        self.alerts
    }

    #[must_use]
    pub const fn retry_metric(&self) -> LocalTxMetric {
        self.retry_metric
    }

    #[must_use]
    pub const fn retry_classification(&self) -> LocalTxRetryPressureClassification {
        self.retry_classification
    }

    #[must_use]
    pub const fn rules_path(&self) -> &'static str {
        self.rules_path
    }

    #[must_use]
    pub const fn runbook_path(&self) -> &'static str {
        self.runbook_path
    }

    #[must_use]
    pub fn is_consistent(&self) -> bool {
        let unique = |items: &[LocalTxMetric]| {
            items
                .iter()
                .enumerate()
                .all(|(i, item)| !items[i + 1..].contains(item))
        };
        unique(self.metrics)
            && self.metrics.contains(&self.retry_metric)
            && self.retry_metric.purpose() == LocalTxMetricPurpose::RetryPressureDiagnostic
            && self
                .alerts
                .iter()
                .enumerate()
                .all(|(i, alert)| !self.alerts[i + 1..].contains(alert))
            && self.alerts.iter().all(|alert| {
                unsafe_settlement(alert.final_status()) && self.metrics.contains(&alert.metric())
            })
    }
}

const LOCALTX_OPERATIONS: LocalTxOperationsDescriptor = LocalTxOperationsDescriptor {
    metrics: &LocalTxMetric::ALL,
    alerts: &LocalTxActionableAlert::ALL,
    retry_metric: LocalTxMetric::RetryAttempts,
    retry_classification: LocalTxRetryPressureClassification::DiagnosticOnly,
    rules_path: "docs/ops/localtx-alerts.rules.yaml",
    runbook_path: "docs/runbooks/202607130312-1705-localtx-unsafe-settlement.md",
};

#[must_use]
pub const fn localtx_operations_descriptor() -> &'static LocalTxOperationsDescriptor {
    &LOCALTX_OPERATIONS
}

/// One LocalTx retry invocation's closed metrics and tracing façade.
///
/// Construction requires typed LocalTx route evidence. Metric names, label keys, and extracted
/// label values stay private so adapter code cannot assemble a parallel dynamic-label path.
pub struct LocalTxObservation<M> {
    domain: &'static str,
    contract_id: &'static str,
    boundary: LocalTxBoundary,
    span: Span,
    marker: PhantomData<fn() -> M>,
}

impl<M> LocalTxObservation<M> {
    /// Start observing one LocalTx retry invocation under the current trace span.
    #[must_use]
    pub fn new(route: HttpRouteBinding<M, LocalTx>, boundary: LocalTxBoundary) -> Self {
        let contract = route.evidence().contract();
        let domain = contract.domain();
        let contract_id = contract.contract_id();
        let span = tracing::span!(
            Level::INFO,
            "localtx.retry",
            domain,
            contract_id,
            boundary = boundary.as_label(),
            attempts = field::Empty,
            retry_status = field::Empty,
            final_status = field::Empty,
        );

        Self {
            domain,
            contract_id,
            boundary,
            span,
            marker: PhantomData,
        }
    }

    /// Record one failed attempt and its independently observed settlement.
    ///
    /// `None` means the transaction never reached an observable settlement (`Unsettled`); it is
    /// intentionally omitted from the final-status field rather than forged as a settlement.
    pub fn record_failed_attempt(
        &self,
        attempt: u32,
        retry_class: TxRetryClass,
        settlement: Option<LocalTxFinalStatus>,
    ) {
        self.increment_failed_attempt(retry_class);
        self.trace_failed_attempt(attempt, retry_class, settlement);
    }

    /// Record one typed deadline stage without exposing dynamic labels to the adapter.
    pub fn record_deadline_exceeded(&self, stage: LocalTxDeadlineStage) {
        metrics::counter!(
            LocalTxMetric::DeadlineExceeded.name(),
            "domain" => self.domain,
            "contract_id" => self.contract_id,
            "boundary" => self.boundary.as_label(),
            "stage" => stage.as_label(),
        )
        .increment(1);
        tracing::warn!(
            parent: &self.span,
            deadline_stage = stage.as_label(),
            "LocalTx execution deadline exceeded"
        );
    }

    fn increment_failed_attempt(&self, retry_class: TxRetryClass) {
        metrics::counter!(
            LocalTxMetric::RetryAttempts.name(),
            "domain" => self.domain,
            "contract_id" => self.contract_id,
            "boundary" => self.boundary.as_label(),
            "retry_class" => retry_class.as_label(),
        )
        .increment(1);
    }

    fn trace_failed_attempt(
        &self,
        attempt: u32,
        retry_class: TxRetryClass,
        settlement: Option<LocalTxFinalStatus>,
    ) {
        match settlement {
            Some(status) => self.trace_settled_attempt(attempt, retry_class, status),
            None => self.trace_unsettled_attempt(attempt, retry_class),
        }
    }

    fn trace_settled_attempt(
        &self,
        attempt: u32,
        retry_class: TxRetryClass,
        status: LocalTxFinalStatus,
    ) {
        let trace = if unsafe_settlement(status) {
            Self::trace_unsafe_attempt
        } else {
            Self::trace_safe_attempt
        };
        trace(self, attempt, retry_class, status);
    }

    fn trace_unsafe_attempt(
        &self,
        attempt: u32,
        retry_class: TxRetryClass,
        status: LocalTxFinalStatus,
    ) {
        tracing::warn!(
            parent: &self.span,
            domain = self.domain,
            contract_id = self.contract_id,
            boundary = self.boundary.as_label(),
            attempt,
            retry_class = retry_class.as_label(),
            final_status = status.as_label(),
            "LocalTx attempt failed with an unsafe settlement"
        );
    }

    fn trace_safe_attempt(
        &self,
        attempt: u32,
        retry_class: TxRetryClass,
        status: LocalTxFinalStatus,
    ) {
        tracing::debug!(
            parent: &self.span,
            attempt,
            retry_class = retry_class.as_label(),
            final_status = status.as_label(),
            "LocalTx attempt failed"
        );
    }

    fn trace_unsettled_attempt(&self, attempt: u32, retry_class: TxRetryClass) {
        tracing::debug!(
            parent: &self.span,
            attempt,
            retry_class = retry_class.as_label(),
            "LocalTx attempt failed before settlement"
        );
    }

    /// Finish this invocation exactly once and emit final metrics only for a real settlement.
    pub fn finish(
        self,
        attempts: u32,
        retry_status: TxRetryFinalStatus,
        settlement: Option<LocalTxFinalStatus>,
    ) {
        self.span.record("attempts", attempts);
        self.span.record("retry_status", retry_status.as_label());
        if let Some(status) = settlement {
            self.span.record("final_status", status.as_label());
        }
        self.trace_retry_completion(attempts, retry_status, settlement);

        let Some(status) = settlement else {
            tracing::debug!(parent: &self.span, attempts, "LocalTx completed without settlement");
            return;
        };

        self.emit_final_metrics(attempts, status);
        self.trace_settled_completion(attempts, status);
    }

    fn trace_retry_completion(
        &self,
        attempts: u32,
        retry_status: TxRetryFinalStatus,
        settlement: Option<LocalTxFinalStatus>,
    ) {
        if retry_status == TxRetryFinalStatus::Exhausted {
            match settlement {
                Some(status) => self.trace_exhausted_settled(attempts, retry_status, status),
                None => self.trace_exhausted_unsettled(attempts, retry_status),
            }
        }
    }

    fn trace_exhausted_settled(
        &self,
        attempts: u32,
        retry_status: TxRetryFinalStatus,
        status: LocalTxFinalStatus,
    ) {
        tracing::warn!(
            parent: &self.span,
            domain = self.domain,
            contract_id = self.contract_id,
            boundary = self.boundary.as_label(),
            attempts,
            retry_status = retry_status.as_label(),
            final_status = status.as_label(),
            "LocalTx retry budget exhausted"
        );
    }

    fn trace_exhausted_unsettled(&self, attempts: u32, retry_status: TxRetryFinalStatus) {
        tracing::warn!(
            parent: &self.span,
            domain = self.domain,
            contract_id = self.contract_id,
            boundary = self.boundary.as_label(),
            attempts,
            retry_status = retry_status.as_label(),
            "LocalTx retry budget exhausted"
        );
    }

    fn emit_final_metrics(&self, attempts: u32, status: LocalTxFinalStatus) {
        metrics::counter!(
            LocalTxMetric::FinalSettlements.name(),
            "domain" => self.domain,
            "contract_id" => self.contract_id,
            "boundary" => self.boundary.as_label(),
            "final_status" => status.as_label(),
        )
        .increment(1);
        metrics::histogram!(
            LocalTxMetric::SettledAttempts.name(),
            "domain" => self.domain,
            "contract_id" => self.contract_id,
            "boundary" => self.boundary.as_label(),
            "final_status" => status.as_label(),
        )
        .record(f64::from(attempts));
    }

    fn trace_settled_completion(&self, attempts: u32, status: LocalTxFinalStatus) {
        let trace = if unsafe_settlement(status) {
            Self::trace_unsafe_completion
        } else {
            Self::trace_safe_completion
        };
        trace(self, attempts, status);
    }

    fn trace_unsafe_completion(&self, attempts: u32, status: LocalTxFinalStatus) {
        tracing::warn!(
            parent: &self.span,
            domain = self.domain,
            contract_id = self.contract_id,
            boundary = self.boundary.as_label(),
            attempts,
            final_status = status.as_label(),
            "LocalTx completed with an unsafe settlement"
        );
    }

    fn trace_safe_completion(&self, attempts: u32, status: LocalTxFinalStatus) {
        tracing::debug!(
            parent: &self.span,
            attempts,
            final_status = status.as_label(),
            "LocalTx completed"
        );
    }
}

const fn unsafe_settlement(status: LocalTxFinalStatus) -> bool {
    matches!(
        status,
        LocalTxFinalStatus::CommitUnknown | LocalTxFinalStatus::RollbackFailed
    )
}

#[cfg(test)]
mod operations_descriptor_tests {
    use super::*;

    fn descriptor(
        metrics: &'static [LocalTxMetric],
        alerts: &'static [LocalTxActionableAlert],
        retry_metric: LocalTxMetric,
    ) -> LocalTxOperationsDescriptor {
        LocalTxOperationsDescriptor {
            metrics,
            alerts,
            retry_metric,
            retry_classification: LocalTxRetryPressureClassification::DiagnosticOnly,
            rules_path: "rules.yaml",
            runbook_path: "runbook.md",
        }
    }

    #[test]
    fn real_descriptor_is_non_vacuous_and_consistent() {
        let descriptor = localtx_operations_descriptor();
        assert_eq!(descriptor.metrics().len(), 4);
        assert_eq!(descriptor.alerts().len(), 2);
        assert!(descriptor.is_consistent());
    }

    #[test]
    fn missing_retry_membership_and_duplicate_identities_are_rejected() {
        const ONLY_FINAL: [LocalTxMetric; 1] = [LocalTxMetric::FinalSettlements];
        const DUPLICATE_FINAL: [LocalTxMetric; 2] = [
            LocalTxMetric::FinalSettlements,
            LocalTxMetric::FinalSettlements,
        ];
        const DUPLICATE_ALERT: [LocalTxActionableAlert; 2] = [
            LocalTxActionableAlert::CommitUnknown,
            LocalTxActionableAlert::CommitUnknown,
        ];
        const COMMIT_UNKNOWN: [LocalTxActionableAlert; 1] = [LocalTxActionableAlert::CommitUnknown];

        assert!(
            !descriptor(&ONLY_FINAL, &COMMIT_UNKNOWN, LocalTxMetric::RetryAttempts).is_consistent()
        );
        assert!(
            !descriptor(
                &DUPLICATE_FINAL,
                &COMMIT_UNKNOWN,
                LocalTxMetric::FinalSettlements,
            )
            .is_consistent()
        );
        assert!(
            !descriptor(
                &LocalTxMetric::ALL,
                &DUPLICATE_ALERT,
                LocalTxMetric::RetryAttempts,
            )
            .is_consistent()
        );
    }
}
