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

use consistency::{LocalTxBoundary, LocalTxFinalStatus, TxRetryClass, TxRetryFinalStatus};
use std::marker::PhantomData;
use tracing::{Level, Span, field};
use vocab::{HttpRouteBinding, http::LocalTx};

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

    fn increment_failed_attempt(&self, retry_class: TxRetryClass) {
        metrics::counter!(
            "localtx_retry_attempts_total",
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
            "localtx_final_total",
            "domain" => self.domain,
            "contract_id" => self.contract_id,
            "boundary" => self.boundary.as_label(),
            "final_status" => status.as_label(),
        )
        .increment(1);
        metrics::histogram!(
            "localtx_attempts",
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
