//! ConsumerTx —— shared durable consumer transaction driver.
//!
//! This module keeps the existing ConsumerBase preflight/claim/lease/broker-settle contract, but
//! changes the Fresh success path: the assembly-private tx handler is implemented only for the
//! concrete Postgres providers selected by generated topology. The provider commits domain writes,
//! outgoing outbox rows, and inbox `done` in one storage transaction; only then can its opaque
//! proof reach this private driver and authorize broker settlement.
//!
//! ref: serverlesstechnology/cqrs persistence/postgres-es/src/event_repository.rs@main

use std::sync::Arc;

use consistency::idempotency::{IdemKey, LeaseToken, SeenState};
use consistency::{EngineErrorKind, InboxReceiptContext};
use diport::{EnvelopeHeaderError, Message};
use futures::StreamExt;
use futures::future::BoxFuture;
use tracing::Instrument as _;

use eventexec::MAX_REDELIVERY;
use eventexec::consumer::{
    ConsumerMeta, LeaseConfig, ReceiptContextBuildError, build_consume_span, dead_letter,
    emit_lease_lost, envelope_header_error_reason, log_lease_lost, receipt_context_error_reason,
    record_dead_letter_skip, renewal_loop, settle, settle_claim_in_progress,
};
use eventexec::consumer_tx::{ConsumerTxOutcome, RejectKind};

/// Closed ConsumerTx external-effect policies used as type-level handler capabilities.
pub(crate) mod policy {
    mod private {
        pub trait Sealed {}
    }

    /// Effects are confined to the durable database transaction.
    #[allow(dead_code)]
    pub(crate) struct TransactionalOnly;
    /// External state is rebuilt from an authoritative source.
    #[allow(dead_code)]
    pub(crate) struct Reconcile;

    impl private::Sealed for TransactionalOnly {}
    impl private::Sealed for Reconcile {}

    /// Sealed marker implemented only by currently activatable policies.
    pub(crate) trait Policy: private::Sealed + Send + Sync + 'static {}

    impl Policy for TransactionalOnly {}
    impl Policy for Reconcile {}
}

/// Assembly-owned durable consumer transaction handler.
///
/// This trait is crate-private and has implementations only for the five concrete Postgres
/// handlers selected by the closed generated plan. Downstream crates cannot add an implementation
/// or enter the Ack-authorizing runner.
pub(crate) trait ConsumerTxHandler<P: policy::Policy>: Send + Sync + 'static {
    /// Execute one claimed delivery while retaining the policy marker and concrete provider proof.
    fn handle(
        self: Arc<Self>,
        message: Message,
        context: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> BoxFuture<'static, ConsumerTxOutcome<postgres::PgConsumerTxCommitProof>>;
}

#[cfg(feature = "audit-consumers")]
impl<M> ConsumerTxHandler<policy::TransactionalOnly> for postgres::PgAuditConsumerTx<M>
where
    M: primitives::MacVerifier + Send + Sync + 'static,
{
    fn handle(
        self: Arc<Self>,
        message: Message,
        context: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> BoxFuture<'static, ConsumerTxOutcome<postgres::PgConsumerTxCommitProof>> {
        postgres::PgAuditConsumerTx::handle(self, message, context, key, lease)
    }
}

#[cfg(feature = "settings-consumers")]
impl ConsumerTxHandler<policy::Reconcile> for postgres::PgSettingsConsumerTx {
    fn handle(
        self: Arc<Self>,
        message: Message,
        context: InboxReceiptContext,
        key: IdemKey,
        lease: LeaseToken,
    ) -> BoxFuture<'static, ConsumerTxOutcome<postgres::PgConsumerTxCommitProof>> {
        postgres::PgSettingsConsumerTx::handle(self, message, context, key, lease)
    }
}

/// Ackable durable consumer runner using ConsumerTx for Fresh messages.
pub(crate) async fn run_consumer_ackable_tx<S, P, H>(
    mut stream: diport::DeliveryStream,
    idempotency: Arc<S>,
    dlx: &diport::DynDeadLetterStore<'static>,
    meta: &ConsumerMeta,
    handler: Arc<H>,
    lease_cfg: LeaseConfig,
    admission: primitives::ConsumerAdmission,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
    P: policy::Policy,
    H: ConsumerTxHandler<P>,
{
    while let Some((d, _permit)) = next_admitted_delivery(&mut stream, &admission).await {
        let diport::Delivery { message, acker } = d;
        consume_one_tx(
            &idempotency,
            dlx,
            meta,
            &handler,
            message,
            Some(acker.as_ref()),
            lease_cfg,
        )
        .await;
    }
}

async fn next_admitted_delivery(
    stream: &mut diport::DeliveryStream,
    admission: &primitives::ConsumerAdmission,
) -> Option<(
    diport::Delivery,
    primitives::AdmissionPermit<primitives::ConsumerLane>,
)> {
    loop {
        if admission.wait_open().await.is_err() {
            return None;
        }
        let permit = match admission.try_enter() {
            Ok(permit) => permit,
            Err(primitives::AdmissionError::Paused) => continue,
            Err(primitives::AdmissionError::Stopped) => return None,
            Err(error) => {
                tracing::error!(error = %error, "consumer-tx: admission invariant failed");
                return None;
            }
        };
        tokio::select! {
            biased;
            closed = admission.wait_closed() => {
                drop(permit);
                if matches!(closed, Err(primitives::AdmissionError::Stopped)) {
                    return None;
                }
            }
            delivery = stream.next() => return delivery.map(|delivery| (delivery, permit)),
        }
    }
}

struct TxPreflight {
    key: IdemKey,
    ctx: InboxReceiptContext,
}

enum TxPreflightError {
    MalformedId,
    InvalidEnvelopeHeader(EnvelopeHeaderError),
    InvalidTenantAuthority(eventexec::TenantAuthorityError),
    InvalidReceiptContext(ReceiptContextBuildError),
}

#[allow(clippy::too_many_arguments)]
async fn consume_one_tx<S, P, H>(
    idempotency: &Arc<S>,
    dlx: &diport::DynDeadLetterStore<'static>,
    meta: &ConsumerMeta,
    handler: &Arc<H>,
    msg: Message,
    acker: Option<&diport::DynAcker<'static>>,
    lease_cfg: LeaseConfig,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
    P: policy::Policy,
    H: ConsumerTxHandler<P>,
{
    let TxPreflight { key, ctx } = match tx_preflight(meta, &msg) {
        Ok(preflight) => preflight,
        Err(error) => {
            reject_tx_preflight(meta, &msg, acker, error).await;
            return;
        }
    };

    let lease = LeaseToken::mint();
    match idempotency.try_claim(&ctx, &key, &lease).await {
        Err(error) => {
            settle_tx_try_claim_error(meta, &msg, acker, &error).await;
        }
        Ok(SeenState::InProgress) => {
            settle_claim_in_progress(acker, meta, &msg, lease_cfg).await;
        }
        Ok(SeenState::Duplicate) => {
            ack_tx_duplicate(meta, &msg, acker).await;
        }
        Ok(SeenState::Fresh) => {
            handle_fresh_tx(
                idempotency,
                dlx,
                meta,
                handler,
                msg,
                ctx,
                key,
                lease,
                acker,
                lease_cfg,
            )
            .await;
        }
    }
}

fn tx_preflight(meta: &ConsumerMeta, msg: &Message) -> Result<TxPreflight, TxPreflightError> {
    let key = IdemKey::parse(msg.id().as_str()).map_err(|_| TxPreflightError::MalformedId)?;
    let header = meta
        .verify_envelope_header(msg)
        .map_err(TxPreflightError::InvalidEnvelopeHeader)?;
    let tenant = meta
        .verify_tenant_authority(msg)
        .map_err(TxPreflightError::InvalidTenantAuthority)?;
    let ctx = meta
        .receipt_context(tenant, &header)
        .map_err(TxPreflightError::InvalidReceiptContext)?;
    Ok(TxPreflight { key, ctx })
}

async fn reject_tx_preflight(
    meta: &ConsumerMeta,
    msg: &Message,
    acker: Option<&diport::DynAcker<'static>>,
    error: TxPreflightError,
) {
    match error {
        TxPreflightError::MalformedId => {
            record_dead_letter_skip(meta, "malformed_id");
            log_tx_parse_failed(msg);
        }
        TxPreflightError::InvalidEnvelopeHeader(error) => {
            record_dead_letter_skip(meta, envelope_header_error_reason(&error));
            log_tx_invalid_envelope_header(meta, msg, &error);
        }
        TxPreflightError::InvalidTenantAuthority(error) => {
            record_dead_letter_skip(meta, error.skip_reason());
            log_tx_invalid_tenant_authority(meta, msg, error);
        }
        TxPreflightError::InvalidReceiptContext(error) => {
            let reason = receipt_context_error_reason(error);
            record_dead_letter_skip(meta, reason);
            log_tx_invalid_receipt_context(meta, msg, reason);
        }
    }
    settle(
        acker,
        diport::AckAction::Reject,
        meta.domain(),
        msg.id().as_str(),
    )
    .await;
}

async fn settle_tx_try_claim_error(
    meta: &ConsumerMeta,
    msg: &Message,
    acker: Option<&diport::DynAcker<'static>>,
    error: &consistency::error::EngineError,
) {
    log_tx_try_claim_failed(meta, msg, error);
    settle(
        acker,
        tx_try_claim_error_action(error),
        meta.domain(),
        msg.id().as_str(),
    )
    .await;
}

fn tx_try_claim_error_action(error: &consistency::error::EngineError) -> diport::AckAction {
    if error.is_transient() {
        diport::AckAction::Requeue
    } else {
        diport::AckAction::Reject
    }
}

async fn ack_tx_duplicate(
    meta: &ConsumerMeta,
    msg: &Message,
    acker: Option<&diport::DynAcker<'static>>,
) {
    log_tx_duplicate(msg, meta);
    settle(
        acker,
        diport::AckAction::Ack,
        meta.domain(),
        msg.id().as_str(),
    )
    .await;
}

fn log_tx_parse_failed(msg: &Message) {
    tracing::warn!(
        message_id = msg.id().as_str(),
        "consumer-tx: IdemKey parse failed, rejected"
    );
}

fn log_tx_invalid_envelope_header(meta: &ConsumerMeta, msg: &Message, error: &EnvelopeHeaderError) {
    tracing::warn!(
        message_id = msg.id().as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        error = %error,
        "consumer-tx: standard envelope header invalid, rejected"
    );
}

fn log_tx_invalid_tenant_authority(
    meta: &ConsumerMeta,
    msg: &Message,
    error: eventexec::TenantAuthorityError,
) {
    tracing::warn!(
        message_id = msg.id().as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        reason = error.skip_reason(),
        "consumer-tx: tenant authority invalid, rejected"
    );
}

fn log_tx_invalid_receipt_context(meta: &ConsumerMeta, msg: &Message, reason: &'static str) {
    tracing::warn!(
        message_id = msg.id().as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        reason,
        "consumer-tx: inbox receipt context invalid, rejected"
    );
}

fn log_tx_try_claim_failed(
    meta: &ConsumerMeta,
    msg: &Message,
    error: &consistency::error::EngineError,
) {
    tracing::warn!(
        message_id = msg.id().as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        consumer_group = meta.consumer_group(),
        error = %error,
        "consumer-tx: idempotency try_claim failed"
    );
}

fn log_tx_duplicate(msg: &Message, meta: &ConsumerMeta) {
    tracing::debug!(
        message_id = msg.id().as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        "consumer-tx: duplicate message, skipping"
    );
}

#[allow(clippy::too_many_arguments)]
async fn handle_fresh_tx<S, P, H>(
    idempotency: &Arc<S>,
    dlx: &diport::DynDeadLetterStore<'static>,
    meta: &ConsumerMeta,
    handler: &Arc<H>,
    msg: Message,
    ctx: InboxReceiptContext,
    key: IdemKey,
    lease: LeaseToken,
    acker: Option<&diport::DynAcker<'static>>,
    lease_cfg: LeaseConfig,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
    P: policy::Policy,
    H: ConsumerTxHandler<P>,
{
    let message_id = msg.id().as_str().to_owned();
    let consume_span = build_consume_span(meta, &message_id, msg.metadata().get(diport::KEY_TRACE));
    let terminal = tokio_util::sync::CancellationToken::new();
    tokio::select! {
        biased;
        () = run_tx_handler_loop(
            idempotency,
            dlx,
            meta,
            handler,
            msg,
            ctx.clone(),
            key.clone(),
            lease.clone(),
            acker,
            terminal.clone(),
        )
            .instrument(consume_span) => {}
        () = renewal_before_terminal(
            idempotency,
            meta,
            &ctx,
            &key,
            &lease,
            lease_cfg,
            &message_id,
            terminal,
        ) => {
            log_lease_lost(meta, &message_id);
            emit_lease_lost(meta.domain());
            settle(acker, diport::AckAction::Requeue, meta.domain(), &message_id).await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn renewal_before_terminal<S>(
    idempotency: &Arc<S>,
    meta: &ConsumerMeta,
    ctx: &InboxReceiptContext,
    key: &IdemKey,
    lease: &LeaseToken,
    lease_cfg: LeaseConfig,
    message_id: &str,
    terminal: tokio_util::sync::CancellationToken,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
{
    tokio::select! {
        biased;
        () = terminal.cancelled() => std::future::pending().await,
        () = renewal_loop(idempotency, meta, ctx, key, lease, lease_cfg, message_id) => {}
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_tx_handler_loop<S, P, H>(
    idempotency: &Arc<S>,
    dlx: &diport::DynDeadLetterStore<'static>,
    meta: &ConsumerMeta,
    handler: &Arc<H>,
    msg: Message,
    ctx: InboxReceiptContext,
    key: IdemKey,
    lease: LeaseToken,
    acker: Option<&diport::DynAcker<'static>>,
    terminal: tokio_util::sync::CancellationToken,
) where
    S: consistency::InboxStore + Send + Sync + 'static,
    P: policy::Policy,
    H: ConsumerTxHandler<P>,
{
    let mut last_requeue_summary = EngineErrorKind::Transient.message();
    for attempt in 1..=MAX_REDELIVERY {
        match Arc::clone(handler)
            .handle(msg.clone(), ctx.clone(), key.clone(), lease.clone())
            .await
        {
            outcome @ ConsumerTxOutcome::Committed(_) => {
                record_consumer_tx_outcome(meta, outcome.as_label());
                // The provider proof means the receipt/domain transaction is durably terminal.
                // Stop lease fencing before broker settlement: a concurrent extend now observes
                // `done` as Lost, but must not cancel the Ack authorized by that proof.
                terminal.cancel();
                settle(
                    acker,
                    diport::AckAction::Ack,
                    meta.domain(),
                    msg.id().as_str(),
                )
                .await;
                return;
            }
            outcome @ ConsumerTxOutcome::Rejected(kind) => {
                record_consumer_tx_outcome(meta, outcome.as_label());
                dead_letter(
                    dlx,
                    idempotency,
                    &ctx,
                    &key,
                    &lease,
                    meta,
                    &msg,
                    attempt,
                    reject_summary(kind),
                    acker,
                    Some(&terminal),
                )
                .await;
                return;
            }
            ConsumerTxOutcome::HandlerTransient => {
                last_requeue_summary = EngineErrorKind::Transient.message();
            }
            outcome @ (ConsumerTxOutcome::InfrastructureTransient
            | ConsumerTxOutcome::CommitUnknown
            | ConsumerTxOutcome::RollbackFailed) => {
                record_consumer_tx_outcome(meta, outcome.as_label());
                log_tx_non_retryable_requeue(meta, &msg, outcome.as_label());
                settle(
                    acker,
                    diport::AckAction::Requeue,
                    meta.domain(),
                    msg.id().as_str(),
                )
                .await;
                return;
            }
            outcome @ ConsumerTxOutcome::Fenced => {
                record_consumer_tx_outcome(meta, outcome.as_label());
                log_lease_lost(meta, msg.id().as_str());
                emit_lease_lost(meta.domain());
                tracing::warn!(
                    message_id = msg.id().as_str(),
                    "consumer-tx: lease lost in transaction, requeued without app dlx"
                );
                settle(
                    acker,
                    diport::AckAction::Requeue,
                    meta.domain(),
                    msg.id().as_str(),
                )
                .await;
                return;
            }
        }
    }
    record_consumer_tx_outcome(
        meta,
        ConsumerTxOutcome::<postgres::PgConsumerTxCommitProof>::HandlerTransient.as_label(),
    );
    log_tx_handler_transient_exhausted(meta, &msg, last_requeue_summary);
    settle(
        acker,
        diport::AckAction::Requeue,
        meta.domain(),
        msg.id().as_str(),
    )
    .await;
}

fn record_consumer_tx_outcome(meta: &ConsumerMeta, outcome: &'static str) {
    metrics::counter!(
        "consumer_tx_outcome_total",
        "domain" => meta.domain().to_owned(),
        "outcome" => outcome,
    )
    .increment(1);
}

fn reject_summary(kind: RejectKind) -> &'static str {
    match kind {
        RejectKind::Permanent => consistency::PermanentErrorKind::Permanent.message(),
        RejectKind::Invariant => consistency::PermanentErrorKind::Invariant.message(),
    }
}

fn log_tx_non_retryable_requeue(meta: &ConsumerMeta, msg: &Message, outcome: &'static str) {
    tracing::warn!(
        message_id = msg.id().as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        consumer_group = meta.consumer_group(),
        outcome,
        "consumer-tx: transaction not locally retryable, requeued without app dlx"
    );
}

fn log_tx_handler_transient_exhausted(meta: &ConsumerMeta, msg: &Message, summary: &'static str) {
    tracing::warn!(
        message_id = msg.id().as_str(),
        domain = meta.domain(),
        contract_id = meta.contract_id(),
        topic = meta.topic(),
        consumer_group = meta.consumer_group(),
        attempts = MAX_REDELIVERY,
        summary,
        "consumer-tx: handler transient budget exhausted, requeued without app dlx"
    );
}

const CONSUMER_TX_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

struct HealthReportingDlx {
    inner: tokio::sync::Mutex<Box<diport::DynDeadLetterStore<'static>>>,
    health: Arc<eventexec::WorkerHealth>,
    domain: String,
}

#[allow(unknown_lints, rss_diport_impl_allowlist)]
// reason(rss_diport_impl_allowlist): assembly-private health wrapper around the injected DLX port;
// it does not construct or replace a provider.
impl diport::DeadLetterStore for HealthReportingDlx {
    async fn write_dead_letter(
        &self,
        record: diport::DeadLetterRecord,
    ) -> Result<(), diport::DeadLetterStoreError> {
        let inner = self.inner.lock().await;
        let result = inner.write_dead_letter(record).await;
        let outcome = if result.is_ok() {
            "ok"
        } else {
            self.health.mark_dlx_write_error();
            "error"
        };
        metrics::counter!(
            "consumer_dlx_write_total",
            "domain" => self.domain.clone(),
            "outcome" => outcome,
        )
        .increment(1);
        result
    }

    async fn shutdown(&self) -> Result<(), diport::DeadLetterStoreError> {
        let inner = self.inner.lock().await;
        inner.shutdown().await
    }
}

fn health_reporting_dlx(
    dlx: Box<diport::DynDeadLetterStore<'static>>,
    health: Arc<eventexec::WorkerHealth>,
    meta: &ConsumerMeta,
) -> Box<diport::DynDeadLetterStore<'static>> {
    diport::DynDeadLetterStore::new_box(HealthReportingDlx {
        inner: tokio::sync::Mutex::new(dlx),
        health,
        domain: meta.domain().to_owned(),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_consumer_ackable_tx_subscriber<S, P, H>(
    name: String,
    subscriber: Box<diport::DynAckableSubscriber<'static>>,
    topic: diport::Topic,
    idempotency: Arc<S>,
    dlx: Box<diport::DynDeadLetterStore<'static>>,
    meta: ConsumerMeta,
    handler: H,
    lease_cfg: LeaseConfig,
    token: tokio_util::sync::CancellationToken,
    health: Arc<eventexec::WorkerHealth>,
    backoff: eventexec::BackoffPolicy,
    admission: primitives::ConsumerAdmission,
) -> eventexec::ManagedBlockingWorker
where
    S: consistency::InboxStore + Send + Sync + 'static,
    P: policy::Policy,
    H: ConsumerTxHandler<P>,
{
    let worker_name = name.clone();
    let runtime = tokio::runtime::Handle::current();
    let health_run = Arc::clone(&health);
    let domain = meta.domain().to_owned();
    let dlx = health_reporting_dlx(dlx, Arc::clone(&health), &meta);
    let handler = Arc::new(handler);
    eventexec::ManagedBlockingWorker::spawn(
        name,
        token,
        Arc::clone(&health),
        CONSUMER_TX_SHUTDOWN_TIMEOUT,
        move |token_run| {
            tracing::debug!(worker = worker_name, "consumer-tx: worker thread started");
            runtime.block_on(async move {
                eventexec::run_ackable_subscription_loop(
                    subscriber,
                    topic,
                    domain,
                    token_run,
                    health_run,
                    backoff,
                    admission,
                    async |stream, admission| {
                        run_consumer_ackable_tx(
                            stream,
                            Arc::clone(&idempotency),
                            dlx.as_ref(),
                            &meta,
                            Arc::clone(&handler),
                            lease_cfg,
                            admission,
                        )
                        .await;
                    },
                )
                .await;
                Ok(())
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::marker::PhantomData;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use consistency::error::{EngineError, EngineErrorKind};
    use consistency::idempotency::{IdemKey, LeaseOutcome, LeaseToken, SeenState};
    use consistency::{ConsumerGroup, InboxReceiptContext, InboxStore};
    use diport::dead_letter_store::{
        DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, DynDeadLetterStore,
    };
    use diport::{
        AckAction, AckableSubscriber, Acker, Delivery, DynAckableSubscriber, DynAcker,
        EnvelopeMetadata, KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION, KEY_TENANT_AUTHORITY, KEY_TENANT_ID,
        ManagedResource as _, Message, SubscriberError, Topic,
    };
    use primitives::{HealthStatus, Mac, MacAlgorithm, MacKey, MacVerifier};

    use super::*;
    use eventexec::{TenantAuthority, TenantAuthorityBinding};

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const SCHEMA_HASH: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    type TestCommitProof = postgres::PgConsumerTxCommitProof;

    fn test_commit_proof() -> TestCommitProof {
        postgres::PgConsumerTxCommitProof::for_test()
    }

    #[derive(Default)]
    struct RecordingMetricKeys(Mutex<Vec<metrics::Key>>);

    impl metrics::Recorder for RecordingMetricKeys {
        fn describe_counter(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }

        fn describe_gauge(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }

        fn describe_histogram(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }

        fn register_counter(
            &self,
            key: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Counter {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(key.to_retained());
            metrics::Counter::noop()
        }

        fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
            metrics::Gauge::noop()
        }

        fn register_histogram(
            &self,
            _: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Histogram {
            metrics::Histogram::noop()
        }
    }

    #[test]
    fn consumer_tx_outcome_metric_covers_the_closed_terminal_set() -> TestResult {
        let recorder = RecordingMetricKeys::default();
        let meta = meta()?;
        let outcomes = [
            ConsumerTxOutcome::Committed(test_commit_proof()),
            ConsumerTxOutcome::HandlerTransient,
            ConsumerTxOutcome::InfrastructureTransient,
            ConsumerTxOutcome::Rejected(RejectKind::Permanent),
            ConsumerTxOutcome::CommitUnknown,
            ConsumerTxOutcome::RollbackFailed,
            ConsumerTxOutcome::Fenced,
        ];
        let mut labels = std::collections::BTreeSet::new();
        metrics::with_local_recorder(&recorder, || {
            for outcome in outcomes {
                let label = outcome.as_label();
                assert!(labels.insert(label), "outcome labels must be unique");
                record_consumer_tx_outcome(&meta, label);
            }
        });

        assert_eq!(
            labels.len(),
            7,
            "metric test must cover every closed outcome"
        );
        let keys = recorder
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(keys.len(), 7, "one terminal metric per closed outcome");
        let observed = keys
            .iter()
            .map(|key| {
                assert_eq!(key.name(), "consumer_tx_outcome_total");
                let metric_labels = key
                    .labels()
                    .map(|label| (label.key(), label.value()))
                    .collect::<std::collections::BTreeMap<_, _>>();
                assert_eq!(metric_labels.len(), 2, "metric labels must stay closed");
                assert_eq!(metric_labels.get("domain").copied(), Some("audit"));
                metric_labels.get("outcome").copied().unwrap_or("")
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(observed, labels);
        Ok(())
    }

    struct TestHandler<P, F> {
        inner: F,
        policy: PhantomData<fn() -> P>,
    }

    impl<P, F> ConsumerTxHandler<P> for TestHandler<P, F>
    where
        P: policy::Policy,
        F: Fn(
                Message,
                InboxReceiptContext,
                IdemKey,
                LeaseToken,
            ) -> BoxFuture<'static, ConsumerTxOutcome<TestCommitProof>>
            + Send
            + Sync
            + 'static,
    {
        fn handle(
            self: Arc<Self>,
            message: Message,
            context: InboxReceiptContext,
            key: IdemKey,
            lease: LeaseToken,
        ) -> BoxFuture<'static, ConsumerTxOutcome<postgres::PgConsumerTxCommitProof>> {
            (self.inner)(message, context, key, lease)
        }
    }

    fn transactional_handler<F>(inner: F) -> TestHandler<policy::TransactionalOnly, F>
    where
        F: Fn(
                Message,
                InboxReceiptContext,
                IdemKey,
                LeaseToken,
            ) -> BoxFuture<'static, ConsumerTxOutcome<TestCommitProof>>
            + Send
            + Sync
            + 'static,
    {
        TestHandler {
            inner,
            policy: PhantomData,
        }
    }

    struct RecordingAcker(Arc<Mutex<Vec<AckAction>>>);

    impl Acker for RecordingAcker {
        async fn settle(&self, action: AckAction) -> Result<(), diport::AckError> {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(action);
            Ok(())
        }
    }

    struct BlockingAckAcker {
        actions: Arc<Mutex<Vec<AckAction>>>,
        ack_started: Arc<tokio::sync::Notify>,
        release_ack: Arc<tokio::sync::Notify>,
    }

    struct CancelAwareSubscriber {
        deliveries: Mutex<Option<Vec<Delivery>>>,
    }

    impl AckableSubscriber for CancelAwareSubscriber {
        async fn subscribe_ackable(
            &self,
            _topic: Topic,
            token: tokio_util::sync::CancellationToken,
        ) -> Result<diport::DeliveryStream, SubscriberError> {
            let deliveries = self
                .deliveries
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take()
                .unwrap_or_default();
            Ok(Box::pin(
                futures::stream::iter(deliveries)
                    .take_until(async move { token.cancelled().await }),
            ))
        }

        async fn shutdown(&self) -> Result<(), SubscriberError> {
            Ok(())
        }
    }

    struct RuntimeIdentitySubscriber {
        observed: Mutex<Option<tokio::sync::oneshot::Sender<tokio::runtime::Id>>>,
    }

    impl AckableSubscriber for RuntimeIdentitySubscriber {
        async fn subscribe_ackable(
            &self,
            _topic: Topic,
            token: tokio_util::sync::CancellationToken,
        ) -> Result<diport::DeliveryStream, SubscriberError> {
            if let Some(observed) = self
                .observed
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take()
            {
                let _ = observed.send(tokio::runtime::Handle::current().id());
            }
            Ok(Box::pin(
                futures::stream::pending::<Delivery>()
                    .take_until(async move { token.cancelled().await }),
            ))
        }

        async fn shutdown(&self) -> Result<(), SubscriberError> {
            Ok(())
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("test subscriber unavailable")]
    struct TestSubscriberUnavailable;

    struct FailingSubscriber;

    impl AckableSubscriber for FailingSubscriber {
        async fn subscribe_ackable(
            &self,
            _topic: Topic,
            _token: tokio_util::sync::CancellationToken,
        ) -> Result<diport::DeliveryStream, SubscriberError> {
            Err(SubscriberError::new(TestSubscriberUnavailable))
        }

        async fn shutdown(&self) -> Result<(), SubscriberError> {
            Ok(())
        }
    }

    /// 前 N 次 subscribe 失败，随后 pending-until-cancel，供 flaky→Healthy 断言。
    struct FlakySubscriber {
        fails_remaining: AtomicU32,
        subscribe_calls: Arc<AtomicU32>,
    }

    impl AckableSubscriber for FlakySubscriber {
        async fn subscribe_ackable(
            &self,
            _topic: Topic,
            token: tokio_util::sync::CancellationToken,
        ) -> Result<diport::DeliveryStream, SubscriberError> {
            self.subscribe_calls.fetch_add(1, Ordering::AcqRel);
            if self.fails_remaining.load(Ordering::Acquire) > 0 {
                self.fails_remaining.fetch_sub(1, Ordering::AcqRel);
                return Err(SubscriberError::new(TestSubscriberUnavailable));
            }
            Ok(Box::pin(
                futures::stream::pending::<Delivery>()
                    .take_until(async move { token.cancelled().await }),
            ))
        }

        async fn shutdown(&self) -> Result<(), SubscriberError> {
            Ok(())
        }
    }

    /// 首轮返回空 stream（自然结束），随后返回 pending-until-cancel，供 resubscribe 断言。
    struct SequenceSubscriber {
        subscribe_calls: Arc<AtomicU32>,
    }

    impl AckableSubscriber for SequenceSubscriber {
        async fn subscribe_ackable(
            &self,
            _topic: Topic,
            token: tokio_util::sync::CancellationToken,
        ) -> Result<diport::DeliveryStream, SubscriberError> {
            let n = self.subscribe_calls.fetch_add(1, Ordering::AcqRel);
            if n == 0 {
                return Ok(Box::pin(futures::stream::iter(Vec::<Delivery>::new())));
            }
            Ok(Box::pin(
                futures::stream::pending::<Delivery>()
                    .take_until(async move { token.cancelled().await }),
            ))
        }

        async fn shutdown(&self) -> Result<(), SubscriberError> {
            Ok(())
        }
    }

    impl Acker for BlockingAckAcker {
        async fn settle(&self, action: AckAction) -> Result<(), diport::AckError> {
            if action == AckAction::Ack {
                self.ack_started.notify_one();
                self.release_ack.notified().await;
            }
            self.actions
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(action);
            Ok(())
        }
    }

    struct NoopDlx;

    impl DeadLetterStore for NoopDlx {
        async fn write_dead_letter(
            &self,
            _record: DeadLetterRecord,
        ) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
    }

    struct RecordingDlx(Arc<AtomicU32>);

    impl DeadLetterStore for RecordingDlx {
        async fn write_dead_letter(
            &self,
            _record: DeadLetterRecord,
        ) -> Result<(), DeadLetterStoreError> {
            self.0.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
    }

    struct TestMac;

    impl MacVerifier for TestMac {
        fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
            let mut out = [0u8; 32];
            for (idx, byte) in key.as_bytes().iter().chain(message.iter()).enumerate() {
                out[idx % 32] ^= *byte;
            }
            Mac::from_bytes(out.to_vec())
        }

        fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
            self.sign(key, algorithm, message).as_bytes() == tag.as_bytes()
        }
    }

    fn tenant() -> TestResult<rss_request_context::TenantId> {
        Ok(rss_request_context::TenantId::parse(TENANT)?)
    }

    fn authority() -> TestResult<Arc<TenantAuthority>> {
        Ok(Arc::new(TenantAuthority::new(
            Arc::new(TestMac),
            MacKey::from_bytes(vec![7; 32]),
            3600,
            60,
            Arc::new(|| 42),
        )?))
    }

    fn meta() -> TestResult<ConsumerMeta> {
        Ok(ConsumerMeta::new(
            "audit",
            "identity",
            "identity.session-created",
            "identity.session-created",
            "audit.session-created",
            authority()?,
        )
        .with_expected_schema("v1", SCHEMA_HASH))
    }

    fn message(id: &str) -> TestResult<Message> {
        let authority = authority()?;
        let token = authority.sign(TenantAuthorityBinding::new(
            tenant()?,
            "identity",
            "identity.session-created",
            "identity.session-created",
            id,
        ))?;
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_TENANT_ID, TENANT);
        md.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
        md.insert_wire_pair(KEY_SCHEMA_HASH, SCHEMA_HASH);
        md.insert_wire_pair(KEY_TENANT_AUTHORITY, &token);
        Ok(Message::new_with_metadata(id, b"{}".to_vec(), md))
    }

    fn delivery_stream(
        id: &str,
        actions: Arc<Mutex<Vec<AckAction>>>,
    ) -> TestResult<diport::DeliveryStream> {
        Ok(Box::pin(futures::stream::iter([Delivery::new(
            message(id)?,
            DynAcker::new_box(RecordingAcker(actions)),
        )])))
    }

    fn blocking_ack_delivery_stream(
        id: &str,
        actions: Arc<Mutex<Vec<AckAction>>>,
        ack_started: Arc<tokio::sync::Notify>,
        release_ack: Arc<tokio::sync::Notify>,
    ) -> TestResult<diport::DeliveryStream> {
        Ok(Box::pin(futures::stream::iter([Delivery::new(
            message(id)?,
            DynAcker::new_box(BlockingAckAcker {
                actions,
                ack_started,
                release_ack,
            }),
        )])))
    }

    struct TxStore {
        state: SeenState,
        claim_error: Option<EngineErrorKind>,
        lose_extension: bool,
        extend_started: Option<Arc<tokio::sync::Notify>>,
        commits: AtomicU32,
        extends: AtomicU32,
    }

    impl TxStore {
        fn fresh() -> Arc<Self> {
            Arc::new(Self {
                state: SeenState::Fresh,
                claim_error: None,
                lose_extension: false,
                extend_started: None,
                commits: AtomicU32::new(0),
                extends: AtomicU32::new(0),
            })
        }

        fn duplicate() -> Arc<Self> {
            Arc::new(Self {
                state: SeenState::Duplicate,
                claim_error: None,
                lose_extension: false,
                extend_started: None,
                commits: AtomicU32::new(0),
                extends: AtomicU32::new(0),
            })
        }

        fn in_progress() -> Arc<Self> {
            Arc::new(Self {
                state: SeenState::InProgress,
                claim_error: None,
                lose_extension: false,
                extend_started: None,
                commits: AtomicU32::new(0),
                extends: AtomicU32::new(0),
            })
        }

        fn claim_error(kind: EngineErrorKind) -> Arc<Self> {
            Arc::new(Self {
                state: SeenState::Fresh,
                claim_error: Some(kind),
                lose_extension: false,
                extend_started: None,
                commits: AtomicU32::new(0),
                extends: AtomicU32::new(0),
            })
        }

        fn fresh_with_terminal_extension_loss(
            extend_started: Arc<tokio::sync::Notify>,
        ) -> Arc<Self> {
            Arc::new(Self {
                state: SeenState::Fresh,
                claim_error: None,
                lose_extension: true,
                extend_started: Some(extend_started),
                commits: AtomicU32::new(0),
                extends: AtomicU32::new(0),
            })
        }
    }

    impl InboxStore for TxStore {
        async fn try_claim(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<SeenState, EngineError> {
            if let Some(kind) = self.claim_error {
                return Err(EngineError::new(kind));
            }
            Ok(self.state)
        }

        async fn extend(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<LeaseOutcome, EngineError> {
            self.extends.fetch_add(1, Ordering::AcqRel);
            if let Some(started) = &self.extend_started {
                started.notify_one();
                tokio::task::yield_now().await;
            }
            Ok(if self.lose_extension {
                LeaseOutcome::Lost
            } else {
                LeaseOutcome::Held
            })
        }

        async fn commit(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<LeaseOutcome, EngineError> {
            self.commits.fetch_add(1, Ordering::AcqRel);
            Ok(LeaseOutcome::Held)
        }

        async fn release(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<(), EngineError> {
            Ok(())
        }
    }

    fn noop_dlx() -> Box<DynDeadLetterStore<'static>> {
        DynDeadLetterStore::new_box(NoopDlx)
    }

    fn recording_dlx(writes: Arc<AtomicU32>) -> Box<DynDeadLetterStore<'static>> {
        DynDeadLetterStore::new_box(RecordingDlx(writes))
    }

    fn lease_cfg() -> LeaseConfig {
        LeaseConfig::from_ttl(Duration::from_secs(60))
    }

    fn consumer_admission() -> primitives::ConsumerAdmission {
        let (control, _, consumer, _) = primitives::prepare_dr_admission_controls().into_parts();
        assert!(control.start_running().is_ok());
        consumer
    }

    #[allow(clippy::expect_used)]
    // reason: 测试 tiny backoff 构造失败即参数写错；item-level carve-out。
    fn tiny_backoff() -> eventexec::BackoffPolicy {
        eventexec::BackoffPolicy::new(Duration::from_millis(1), Duration::from_millis(4))
            .expect("valid tiny backoff")
    }

    #[tokio::test]
    async fn tx_committed_acks_without_calling_inbox_commit() -> TestResult {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let store = TxStore::fresh();
        let calls = Arc::new(AtomicU32::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_calls = Arc::clone(&handler_calls);
            Box::pin(async move {
                handler_calls.fetch_add(1, Ordering::AcqRel);
                ConsumerTxOutcome::Committed(test_commit_proof())
            })
        });

        run_consumer_ackable_tx(
            delivery_stream("evt-tx-ack", Arc::clone(&actions))?,
            Arc::clone(&store),
            (noop_dlx()).as_ref(),
            &(meta()?),
            Arc::new(handler),
            lease_cfg(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Ack]
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(
            store.commits.load(Ordering::Acquire),
            0,
            "ConsumerTx handler owns inbox done inside its transaction"
        );
        Ok(())
    }

    #[tokio::test]
    async fn committed_proof_fences_terminal_lease_loss_until_ack_finishes() -> TestResult {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let ack_started = Arc::new(tokio::sync::Notify::new());
        let release_ack = Arc::new(tokio::sync::Notify::new());
        let extend_started = Arc::new(tokio::sync::Notify::new());
        let handler_extend_started = Arc::clone(&extend_started);
        let store = TxStore::fresh_with_terminal_extension_loss(Arc::clone(&extend_started));
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_extend_started = Arc::clone(&handler_extend_started);
            Box::pin(async move {
                handler_extend_started.notified().await;
                ConsumerTxOutcome::Committed(test_commit_proof())
            })
        });
        let dlx = noop_dlx();
        let meta = meta()?;
        let run = run_consumer_ackable_tx(
            blocking_ack_delivery_stream(
                "evt-tx-terminal-ack-race",
                Arc::clone(&actions),
                Arc::clone(&ack_started),
                Arc::clone(&release_ack),
            )?,
            Arc::clone(&store),
            dlx.as_ref(),
            &meta,
            Arc::new(handler),
            LeaseConfig::from_ttl(Duration::from_millis(3)),
            consumer_admission(),
        );
        tokio::pin!(run);

        tokio::select! {
            () = ack_started.notified() => {}
            () = &mut run => return Err(std::io::Error::other("run ended before Ack blocked").into()),
        }
        testkit::await_delay(Duration::from_millis(10)).await;
        assert!(
            actions
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty(),
            "terminal lease loss must not replace the proof-authorized Ack"
        );
        release_ack.notify_one();
        run.await;
        assert_eq!(
            *actions.lock().unwrap_or_else(|error| error.into_inner()),
            vec![AckAction::Ack]
        );
        assert!(store.extends.load(Ordering::Acquire) >= 1);
        Ok(())
    }

    #[tokio::test]
    async fn dlx_commit_fences_terminal_lease_loss_until_ack_finishes() -> TestResult {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let ack_started = Arc::new(tokio::sync::Notify::new());
        let release_ack = Arc::new(tokio::sync::Notify::new());
        let extend_started = Arc::new(tokio::sync::Notify::new());
        let handler_extend_started = Arc::clone(&extend_started);
        let store = TxStore::fresh_with_terminal_extension_loss(Arc::clone(&extend_started));
        let writes = Arc::new(AtomicU32::new(0));
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_extend_started = Arc::clone(&handler_extend_started);
            Box::pin(async move {
                handler_extend_started.notified().await;
                ConsumerTxOutcome::Rejected(RejectKind::Permanent)
            })
        });
        let dlx = recording_dlx(Arc::clone(&writes));
        let meta = meta()?;
        let run = run_consumer_ackable_tx(
            blocking_ack_delivery_stream(
                "evt-tx-terminal-dlx-race",
                Arc::clone(&actions),
                Arc::clone(&ack_started),
                Arc::clone(&release_ack),
            )?,
            Arc::clone(&store),
            dlx.as_ref(),
            &meta,
            Arc::new(handler),
            LeaseConfig::from_ttl(Duration::from_millis(3)),
            consumer_admission(),
        );
        tokio::pin!(run);

        tokio::select! {
            () = ack_started.notified() => {}
            () = &mut run => return Err(std::io::Error::other("DLX run ended before Ack blocked").into()),
        }
        testkit::await_delay(Duration::from_millis(10)).await;
        assert!(
            actions
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty(),
            "durable DLX terminal must retain its proof-authorized Ack"
        );
        release_ack.notify_one();
        run.await;
        assert_eq!(
            *actions.lock().unwrap_or_else(|error| error.into_inner()),
            vec![AckAction::Ack]
        );
        assert_eq!(writes.load(Ordering::Acquire), 1);
        assert_eq!(store.commits.load(Ordering::Acquire), 1);
        Ok(())
    }

    #[tokio::test]
    async fn tx_duplicate_acks_without_calling_handler() -> TestResult {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let store = TxStore::duplicate();
        let calls = Arc::new(AtomicU32::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_calls = Arc::clone(&handler_calls);
            Box::pin(async move {
                handler_calls.fetch_add(1, Ordering::AcqRel);
                ConsumerTxOutcome::Committed(test_commit_proof())
            })
        });

        run_consumer_ackable_tx(
            delivery_stream("evt-tx-duplicate", Arc::clone(&actions))?,
            store,
            (noop_dlx()).as_ref(),
            &(meta()?),
            Arc::new(handler),
            lease_cfg(),
            consumer_admission(),
        )
        .await;

        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Ack]
        );
        assert_eq!(calls.load(Ordering::Acquire), 0);
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    // reason: 本测断言墙钟延迟下界（InProgress 不得立即 churn）；不注入 Clock 避免改 lease 接缝。
    async fn tx_in_progress_delays_then_requeues_without_calling_handler() -> TestResult {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let store = TxStore::in_progress();
        let calls = Arc::new(AtomicU32::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_calls = Arc::clone(&handler_calls);
            Box::pin(async move {
                handler_calls.fetch_add(1, Ordering::AcqRel);
                ConsumerTxOutcome::Committed(test_commit_proof())
            })
        });
        let started = std::time::Instant::now();

        run_consumer_ackable_tx(
            delivery_stream("evt-tx-in-progress", Arc::clone(&actions))?,
            store,
            (noop_dlx()).as_ref(),
            &(meta()?),
            Arc::new(handler),
            LeaseConfig::from_ttl(Duration::from_millis(15)),
            consumer_admission(),
        )
        .await;

        assert!(started.elapsed() >= Duration::from_millis(5));
        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Requeue]
        );
        assert_eq!(calls.load(Ordering::Acquire), 0);
        Ok(())
    }

    #[tokio::test]
    async fn tx_handler_transient_exhaustion_requeues_without_dead_letter_or_commit() -> TestResult
    {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let store = TxStore::fresh();
        let dlx_writes = Arc::new(AtomicU32::new(0));
        let calls = Arc::new(AtomicU32::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_calls = Arc::clone(&handler_calls);
            Box::pin(async move {
                handler_calls.fetch_add(1, Ordering::AcqRel);
                ConsumerTxOutcome::HandlerTransient
            })
        });

        run_consumer_ackable_tx(
            delivery_stream("evt-tx-requeue", Arc::clone(&actions))?,
            Arc::clone(&store),
            (recording_dlx(Arc::clone(&dlx_writes))).as_ref(),
            &(meta()?),
            Arc::new(handler),
            lease_cfg(),
            consumer_admission(),
        )
        .await;

        assert_eq!(calls.load(Ordering::Acquire), MAX_REDELIVERY);
        assert_eq!(dlx_writes.load(Ordering::Acquire), 0);
        assert_eq!(store.commits.load(Ordering::Acquire), 0);
        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Requeue]
        );
        Ok(())
    }

    #[tokio::test]
    async fn tx_commit_unknown_requeues_without_retry_dead_letter_or_commit() -> TestResult {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let store = TxStore::fresh();
        let dlx_writes = Arc::new(AtomicU32::new(0));
        let calls = Arc::new(AtomicU32::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_calls = Arc::clone(&handler_calls);
            Box::pin(async move {
                handler_calls.fetch_add(1, Ordering::AcqRel);
                ConsumerTxOutcome::CommitUnknown
            })
        });

        run_consumer_ackable_tx(
            delivery_stream("evt-tx-commit-unknown", Arc::clone(&actions))?,
            Arc::clone(&store),
            (recording_dlx(Arc::clone(&dlx_writes))).as_ref(),
            &(meta()?),
            Arc::new(handler),
            lease_cfg(),
            consumer_admission(),
        )
        .await;
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(dlx_writes.load(Ordering::Acquire), 0);
        assert_eq!(store.commits.load(Ordering::Acquire), 0);
        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Requeue]
        );
        Ok(())
    }

    #[tokio::test]
    async fn tx_non_retryable_outcomes_requeue_once_without_side_effects() -> TestResult {
        type OutcomeFactory = fn() -> ConsumerTxOutcome<TestCommitProof>;
        let cases: [(&str, OutcomeFactory); 4] = [
            ("evt-tx-infrastructure", || {
                ConsumerTxOutcome::InfrastructureTransient
            }),
            ("evt-tx-unknown-table", || ConsumerTxOutcome::CommitUnknown),
            ("evt-tx-rollback-failed", || {
                ConsumerTxOutcome::RollbackFailed
            }),
            ("evt-tx-fenced-table", || ConsumerTxOutcome::Fenced),
        ];

        for (event_id, outcome) in cases {
            let actions = Arc::new(Mutex::new(Vec::new()));
            let store = TxStore::fresh();
            let dlx_writes = Arc::new(AtomicU32::new(0));
            let calls = Arc::new(AtomicU32::new(0));
            let handler_calls = Arc::clone(&calls);
            let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
                let handler_calls = Arc::clone(&handler_calls);
                Box::pin(async move {
                    handler_calls.fetch_add(1, Ordering::AcqRel);
                    outcome()
                })
            });

            run_consumer_ackable_tx(
                delivery_stream(event_id, Arc::clone(&actions))?,
                Arc::clone(&store),
                (recording_dlx(Arc::clone(&dlx_writes))).as_ref(),
                &(meta()?),
                Arc::new(handler),
                lease_cfg(),
                consumer_admission(),
            )
            .await;

            assert_eq!(calls.load(Ordering::Acquire), 1, "event_id={event_id}");
            assert_eq!(dlx_writes.load(Ordering::Acquire), 0, "event_id={event_id}");
            assert_eq!(
                store.commits.load(Ordering::Acquire),
                0,
                "event_id={event_id}"
            );
            assert_eq!(
                *actions.lock().unwrap_or_else(|error| error.into_inner()),
                vec![AckAction::Requeue],
                "event_id={event_id}"
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn tx_reject_kinds_dead_letter_once_and_commit_receipt() -> TestResult {
        for (message_id, kind) in [
            ("evt-tx-reject-permanent", RejectKind::Permanent),
            ("evt-tx-reject-invariant", RejectKind::Invariant),
        ] {
            let actions = Arc::new(Mutex::new(Vec::new()));
            let store = TxStore::fresh();
            let dlx_writes = Arc::new(AtomicU32::new(0));
            let calls = Arc::new(AtomicU32::new(0));
            let handler_calls = Arc::clone(&calls);
            let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
                let handler_calls = Arc::clone(&handler_calls);
                Box::pin(async move {
                    handler_calls.fetch_add(1, Ordering::AcqRel);
                    ConsumerTxOutcome::Rejected(kind)
                })
            });

            run_consumer_ackable_tx(
                delivery_stream(message_id, Arc::clone(&actions))?,
                Arc::clone(&store),
                (recording_dlx(Arc::clone(&dlx_writes))).as_ref(),
                &(meta()?),
                Arc::new(handler),
                lease_cfg(),
                consumer_admission(),
            )
            .await;

            assert_eq!(calls.load(Ordering::Acquire), 1);
            assert_eq!(dlx_writes.load(Ordering::Acquire), 1);
            assert_eq!(store.commits.load(Ordering::Acquire), 1);
            assert_eq!(
                *actions.lock().unwrap_or_else(|e| e.into_inner()),
                vec![AckAction::Ack]
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn tx_lease_lost_requeues_without_retry_dead_letter_or_commit() -> TestResult {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let store = TxStore::fresh();
        let dlx_writes = Arc::new(AtomicU32::new(0));
        let calls = Arc::new(AtomicU32::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_calls = Arc::clone(&handler_calls);
            Box::pin(async move {
                handler_calls.fetch_add(1, Ordering::AcqRel);
                ConsumerTxOutcome::Fenced
            })
        });

        run_consumer_ackable_tx(
            delivery_stream("evt-tx-lease-lost", Arc::clone(&actions))?,
            Arc::clone(&store),
            (recording_dlx(Arc::clone(&dlx_writes))).as_ref(),
            &(meta()?),
            Arc::new(handler),
            lease_cfg(),
            consumer_admission(),
        )
        .await;

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(dlx_writes.load(Ordering::Acquire), 0);
        assert_eq!(store.commits.load(Ordering::Acquire), 0);
        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Requeue]
        );
        Ok(())
    }

    #[tokio::test]
    async fn tx_malformed_id_rejects_without_calling_handler() -> TestResult {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let store = TxStore::fresh();
        let calls = Arc::new(AtomicU32::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let handler_calls = Arc::clone(&handler_calls);
            Box::pin(async move {
                handler_calls.fetch_add(1, Ordering::AcqRel);
                ConsumerTxOutcome::Committed(test_commit_proof())
            })
        });

        run_consumer_ackable_tx(
            delivery_stream("", Arc::clone(&actions))?,
            store,
            (noop_dlx()).as_ref(),
            &(meta()?),
            Arc::new(handler),
            lease_cfg(),
            consumer_admission(),
        )
        .await;

        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Reject]
        );
        Ok(())
    }

    #[tokio::test]
    async fn tx_try_claim_error_settles_by_error_kind_without_handler() -> TestResult {
        let cases = [
            (EngineErrorKind::Transient, AckAction::Requeue),
            (EngineErrorKind::Permanent, AckAction::Reject),
            (EngineErrorKind::Invariant, AckAction::Reject),
        ];
        for (kind, expected_action) in cases {
            let actions = Arc::new(Mutex::new(Vec::new()));
            let calls = Arc::new(AtomicU32::new(0));
            let handler_calls = Arc::clone(&calls);
            let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
                let handler_calls = Arc::clone(&handler_calls);
                Box::pin(async move {
                    handler_calls.fetch_add(1, Ordering::AcqRel);
                    ConsumerTxOutcome::Committed(test_commit_proof())
                })
            });

            run_consumer_ackable_tx(
                delivery_stream("evt-tx-claim-error", Arc::clone(&actions))?,
                TxStore::claim_error(kind),
                (noop_dlx()).as_ref(),
                &(meta()?),
                Arc::new(handler),
                lease_cfg(),
                consumer_admission(),
            )
            .await;

            assert_eq!(calls.load(Ordering::Acquire), 0, "kind={kind:?}");
            assert_eq!(
                *actions.lock().unwrap_or_else(|e| e.into_inner()),
                vec![expected_action],
                "kind={kind:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn tx_try_claim_failed_log_includes_route_context() -> TestResult {
        use std::collections::HashMap;

        use tracing::field::{Field, Visit};
        use tracing::{Event, Subscriber};
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;

        struct CaptureLayer {
            events: Arc<Mutex<Vec<HashMap<String, String>>>>,
        }

        struct FieldVisitor {
            fields: HashMap<String, String>,
        }

        impl Visit for FieldVisitor {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.fields
                    .insert(field.name().to_string(), format!("{value:?}"));
            }

            fn record_str(&mut self, field: &Field, value: &str) {
                self.fields
                    .insert(field.name().to_string(), value.to_string());
            }

            fn record_u64(&mut self, field: &Field, value: u64) {
                self.fields
                    .insert(field.name().to_string(), value.to_string());
            }

            fn record_i64(&mut self, field: &Field, value: i64) {
                self.fields
                    .insert(field.name().to_string(), value.to_string());
            }
        }

        impl<S> Layer<S> for CaptureLayer
        where
            S: Subscriber,
        {
            fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
                if *event.metadata().level() != tracing::Level::WARN {
                    return;
                }
                let mut visitor = FieldVisitor {
                    fields: HashMap::new(),
                };
                event.record(&mut visitor);
                self.events
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(visitor.fields);
            }
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CaptureLayer {
            events: Arc::clone(&events),
        });
        let meta = meta()?;
        let msg = message("evt-tx-claim-log")?;
        let error = EngineError::new(EngineErrorKind::Transient);
        tracing::subscriber::with_default(subscriber, || {
            log_tx_try_claim_failed(&meta, &msg, &error);
        });

        let events = events.lock().unwrap_or_else(|e| e.into_inner());
        let event = events
            .iter()
            .find(|fields| {
                fields
                    .get("message_id")
                    .is_some_and(|value| value == "evt-tx-claim-log")
            })
            .ok_or_else(|| std::io::Error::other("try_claim log event not captured"))?;
        assert_eq!(event.get("domain").map(String::as_str), Some("audit"));
        assert_eq!(
            event.get("contract_id").map(String::as_str),
            Some("identity.session-created")
        );
        assert_eq!(
            event.get("topic").map(String::as_str),
            Some("identity.session-created")
        );
        assert_eq!(
            event.get("consumer_group").map(String::as_str),
            Some("audit.session-created")
        );
        Ok(())
    }

    #[test]
    fn receipt_context_clone_is_available_for_tx_handler_budget() -> TestResult {
        let ctx = InboxReceiptContext::new(
            tenant()?,
            ConsumerGroup::parse("audit.session-created")?,
            "audit",
            "identity.session-created",
            "identity.session-created",
            "v1",
            SCHEMA_HASH,
            None,
            None,
        )?;
        let cloned = ctx.clone();
        assert_eq!(ctx, cloned);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn consumer_tx_thread_enters_the_assembly_runtime() -> TestResult {
        let assembly_runtime = tokio::runtime::Handle::current().id();
        let (observed_sender, observed_receiver) = tokio::sync::oneshot::channel();
        let worker = spawn_consumer_ackable_tx_subscriber::<TxStore, policy::TransactionalOnly, _>(
            "consumer-tx-runtime-regression".to_owned(),
            DynAckableSubscriber::new_box(RuntimeIdentitySubscriber {
                observed: Mutex::new(Some(observed_sender)),
            }),
            Topic::new("identity.session-created"),
            TxStore::fresh(),
            noop_dlx(),
            meta()?,
            transactional_handler(move |_msg, _ctx, _key, _lease| {
                Box::pin(async { ConsumerTxOutcome::Committed(test_commit_proof()) })
            }),
            lease_cfg(),
            tokio_util::sync::CancellationToken::new(),
            Arc::new(eventexec::WorkerHealth::starting()),
            tiny_backoff(),
            consumer_admission(),
        );

        assert_eq!(observed_receiver.await?, assembly_runtime);
        worker.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn consumer_tx_subscribe_failure_stays_unavailable_until_cancel() -> TestResult {
        let health = Arc::new(eventexec::WorkerHealth::starting());
        let token = tokio_util::sync::CancellationToken::new();
        let worker = spawn_consumer_ackable_tx_subscriber::<TxStore, policy::TransactionalOnly, _>(
            "consumer-tx-subscribe-failure".to_owned(),
            DynAckableSubscriber::new_box(FailingSubscriber),
            Topic::new("identity.session-created"),
            TxStore::fresh(),
            noop_dlx(),
            meta()?,
            transactional_handler(move |_msg, _ctx, _key, _lease| {
                Box::pin(async { ConsumerTxOutcome::Committed(test_commit_proof()) })
            }),
            lease_cfg(),
            token.clone(),
            Arc::clone(&health),
            tiny_backoff(),
            consumer_admission(),
        );

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if health.detail() == "subscriber-unavailable" {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| std::io::Error::other("timed out waiting for subscriber-unavailable"))?;
        assert_eq!(health.status(), HealthStatus::Unhealthy);
        assert_eq!(health.detail(), "subscriber-unavailable");
        token.cancel();
        worker.shutdown().await?;
        assert_eq!(health.detail(), "subscriber-unavailable");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn consumer_tx_subscribe_flaky_recovers_to_healthy() -> TestResult {
        let health = Arc::new(eventexec::WorkerHealth::starting());
        let token = tokio_util::sync::CancellationToken::new();
        let subscribe_calls = Arc::new(AtomicU32::new(0));
        let worker = spawn_consumer_ackable_tx_subscriber::<TxStore, policy::TransactionalOnly, _>(
            "consumer-tx-subscribe-flaky".to_owned(),
            DynAckableSubscriber::new_box(FlakySubscriber {
                fails_remaining: AtomicU32::new(2),
                subscribe_calls: Arc::clone(&subscribe_calls),
            }),
            Topic::new("identity.session-created"),
            TxStore::fresh(),
            noop_dlx(),
            meta()?,
            transactional_handler(move |_msg, _ctx, _key, _lease| {
                Box::pin(async { ConsumerTxOutcome::Committed(test_commit_proof()) })
            }),
            lease_cfg(),
            token.clone(),
            Arc::clone(&health),
            tiny_backoff(),
            consumer_admission(),
        );

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if subscribe_calls.load(Ordering::Acquire) >= 3
                    && health.status() == HealthStatus::Healthy
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .map_err(|_| std::io::Error::other("timed out waiting for flaky subscribe → Healthy"))?;
        assert!(subscribe_calls.load(Ordering::Acquire) >= 3);
        assert_eq!(health.status(), HealthStatus::Healthy);
        token.cancel();
        worker.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn consumer_tx_stream_end_resubscribes_until_healthy() -> TestResult {
        let health = Arc::new(eventexec::WorkerHealth::starting());
        let token = tokio_util::sync::CancellationToken::new();
        let subscribe_calls = Arc::new(AtomicU32::new(0));
        let worker = spawn_consumer_ackable_tx_subscriber::<TxStore, policy::TransactionalOnly, _>(
            "consumer-tx-stream-end-resubscribe".to_owned(),
            DynAckableSubscriber::new_box(SequenceSubscriber {
                subscribe_calls: Arc::clone(&subscribe_calls),
            }),
            Topic::new("identity.session-created"),
            TxStore::fresh(),
            noop_dlx(),
            meta()?,
            transactional_handler(move |_msg, _ctx, _key, _lease| {
                Box::pin(async { ConsumerTxOutcome::Committed(test_commit_proof()) })
            }),
            lease_cfg(),
            token.clone(),
            Arc::clone(&health),
            tiny_backoff(),
            consumer_admission(),
        );

        // tiny_backoff（1ms base）注入后无需 wall-clock 1s 等待二次订阅。
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if subscribe_calls.load(Ordering::Acquire) >= 2
                    && health.status() == HealthStatus::Healthy
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .map_err(|_| std::io::Error::other("timed out waiting for resubscribe + Healthy"))?;
        assert!(subscribe_calls.load(Ordering::Acquire) >= 2);
        assert_eq!(health.status(), HealthStatus::Healthy);
        token.cancel();
        worker.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn consumer_tx_worker_shutdown_stops_new_admission_and_drains_inflight_delivery()
    -> TestResult {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let handler_started = Arc::new(tokio::sync::Notify::new());
        let release_handler = Arc::new(tokio::sync::Notify::new());
        let committed = Arc::new(AtomicU32::new(0));
        let handler_calls = Arc::new(AtomicU32::new(0));
        let first = Delivery::new(
            message("evt-tx-drain-first")?,
            DynAcker::new_box(RecordingAcker(Arc::clone(&actions))),
        );
        let second = Delivery::new(
            message("evt-tx-drain-second")?,
            DynAcker::new_box(RecordingAcker(Arc::clone(&actions))),
        );
        let committed_run = Arc::clone(&committed);
        let handler_calls_run = Arc::clone(&handler_calls);
        let handler_started_run = Arc::clone(&handler_started);
        let release_handler_run = Arc::clone(&release_handler);
        let handler = transactional_handler(move |_msg, _ctx, _key, _lease| {
            let committed_run = Arc::clone(&committed_run);
            let handler_calls_run = Arc::clone(&handler_calls_run);
            let handler_started_run = Arc::clone(&handler_started_run);
            let release_handler_run = Arc::clone(&release_handler_run);
            Box::pin(async move {
                handler_calls_run.fetch_add(1, Ordering::AcqRel);
                handler_started_run.notify_one();
                release_handler_run.notified().await;
                committed_run.fetch_add(1, Ordering::AcqRel);
                ConsumerTxOutcome::Committed(test_commit_proof())
            })
        });
        let worker = spawn_consumer_ackable_tx_subscriber::<TxStore, policy::TransactionalOnly, _>(
            "consumer-tx-inflight-drain".to_owned(),
            DynAckableSubscriber::new_box(CancelAwareSubscriber {
                deliveries: Mutex::new(Some(vec![first, second])),
            }),
            Topic::new("identity.session-created"),
            TxStore::fresh(),
            noop_dlx(),
            meta()?,
            handler,
            lease_cfg(),
            tokio_util::sync::CancellationToken::new(),
            Arc::new(eventexec::WorkerHealth::starting()),
            tiny_backoff(),
            consumer_admission(),
        );

        tokio::time::timeout(Duration::from_secs(1), handler_started.notified()).await?;
        let shutdown = worker.shutdown();
        tokio::pin!(shutdown);
        assert!(futures::poll!(&mut shutdown).is_pending());
        assert_eq!(committed.load(Ordering::Acquire), 0);
        release_handler.notify_one();
        shutdown.await?;

        assert_eq!(committed.load(Ordering::Acquire), 1);
        assert_eq!(handler_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            *actions.lock().unwrap_or_else(|error| error.into_inner()),
            vec![AckAction::Ack]
        );
        Ok(())
    }
}
