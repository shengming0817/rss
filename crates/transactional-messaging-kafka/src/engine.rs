//! Native ownership and callback correlation, confined to one dedicated thread.
//!
//! ref: rust-rdkafka src/producer/base_producer.rs@598ac4ba1f714852bdf4e5685fe10cf5a66e947c
//! Adopt synchronous admission + delivery reports; retain Rust ownership outside C opaque pointers.
use crate::{KafkaError, KafkaPublishReceipt, config::PublishPlan, record::Record};
use rdkafka::{
    ClientContext, Message,
    error::{KafkaError as ProviderError, RDKafkaErrorCode},
    message::DeliveryResult,
    producer::{BaseProducer, BaseRecord, Producer, ProducerContext, PurgeConfig},
};
use rss_transactional_messaging::transport::{
    PublishFailure, PublishFailureKind as Kind, PublishFailureReason as Reason,
    PublishFailureStage as Stage, PublishOutcome,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, mpsc},
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

pub(crate) type Outcome = PublishOutcome<KafkaPublishReceipt>;
type Reply = oneshot::Sender<Outcome>;
const POLL: Duration = Duration::from_millis(5);
pub(crate) struct Command {
    pub(crate) record: Record,
    pub(crate) deadline: Instant,
    pub(crate) reply: Reply,
}
pub(crate) struct Admission {
    pub(crate) sender: Option<mpsc::SyncSender<Command>>,
    pub(crate) close: Option<Instant>,
    failed: bool,
}
pub(crate) struct Shared {
    pub(crate) admission: Mutex<Admission>,
    pending: Mutex<HashMap<usize, Reply>>,
    #[cfg(feature = "test-support")]
    pub(crate) gate: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
    #[cfg(feature = "test-support")]
    pub(crate) pre_send_gate: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
}
impl Shared {
    pub(crate) fn new(sender: mpsc::SyncSender<Command>) -> Self {
        Self {
            admission: Mutex::new(Admission {
                sender: Some(sender),
                close: None,
                failed: false,
            }),
            pending: Mutex::new(HashMap::new()),
            #[cfg(feature = "test-support")]
            gate: Mutex::new(None),
            #[cfg(feature = "test-support")]
            pre_send_gate: Mutex::new(None),
        }
    }
    pub(crate) fn close(&self, deadline: Instant) {
        let mut state = lock(&self.admission);
        state.sender.take();
        state.close = Some(state.close.map_or(deadline, |old| old.min(deadline)));
    }
    fn fail(&self) {
        let mut state = lock(&self.admission);
        state.failed = true;
        state.sender.take();
        state.close = Some(now());
    }
    fn failed(&self) -> bool {
        lock(&self.admission).failed
    }
    fn closing(&self) -> Option<Instant> {
        lock(&self.admission).close
    }
    fn complete(&self, token: usize, outcome: Outcome) {
        if let Some(reply) = lock(&self.pending).remove(&token) {
            let _ = reply.send(outcome);
        }
    }
    #[cfg(feature = "test-support")]
    pub(crate) fn pending_count(&self) -> usize {
        lock(&self.pending).len()
    }
}
// reason: these private locks contain no caller callbacks; cleanup must reclaim entries even during unwind.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
#[allow(clippy::disallowed_methods)]
// reason: adapter-local monotonic watchdog, initialized immediately from OperationDeadline; not business time.
pub(crate) fn now() -> Instant {
    Instant::now()
}
pub(crate) fn failure(kind: Kind, stage: Stage, reason: Reason) -> PublishFailure {
    PublishFailure::new(kind, stage, reason)
}
pub(crate) fn unavailable() -> Outcome {
    PublishOutcome::DefinitelyNotPublished(failure(
        Kind::Transient,
        Stage::Admission,
        Reason::TransportUnavailable,
    ))
}
pub(crate) fn ambiguous() -> Outcome {
    PublishOutcome::Ambiguous(failure(
        Kind::Transient,
        Stage::Confirm,
        Reason::TransportUnavailable,
    ))
}
pub(crate) fn expired() -> Outcome {
    PublishOutcome::DefinitelyNotPublished(failure(
        Kind::Transient,
        Stage::Admission,
        Reason::DeadlineElapsed,
    ))
}

struct Context {
    shared: Arc<Shared>,
    plan: Arc<PublishPlan>,
}
struct DomainLabel<'a>(&'a rss_transactional_messaging::message::MessagingDomain);
impl rss_redact::Redact for DomainLabel<'_> {
    fn redact_scoped(&self, _: rss_redact::RedactScope) -> String {
        // Authored domain is a validated public routing namespace; never a tenant or credential value.
        self.0.as_str().to_owned()
    }
}
impl ClientContext for Context {
    fn log(&self, _: rdkafka::config::RDKafkaLogLevel, _: &str, _: &str) {
        // reason: native log text may contain credentials or provider coordinates; never forward it.
    }
    fn error(&self, error: ProviderError, _: &str) {
        let fatal = error.rdkafka_error_code() == Some(RDKafkaErrorCode::Fatal);
        if fatal {
            self.shared.fail();
        }
        let classified = provider_failure(&error, Stage::Send);
        tracing::warn!(
            phase = "transport",
            stage = classified.stage().as_label(),
            client_id = %rss_redact::safe(&self.plan.client_id, rss_redact::RedactScope::ServerLog),
            domain = %rss_redact::safe(&DomainLabel(&self.plan.domain), rss_redact::RedactScope::ServerLog),
            fatal,
            reason = classified.reason().as_label(),
            kind = ?classified.kind(),
            "Kafka transport event"
        );
    }
}
impl ProducerContext for Context {
    type DeliveryOpaque = usize;
    fn delivery(&self, report: &DeliveryResult<'_>, token: usize) {
        let outcome = match report {
            Ok(message) => PublishOutcome::Confirmed(KafkaPublishReceipt {
                topic: message.topic().to_owned(),
                partition: message.partition(),
                offset: message.offset(),
            }),
            Err((error, _)) => {
                if error.rdkafka_error_code() == Some(RDKafkaErrorCode::Fatal) {
                    self.shared.fail();
                }
                PublishOutcome::Ambiguous(provider_failure(error, Stage::Confirm))
            }
        };
        self.shared.complete(token, outcome);
    }
}
fn provider_failure(error: &ProviderError, stage: Stage) -> PublishFailure {
    let (kind, reason) = match error.rdkafka_error_code() {
        Some(
            RDKafkaErrorCode::MessageSizeTooLarge
            | RDKafkaErrorCode::InvalidMessageSize
            | RDKafkaErrorCode::InvalidArgument,
        ) => (Kind::Permanent, Reason::InvalidMessage),
        Some(
            RDKafkaErrorCode::TopicAuthorizationFailed
            | RDKafkaErrorCode::ClusterAuthorizationFailed
            | RDKafkaErrorCode::Authentication
            | RDKafkaErrorCode::SaslAuthenticationFailed,
        ) => (Kind::Permanent, Reason::ProviderRejected),
        Some(RDKafkaErrorCode::MessageTimedOut | RDKafkaErrorCode::RequestTimedOut) => {
            (Kind::Transient, Reason::TransportUnavailable)
        }
        _ => (Kind::Transient, Reason::TransportUnavailable),
    };
    failure(kind, stage, reason)
}
struct Cleanup(Arc<Shared>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        self.0.close(now());
        // Declared before producer: even unwind destroys native client before reclaiming pending senders.
        for (_, reply) in lock(&self.0.pending).drain() {
            let _ = reply.send(ambiguous());
        }
    }
}

pub(crate) fn run(
    native: rdkafka::ClientConfig,
    config: Arc<PublishPlan>,
    shared: Arc<Shared>,
    receiver: mpsc::Receiver<Command>,
    startup: oneshot::Sender<Result<(), KafkaError>>,
) -> Result<(), KafkaError> {
    let _cleanup = Cleanup(shared.clone());
    let initialized = native.create_with_context(Context {
        shared: shared.clone(),
        plan: config.clone(),
    });
    drop(native);
    let producer: BaseProducer<Context> = match initialized {
        Ok(p) => p,
        Err(_) => {
            let _ = startup.send(Err(KafkaError::Initialization));
            return Err(KafkaError::Initialization);
        }
    };
    if startup.send(Ok(())).is_err() {
        shared.close(now());
    }
    let mut token = 0usize;
    let result = drive(&producer, &shared, &receiver, &config, &mut token);
    if result.is_err() {
        producer.purge(PurgeConfig::default().queue().inflight().non_blocking());
    }
    drop(producer);
    // Cleanup runs only after native destruction; no callback can subsequently access a pending entry.
    result
}
fn drive(
    producer: &BaseProducer<Context>,
    shared: &Shared,
    receiver: &mpsc::Receiver<Command>,
    config: &PublishPlan,
    token: &mut usize,
) -> Result<(), KafkaError> {
    loop {
        producer.poll(Duration::ZERO);
        observe_fatal(producer, shared);
        if shared.failed() {
            reject_queued(receiver);
            return Err(KafkaError::OwnerFailed);
        }
        if shared.closing().is_some_and(|end| now() >= end) {
            reject_queued(receiver);
            return Err(KafkaError::DeadlineElapsed);
        }
        match receiver.recv_timeout(POLL) {
            Ok(command) => send(producer, shared, command, config, token)?,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let end = shared.closing().unwrap_or_else(now);
                let flushed = producer.flush(end.saturating_duration_since(now()));
                observe_fatal(producer, shared);
                return if shared.failed() {
                    Err(KafkaError::OwnerFailed)
                } else {
                    flushed.map_err(|_| KafkaError::Shutdown)
                };
            }
        }
    }
}
fn observe_fatal(producer: &BaseProducer<Context>, shared: &Shared) {
    // The Event API may expose an underlying code instead of Fatal; query the authoritative client flag.
    if !shared.failed() && producer.client().fatal_error().is_some() {
        producer
            .context()
            .error(ProviderError::Global(RDKafkaErrorCode::Fatal), "");
    }
}
fn reject_queued(receiver: &mpsc::Receiver<Command>) {
    while let Ok(command) = receiver.try_recv() {
        let _ = command.reply.send(unavailable());
    }
}
fn send(
    producer: &BaseProducer<Context>,
    shared: &Shared,
    command: Command,
    config: &PublishPlan,
    token: &mut usize,
) -> Result<(), KafkaError> {
    #[cfg(feature = "test-support")]
    pause_gate(shared, &shared.pre_send_gate);
    if command.reply.is_closed() {
        return Ok(());
    }
    let state = lock(&shared.admission);
    if state.close.is_some_and(|end| now() >= end) {
        let _ = command.reply.send(unavailable());
        return Ok(());
    }
    if now() >= command.deadline {
        let _ = command.reply.send(expired());
        return Ok(());
    }
    if lock(&shared.pending).len() >= config.limits.in_flight {
        let _ = command.reply.send(unavailable());
        return Ok(());
    }
    let Some(next) = token.checked_add(1) else {
        let _ = command.reply.send(unavailable());
        drop(state);
        shared.close(now());
        return Err(KafkaError::OwnerFailed);
    };
    *token = next;
    let Record {
        topic,
        key,
        payload,
        headers,
    } = command.record;
    lock(&shared.pending).insert(next, command.reply);
    let mut record = BaseRecord::with_opaque_to(&topic, next)
        .payload(&payload)
        .headers(headers);
    if let Some(key) = &key {
        record = record.key(key);
    }
    // The nonblocking native admission and forced close share one linearization lock.
    let sent = producer.send(record);
    drop(state);
    observe_fatal(producer, shared);
    match sent {
        Err((error, _)) => shared.complete(
            next,
            PublishOutcome::DefinitelyNotPublished(provider_failure(&error, Stage::Send)),
        ),
        Ok(()) => {
            #[cfg(feature = "test-support")]
            pause_gate(shared, &shared.gate);
        }
    }
    Ok(())
}
#[cfg(feature = "test-support")]
fn pause_gate(shared: &Shared, gate: &Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>) {
    let gate = lock(gate).take();
    if let Some((entered, mut release)) = gate {
        let _ = entered.send(());
        while matches!(release.try_recv(), Err(oneshot::error::TryRecvError::Empty)) {
            if shared.closing().is_some() {
                break;
            }
            std::thread::sleep(POLL);
        }
    }
}

#[cfg(test)]
pub(crate) fn assert_cleanup_for_unit_test() {
    let (sender, _receiver) = mpsc::sync_channel(1);
    let shared = Arc::new(Shared::new(sender));
    let (reply, mut receiver) = oneshot::channel();
    lock(&shared.pending).insert(1, reply);
    drop(Cleanup(shared.clone()));
    assert!(lock(&shared.pending).is_empty());
    assert!(matches!(
        receiver.try_recv(),
        Ok(PublishOutcome::Ambiguous(_))
    ));
    assert!(lock(&shared.admission).sender.is_none());
}

#[cfg(test)]
#[test]
fn typed_provider_diagnostics_preserve_auth_timeout_and_unknown() {
    for (code, kind, reason) in [
        (
            RDKafkaErrorCode::Authentication,
            Kind::Permanent,
            Reason::ProviderRejected,
        ),
        (
            RDKafkaErrorCode::SaslAuthenticationFailed,
            Kind::Permanent,
            Reason::ProviderRejected,
        ),
        (
            RDKafkaErrorCode::TopicAuthorizationFailed,
            Kind::Permanent,
            Reason::ProviderRejected,
        ),
        (
            RDKafkaErrorCode::MessageTimedOut,
            Kind::Transient,
            Reason::TransportUnavailable,
        ),
        (
            RDKafkaErrorCode::QueueFull,
            Kind::Transient,
            Reason::TransportUnavailable,
        ),
        (
            RDKafkaErrorCode::Unknown,
            Kind::Transient,
            Reason::TransportUnavailable,
        ),
    ] {
        let classified = provider_failure(&ProviderError::MessageProduction(code), Stage::Confirm);
        assert_eq!(classified, failure(kind, Stage::Confirm, reason));
    }
}

#[cfg(test)]
#[test]
fn fatal_callback_seals_owner_and_finishes_pending_as_ambiguous() -> anyhow::Result<()> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let shared = Arc::new(Shared::new(sender));
    let (reply, mut result) = oneshot::channel();
    lock(&shared.pending).insert(1, reply);
    let plan = Arc::new(PublishPlan {
        client_id: crate::KafkaClientId::parse("fatal-test")?,
        domain: rss_transactional_messaging::message::MessagingDomain::parse("events")?,
        routes: HashMap::new(),
        limits: crate::KafkaLimits::new(1, 1, 1024, Duration::from_secs(1))?,
    });
    Context {
        shared: shared.clone(),
        plan: plan.clone(),
    }
    .error(
        ProviderError::Global(RDKafkaErrorCode::Fatal),
        "SECRET_BAIT",
    );
    assert!(lock(&shared.admission).sender.is_none());
    let (startup, _ready) = oneshot::channel();
    let finished = run(
        rdkafka::ClientConfig::new(),
        plan,
        shared.clone(),
        receiver,
        startup,
    );
    assert_eq!(finished, Err(KafkaError::OwnerFailed));
    assert!(lock(&shared.pending).is_empty());
    assert!(matches!(
        result.try_recv(),
        Ok(PublishOutcome::Ambiguous(_))
    ));
    Ok(())
}

#[cfg(test)]
#[test]
fn native_timeouts_are_not_core_deadlines() {
    for code in [
        RDKafkaErrorCode::MessageTimedOut,
        RDKafkaErrorCode::RequestTimedOut,
    ] {
        assert_eq!(
            provider_failure(&ProviderError::MessageProduction(code), Stage::Confirm).reason(),
            Reason::TransportUnavailable
        );
    }
}

#[cfg(test)]
#[test]
fn callback_logs_identify_client_and_domain_without_provider_text() -> anyhow::Result<()> {
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            lock(&self.0).extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        } // reason: in-memory writes are immediate.
    }
    let output = Capture(Arc::new(Mutex::new(Vec::new())));
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let (sender, _receiver) = mpsc::sync_channel(1);
    let context = Context {
        shared: Arc::new(Shared::new(sender)),
        plan: Arc::new(PublishPlan {
            client_id: crate::KafkaClientId::parse("orders-writer")?,
            domain: rss_transactional_messaging::message::MessagingDomain::parse("events")?,
            routes: HashMap::new(),
            limits: crate::KafkaLimits::new(1, 1, 1024, Duration::from_secs(1))?,
        }),
    };
    tracing::subscriber::with_default(subscriber, || {
        context.error(
            ProviderError::Global(RDKafkaErrorCode::Authentication),
            "SECRET_BAIT ssl://broker:9092",
        )
    });
    let text = String::from_utf8(lock(&output.0).clone())?;
    for expected in [
        "client_id=orders-writer",
        "domain=events",
        "stage=\"send\"",
        "reason=\"provider_rejected\"",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert!(!text.contains("SECRET_BAIT"));
    assert!(!text.contains("broker:9092"));
    Ok(())
}
