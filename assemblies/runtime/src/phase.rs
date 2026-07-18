/// Production runtime assembly phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimePhase {
    /// Preflight credential provider configuration and external key sources.
    BuildProvider,
    /// Build infrastructure bundles and shared runtime dependencies.
    BuildInfra,
    /// Wire domain roots, module outputs, probes, and workers.
    WireDomains,
    /// Finalize authenticated and health listeners.
    Finalize,
    /// Launch listeners and register shutdown resources.
    Launch,
}

impl RuntimePhase {
    /// Stable phase order used by tests and low-cardinality logs.
    pub const ALL: [Self; 5] = [
        Self::BuildProvider,
        Self::BuildInfra,
        Self::WireDomains,
        Self::Finalize,
        Self::Launch,
    ];

    /// Stable low-cardinality label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BuildProvider => "build_provider",
            Self::BuildInfra => "build_infra",
            Self::WireDomains => "wire_domains",
            Self::Finalize => "finalize",
            Self::Launch => "launch",
        }
    }
}

use crate::config::{RuntimeConfigSnapshot, SnapshotConfig};

/// Process-wide inputs shared by the mutually exclusive serving and operator preparations.
pub(crate) struct PreparedRuntimeInputs {
    config: RuntimeConfigSnapshot,
    trace_export: Option<otel::OtelExporter>,
}

impl PreparedRuntimeInputs {
    pub(crate) fn new(
        config: RuntimeConfigSnapshot,
        trace_export: Option<otel::OtelExporter>,
    ) -> Self {
        Self {
            config,
            trace_export,
        }
    }

    pub(crate) fn config(&self) -> SnapshotConfig<'_> {
        self.config.view()
    }

    pub(crate) fn take_trace_export(&mut self) -> Option<otel::OtelExporter> {
        self.trace_export.take()
    }
}

/// Serving-only runtime inputs.
///
/// INVARIANT: RUNTIME-CONFIG-SNAPSHOT-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" } -- the crate-private constructor requires an owned process snapshot and a non-optional typed password blocklist, while operator inputs cannot be passed to [`crate::run`].
pub struct ServingRuntimeInputs {
    prepared: PreparedRuntimeInputs,
    password_blocklist: std::sync::Arc<secure::DigestPasswordBlocklist>,
}

impl ServingRuntimeInputs {
    pub(crate) fn new(
        prepared: PreparedRuntimeInputs,
        password_blocklist: std::sync::Arc<secure::DigestPasswordBlocklist>,
    ) -> Self {
        Self {
            prepared,
            password_blocklist,
        }
    }

    /// Mint a borrowed capability for the process snapshot owned by the phase orchestrator.
    pub(crate) fn config(&self) -> SnapshotConfig<'_> {
        self.prepared.config()
    }

    /// Borrow the typed local policy loaded before any external provider construction.
    pub(crate) fn password_blocklist(&self) -> &std::sync::Arc<secure::DigestPasswordBlocklist> {
        &self.password_blocklist
    }

    /// Move the optional trace exporter into the launch phase while retaining the process snapshot
    /// until `run()` exits.
    pub(crate) fn take_trace_export(&mut self) -> Option<otel::OtelExporter> {
        self.prepared.take_trace_export()
    }

    pub(crate) fn prepared_mut(&mut self) -> &mut PreparedRuntimeInputs {
        &mut self.prepared
    }
}

/// Operator-only runtime inputs. Password-policy capabilities are intentionally unrepresentable.
pub struct OperatorRuntimeInputs {
    prepared: PreparedRuntimeInputs,
}

impl OperatorRuntimeInputs {
    pub(crate) fn new(prepared: PreparedRuntimeInputs) -> Self {
        Self { prepared }
    }

    /// Mint a borrowed capability for operator configuration consumers.
    pub(crate) fn config(&self) -> SnapshotConfig<'_> {
        self.prepared.config()
    }

    pub(crate) fn prepared_mut(&mut self) -> &mut PreparedRuntimeInputs {
        &mut self.prepared
    }
}

/// Marker returned when runtime launch exits cleanly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeOutputs;

impl RuntimeOutputs {
    /// Construct the launch completion marker.
    pub const fn completed() -> Self {
        Self
    }
}

/// Emit bounded phase logs and preserve the original result.
pub fn phase_result<T>(phase: RuntimePhase, result: anyhow::Result<T>) -> anyhow::Result<T> {
    match result {
        Ok(value) => {
            log_phase_completed(phase);
            Ok(value)
        }
        Err(err) => {
            log_phase_failed(phase, err.as_ref());
            Err(err)
        }
    }
}

fn log_phase_completed(phase: RuntimePhase) {
    tracing::info!(runtime.phase = phase.as_str(), "runtime phase completed");
}

fn log_phase_failed(phase: RuntimePhase, err: &dyn std::error::Error) {
    tracing::warn!(
        runtime.phase = phase.as_str(),
        error = %secure::redact_error(err),
        "runtime phase failed"
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    // reason: phase unit tests use expect for direct assertion failures and poisoned test mutexes.

    use super::*;
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::layer::{Context as LayerContext, Layer};
    use tracing_subscriber::prelude::*;

    struct MissingConfigSource;

    impl crate::config::RuntimeConfigSource for MissingConfigSource {
        fn read(
            &mut self,
            _key: &crate::config::RuntimeConfigKey,
        ) -> crate::config::CapturedConfigValue {
            crate::config::CapturedConfigValue::Missing
        }
    }

    struct BaitConfigSource;

    impl crate::config::RuntimeConfigSource for BaitConfigSource {
        fn read(
            &mut self,
            _key: &crate::config::RuntimeConfigKey,
        ) -> crate::config::CapturedConfigValue {
            crate::config::CapturedConfigValue::Present(secure::SecretText::from_string(
                "postgres://user:dsn-password@db/vault-token.jwt-hmac.PEM".to_owned(),
            ))
        }
    }

    fn test_password_blocklist() -> Arc<secure::DigestPasswordBlocklist> {
        Arc::new(
            crypto::load_password_blocklist_from_reader(std::io::Cursor::new(include_bytes!(
                "../../../deploy/password-blocklist.demo.sha256"
            )))
            .unwrap_or_else(|_| unreachable!()),
        )
    }

    #[test]
    fn runtime_phase_labels_are_closed_and_ordered() {
        let labels: Vec<_> = RuntimePhase::ALL
            .iter()
            .copied()
            .map(RuntimePhase::as_str)
            .collect();
        assert_eq!(
            labels,
            [
                "build_provider",
                "build_infra",
                "wire_domains",
                "finalize",
                "launch"
            ]
        );
        assert_eq!(
            labels.iter().copied().collect::<BTreeSet<_>>().len(),
            RuntimePhase::ALL.len(),
            "phase labels must be unique"
        );
        assert!(
            labels
                .iter()
                .all(|label| label.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_')),
            "phase labels must stay low-cardinality snake_case"
        );
    }

    #[test]
    fn runtime_phase_harness_captures_current_phase_order_golden() {
        assert_eq!(
            phase_order_transcript(),
            "build_provider -> build_infra -> wire_domains -> finalize -> launch"
        );
    }

    fn phase_order_transcript() -> String {
        RuntimePhase::ALL
            .iter()
            .copied()
            .map(RuntimePhase::as_str)
            .collect::<Vec<_>>()
            .join(" -> ")
    }

    #[test]
    fn runtime_config_inputs_separate_serving_policy_from_operator_capabilities() {
        let snapshot = RuntimeConfigSnapshot::capture(MissingConfigSource)
            .expect("closed catalog capture succeeds");
        let blocklist = test_password_blocklist();
        let prepared = PreparedRuntimeInputs::new(snapshot, None);
        let mut serving = ServingRuntimeInputs::new(prepared, Arc::clone(&blocklist));
        assert!(serving.config().value("RSS_VAULT_TOKEN").is_none());
        assert!(Arc::ptr_eq(serving.password_blocklist(), &blocklist));
        assert!(serving.take_trace_export().is_none());

        let snapshot = RuntimeConfigSnapshot::capture(MissingConfigSource)
            .expect("closed catalog capture succeeds");
        let mut operator = OperatorRuntimeInputs::new(PreparedRuntimeInputs::new(snapshot, None));
        assert!(operator.config().value("RSS_VAULT_TOKEN").is_none());
        assert!(operator.prepared_mut().take_trace_export().is_none());
    }

    #[test]
    fn runtime_config_anyhow_chain_and_phase_log_remain_opaque() {
        let snapshot = RuntimeConfigSnapshot::capture(BaitConfigSource)
            .expect("closed catalog capture succeeds");
        let error = anyhow::anyhow!("{snapshot:?}");
        let chain = format!("{error:#}");
        let recorder = EventRecorder::default();
        let subscriber = tracing_subscriber::registry().with(recorder.clone());

        let result = tracing::subscriber::with_default(subscriber, || {
            phase_result::<()>(RuntimePhase::BuildInfra, Err(error))
        });
        assert!(result.is_err());

        let events = recorder.events();
        let phase_error = events[0].error.as_deref().unwrap_or_default();
        assert_eq!(chain, "RuntimeConfigSnapshot(<redacted>)");
        assert_eq!(phase_error, "RuntimeConfigSnapshot(<redacted>)");
        for fragment in ["dsn-password", "vault-token", "jwt-hmac", "PEM"] {
            assert!(!chain.contains(fragment));
            assert!(!phase_error.contains(fragment));
        }
    }

    #[test]
    fn runtime_outputs_is_completion_marker() {
        let output = RuntimeOutputs::completed();
        assert_eq!(output, RuntimeOutputs);
    }

    #[test]
    fn phase_result_passes_through_ok_and_error() {
        let ok = phase_result(RuntimePhase::BuildInfra, Ok::<_, anyhow::Error>(7))
            .expect("ok result must pass through");
        assert_eq!(ok, 7);

        let err = phase_result::<()>(RuntimePhase::BuildInfra, Err(anyhow::anyhow!("boom")))
            .expect_err("error must pass through");
        assert_eq!(err.to_string(), "boom");
    }

    #[test]
    fn phase_result_logs_error_from_question_mark_phase_body() {
        let recorder = EventRecorder::default();
        let subscriber = tracing_subscriber::registry().with(recorder.clone());
        let result = tracing::subscriber::with_default(subscriber, || {
            phase_result(
                RuntimePhase::BuildProvider,
                (|| {
                    Err::<(), _>(anyhow::anyhow!("phase body failed"))?;
                    Ok::<_, anyhow::Error>(())
                })(),
            )
        });

        let err = result.expect_err("phase body error must pass through");
        assert_eq!(err.to_string(), "phase body failed");
        let events = recorder.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].runtime_phase.as_deref(), Some("build_provider"));
        assert_eq!(events[0].error.as_deref(), Some("phase body failed"));
    }

    #[test]
    fn phase_result_logs_only_closed_phase_labels() {
        let recorder = EventRecorder::default();
        let subscriber = tracing_subscriber::registry().with(recorder.clone());
        tracing::subscriber::with_default(subscriber, || {
            let _ = phase_result(RuntimePhase::Launch, Ok::<_, anyhow::Error>(()));
            let _ = phase_result::<()>(RuntimePhase::Finalize, Err(anyhow::anyhow!("fail")));
        });

        let events = recorder.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].runtime_phase.as_deref(), Some("launch"));
        assert_eq!(events[1].runtime_phase.as_deref(), Some("finalize"));
        assert!(events[0].error.is_none());
        assert_eq!(events[1].error.as_deref(), Some("fail"));
        assert!(
            events
                .iter()
                .all(|event| event.runtime_phase.as_deref().is_some_and(|phase| {
                    RuntimePhase::ALL
                        .iter()
                        .copied()
                        .map(RuntimePhase::as_str)
                        .any(|closed_phase| closed_phase == phase)
                }) && event.message.is_some()),
            "phase logs must only record closed phase labels"
        );
    }

    #[test]
    fn phase_result_redacts_error_field() {
        let recorder = EventRecorder::default();
        let subscriber = tracing_subscriber::registry().with(recorder.clone());
        tracing::subscriber::with_default(subscriber, || {
            let _ = phase_result::<()>(
                RuntimePhase::Finalize,
                Err(anyhow::anyhow!(
                    "connect postgres://svc:s3cr3t@db.internal:5432/app refused"
                )),
            );
        });

        let events = recorder.events();
        assert_eq!(events.len(), 1);
        let error = events[0]
            .error
            .as_deref()
            .expect("error field must be logged");
        assert!(
            !error.contains("s3cr3t"),
            "error field must be redacted: {error}"
        );
        assert!(
            error.contains("postgres://<redacted>@db.internal:5432/app"),
            "error field must retain redacted diagnostic shape: {error}"
        );
    }

    #[derive(Clone, Default)]
    struct EventRecorder {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    impl EventRecorder {
        fn events(&self) -> Vec<CapturedEvent> {
            self.events
                .lock()
                .expect("event recorder mutex is not poisoned")
                .clone()
        }
    }

    impl<S> Layer<S> for EventRecorder
    where
        S: Subscriber,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
            let mut visitor = FieldRecorder::default();
            event.record(&mut visitor);
            self.events
                .lock()
                .expect("event recorder mutex is not poisoned")
                .push(visitor.event);
        }
    }

    #[derive(Clone, Debug, Default)]
    struct CapturedEvent {
        runtime_phase: Option<String>,
        message: Option<String>,
        error: Option<String>,
    }

    #[derive(Default)]
    struct FieldRecorder {
        event: CapturedEvent,
    }

    impl Visit for FieldRecorder {
        fn record_str(&mut self, field: &Field, value: &str) {
            match field.name() {
                "runtime.phase" => self.event.runtime_phase = Some(value.to_string()),
                "message" => self.event.message = Some(value.to_string()),
                "error" => self.event.error = Some(value.to_string()),
                _ => {}
            }
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            match field.name() {
                "message" => self.event.message = Some(format!("{value:?}")),
                "error" => self.event.error = Some(format!("{value:?}")),
                _ => {}
            }
        }
    }
}
