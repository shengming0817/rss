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
    /// Stable phase order used by transition and low-cardinality log tests.
    #[cfg(test)]
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

mod domains;
mod finalize;
mod infra;
mod launch;
pub(crate) mod maintenance;
mod provider;

pub(crate) use maintenance::wire_revocation_sweeper;

use crate::config::{RuntimeConfigSnapshot, SnapshotConfig};
use bootstrap::DomainModuleResult;
use infra::domain_transport::DomainTransportRuntime;
use std::sync::Arc;

const PG_MODULE_COMMITTED_ONCE: &str = "PG module is committed once";
const TOKEN_MODULE_COMMITTED_ONCE: &str = "token provider module is committed once";

/// Option-backed module that is written during a phase and taken exactly once on the success path.
struct UncommittedModule {
    module: Option<DomainModuleResult>,
    committed_once: &'static str,
}

impl UncommittedModule {
    fn new(committed_once: &'static str) -> Self {
        Self {
            module: Some(DomainModuleResult::default()),
            committed_once,
        }
    }

    fn get_mut(&mut self) -> &mut DomainModuleResult {
        self.module
            .as_mut()
            .unwrap_or_else(|| unreachable!("{}", self.committed_once))
    }

    fn take(&mut self) -> DomainModuleResult {
        self.module
            .take()
            .unwrap_or_else(|| unreachable!("{}", self.committed_once))
    }

    fn take_or_default(&mut self) -> DomainModuleResult {
        self.module.take().unwrap_or_default()
    }

    fn restore(&mut self, module: DomainModuleResult) {
        self.module = Some(module);
    }
}

#[cfg(test)]
pub(crate) use domains::validate_domain_listener_evidence;
#[cfg(test)]
pub(crate) use infra::after_required_preflight;
pub(crate) use infra::domain_transport::{
    SPIFFE_ENDPOINT_SOCKET_ENV, required_spiffe_endpoint_from_value,
};

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) use super::infra::dlx::build_dlx_lifecycle_bootstrap_config_from;
    pub(crate) use super::infra::domain_transport::{
        DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV, DOMAIN_TRANSPORT_READY_PROBE_NAME,
        DomainTransportConfig, DomainTransportRuntime, DomainTransportRuntimeInner,
        InProcDomainTransport, RuntimeDomainTransport, SPIFFE_ENDPOINT_SOCKET_ENV,
        build_domain_transport_targets_from, required_spiffe_endpoint_from_value,
    };
    pub(crate) use super::infra::keyring::{
        COMMAND_IDEMPOTENCY_KEYS_ENV, build_command_idempotency_keyring_from,
    };
    pub(crate) use super::maintenance::{
        AUTH_GRANT_SWEEPER_PROBE_NAME, AUTH_GRANT_SWEEPER_WORKER_NAME, AuthGrantSweepFuture,
        AuthGrantSweepRunner, REVOCATION_SWEEPER_PROBE_NAME, REVOCATION_SWEEPER_WORKER_NAME,
        RLS_READY_PROBE_NAME, RevocationSweepFuture, RevocationSweepObservation,
        RevocationSweepRunner, RlsReadyProbe, SERVICE_TOKEN_REPLAY_SWEEPER_PROBE_NAME,
        SERVICE_TOKEN_REPLAY_SWEEPER_WORKER_NAME, SweeperHealth, run_auth_grant_sweeper_loop,
        run_revocation_sweeper_loop, sweeper_module_result, wire_revocation_sweeper,
    };
}

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
/// INVARIANT: RUNTIME-CONFIG-SNAPSHOT-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" } -- the crate-private constructor requires an owned process snapshot and a non-optional typed password blocklist, while operator inputs cannot be passed to [`crate::run`]; serving and operator provider APIs can only borrow the unforgeable [`SnapshotConfig`] minted from these owned inputs, and Projection dispatch accepts only its distinct nested input owner.
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

/// Operator-only inputs: no serving password-policy or ambient-config source is representable.
pub struct OperatorRuntimeInputs {
    prepared: PreparedRuntimeInputs,
}

/// Projection-control-only inputs minted from the dedicated closed configuration generation.
///
/// The private nested operator input lets the existing control implementation reuse lifecycle
/// machinery without making a generic operator or serving generation acceptable at the binary
/// Projection dispatch boundary.
pub struct ProjectionOperatorRuntimeInputs {
    operator: OperatorRuntimeInputs,
}

/// Proof that a consumer belongs to the operator runtime, never the serving runtime.
#[derive(Clone, Copy)]
pub(crate) struct OperatorRuntimeCapability<'a> {
    _operator: &'a OperatorRuntimeInputs,
}

impl OperatorRuntimeInputs {
    pub(crate) fn new(prepared: PreparedRuntimeInputs) -> anyhow::Result<Self> {
        Ok(Self { prepared })
    }

    /// Mint a borrowed capability for operator configuration consumers.
    pub(crate) fn config(&self) -> SnapshotConfig<'_> {
        self.prepared.config()
    }

    pub(crate) fn operator_capability(&self) -> OperatorRuntimeCapability<'_> {
        OperatorRuntimeCapability { _operator: self }
    }

    pub(crate) fn prepared_mut(&mut self) -> &mut PreparedRuntimeInputs {
        &mut self.prepared
    }
}

impl ProjectionOperatorRuntimeInputs {
    pub(crate) fn new(prepared: PreparedRuntimeInputs) -> anyhow::Result<Self> {
        Ok(Self {
            operator: OperatorRuntimeInputs::new(prepared)?,
        })
    }

    #[cfg(feature = "operator-cli")]
    pub(crate) fn operator_inputs(&self) -> &OperatorRuntimeInputs {
        &self.operator
    }

    pub(crate) fn prepared_mut(&mut self) -> &mut PreparedRuntimeInputs {
        self.operator.prepared_mut()
    }
}

struct PhaseContext<'a> {
    runtime_inputs: &'a mut ServingRuntimeInputs,
    runtime_plan: crate::plan::RuntimePlan,
}

/// Pre-domain phase context that linearly carries the plan-owned composition capability.
struct DomainPhaseContext<'a> {
    context: PhaseContext<'a>,
    domain_execution_plan: crate::plan::DomainExecutionPlan,
}

impl<'a> DomainPhaseContext<'a> {
    fn new(
        runtime_inputs: &'a mut ServingRuntimeInputs,
        runtime_plan: crate::plan::RuntimePlan,
        domain_execution_plan: crate::plan::DomainExecutionPlan,
    ) -> Self {
        Self {
            context: PhaseContext {
                runtime_inputs,
                runtime_plan,
            },
            domain_execution_plan,
        }
    }

    fn into_parts(self) -> (PhaseContext<'a>, crate::plan::DomainExecutionPlan) {
        (self.context, self.domain_execution_plan)
    }
}

impl<'a> std::ops::Deref for DomainPhaseContext<'a> {
    type Target = PhaseContext<'a>;

    fn deref(&self) -> &Self::Target {
        &self.context
    }
}

impl PhaseContext<'_> {
    fn config(&self) -> SnapshotConfig<'_> {
        self.runtime_inputs.config()
    }

    fn password_blocklist(&self) -> &Arc<secure::DigestPasswordBlocklist> {
        self.runtime_inputs.password_blocklist()
    }

    fn take_trace_export(&mut self) -> Option<otel::OtelExporter> {
        self.runtime_inputs.take_trace_export()
    }
}

/// INVARIANT: RUNTIME-PHASE-TRANSITION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private state fields, exact associated Next chain, consuming transition receivers, and non-Clone lifecycle owners" } -- production startup is representable only as the closed `Planned -> ProvidersBuilt -> InfraBuilt -> DomainsWired -> Finalized -> runtimeexec::RuntimeOutputs` chain; every transition consumes its predecessor and selects its phase label through this trait.
mod sealed {
    pub(super) trait Sealed {}
}

trait RuntimePhaseState: sealed::Sealed {
    type Next;
    const PHASE: RuntimePhase;
}

#[must_use]
pub(crate) struct Planned<'a> {
    runtime_inputs: &'a mut ServingRuntimeInputs,
}

#[must_use]
pub(crate) struct ProvidersBuilt<'a> {
    context: DomainPhaseContext<'a>,
    provider_build: crate::provider_output::ProviderBuild,
    provider_factories: crate::provider_output::ProviderFactoryDispatch,
    listener_execution_plan: crate::plan::ListenerExecutionPlan,
    placement_execution_plan: crate::plan::PlacementExecutionPlan,
    rate_limiter: Arc<ratelimit::GovernorLimiter>,
    serving_config: crate::config::RuntimeServingConfigParts,
    runtime_rss_access: Option<crate::infra::oidc::RuntimeAccessProvider<diport::RssAccessProfile>>,
    runtime_federated_access:
        Option<crate::infra::oidc::RuntimeAccessProvider<diport::FederatedAccessProfile>>,
}

#[must_use]
pub(crate) struct InfraBuilt<'a> {
    context: DomainPhaseContext<'a>,
    provider_build: crate::provider_output::ProviderBuild,
    provider_factories: crate::provider_output::ProviderFactoryDispatch,
    listener_execution_plan: crate::plan::ListenerExecutionPlan,
    placement_execution_plan: crate::plan::PlacementExecutionPlan,
    rate_limiter: Arc<ratelimit::GovernorLimiter>,
    deps: crate::SharedRuntimeDeps,
    s3_canary_config: crate::infra::s3::S3CanaryConfig,
    wiring_inputs: infra::RuntimeWiringInputs,
    domain_transport: DomainTransportRuntime,
    metrics_exporter: Arc<dyn diport::MetricsExporter>,
    command_idempotency_keyring: Arc<eventexec::command::CommandIdempotencyKeyring>,
    signing_rotation_probe: Option<crate::infra::signing_rotation::SigningKeyRotationProbe>,
    runtime_rss_access: Option<crate::infra::oidc::RuntimeAccessProvider<diport::RssAccessProfile>>,
    runtime_federated_access:
        Option<crate::infra::oidc::RuntimeAccessProvider<diport::FederatedAccessProfile>>,
    runtime_service_token: Option<crate::infra::oidc::RuntimeServiceTokenProvider>,
}

#[must_use]
pub(crate) struct DomainsWired<'a> {
    context: PhaseContext<'a>,
    listener_execution_plan: crate::plan::ListenerExecutionPlan,
    rate_limiter: Arc<ratelimit::GovernorLimiter>,
    deps: crate::SharedRuntimeDeps,
    runtime_rss_access: Option<crate::infra::oidc::RuntimeAccessProvider<diport::RssAccessProfile>>,
    runtime_federated_access:
        Option<crate::infra::oidc::RuntimeAccessProvider<diport::FederatedAccessProfile>>,
    runtime_service_token: Option<crate::infra::oidc::RuntimeServiceTokenProvider>,
    domain_transport: DomainTransportRuntime,
    command_idempotency_keyring: Arc<eventexec::command::CommandIdempotencyKeyring>,
    metrics_exporter: Arc<dyn diport::MetricsExporter>,
    registry: bootstrap::Registry,
    provider_build: crate::provider_output::CompletedProviderBuild,
    placement_execution_plan: crate::plan::PlacementExecutionPlan,
}

#[must_use]
pub(crate) struct Finalized<'a> {
    context: PhaseContext<'a>,
    provider_build: crate::provider_output::CompletedProviderBuild,
    deps: crate::SharedRuntimeDeps,
    runtime_rss_access: Option<crate::infra::oidc::RuntimeAccessProvider<diport::RssAccessProfile>>,
    runtime_federated_access:
        Option<crate::infra::oidc::RuntimeAccessProvider<diport::FederatedAccessProfile>>,
    runtime_service_token: Option<crate::infra::oidc::RuntimeServiceTokenProvider>,
    domain_transport: DomainTransportRuntime,
    command_idempotency_keyring: Arc<eventexec::command::CommandIdempotencyKeyring>,
    listeners: crate::routes::FinalizedListenerSet,
    probe_receipt: crate::routes::FinalizedProbeReceipt,
    inventory_publisher: runtimeexec::inventory::InventoryPublisher,
}

impl sealed::Sealed for Planned<'_> {}
impl sealed::Sealed for ProvidersBuilt<'_> {}
impl sealed::Sealed for InfraBuilt<'_> {}
impl sealed::Sealed for DomainsWired<'_> {}
impl sealed::Sealed for Finalized<'_> {}

impl<'a> RuntimePhaseState for Planned<'a> {
    type Next = ProvidersBuilt<'a>;
    const PHASE: RuntimePhase = RuntimePhase::BuildProvider;
}

impl<'a> RuntimePhaseState for ProvidersBuilt<'a> {
    type Next = InfraBuilt<'a>;
    const PHASE: RuntimePhase = RuntimePhase::BuildInfra;
}

impl<'a> RuntimePhaseState for InfraBuilt<'a> {
    type Next = DomainsWired<'a>;
    const PHASE: RuntimePhase = RuntimePhase::WireDomains;
}

impl<'a> RuntimePhaseState for DomainsWired<'a> {
    type Next = Finalized<'a>;
    const PHASE: RuntimePhase = RuntimePhase::Finalize;
}

impl RuntimePhaseState for Finalized<'_> {
    type Next = runtimeexec::RuntimeOutputs;
    const PHASE: RuntimePhase = RuntimePhase::Launch;
}

/// Execute the only production serving phase sequence.
pub(crate) async fn execute(
    runtime_inputs: &mut ServingRuntimeInputs,
) -> anyhow::Result<runtimeexec::RuntimeOutputs> {
    let planned = Planned { runtime_inputs };
    let providers = planned.build_providers().await?;
    let infra = providers.build_infra().await?;
    let domains = infra.wire_domains().await?;
    let finalized = domains.finalize().await?;
    finalized.launch().await
}

/// Emit bounded phase logs and preserve the original result.
fn phase_result<T>(phase: RuntimePhase, result: anyhow::Result<T>) -> anyhow::Result<T> {
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

    static PHASE_LOG_TEST_LOCK: Mutex<()> = Mutex::new(());

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
        let snapshot = RuntimeConfigSnapshot::capture_test(MissingConfigSource)
            .expect("closed catalog capture succeeds");
        let blocklist = test_password_blocklist();
        let prepared = PreparedRuntimeInputs::new(snapshot, None);
        let mut serving = ServingRuntimeInputs::new(prepared, Arc::clone(&blocklist));
        assert!(serving.config().value("RSS_VAULT_TOKEN").is_none());
        assert!(Arc::ptr_eq(serving.password_blocklist(), &blocklist));
        assert!(serving.take_trace_export().is_none());

        let snapshot = crate::config::test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ])
        .expect("closed projection operator catalog capture succeeds");
        let mut operator = OperatorRuntimeInputs::new(PreparedRuntimeInputs::new(snapshot, None))
            .expect("bind operator workflow runtime");
        assert!(operator.config().value("RSS_VAULT_TOKEN").is_none());
        assert!(operator.prepared_mut().take_trace_export().is_none());

        let snapshot = crate::config::test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ])
        .expect("closed projection operator catalog capture succeeds");
        let mut projection =
            ProjectionOperatorRuntimeInputs::new(PreparedRuntimeInputs::new(snapshot, None))
                .expect("bind projection operator workflow runtime");
        assert!(
            projection
                .operator_inputs()
                .config()
                .value("RSS_VAULT_TOKEN")
                .is_none()
        );
        assert!(projection.prepared_mut().take_trace_export().is_none());
    }

    #[test]
    fn runtime_phase_config_anyhow_chain_and_phase_log_remain_opaque() {
        let _guard = PHASE_LOG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let snapshot = RuntimeConfigSnapshot::capture_test(BaitConfigSource)
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
        assert_eq!(
            events.len(),
            1,
            "phase failure must emit exactly one tracing event"
        );
        let phase_error = events[0].error.as_deref().unwrap_or_default();
        assert_eq!(chain, "RuntimeConfigSnapshot(<redacted>)");
        assert_eq!(phase_error, "RuntimeConfigSnapshot(<redacted>)");
        for fragment in ["dsn-password", "vault-token", "jwt-hmac", "PEM"] {
            assert!(!chain.contains(fragment));
            assert!(!phase_error.contains(fragment));
        }
    }

    #[test]
    fn runtime_phase_outputs_is_completion_marker() {
        static_assertions::assert_not_impl_any!(runtimeexec::RuntimeOutputs: Clone, Copy);
        static_assertions::assert_not_impl_any!(crate::routes::FinalizedProbeReceipt: Clone, Copy);
    }

    #[test]
    fn runtime_phase_result_passes_through_ok_and_error() {
        let ok = phase_result(RuntimePhase::BuildInfra, Ok::<_, anyhow::Error>(7))
            .expect("ok result must pass through");
        assert_eq!(ok, 7);

        let err = phase_result::<()>(RuntimePhase::BuildInfra, Err(anyhow::anyhow!("boom")))
            .expect_err("error must pass through");
        assert_eq!(err.to_string(), "boom");
    }

    #[test]
    fn runtime_phase_result_logs_error_from_question_mark_phase_body() {
        let _guard = PHASE_LOG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    fn runtime_phase_result_logs_only_closed_phase_labels() {
        let _guard = PHASE_LOG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let recorder = EventRecorder::default();
        let subscriber = tracing_subscriber::registry().with(recorder.clone());
        tracing::subscriber::with_default(subscriber, || {
            for phase in RuntimePhase::ALL {
                let _ = phase_result(phase, Ok::<_, anyhow::Error>(()));
            }
        });

        let events = recorder.events();
        assert_eq!(events.len(), RuntimePhase::ALL.len());
        assert_eq!(
            events
                .iter()
                .map(|event| event.runtime_phase.as_deref().unwrap_or_default())
                .collect::<Vec<_>>(),
            RuntimePhase::ALL
                .iter()
                .copied()
                .map(RuntimePhase::as_str)
                .collect::<Vec<_>>()
        );
        assert!(
            events
                .iter()
                .all(|event| event.runtime_phase.as_deref().is_some_and(|phase| {
                    RuntimePhase::ALL
                        .iter()
                        .copied()
                        .map(RuntimePhase::as_str)
                        .any(|closed_phase| closed_phase == phase)
                }) && event.message.is_some()
                    && event.error.is_none()),
            "phase logs must only record closed phase labels"
        );
    }

    #[test]
    fn runtime_phase_result_redacts_error_field() {
        let _guard = PHASE_LOG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let recorder = EventRecorder::default();
        let subscriber = tracing_subscriber::registry().with(recorder.clone());
        tracing::subscriber::with_default(subscriber, || {
            for phase in RuntimePhase::ALL {
                let _ = phase_result::<()>(
                    phase,
                    Err(anyhow::anyhow!(
                        "connect postgres://svc:s3cr3t@db.internal:5432/app refused"
                    )),
                );
            }
        });

        let events = recorder.events();
        assert_eq!(events.len(), RuntimePhase::ALL.len());
        for (event, phase) in events.iter().zip(RuntimePhase::ALL) {
            assert_eq!(event.runtime_phase.as_deref(), Some(phase.as_str()));
            let error = event.error.as_deref().expect("error field must be logged");
            assert!(
                !error.contains("s3cr3t"),
                "error field must be redacted: {error}"
            );
            assert!(
                error.contains("postgres://<redacted>@db.internal:5432/app"),
                "error field must retain redacted diagnostic shape: {error}"
            );
        }
    }

    #[test]
    fn runtime_phase_transition_types_are_exact_and_non_copyable() {
        use static_assertions::{assert_not_impl_any, assert_type_eq_all, assert_type_ne_all};

        trait TypeEq<T: ?Sized> {}
        impl<T: ?Sized> TypeEq<T> for T {}
        fn assert_type_eq<T, U>()
        where
            T: ?Sized + TypeEq<U>,
            U: ?Sized,
        {
        }
        fn assert_lifetime_bound_chain<'a>(_: &'a ()) {
            assert_type_eq::<<Planned<'a> as RuntimePhaseState>::Next, ProvidersBuilt<'a>>();
            assert_type_eq::<<ProvidersBuilt<'a> as RuntimePhaseState>::Next, InfraBuilt<'a>>();
            assert_type_eq::<<InfraBuilt<'a> as RuntimePhaseState>::Next, DomainsWired<'a>>();
            assert_type_eq::<<DomainsWired<'a> as RuntimePhaseState>::Next, Finalized<'a>>();
            assert_type_eq::<<Finalized<'a> as RuntimePhaseState>::Next, runtimeexec::RuntimeOutputs>(
            );
        }
        assert_lifetime_bound_chain(&());

        assert_type_eq_all!(
            <Planned<'static> as RuntimePhaseState>::Next,
            ProvidersBuilt<'static>
        );
        assert_type_eq_all!(
            <ProvidersBuilt<'static> as RuntimePhaseState>::Next,
            InfraBuilt<'static>
        );
        assert_type_eq_all!(
            <InfraBuilt<'static> as RuntimePhaseState>::Next,
            DomainsWired<'static>
        );
        assert_type_eq_all!(
            <DomainsWired<'static> as RuntimePhaseState>::Next,
            Finalized<'static>
        );
        assert_type_eq_all!(
            <Finalized<'static> as RuntimePhaseState>::Next,
            runtimeexec::RuntimeOutputs
        );

        assert_type_ne_all!(
            Planned<'static>,
            ProvidersBuilt<'static>,
            InfraBuilt<'static>,
            DomainsWired<'static>,
            Finalized<'static>,
            runtimeexec::RuntimeOutputs
        );

        assert_not_impl_any!(Planned<'static>: Clone, Copy, std::fmt::Debug, Default);
        assert_not_impl_any!(crate::plan::DomainExecutionPlan: Clone, Copy, std::fmt::Debug, Default);
        assert_not_impl_any!(DomainPhaseContext<'static>: Clone, Copy, std::fmt::Debug, Default);
        assert_not_impl_any!(ProvidersBuilt<'static>: Clone, Copy, std::fmt::Debug, Default);
        assert_not_impl_any!(InfraBuilt<'static>: Clone, Copy, std::fmt::Debug, Default);
        assert_not_impl_any!(DomainsWired<'static>: Clone, Copy, std::fmt::Debug, Default);
        assert_not_impl_any!(Finalized<'static>: Clone, Copy, std::fmt::Debug, Default);
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
