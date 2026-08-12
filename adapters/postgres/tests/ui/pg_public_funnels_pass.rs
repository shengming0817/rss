use postgres::{
    DlxPayloadProtector, PgConfig, PgProjectionOperatorConfig, PgProjectionOperatorDeps,
    PgProjectionSourceReadConfig, PgReadinessInterval, PgRlsAttestationInterval, PgRuntimeDeps,
    PgRuntimeHandle, PgRuntimeMonitorConfig, PgTenantReadConfig,
};
use std::sync::Arc;
use std::time::Duration;

fn runtime_capabilities_are_available(handle: &PgRuntimeHandle) {
    let _: PgRuntimeHandle = handle.clone();
    let _ = handle.infra();
    let _ = handle.readiness_handle();
    let _ = handle.rls_readiness();
}

fn runtime_owner_has_one_lifecycle_exit(deps: PgRuntimeDeps) {
    let handle = deps.handle();
    runtime_capabilities_are_available(&handle);
    let config = PgRuntimeMonitorConfig::new(
        PgReadinessInterval::try_new(Duration::from_secs(1)).expect("interval"),
        PgRlsAttestationInterval::default(),
    );
    let (_resources, factory) = deps.into_runtime_parts(config);
    let _ = factory.spawn(tokio_util::sync::CancellationToken::new());
}

fn tenant_reader_config_is_an_explicit_public_type(config: PgConfig) -> PgTenantReadConfig {
    PgTenantReadConfig::new(config)
}

fn projection_operator_is_purpose_specific(
    deps: &PgProjectionOperatorDeps,
    scope: eventexec::ProjectionSourceScope,
    target: Arc<dyn eventexec::ProjectionTarget>,
    protector: DlxPayloadProtector,
    receipt: authn::ProjectionMaintenanceReceipt,
    selector: &eventexec::ProjectionSelector,
    execution: eventexec::ProjectionExecutionContext,
) {
    let capability = deps
        .authorize_projection_target(receipt, postgres::ProjectionReplayAction, selector, scope)
        .expect("target-bound receipt");
    let _ = capability.into_replay_stores(execution, target, protector);
}

async fn projection_operator_clock_is_explicit(
    operator: &PgProjectionOperatorConfig,
    source: &PgProjectionSourceReadConfig,
    clock: Arc<dyn diport::Clock>,
) {
    let _ = PgProjectionOperatorDeps::connect(operator, source, clock).await;
}

fn main() {}
