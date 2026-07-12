use postgres::{DlxPayloadProtector, PgMaintenanceDeps, PgRuntimeDeps, PgRuntimeHandle};
use std::time::Duration;

fn runtime_capabilities_are_available(handle: &PgRuntimeHandle) {
    let _: PgRuntimeHandle = handle.clone();
    let _ = handle.infra();
    let _ = handle.readiness_handle();
    let _ = handle.rls_ready_handle();
}

fn runtime_owner_has_one_lifecycle_exit(deps: PgRuntimeDeps) {
    let handle = deps.handle();
    runtime_capabilities_are_available(&handle);
    let (_resources, factory) = deps.into_runtime_parts(Duration::from_secs(1));
    let _ = factory.spawn(tokio_util::sync::CancellationToken::new());
}

fn maintenance_is_purpose_specific(
    deps: &PgMaintenanceDeps,
    protector: DlxPayloadProtector,
    receipt: &authn::ProjectionMaintenanceReceipt,
    selector: &eventexec::ProjectionSelector,
) {
    let stores = deps
        .projection_replay_stores(receipt, selector, protector)
        .expect("target-bound receipt");
    let _ = stores.into_parts().expect("receipt remains target-bound");
    let _ = deps.dlq_store_without_payload_replay();
}

fn main() {}
