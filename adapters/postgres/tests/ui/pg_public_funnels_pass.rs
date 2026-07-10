use postgres::{DlxPayloadProtector, PgMaintenanceDeps, PgRuntimeDeps};

fn runtime_infra_is_available(deps: &PgRuntimeDeps) {
    let _ = deps.infra();
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
