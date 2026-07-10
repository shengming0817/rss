use postgres::{DlxPayloadProtector, PgMaintenanceDeps};

fn cannot_get_replay_stores_without_capability(
    deps: &PgMaintenanceDeps,
    protector: DlxPayloadProtector,
) {
    let _ = deps.projection_replay_stores(protector);
}

fn main() {}
