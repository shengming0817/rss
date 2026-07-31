use postgres::{DlxPayloadProtector, PgProjectionOperatorDeps};

fn cannot_get_replay_stores_without_capability(
    deps: &PgProjectionOperatorDeps,
    protector: DlxPayloadProtector,
) {
    let _ = deps.projection_replay_stores(protector);
}

fn main() {}
