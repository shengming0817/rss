use postgres::PgRuntimeDeps;
use std::time::Duration;

fn owner_has_one_lifecycle_exit(owner: PgRuntimeDeps) {
    let _first = owner.into_runtime_parts(Duration::from_secs(1));
    let _second = owner.into_runtime_parts(Duration::from_secs(1));
}

fn main() {}
