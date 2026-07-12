use postgres::PgRuntimeDeps;

fn old_capability_and_lifecycle_paths(owner: &PgRuntimeDeps) {
    let _ = owner.infra();
    let _ = owner.store_guard();
}

fn main() {}
