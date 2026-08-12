use postgres::{PgReadinessInterval, PgRlsAttestationInterval, PgRuntimeDeps, PgRuntimeMonitorConfig};

fn owner_has_one_lifecycle_exit(owner: PgRuntimeDeps) {
    let config = PgRuntimeMonitorConfig::new(
        PgReadinessInterval::default(),
        PgRlsAttestationInterval::default(),
    );
    let _first = owner.into_runtime_parts(config);
    let _second = owner.into_runtime_parts(config);
}

fn main() {}
