use postgres::{PgReadinessInterval, PgRlsAttestationInterval, PgRuntimeMonitorConfig};

fn intervals_are_not_interchangeable(
    readiness: PgReadinessInterval,
    rls: PgRlsAttestationInterval,
) {
    let _ = PgRuntimeMonitorConfig::new(rls, readiness);
}

fn main() {}
