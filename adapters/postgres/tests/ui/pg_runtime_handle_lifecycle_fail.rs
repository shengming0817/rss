use postgres::PgRuntimeHandle;

fn consume_lifecycle(handle: PgRuntimeHandle) {
    let _ = handle.into_runtime_parts(postgres::PgRuntimeMonitorConfig::new(
        postgres::PgReadinessInterval::default(),
        postgres::PgRlsAttestationInterval::default(),
    ));
}

fn main() {}
