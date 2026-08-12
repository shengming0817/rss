use postgres::PgRlsReadiness;
use std::sync::atomic::AtomicBool;

fn external_code_cannot_forge_or_mutate() {
    let _readiness = PgRlsReadiness(AtomicBool::new(true));
}

fn external_code_cannot_mutate(readiness: &PgRlsReadiness) {
    readiness.mark(false);
}

fn main() {}
