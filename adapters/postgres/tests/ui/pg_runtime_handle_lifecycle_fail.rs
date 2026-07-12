use postgres::PgRuntimeHandle;
use std::time::Duration;

fn consume_lifecycle(handle: PgRuntimeHandle) {
    let _ = handle.into_runtime_parts(Duration::from_secs(1));
}

fn main() {}
