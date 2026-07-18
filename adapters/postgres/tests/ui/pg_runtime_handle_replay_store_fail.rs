use postgres::PgRuntimeHandle;

fn replay_writer_is_not_shared(handle: &PgRuntimeHandle) {
    let _ = handle.service_token_replay_store();
}

fn main() {}
