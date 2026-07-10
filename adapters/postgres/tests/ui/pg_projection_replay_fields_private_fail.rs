use postgres::PgProjectionReplayStores;

fn cannot_extract_one_store(stores: PgProjectionReplayStores) {
    let _ = stores.events;
}

fn main() {}
