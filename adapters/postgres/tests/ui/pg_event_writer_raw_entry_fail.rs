use consistency::EventEntry;
use eventexec::event::ReviewedEventWriter as _;
use postgres::{PgEmitter, PgOutboxCdcEmitter};

async fn relay_writer(writer: &PgEmitter, entry: EventEntry) {
    writer.write(entry).await.unwrap();
}

async fn cdc_writer(writer: &PgOutboxCdcEmitter, entry: EventEntry) {
    writer.write(entry).await.unwrap();
}

fn main() {}
