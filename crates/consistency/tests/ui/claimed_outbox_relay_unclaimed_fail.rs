use consistency::{EngineError, OutboxRelay, StoredOutboxEntry};

async fn relay_unclaimed<R: OutboxRelay>(
    relay: &R,
    entry: StoredOutboxEntry,
) -> Result<(), EngineError> {
    let _ = relay.relay(entry).await?;
    Ok(())
}

fn main() {}
