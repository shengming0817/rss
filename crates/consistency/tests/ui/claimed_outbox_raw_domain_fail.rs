use consistency::{EngineError, OutboxRelay};

async fn claim_from_raw_domain<S: OutboxRelay>(source: &S) -> Result<(), EngineError> {
    let _ = source.claim_batch("identity", 10).await?;
    Ok(())
}

fn main() {}
