use consistency::{EngineError, OutboxSource};

async fn claim_from_raw_domain<S: OutboxSource>(source: &S) -> Result<(), EngineError> {
    let _ = source.claim_batch("identity", 10).await?;
    Ok(())
}

fn main() {}
