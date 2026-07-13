use consistency::{EngineError, OutboxRelay};

async fn relay_twice<R: OutboxRelay>(
    relay: &R,
    claim: R::Claim,
) -> Result<(), EngineError> {
    let _ = relay.relay(claim).await?;
    let _ = relay.relay(claim).await?;
    Ok(())
}

fn main() {}
