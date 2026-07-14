use consistency::OutboxRelay;

fn clone_claim<S: OutboxRelay>(claim: S::Claim) -> S::Claim {
    claim.clone()
}

fn main() {}
