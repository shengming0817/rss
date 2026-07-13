use consistency::OutboxSource;

fn clone_claim<S: OutboxSource>(claim: S::Claim) -> S::Claim {
    claim.clone()
}

fn main() {}
