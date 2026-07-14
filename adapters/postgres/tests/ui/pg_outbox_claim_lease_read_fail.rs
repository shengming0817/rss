//! INVARIANT: PG-OUTBOX-CLAIM-SEAL-01 { level = "Hard", exec = "verify", source = "trybuild" }

type Claim = <postgres::PgOutbox as consistency::OutboxRelay>::Claim;

fn read_lease(claim: &Claim) {
    let _ = claim.lease_token();
}

fn main() {}
