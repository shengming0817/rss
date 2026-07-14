//! INVARIANT: PG-OUTBOX-CLAIM-SEAL-01 { level = "Hard", exec = "verify", source = "trybuild" }

type Claim = <postgres::PgOutbox as consistency::OutboxRelay>::Claim;

fn construct() -> Claim {
    Claim::new()
}

fn main() {}
