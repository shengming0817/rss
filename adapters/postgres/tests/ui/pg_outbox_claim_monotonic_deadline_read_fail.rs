//! INVARIANT: PG-OUTBOX-CLAIM-SEAL-01 · PG-OUTBOX-SETTLEMENT-CAPABILITY-01 { level = "Hard", exec = "test", source = "trybuild" }

type Claim = <postgres::PgOutbox as consistency::OutboxRelay>::Claim;

fn read_monotonic_deadline(claim: &Claim) {
    let _ = claim.lease.monotonic_deadline;
}

fn main() {}
