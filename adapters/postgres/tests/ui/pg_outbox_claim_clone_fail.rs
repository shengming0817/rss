//! INVARIANT: PG-OUTBOX-CLAIM-SEAL-01 { level = "Hard", exec = "verify", source = "trybuild" }

type Claim = <postgres::PgOutbox as consistency::OutboxSource>::Claim;

fn requires_clone<T: Clone>() {}

fn main() {
    requires_clone::<Claim>();
}
