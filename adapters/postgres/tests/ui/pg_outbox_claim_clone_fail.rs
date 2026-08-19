//! INVARIANT: PG-OUTBOX-CLAIM-SEAL-01 { level = "Medium", exec = "test", source = "trybuild" }

type Claim = <postgres::PgOutbox as consistency::OutboxRelay>::Claim;

fn requires_clone<T: Clone>() {}

fn main() {
    requires_clone::<Claim>();
}
