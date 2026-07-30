//! INVARIANT: PG-TX-CONCERN-CAPABILITY-01 { level = "Hard", exec = "test", source = "trybuild" }

use postgres::tx_boundary_proof::{OutboxTx, reconcile_operation};

fn cross_concern(tx: &mut OutboxTx<'_>) {
    reconcile_operation(tx);
}

fn main() {}
