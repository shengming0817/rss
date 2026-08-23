//! INVARIANT: PG-TX-CONCERN-CAPABILITY-01 { level = "Medium", exec = "integration-critical", source = "trybuild" }

use postgres::tx_boundary_proof::{
    IdentityTx, ServingWriteLane, outbox_operation,
};

fn cross_concern(mut tx: IdentityTx<'_, '_, ServingWriteLane>) {
    outbox_operation(&mut tx);
}

fn main() {}
