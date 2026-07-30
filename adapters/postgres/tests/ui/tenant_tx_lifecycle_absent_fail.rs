use postgres::tx_boundary_proof::{ServingWriteLane, TenantTx};

fn settle(tx: TenantTx<'_, ServingWriteLane>) {
    let _ = tx.commit();
}

fn main() {}
