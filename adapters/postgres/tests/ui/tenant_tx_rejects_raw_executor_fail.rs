use postgres::tx_boundary_proof::{ServingWriteLane, TenantTx};

fn arbitrary_sql(tx: &mut TenantTx<'_, ServingWriteLane>) {
    let _ = tx.executor();
}

fn main() {}
