use postgres::tx_boundary_proof::{IdentityWrite, ServingWriteLane, TenantTx};

fn forge<'borrow, 'tx>(tx: &'borrow mut TenantTx<'tx, ServingWriteLane>) {
    let _ = IdentityWrite { tx };
}

fn main() {}
