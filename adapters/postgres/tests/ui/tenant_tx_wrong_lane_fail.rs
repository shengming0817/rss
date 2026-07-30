use postgres::tx_boundary_proof::{
    MaintenanceWriteLane, TenantTx, require_serving_write_tx,
};

fn cross_lane(tx: &mut TenantTx<'_, MaintenanceWriteLane>) {
    require_serving_write_tx(tx);
}

fn main() {}
