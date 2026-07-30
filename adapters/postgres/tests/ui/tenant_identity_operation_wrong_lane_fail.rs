use postgres::tx_boundary_proof::{IdentityTx, MaintenanceWriteLane, serving_identity_write};

fn cross_lane(mut tx: IdentityTx<'_, '_, MaintenanceWriteLane>) {
    let _ = serving_identity_write(&mut tx);
}

fn main() {}
