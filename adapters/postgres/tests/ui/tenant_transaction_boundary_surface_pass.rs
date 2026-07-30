use postgres::tx_boundary_proof::{
    IdentityTx, MaintenanceWriteLane, OutboxTx, ReconcileTx, ServingReadLane, ServingWriteLane,
    TenantDb, TenantTx, outbox_operation, reconcile_operation, require_identity_operation,
    require_identity_write, require_maintenance_write_tx, require_serving_write_tx,
    serving_identity_write,
};

fn exact_lane_surfaces_are_reachable(
    _read_db: &TenantDb<ServingReadLane>,
    read_tx: &mut TenantTx<'_, ServingReadLane>,
    write_tx: &mut TenantTx<'_, ServingWriteLane>,
    maintenance_tx: &mut TenantTx<'_, MaintenanceWriteLane>,
    mut identity_tx: IdentityTx<'_, '_, ServingWriteLane>,
    outbox_tx: &mut OutboxTx<'_>,
    reconcile_tx: &mut ReconcileTx<'_, ServingWriteLane>,
) {
    let _ = read_tx.tenant();
    let _ = write_tx.tenant();
    let _ = maintenance_tx.tenant();
    require_serving_write_tx(write_tx);
    let mut identity = serving_identity_write(&mut identity_tx);
    require_identity_write(&mut identity);
    outbox_operation(outbox_tx);
    reconcile_operation(reconcile_tx);
    require_maintenance_write_tx(maintenance_tx);
    require_identity_operation(|_tx| Box::pin(async move { Ok(()) }));
}

fn main() {}
