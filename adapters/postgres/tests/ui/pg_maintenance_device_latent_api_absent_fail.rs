use postgres::PgMaintenanceDeps;

fn no_legacy_device_latent_path(owner: &PgMaintenanceDeps) {
    let _future = owner.record_device_latent_inspection_start_audit();
}

fn main() {}
