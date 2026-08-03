use postgres::PgDeviceLatentOperatorDeps;

fn cannot_escape_to_general_maintenance(owner: &PgDeviceLatentOperatorDeps) {
    let _store = owner.reconcile_store();
}

fn main() {}
