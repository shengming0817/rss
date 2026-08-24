use postgres::PgMaintenanceDeps;

fn cannot_borrow_all_infra(deps: &PgMaintenanceDeps) {
    let _ = deps.infra();
}

fn main() {}
