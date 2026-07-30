use postgres::tx_boundary_proof::require_serving_write_tx;

fn substitute(conn: &mut sqlx::PgConnection) {
    require_serving_write_tx(conn);
}

fn main() {}
