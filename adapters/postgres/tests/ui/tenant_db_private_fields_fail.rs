use postgres::tx_boundary_proof::{ServingReadLane, TenantDb};

fn forge(pool: sqlx::PgPool) {
    let _ = TenantDb::<ServingReadLane> {
        pool,
        lane: ServingReadLane,
    };
}

fn main() {}
