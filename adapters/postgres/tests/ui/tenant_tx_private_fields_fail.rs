use postgres::tx_boundary_proof::{ServingWriteLane, TenantTx};

fn forge<'a>(conn: &'a mut sqlx::PgConnection, tenant: vocab::TenantId) {
    let _ = TenantTx::<ServingWriteLane> {
        conn,
        tenant,
        _lane: std::marker::PhantomData,
    };
}

fn main() {}
