use rss_transactional_messaging_postgres::{PgError, PgTransaction};

async fn escape(tx: &mut PgTransaction<'_>) -> Result<&'static mut sqlx::PgConnection, PgError> {
    tx.with_connection(|connection| Box::pin(async move { Ok(connection) })).await
}

fn main() {}
