use futures::future::BoxFuture;
use rss_transactional_messaging_postgres::PgTransaction;

fn borrowed_query<'a>(
    transaction: &'a mut PgTransaction<'_>,
) -> BoxFuture<'a, Result<(), rss_transactional_messaging_postgres::PgError>> {
    Box::pin(async move {
        transaction
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query("SELECT 1").execute(connection).await?;
                    Ok(())
                })
            })
            .await
    })
}

#[test]
fn trusted_extension_borrows_connection_without_owning_it() {
    let _ = borrowed_query;
}

#[test]
fn lease_policy_retains_authoritative_ttl() -> Result<(), Box<dyn std::error::Error>> {
    use rss_transactional_messaging::policy::LeaseRenewalPolicy;
    let ttl = std::time::Duration::from_secs(60);
    let policy = LeaseRenewalPolicy::from_ttl(ttl)?;
    assert_eq!(policy.ttl(), ttl);
    Ok(())
}
