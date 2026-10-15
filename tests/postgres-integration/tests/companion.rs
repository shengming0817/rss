//! Additional execution fences remain owned by the outer transaction.
use super::{deadline, message};
use rss_request_context::TenantId;
use rss_transactional_messaging::error::MessagingErrorKind;
use rss_transactional_messaging_postgres::PgRuntime;
use std::sync::Arc;

pub(super) async fn run(runtime: Arc<PgRuntime>, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    let target = message("companion").metadata().tenant_id();
    let source = TenantId::parse("00000000-0000-0000-0000-000000000073")?;
    let owner_copy = owner.clone();
    runtime.local_tx(target, deadline(), move |tx| Box::pin(async move {
        let scope: (String, String) = tx.with_tenant_connection(source, |c| Box::pin(async move {
            sqlx::query_as("SELECT current_setting('rss.tenant_id'),current_setting('rss.execution_epoch')")
                .fetch_one(c).await
        })).await?;
        assert_eq!(scope, (source.to_string(), "1".into()));
        assert_eq!(tx.tenant_id(), target);
        let restored: String = tx.with_connection(|c| Box::pin(async move {
            sqlx::query_scalar("SELECT current_setting('rss.tenant_id')").fetch_one(c).await
        })).await?;
        assert_eq!(restored, target.to_string());
        // Independent owner cannot advance the source epoch before the host settles.
        let mut contender = owner_copy.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='100ms'").execute(&mut *contender).await?;
        let blocked = sqlx::query("UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid")
            .bind(source.to_string()).execute(&mut *contender).await;
        assert_eq!(blocked.expect_err("companion fence held").as_database_error().and_then(|e| e.code()).as_deref(), Some("55P03"));
        contender.rollback().await?;
        Ok(())
    })).await.fold(Ok, Err, Err, Err, Err, Err)?;
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid",
    )
    .bind(source.to_string())
    .execute(owner)
    .await?;
    let stale = runtime
        .local_tx(target, deadline(), move |tx| {
            Box::pin(async move {
                tx.with_tenant_connection(source, |_| {
                    Box::pin(async move {
                        panic!("stale companion must not run its callback");
                        #[allow(unreachable_code)]
                        Ok(())
                    })
                })
                .await
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err);
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=1 WHERE tenant_id=$1::uuid",
    )
    .bind(source.to_string())
    .execute(owner)
    .await?;
    assert_eq!(
        stale.expect_err("source epoch changed").kind(),
        MessagingErrorKind::OwnershipLost
    );
    let missing = TenantId::parse("99999999-9999-9999-9999-999999999999")?;
    let rejected = runtime
        .local_tx(target, deadline(), move |tx| {
            Box::pin(async move {
                tx.with_tenant_connection(missing, |_| Box::pin(async move { Ok(()) }))
                    .await
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err);
    assert_eq!(
        rejected.expect_err("unbound companion").kind(),
        MessagingErrorKind::OwnershipLost
    );
    Ok(())
}
