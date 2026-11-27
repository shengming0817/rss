use crate::support::*;
use rss_identity_core::account::AccountKey;
use rss_request_context::TenantId;

pub async fn roles(f: &Fixture) -> anyhow::Result<()> {
    let other = AccountKey {
        tenant: TenantId::parse(B)?,
        principal: f.key.principal,
    };
    f.maintenance
        .initialize(
            binding(other.tenant),
            other,
            login("admin"),
            password(),
            deadline(),
        )
        .await?;
    let mut tx = f.owner.begin().await?;
    fence(&mut tx, binding(f.key.tenant)).await?;
    sqlx::query("SET LOCAL ROLE identity_maintenance")
        .execute(&mut *tx)
        .await?;
    let visible: Vec<String> =
        sqlx::query_scalar("SELECT tenant_id::text FROM identity_authority.accounts")
            .fetch_all(&mut *tx)
            .await?;
    assert_eq!(visible, [A]);
    let forbidden = sqlx::query("UPDATE identity_authority.accounts SET enabled=false")
        .execute(&mut *tx)
        .await;
    assert_eq!(
        forbidden
            .unwrap_err()
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref(),
        Some("42501")
    );
    tx.rollback().await?;
    Ok(())
}
