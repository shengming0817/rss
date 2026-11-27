use crate::support::*;
use rss_identity_core::account::AccountKey;
use rss_request_context::TenantId;

#[allow(clippy::unwrap_used, reason = "test fixture")]
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
    sqlx::query("SET LOCAL search_path=identity_authority,pg_catalog")
        .execute(&mut *tx)
        .await?;
    assert_eq!(
        rss_identity_postgres::schema_signature(&mut tx)
            .await?
            .as_deref(),
        Some(rss_identity_postgres::SCHEMA_SIGNATURE.trim())
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SHOW search_path")
            .fetch_one(&mut *tx)
            .await?,
        "identity_authority, pg_catalog"
    );
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

pub async fn check_delegation(f: &Fixture) -> anyhow::Result<()> {
    // Check a non-inherited catalog grant using a disposable NOLOGIN role.
    let mut tx = f.owner.begin().await?;
    sqlx::raw_sql("CREATE ROLE identity_probe_test NOLOGIN; GRANT SELECT ON identity_authority.schema_version TO identity_probe_test WITH GRANT OPTION; GRANT identity_probe_test TO identity_maintenance WITH INHERIT FALSE, SET TRUE; SET LOCAL ROLE identity_maintenance")
        .execute(&mut *tx).await?;
    assert!(matches!(
        rss_identity_postgres::verify_profile(
            &mut tx,
            rss_identity_postgres::AuthorityProfile::Maintenance,
            f.instance
        )
        .await,
        Err(rss_identity_postgres::AuthorityError::StorageIncompatible(
            rss_identity_postgres::StorageMismatch::Privileges
        ))
    ));
    tx.rollback().await?;
    Ok(())
}

/// The schema attestation deliberately excludes ownership and ACLs. Exercise both
/// independently of the structural signature and of the consumer role grants.
pub async fn capacity_definer(f: &Fixture) -> anyhow::Result<()> {
    use rss_identity_postgres::{
        AuthorityError, AuthorityProfile, StorageMismatch, verify_profile,
    };
    let mut tx = f.owner.begin().await?;
    sqlx::raw_sql(
        "CREATE ROLE capacity_probe_owner NOLOGIN;
        ALTER FUNCTION identity_authority.account_capacity_delta() OWNER TO capacity_probe_owner;
        SET LOCAL ROLE identity_runtime",
    )
    .execute(&mut *tx)
    .await?;
    assert!(matches!(
        verify_profile(&mut tx, AuthorityProfile::Runtime, f.instance).await,
        Err(AuthorityError::StorageIncompatible(
            StorageMismatch::Privileges
        ))
    ));
    sqlx::raw_sql("RESET ROLE;
        ALTER SCHEMA identity_authority OWNER TO capacity_probe_owner;
        ALTER FUNCTION identity_authority.share_host_tenant() OWNER TO capacity_probe_owner;
        ALTER FUNCTION identity_authority.share_subject(uuid) OWNER TO capacity_probe_owner;
        ALTER FUNCTION identity_authority.share_provider(uuid) OWNER TO capacity_probe_owner;
        ALTER FUNCTION identity_authority.lock_session(bytea,uuid,text,text,uuid) OWNER TO capacity_probe_owner;
        GRANT SELECT,UPDATE ON identity_authority.tenants,identity_authority.accounts,identity_authority.memberships,identity_authority.providers TO capacity_probe_owner;
        GRANT SELECT(tenant_id,kind,occupied),UPDATE(occupied) ON identity_authority.tenant_state TO capacity_probe_owner;
        SET LOCAL ROLE identity_runtime").execute(&mut *tx).await?;
    verify_profile(&mut tx, AuthorityProfile::Runtime, f.instance).await?;
    sqlx::raw_sql("RESET ROLE; REVOKE UPDATE(occupied) ON identity_authority.tenant_state FROM capacity_probe_owner; SET LOCAL ROLE identity_runtime").execute(&mut *tx).await?;
    assert!(matches!(
        verify_profile(&mut tx, AuthorityProfile::Runtime, f.instance).await,
        Err(AuthorityError::StorageIncompatible(
            StorageMismatch::Privileges
        ))
    ));
    tx.rollback().await?;
    Ok(())
}
