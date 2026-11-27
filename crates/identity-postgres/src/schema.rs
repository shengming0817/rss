//! Identity owns its schema; host deployment owns database roles, RSS migrations and tenant fences.
use crate::{AuthorityError, AuthorityProfile};
use rss_identity_core::InstanceId;
use rss_transactional_messaging_postgres::PgError;
use sqlx::PgConnection;
pub const SCHEMA_VERSION: i32 = 24;
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_authority.sql");
pub const SCHEMA_SIGNATURE_SQL: &str = include_str!("schema-signature.sql");
pub const SCHEMA_SIGNATURE: &str = include_str!("schema-signature.sha256");
/// Run inside the host's migration transaction on an empty identity schema.
pub async fn install(
    connection: &mut PgConnection,
    instance: InstanceId,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(MIGRATION_SQL)
        .execute(&mut *connection)
        .await?;
    use ring::rand::SecureRandom;
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    ring::rand::SystemRandom::new()
        .fill(key.as_mut())
        .map_err(|_| sqlx::Error::Protocol("cursor key generation failed".into()))?;
    sqlx::query(
        "INSERT INTO identity_authority.deployment(authority_id,account_cursor_key) VALUES($1,$2)",
    )
    .bind(instance.as_uuid())
    .bind(key.as_slice())
    .execute(connection)
    .await?;
    Ok(())
}
/// Grant to a host-chosen role. Does not create users, pools, secrets, epochs or memberships.
pub async fn grant_profile(
    connection: &mut PgConnection,
    role: &str,
    profile: AuthorityProfile,
) -> Result<(), sqlx::Error> {
    if role.is_empty() || role.len() > 63 || role.contains('\0') {
        return Err(sqlx::Error::Protocol("invalid role identifier".into()));
    }
    let role = format!("\"{}\"", role.replace('"', "\"\""));
    let sql = match profile {
        AuthorityProfile::Runtime => include_str!("grants-runtime.sql"),
        AuthorityProfile::Maintenance => include_str!("grants-maintenance.sql"),
        AuthorityProfile::Provisioning => include_str!("grants-provisioning.sql"),
    };
    // Only substitution is a quoted identifier; embedded quotes are doubled above.
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql.replace("{role}", &role)))
        .execute(connection)
        .await?;
    Ok(())
}
/// Verify the current SQL role against the same storage contract used by authority startup.
/// The host owns the connection, transaction and role selection; this does not commit anything.
pub async fn verify_profile(
    connection: &mut PgConnection,
    profile: AuthorityProfile,
    instance: InstanceId,
) -> Result<(), AuthorityError> {
    crate::check_probe(
        probe(connection, profile, instance)
            .await
            .map_err(|_| AuthorityError::Unavailable),
    )
}

// These lock ports must remain callable only by the roles explicitly granted each port.
// A SET-reachable role with delegation rights could otherwise bypass the embedded role profile.
async fn lock_grants_are_private(c: &mut PgConnection) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(include_str!("lock-function-privileges.sql"))
        .fetch_one(c)
        .await
}

pub(crate) async fn probe(
    connection: &mut PgConnection,
    profile: AuthorityProfile,
    instance: InstanceId,
) -> Result<Option<String>, PgError> {
    let schema_exists: bool =
        sqlx::query_scalar("SELECT to_regnamespace('identity_authority') IS NOT NULL")
            .fetch_one(&mut *connection)
            .await?;
    if !schema_exists {
        return Ok(Some("schema-contract".into()));
    }
    let usage: bool = sqlx::query_scalar(
        "SELECT has_schema_privilege(current_user,'identity_authority','USAGE')",
    )
    .fetch_one(&mut *connection)
    .await?;
    if !usage {
        return Ok(Some("privileges".into()));
    }
    for table in [
        "identity_authority.schema_version",
        "identity_authority.deployment",
    ] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(&mut *connection)
            .await?;
        if !exists {
            return Ok(Some("schema-contract".into()));
        }
        let readable: bool =
            sqlx::query_scalar("SELECT has_table_privilege(current_user,$1,'SELECT')")
                .bind(table)
                .fetch_one(&mut *connection)
                .await?;
        if !readable {
            return Ok(Some("privileges".into()));
        }
    }
    if crate::storage::authority_id(connection).await? != instance.as_uuid() {
        return Ok(Some("deployment-identity".into()));
    }
    let versions: Vec<i32> =
        sqlx::query_scalar("SELECT version FROM identity_authority.schema_version")
            .fetch_all(&mut *connection)
            .await?;
    if versions != [SCHEMA_VERSION] {
        return Ok(Some("schema-version".into()));
    }
    let signature: Option<String> = sqlx::query_scalar(SCHEMA_SIGNATURE_SQL)
        .fetch_one(&mut *connection)
        .await?;
    if signature.as_deref() != Some(SCHEMA_SIGNATURE.trim()) {
        return Ok(Some("schema-contract".into()));
    }
    let result: String = sqlx::query_scalar(include_str!("probe.sql"))
        .bind(match profile {
            AuthorityProfile::Runtime => "runtime",
            AuthorityProfile::Maintenance => "maintenance",
            AuthorityProfile::Provisioning => "provisioning",
        })
        .fetch_one(&mut *connection)
        .await?;
    if !lock_grants_are_private(connection).await? {
        return Ok(Some("privileges".into()));
    }
    if result != "ok" {
        return Ok(Some(result));
    }
    let safe: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM pg_roles r WHERE pg_has_role(current_user,r.oid,'SET') AND has_table_privilege(r.oid,'rss_audit.records','MAINTAIN'))")
        .fetch_one(&mut *connection).await?;
    if !safe {
        return Ok(Some("privileges".into()));
    }
    Ok(Some("ok".into()))
}

/// Narrow metadata admission grants for a host business transaction role. In particular this
/// does not grant password, provider credential, session or profile-observation access.
pub async fn grant_profile_source_admission(
    c: &mut PgConnection,
    role: &str,
) -> Result<(), sqlx::Error> {
    if role.is_empty() || role.len() > 63 || role.contains('\0') {
        return Err(sqlx::Error::Protocol("invalid role identifier".into()));
    }
    let role = format!("\"{}\"", role.replace('"', "\"\""));
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("GRANT USAGE ON SCHEMA identity_authority TO {role}; GRANT SELECT ON identity_authority.schema_version TO {role}; GRANT SELECT(singleton,authority_id) ON identity_authority.deployment TO {role}; GRANT EXECUTE ON FUNCTION identity_authority.share_host_tenant() TO {role}; GRANT SELECT(tenant_id,provider_id,enabled,config_version,settings) ON identity_authority.providers TO {role}; GRANT EXECUTE ON FUNCTION identity_authority.share_provider(uuid) TO {role};"))).execute(c).await?;
    Ok(())
}
/// Verify only this narrow Identity profile; unrelated host schema privileges are unaffected.
pub async fn verify_profile_source_admission(
    c: &mut PgConnection,
    instance: InstanceId,
) -> Result<(), AuthorityError> {
    verify_host_admission(c, instance, false).await
}
/// Combined metadata and platform subject admission profile for a host business role.
/// This grants no credentials, session material, profile observations or write authority.
pub async fn grant_platform_subject_admission(
    c: &mut PgConnection,
    role: &str,
) -> Result<(), sqlx::Error> {
    grant_profile_source_admission(c, role).await?;
    let role = format!("\"{}\"", role.replace('"', "\"\""));
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("GRANT SELECT(tenant_id,principal_id,enabled,auth_epoch) ON identity_authority.accounts TO {role}; GRANT SELECT(tenant_id,principal_id,active,epoch) ON identity_authority.memberships TO {role}; GRANT SELECT(tenant_id,principal_id,identity_id,provider_id) ON identity_authority.external_identities TO {role}; GRANT SELECT(revocation_epoch) ON identity_authority.providers TO {role}; GRANT EXECUTE ON FUNCTION identity_authority.share_subject(uuid) TO {role};"))).execute(c).await?;
    Ok(())
}
/// Verify the combined host admission profile, including SET-reachable roles.
pub async fn verify_platform_subject_admission(
    c: &mut PgConnection,
    instance: InstanceId,
) -> Result<(), AuthorityError> {
    verify_host_admission(c, instance, true).await
}
async fn verify_host_admission(
    c: &mut PgConnection,
    instance: InstanceId,
    platform: bool,
) -> Result<(), AuthorityError> {
    let result=async {
        // SET reachability includes NOINHERIT membership; effective privileges alone are insufficient.
        let reachable_safe:bool=sqlx::query_scalar("WITH reachable AS (SELECT oid,rolsuper,rolbypassrls,rolcreaterole FROM pg_roles WHERE pg_has_role(current_user,oid,'SET')) SELECT NOT EXISTS(SELECT FROM reachable r WHERE r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR has_schema_privilege(r.oid,'identity_authority','CREATE')) AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN pg_attribute a JOIN pg_class cl ON cl.oid=a.attrelid JOIN pg_namespace n ON n.oid=cl.relnamespace WHERE n.nspname='identity_authority' AND cl.relkind='r' AND a.attnum>0 AND NOT a.attisdropped AND ((has_column_privilege(r.oid,a.attrelid,a.attnum,'SELECT') AND NOT ((cl.relname='schema_version' OR (cl.relname='deployment' AND a.attname IN ('singleton','authority_id'))) OR (cl.relname='providers' AND a.attname IN ('tenant_id','provider_id','enabled','config_version','settings')) OR ($1 AND ((cl.relname='accounts' AND a.attname IN ('tenant_id','principal_id','enabled','auth_epoch')) OR (cl.relname='memberships' AND a.attname IN ('tenant_id','principal_id','active','epoch')) OR (cl.relname='external_identities' AND a.attname IN ('tenant_id','principal_id','identity_id','provider_id')) OR (cl.relname='providers' AND a.attname='revocation_epoch'))))) OR has_column_privilege(r.oid,a.attrelid,a.attnum,'UPDATE') OR has_column_privilege(r.oid,a.attrelid,a.attnum,'INSERT,REFERENCES') OR has_table_privilege(r.oid,a.attrelid,'DELETE,TRUNCATE,TRIGGER')))").bind(platform).fetch_one(&mut *c).await?;
        if !reachable_safe {return Ok::<_,sqlx::Error>(false);}
        let functions_ok:bool=sqlx::query_scalar("SELECT has_function_privilege(current_user,'identity_authority.share_host_tenant()','EXECUTE') AND has_function_privilege(current_user,'identity_authority.share_provider(uuid)','EXECUTE') AND has_function_privilege(current_user,'identity_authority.share_subject(uuid)','EXECUTE')=$1 AND NOT EXISTS(SELECT FROM pg_roles r CROSS JOIN pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE pg_has_role(current_user,r.oid,'SET') AND n.nspname='identity_authority' AND has_function_privilege(r.oid,p.oid,'EXECUTE') AND NOT (p.oid IN ('identity_authority.share_provider(uuid)'::regprocedure,'identity_authority.share_host_tenant()'::regprocedure) OR ($1 AND p.oid='identity_authority.share_subject(uuid)'::regprocedure)))").bind(platform).fetch_one(&mut *c).await?;
        if !functions_ok || !lock_grants_are_private(c).await? {return Ok(false);}
        let valid:bool=sqlx::query_scalar("SELECT NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT has_schema_privilege(current_user,'identity_authority','CREATE') AND has_schema_privilege(current_user,'identity_authority','USAGE') FROM pg_roles WHERE rolname=current_user").fetch_one(&mut *c).await?;
        if !valid {return Ok::<_,sqlx::Error>(false);}
        let valid:bool=sqlx::query_scalar("SELECT bool_and(has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT') = ((cl.relname='schema_version' OR (cl.relname='deployment' AND a.attname IN ('singleton','authority_id'))) OR (cl.relname='providers' AND a.attname IN ('tenant_id','provider_id','enabled','config_version','settings')) OR ($1 AND ((cl.relname='accounts' AND a.attname IN ('tenant_id','principal_id','enabled','auth_epoch')) OR (cl.relname='memberships' AND a.attname IN ('tenant_id','principal_id','active','epoch')) OR (cl.relname='external_identities' AND a.attname IN ('tenant_id','principal_id','identity_id','provider_id')) OR (cl.relname='providers' AND a.attname='revocation_epoch')))) AND NOT has_column_privilege(current_user,a.attrelid,a.attnum,'UPDATE') AND NOT has_column_privilege(current_user,a.attrelid,a.attnum,'INSERT') AND NOT has_column_privilege(current_user,a.attrelid,a.attnum,'REFERENCES') AND NOT has_table_privilege(current_user,a.attrelid,'DELETE,TRUNCATE,TRIGGER')) FROM pg_attribute a JOIN pg_class cl ON cl.oid=a.attrelid JOIN pg_namespace n ON n.oid=cl.relnamespace WHERE n.nspname='identity_authority' AND cl.relkind='r' AND a.attnum>0 AND NOT a.attisdropped").bind(platform).fetch_one(&mut *c).await?;
        if !valid {return Ok(false);}
        let actual:uuid::Uuid=sqlx::query_scalar("SELECT authority_id FROM identity_authority.deployment").fetch_one(&mut *c).await?;
        let versions:Vec<i32>=sqlx::query_scalar("SELECT version FROM identity_authority.schema_version").fetch_all(&mut *c).await?;
        let signature:Option<String>=sqlx::query_scalar(SCHEMA_SIGNATURE_SQL).fetch_one(c).await?;
        Ok(actual==instance.as_uuid() && versions==[SCHEMA_VERSION] && signature.as_deref()==Some(SCHEMA_SIGNATURE.trim()))
    }.await.map_err(|_|AuthorityError::Unavailable)?;
    if result {
        Ok(())
    } else {
        Err(AuthorityError::Configuration)
    }
}

/// Grant only schema usage and execution of the bounded read function. The host owns the role.
pub async fn grant_personnel_fact_read(
    c: &mut PgConnection,
    role: &str,
) -> Result<(), sqlx::Error> {
    if role.is_empty() || role.len() > 63 || role.contains('\0') {
        return Err(sqlx::Error::Protocol("invalid role identifier".into()));
    }
    let role = format!("\"{}\"", role.replace('"', "\"\""));
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "GRANT USAGE ON SCHEMA identity_authority TO {role}; GRANT EXECUTE ON FUNCTION identity_authority.personnel_facts(uuid,uuid,uuid[],text,text,text[],bigint) TO {role}"
    )))
    .execute(c).await?;
    Ok(())
}

/// Verify a dedicated personnel reader. Host-owned schema privileges are independent.
pub async fn verify_personnel_fact_read(c: &mut PgConnection) -> Result<(), AuthorityError> {
    use crate::StorageMismatch;
    let signature: Option<String> = sqlx::query_scalar(SCHEMA_SIGNATURE_SQL)
        .fetch_one(&mut *c)
        .await
        .map_err(|_| AuthorityError::Unavailable)?;
    if signature.as_deref() != Some(SCHEMA_SIGNATURE.trim()) {
        return Err(AuthorityError::StorageIncompatible(
            StorageMismatch::SchemaContract,
        ));
    }
    let safe: bool = sqlx::query_scalar(include_str!("personnel-fact-privileges.sql"))
        .fetch_one(c)
        .await
        .map_err(|_| AuthorityError::Unavailable)?;
    if !safe {
        return Err(AuthorityError::StorageIncompatible(
            StorageMismatch::Privileges,
        ));
    }
    Ok(())
}
