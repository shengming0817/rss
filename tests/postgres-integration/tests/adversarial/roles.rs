//! INVARIANT: TMSG-RELAY-ROLE-01 — exact definer posture, independent of runtime membership.
use super::*;

pub(super) async fn run(owner: &sqlx::PgPool, config: &PgConfig) -> anyhow::Result<()> {
    accepted(config).await?;
    let mut results = Vec::new();
    for (damage, repair) in [
        ("LOGIN", "NOLOGIN"),
        ("SUPERUSER", "NOSUPERUSER"),
        ("BYPASSRLS", "NOBYPASSRLS"),
        ("CREATEROLE", "NOCREATEROLE"),
        ("CREATEDB", "NOCREATEDB"),
        ("REPLICATION", "NOREPLICATION"),
    ] {
        // SQL safety: role and attributes are closed fixture literals.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER ROLE rss_tmsg_relay {damage}"
        )))
        .execute(owner)
        .await?;
        // The shared fencing probe runs first and projects SUPERUSER drift as Functions.
        let category = if damage == "SUPERUSER" {
            PgStorageContractFailure::Functions
        } else {
            PgStorageContractFailure::RelayRole
        };
        let result = rejected(config, category).await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER ROLE rss_tmsg_relay {repair}"
        )))
        .execute(owner)
        .await?;
        accepted(config).await?;
        eprintln!("relay-role attribute={damage} expected_rejection={result:?}");
        results.push((damage, result));
    }
    let membership_result = memberships(owner, config).await;
    for (attribute, result) in results {
        result.map_err(|e| anyhow::anyhow!("relay attribute {attribute}: {e}"))?;
    }
    membership_result
}

async fn accepted(config: &PgConfig) -> anyhow::Result<()> {
    let runtime =
        PgRuntime::connect(config.clone(), Timer::new(), fence_fixture::binding()).await?;
    runtime.close().await;
    Ok(())
}
async fn rejected(config: &PgConfig, category: PgStorageContractFailure) -> anyhow::Result<()> {
    let error =
        match PgRuntime::connect(config.clone(), Timer::new(), fence_fixture::binding()).await {
            Ok(runtime) => {
                runtime.close().await;
                anyhow::bail!("probe accepted role drift");
            }
            Err(error) => error,
        };
    let rendered = format!("{error} {error:?}");
    anyhow::ensure!(
        matches!(error,PgError::IncompatibleStorageContract(actual) if actual==category),
        "unexpected closed category: {rendered}"
    );
    for secret in [
        "rss_tmsg_relay",
        "tmsg_runtime",
        "fixture-only",
        "role_drift_parent",
        "postgres://",
    ] {
        assert!(
            !rendered.contains(secret),
            "diagnostic leaked fixture identity or credential"
        );
    }
    Ok(())
}

async fn memberships(owner: &sqlx::PgPool, config: &PgConfig) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE ROLE role_drift_parent NOLOGIN CREATEROLE CREATEDB REPLICATION; CREATE ROLE role_drift_middle NOLOGIN; CREATE TABLE public.role_drift_effect(value integer); GRANT SELECT ON public.role_drift_effect TO role_drift_parent; GRANT role_drift_parent TO role_drift_middle WITH INHERIT TRUE, SET TRUE")
        .execute(owner).await?;
    let mut results = Vec::new();
    for inherit_attribute in ["INHERIT", "NOINHERIT"] {
        // The role-level flag alone grants nothing; per-membership options are tested below.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER ROLE rss_tmsg_relay {inherit_attribute}"
        )))
        .execute(owner)
        .await?;
        accepted(config).await?;
        for parent in ["role_drift_parent", "role_drift_middle"] {
            for (inherit, set) in [(true, true), (true, false), (false, true), (false, false)] {
                results.push(membership_case(owner, config, parent, inherit, set).await);
            }
        }
    }
    sqlx::raw_sql("ALTER ROLE rss_tmsg_relay INHERIT; REVOKE role_drift_parent FROM role_drift_middle; GRANT rss_tmsg_relay TO role_drift_middle WITH INHERIT TRUE, SET TRUE")
        .execute(owner).await?;
    for relay in ["rss_tmsg_relay", "role_drift_middle"] {
        // Incoming runtime -> relay membership is a separate contract from relay -> parent.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "GRANT {relay} TO tmsg_runtime WITH INHERIT FALSE, SET FALSE"
        )))
        .execute(owner)
        .await?;
        // The shared fencing probe already rejects runtime -> relay membership.
        let result = rejected(config, PgStorageContractFailure::Functions).await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "REVOKE {relay} FROM tmsg_runtime"
        )))
        .execute(owner)
        .await?;
        result?;
        accepted(config).await?;
    }
    sqlx::raw_sql("REVOKE rss_tmsg_relay FROM role_drift_middle; DROP TABLE public.role_drift_effect; DROP ROLE role_drift_middle; DROP ROLE role_drift_parent")
        .execute(owner).await?;
    results.into_iter().collect()
}

async fn membership_case(
    owner: &sqlx::PgPool,
    config: &PgConfig,
    parent: &str,
    inherit: bool,
    set: bool,
) -> anyhow::Result<()> {
    // SQL safety: parent comes only from the closed fixture array; booleans are typed.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "GRANT {parent} TO rss_tmsg_relay WITH INHERIT {inherit}, SET {set}"
    )))
    .execute(owner)
    .await?;
    let capabilities: (bool,bool,bool,bool) = sqlx::query_as("SELECT pg_has_role('rss_tmsg_relay','role_drift_parent','MEMBER'),pg_has_role('rss_tmsg_relay','role_drift_parent','USAGE'),pg_has_role('rss_tmsg_relay','role_drift_parent','SET'),has_table_privilege('rss_tmsg_relay','public.role_drift_effect','SELECT')")
        .fetch_one(owner).await?;
    assert_eq!(capabilities, (true, inherit, set, inherit));
    let attributes: (bool,bool,bool) = sqlx::query_as("SELECT rolcreaterole,rolcreatedb,rolreplication FROM pg_roles WHERE rolname='rss_tmsg_relay'").fetch_one(owner).await?;
    assert_eq!(
        attributes,
        (false, false, false),
        "special role attributes are not inherited object privileges"
    );
    let result = rejected(config, PgStorageContractFailure::RelayRole).await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "REVOKE {parent} FROM rss_tmsg_relay"
    )))
    .execute(owner)
    .await?;
    eprintln!(
        "relay-role parent={parent} inherit={inherit} set={set} rejected={}",
        result.is_ok()
    );
    accepted(config).await?;
    result
}
