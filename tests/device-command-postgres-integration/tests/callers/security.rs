use super::*;

pub(super) async fn declarations(f: &Fixture) -> anyhow::Result<()> {
    let before = snapshot(f).await?;
    for names in [
        vec!["device_peer"],
        vec!["device_runtime"],
        vec!["device_runtime", "device_peer", "missing_role"],
        vec!["Device_Runtime", "device_peer"],
        vec![" device_runtime", "device_peer"],
        vec!["device_runtime", "device_peer", "device_owner"],
    ] {
        assert!(!admit(f, CallerRoles::new(&names)?).await?);
    }
    // PostgreSQL names have a storage limit; a longer input must never alias its prefix.
    let long = "x".repeat(63);
    let truncated = format!("{long}suffix");
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE ROLE \"{long}\" LOGIN")))
        .execute(&f.owner)
        .await?;
    let rejected = admit(
        f,
        CallerRoles::new(&["device_runtime", "device_peer", &truncated])?,
    )
    .await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP ROLE \"{long}\"")))
        .execute(&f.owner)
        .await?;
    assert!(!rejected?);
    assert_eq!(snapshot(f).await?, before);
    Ok(())
}

pub(super) async fn catalog(f: &Fixture) -> anyhow::Result<()> {
    // Populate both tenants so the read-only assertions cannot pass on empty tables alone.
    for tenant in [TENANT, OTHER] {
        let s = scope(tenant)?;
        f.initialize(s, Coordinate::new(1, 1)?).await?;
        f.queue("security-retained", s, Coordinate::new(1, 1)?)
            .await?;
    }
    for (change, restore) in [
        (
            "ALTER ROLE device_peer NOLOGIN",
            "ALTER ROLE device_peer LOGIN",
        ),
        (
            "REVOKE USAGE ON SCHEMA rss_device_command FROM device_peer",
            "GRANT USAGE ON SCHEMA rss_device_command TO device_peer",
        ),
        (
            "REVOKE SELECT ON rss_device_command.commands FROM device_peer",
            "GRANT SELECT ON rss_device_command.commands TO device_peer",
        ),
        (
            "REVOKE EXECUTE ON FUNCTION rss_device_command.initialize(uuid,uuid,bigint,bigint) FROM device_peer",
            "GRANT EXECUTE ON FUNCTION rss_device_command.initialize(uuid,uuid,bigint,bigint) TO device_peer",
        ),
        (
            "GRANT SELECT ON rss_device_command.commands TO device_peer WITH GRANT OPTION",
            "REVOKE GRANT OPTION FOR SELECT ON rss_device_command.commands FROM device_peer",
        ),
        (
            "GRANT SELECT(command_id) ON rss_device_command.commands TO device_peer WITH GRANT OPTION",
            "REVOKE SELECT(command_id) ON rss_device_command.commands FROM device_peer",
        ),
        (
            "GRANT UPDATE ON rss_device_command.commands TO device_peer",
            "REVOKE UPDATE ON rss_device_command.commands FROM device_peer",
        ),
        (
            "GRANT UPDATE(status) ON rss_device_command.commands TO device_peer",
            "REVOKE UPDATE(status) ON rss_device_command.commands FROM device_peer",
        ),
        (
            "GRANT CREATE ON SCHEMA rss_device_command TO device_peer",
            "REVOKE CREATE ON SCHEMA rss_device_command FROM device_peer",
        ),
        (
            "GRANT SELECT ON rss_device_command.commands TO PUBLIC",
            "REVOKE SELECT ON rss_device_command.commands FROM PUBLIC",
        ),
        (
            "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_device_command TO PUBLIC",
            "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_device_command FROM PUBLIC",
        ),
        (
            "ALTER TABLE rss_device_command.commands OWNER TO device_peer",
            "ALTER TABLE rss_device_command.commands OWNER TO device_owner; REVOKE ALL ON rss_device_command.commands FROM device_peer; GRANT SELECT ON rss_device_command.commands TO device_peer",
        ),
        (
            "ALTER SCHEMA rss_device_command OWNER TO device_peer",
            "ALTER SCHEMA rss_device_command OWNER TO device_owner; REVOKE ALL ON SCHEMA rss_device_command FROM device_peer; GRANT USAGE ON SCHEMA rss_device_command TO device_peer",
        ),
    ] {
        reject_change(f, change, restore).await?;
    }
    for attribute in [
        "SUPERUSER",
        "BYPASSRLS",
        "CREATEROLE",
        "CREATEDB",
        "REPLICATION",
    ] {
        reject_change(
            f,
            &format!("ALTER ROLE device_peer {attribute}"),
            &format!("ALTER ROLE device_peer NO{attribute}"),
        )
        .await?;
    }
    membership(f).await?;
    outsider(f).await
}

async fn membership(f: &Fixture) -> anyhow::Result<()> {
    for (grant, revoke) in [
        (
            "GRANT device_runtime TO device_peer WITH ADMIN TRUE, INHERIT FALSE, SET FALSE",
            "REVOKE device_runtime FROM device_peer",
        ),
        (
            "GRANT device_owner TO device_peer WITH ADMIN TRUE, INHERIT FALSE, SET FALSE",
            "REVOKE device_owner FROM device_peer",
        ),
        (
            "GRANT device_runtime TO device_peer WITH INHERIT TRUE, SET FALSE",
            "REVOKE device_runtime FROM device_peer",
        ),
        (
            "GRANT device_peer TO device_runtime WITH INHERIT FALSE, SET TRUE",
            "REVOKE device_peer FROM device_runtime",
        ),
        (
            "GRANT device_owner TO device_peer WITH INHERIT TRUE, SET FALSE",
            "REVOKE device_owner FROM device_peer",
        ),
        (
            "GRANT device_owner TO device_peer WITH INHERIT FALSE, SET TRUE",
            "REVOKE device_owner FROM device_peer",
        ),
    ] {
        reject_change(f, grant, revoke).await?;
    }
    sqlx::raw_sql("CREATE ROLE command_bridge NOLOGIN; CREATE ROLE command_privileged NOLOGIN")
        .execute(&f.owner)
        .await?;
    for (change, restore) in [
        (
            "GRANT device_runtime TO command_bridge WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT command_bridge TO device_peer WITH INHERIT FALSE, SET TRUE",
            "REVOKE command_bridge FROM device_peer; REVOKE device_runtime FROM command_bridge",
        ),
        (
            "GRANT command_privileged TO device_peer WITH ADMIN TRUE, INHERIT FALSE, SET FALSE",
            "REVOKE command_privileged FROM device_peer",
        ),
        (
            "GRANT device_runtime TO command_bridge WITH INHERIT TRUE, SET FALSE; GRANT command_bridge TO device_peer WITH INHERIT FALSE, SET TRUE",
            "REVOKE command_bridge FROM device_peer; REVOKE device_runtime FROM command_bridge",
        ),
        (
            "GRANT device_owner TO command_bridge WITH INHERIT TRUE, SET FALSE; GRANT command_bridge TO device_peer WITH INHERIT FALSE, SET TRUE",
            "REVOKE command_bridge FROM device_peer; REVOKE device_owner FROM command_bridge",
        ),
        (
            "GRANT UPDATE ON rss_device_command.commands TO command_privileged; GRANT command_privileged TO command_bridge WITH INHERIT TRUE, SET FALSE; GRANT command_bridge TO device_peer WITH INHERIT FALSE, SET TRUE",
            "REVOKE command_bridge FROM device_peer; REVOKE command_privileged FROM command_bridge; REVOKE UPDATE ON rss_device_command.commands FROM command_privileged",
        ),
    ] {
        reject_change(f, change, restore).await?;
    }
    sqlx::raw_sql("DROP ROLE command_bridge,command_privileged")
        .execute(&f.owner)
        .await?;
    Ok(())
}

async fn outsider(f: &Fixture) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE ROLE command_outsider LOGIN; CREATE ROLE command_bridge NOLOGIN; CREATE ROLE command_hop NOLOGIN").execute(&f.owner).await?;
    for (change, restore) in [
        (
            "GRANT device_peer TO command_outsider WITH ADMIN TRUE, INHERIT FALSE, SET FALSE",
            "REVOKE device_peer FROM command_outsider",
        ),
        (
            "GRANT device_owner TO command_outsider WITH ADMIN TRUE, INHERIT FALSE, SET FALSE",
            "REVOKE device_owner FROM command_outsider",
        ),
        (
            "GRANT device_peer TO command_bridge WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT command_bridge TO command_outsider WITH INHERIT FALSE, SET TRUE",
            "REVOKE command_bridge FROM command_outsider; REVOKE device_peer FROM command_bridge",
        ),
        (
            "GRANT pg_read_all_data TO command_bridge WITH INHERIT FALSE, SET TRUE; GRANT command_bridge TO command_outsider WITH ADMIN TRUE, INHERIT FALSE, SET FALSE",
            "REVOKE command_bridge FROM command_outsider; REVOKE pg_read_all_data FROM command_bridge",
        ),
        (
            "GRANT USAGE ON SCHEMA rss_device_command TO command_outsider",
            "REVOKE USAGE ON SCHEMA rss_device_command FROM command_outsider",
        ),
        (
            "GRANT SELECT(command_id) ON rss_device_command.commands TO command_bridge",
            "REVOKE SELECT(command_id) ON rss_device_command.commands FROM command_bridge",
        ),
        (
            "GRANT device_peer TO command_outsider WITH INHERIT TRUE, SET FALSE",
            "REVOKE device_peer FROM command_outsider",
        ),
        (
            "GRANT device_peer TO command_outsider WITH INHERIT FALSE, SET TRUE",
            "REVOKE device_peer FROM command_outsider",
        ),
        (
            "GRANT device_peer TO command_bridge WITH INHERIT TRUE, SET FALSE",
            "REVOKE device_peer FROM command_bridge",
        ),
        (
            "GRANT device_peer TO command_bridge WITH INHERIT FALSE, SET TRUE; GRANT command_bridge TO command_hop WITH INHERIT FALSE, SET TRUE; GRANT command_hop TO command_outsider WITH INHERIT FALSE, SET TRUE",
            "REVOKE command_hop FROM command_outsider; REVOKE command_bridge FROM command_hop; REVOKE device_peer FROM command_bridge",
        ),
        (
            "GRANT device_peer TO command_bridge WITH INHERIT TRUE, SET FALSE; GRANT command_bridge TO command_outsider WITH INHERIT FALSE, SET TRUE",
            "REVOKE command_bridge FROM command_outsider; REVOKE device_peer FROM command_bridge",
        ),
    ] {
        reject_change(f, change, restore).await?;
    }
    sqlx::raw_sql("DROP ROLE command_outsider,command_bridge,command_hop")
        .execute(&f.owner)
        .await?;
    Ok(())
}
