use super::*;

// F4.3: restoring definitions uses the shipped migration, never a second copy of the body.
fn definition(name: &str) -> anyhow::Result<String> {
    let marker = format!("CREATE FUNCTION rss_device_command.{name}(");
    let rest = rss_device_command_postgres::MIGRATION_SQL
        .split_once(&marker)
        .and_then(|(_, rest)| rest.split_once("$$;"))
        .ok_or_else(|| anyhow::anyhow!("missing canonical function {name}"))?
        .0;
    Ok(format!(
        "{}{}$$;",
        marker.replacen("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1),
        rest
    ))
}

pub(super) async fn executable_contract(f: &Fixture) -> anyhow::Result<()> {
    let s = Scope::new(
        scope(TENANT)?.tenant(),
        DeviceId::parse("550e8400-e29b-41d4-a716-446655449372")?,
    );
    let c = Coordinate::new(1, 1)?;
    f.initialize(s, c).await?;
    let original = f.queue("probe-retained", s, c).await?;
    for (name, body) in [("enqueue", "SELECT NULL::void;"), ("save", "SELECT true;")] {
        let restore = definition(name)?;
        let header = restore
            .split_once("AS $$")
            .ok_or_else(|| anyhow::anyhow!("missing body delimiter"))?
            .0;
        reject(
            f,
            &format!("{header}AS $$ {body} $$;"),
            &restore,
            "functions",
        )
        .await?;
        assert_eq!(f.load("probe-retained", s).await?, Some(original.clone()));
        assert_eq!(f.count("commands", "probe-retained").await?, 1);
        assert_eq!(f.count("outbox", "dispatch.probe-retained").await?, 1);
    }
    function_attributes(f).await?;
    relation_drift(f).await?;
    assert_eq!(f.load("probe-retained", s).await?, Some(original));
    Ok(())
}
async fn function_attributes(f: &Fixture) -> anyhow::Result<()> {
    for (change, restore) in [
        (
            "ALTER FUNCTION rss_device_command.save(uuid,uuid,text,bigint,text,bigint,bigint,bigint) STRICT",
            "ALTER FUNCTION rss_device_command.save(uuid,uuid,text,bigint,text,bigint,bigint,bigint) CALLED ON NULL INPUT",
        ),
        (
            "ALTER FUNCTION rss_device_command.enqueue(uuid,uuid,text,bigint,bigint,bytea,bigint,bigint,text,bytea,text) STABLE",
            "ALTER FUNCTION rss_device_command.enqueue(uuid,uuid,text,bigint,bigint,bytea,bigint,bigint,text,bytea,text) VOLATILE",
        ),
    ] {
        reject(f, change, restore, "functions").await?;
    }
    Ok(())
}
async fn relation_drift(f: &Fixture) -> anyhow::Result<()> {
    reject(
        f,
        "ALTER SCHEMA rss_device_command RENAME TO device_command_unavailable",
        "ALTER SCHEMA device_command_unavailable RENAME TO rss_device_command",
        "revision",
    )
    .await?;
    // Keep the trigger helper outside the component so the relation guard is the rejecting check.
    sqlx::raw_sql("CREATE FUNCTION public.swallow_command_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$").execute(&f.owner).await?;
    let triggers = async {
        for event in ["INSERT", "UPDATE"] {
            reject(f, &format!("CREATE TRIGGER swallow BEFORE {event} ON rss_device_command.commands FOR EACH ROW EXECUTE FUNCTION public.swallow_command_write()"),
                "DROP TRIGGER swallow ON rss_device_command.commands", "relations").await?;
        }
        Ok::<(), anyhow::Error>(())
    }.await;
    sqlx::raw_sql("DROP FUNCTION public.swallow_command_write()")
        .execute(&f.owner)
        .await?;
    triggers?;
    for event in ["INSERT", "UPDATE"] {
        reject(f, &format!("CREATE RULE swallow AS ON {event} TO rss_device_command.commands DO INSTEAD NOTHING"),
            "DROP RULE swallow ON rss_device_command.commands", "relations").await?;
    }
    reject(
        f,
        "ALTER TABLE rss_device_command.commands SET UNLOGGED",
        "ALTER TABLE rss_device_command.commands SET LOGGED",
        "relations",
    )
    .await?;
    Ok(())
}
async fn snapshot(f: &Fixture) -> anyhow::Result<String> {
    // Administrator reads capture every tenant and both sides of the transaction seam.
    Ok(sqlx::query_scalar("SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(c) ORDER BY tenant_id,command_id) FROM rss_device_command.commands c),(SELECT jsonb_agg(to_jsonb(a) ORDER BY tenant_id,device_id) FROM rss_device_command.authorities a),(SELECT jsonb_agg(to_jsonb(o) ORDER BY tenant_id,message_id) FROM rss_transactional_messaging.outbox o))::text").fetch_one(&f.owner).await?)
}
async fn reject(f: &Fixture, change: &str, restore: &str, reason: &str) -> anyhow::Result<()> {
    let before = snapshot(f).await?;
    // SQL comes only from closed test cases and the bundled migration.
    sqlx::raw_sql(sqlx::AssertSqlSafe(change))
        .execute(&f.owner)
        .await?;
    let result = super::review::admission_reason(f, reason).await;
    // Restore even when the admission assertion returns an error.
    sqlx::raw_sql(sqlx::AssertSqlSafe(restore))
        .execute(&f.owner)
        .await?;
    result?;
    assert_eq!(snapshot(f).await?, before, "admission must be read-only");
    let (runtime, _, _) = stores(f.config.clone()).await?;
    runtime.close().await;
    Ok(())
}
