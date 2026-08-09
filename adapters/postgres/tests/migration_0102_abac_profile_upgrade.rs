use std::borrow::Cow;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn migrations_through(last_version: i64) -> sqlx::migrate::Migrator {
    let embedded = sqlx::migrate!("./migrations");
    let migrations = embedded
        .iter()
        .filter(|migration| migration.version <= last_version)
        .cloned()
        .collect();
    sqlx::migrate::Migrator {
        migrations: Cow::Owned(migrations),
        ignore_missing: false,
        locking: false,
        no_tx: embedded.no_tx,
    }
}

async fn connect(params: &testkit::PgConnParams) -> Result<sqlx::PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(2)
        .connect_with(
            PgConnectOptions::new()
                .host(&params.host)
                .port(params.port)
                .database(&params.database)
                .username(&params.username)
                .password(&params.password)
                .ssl_mode(PgSslMode::Prefer),
        )
        .await
}

fn legacy_rule(operator: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "rules": [{
            "condition": {"attribute": "resource.owner", "operator": operator},
            "effect": "allow",
            "obligations": {"rowScope": null, "fieldMask": []}
        }]
    })
}

async fn insert_policy(
    pool: &sqlx::PgPool,
    tenant: uuid::Uuid,
    id: &str,
    rules: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO public.abac_policies
         (tenant_id,id,version,contract_id,permission,effective_from,rules)
         VALUES ($1::uuid,$2,1,'identity.account-status-get','identity:account-security:read',to_timestamp(0),$3)",
    )
    .bind(tenant.to_string())
    .bind(id)
    .bind(rules)
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_losslessly_rewrites_legacy_profile_and_installs_typed_constraints() -> TestResult {
    let fixture = testkit::owned_postgres().await?;
    let pool = connect(fixture.owner_params()).await?;
    migrations_through(101).run(&pool).await?;
    let tenant = uuid::Uuid::new_v4();
    for (id, operator) in [
        ("eq", serde_json::json!({"kind":"eq","value":"eng"})),
        ("ne", serde_json::json!({"kind":"ne","value":"ops"})),
        (
            "like",
            serde_json::json!({"kind":"like","pattern":"team-*"}),
        ),
        (
            "eq-attr",
            serde_json::json!({"kind":"eqAttr","attribute":"principal.id"}),
        ),
    ] {
        insert_policy(&pool, tenant, id, legacy_rule(operator)).await?;
    }
    let resource_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.resource_attributes
         (tenant_id,contract_id,permission,resource_id,attribute_key,attribute_value,effective_from)
         VALUES ($1::uuid,'identity.account-status-get','identity:account-security:read',$2::uuid,'resource.owner','alice',to_timestamp(0))",
    )
    .bind(tenant.to_string())
    .bind(resource_id.to_string())
    .execute(&pool)
    .await?;

    migrations_through(102).run(&pool).await?;
    let operators: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT id, rules #> '{rules,0,condition,operator}'
         FROM public.abac_policies WHERE tenant_id=$1::uuid ORDER BY id",
    )
    .bind(tenant.to_string())
    .fetch_all(&pool)
    .await?;
    assert_eq!(operators.len(), 4);
    assert_eq!(operators[0].1["family"], "equality");
    assert_eq!(operators[1].1["operand"]["kind"], "attribute");
    assert_eq!(operators[2].1["predicate"], "glob");
    assert_eq!(operators[3].1["predicate"], "ne");
    let typed: serde_json::Value = sqlx::query_scalar(
        "SELECT attribute_value FROM public.resource_attributes
         WHERE tenant_id=$1::uuid AND resource_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(resource_id.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        typed,
        serde_json::json!({"valueType":"string","value":"alice"})
    );

    for invalid in [
        serde_json::from_str(r#"{"valueType":"integer","value":9223372036854775808}"#)?,
        serde_json::json!({"valueType":"decimal","value":"1.0"}),
    ] {
        let result = sqlx::query(
            "INSERT INTO public.resource_attributes
             (tenant_id,contract_id,permission,resource_id,attribute_key,attribute_value,effective_from)
             VALUES ($1::uuid,'identity.account-status-get','identity:account-security:read',$2::uuid,'resource.rank',$3,to_timestamp(0))",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&invalid)
        .execute(&pool)
        .await;
        assert!(result.is_err(), "typed CHECK must reject {invalid}");
    }

    pool.close().await;
    drop(fixture);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn ambiguous_or_malformed_legacy_rows_abort_0102_atomically() -> TestResult {
    let fixture = testkit::owned_postgres().await?;
    let pool = connect(fixture.owner_params()).await?;
    migrations_through(101).run(&pool).await?;
    let tenant = uuid::Uuid::new_v4();
    let gt = legacy_rule(serde_json::json!({"kind":"gt","value":"3"}));
    insert_policy(&pool, tenant, "ambiguous-gt", gt.clone()).await?;
    assert!(migrations_through(102).run(&pool).await.is_err());
    let ledger: Option<i64> =
        sqlx::query_scalar("SELECT max(version) FROM public._sqlx_migrations WHERE success")
            .fetch_one(&pool)
            .await?;
    assert_eq!(ledger, Some(101));
    let unchanged: serde_json::Value =
        sqlx::query_scalar("SELECT rules FROM public.abac_policies WHERE id='ambiguous-gt'")
            .fetch_one(&pool)
            .await?;
    assert_eq!(unchanged, gt);

    sqlx::query("DELETE FROM public.abac_policies WHERE id='ambiguous-gt'")
        .execute(&pool)
        .await?;
    let malformed = serde_json::json!({
        "rules": [{
            "condition": {"attribute":"resource.owner","operator":{"kind":"eq","value":"alice"}},
            "effect":"maybe",
            "obligations":{"rowScope":null,"fieldMask":[]}
        }]
    });
    insert_policy(&pool, tenant, "malformed-effect", malformed.clone()).await?;
    assert!(migrations_through(102).run(&pool).await.is_err());
    let unchanged: serde_json::Value =
        sqlx::query_scalar("SELECT rules FROM public.abac_policies WHERE id='malformed-effect'")
            .fetch_one(&pool)
            .await?;
    assert_eq!(unchanged, malformed);

    pool.close().await;
    drop(fixture);
    Ok(())
}

async fn assert_locking_lane_blocks_then_allows_upgrade(statement: &str) -> TestResult {
    let fixture = testkit::owned_postgres().await?;
    let pool = connect(fixture.owner_params()).await?;
    migrations_through(101).run(&pool).await?;
    let tenant = uuid::Uuid::new_v4();
    let legacy = legacy_rule(serde_json::json!({"kind":"eq","value":"eng"}));
    insert_policy(&pool, tenant, "lock-proof", legacy.clone()).await?;

    let mut blocker = pool.acquire().await?;
    sqlx::query("BEGIN").execute(&mut *blocker).await?;
    sqlx::query(statement).execute(&mut *blocker).await?;

    let migration_pool = pool.clone();
    let blocked =
        tokio::spawn(async move { migrations_through(102).run(&migration_pool).await }).await?;
    assert!(
        blocked.is_err(),
        "0102 must honor its five-second lock timeout"
    );
    let ledger: Option<i64> =
        sqlx::query_scalar("SELECT max(version) FROM public._sqlx_migrations WHERE success")
            .fetch_one(&pool)
            .await?;
    assert_eq!(ledger, Some(101));
    let unchanged: serde_json::Value =
        sqlx::query_scalar("SELECT rules FROM public.abac_policies WHERE id='lock-proof'")
            .fetch_one(&pool)
            .await?;
    assert_eq!(unchanged, legacy);

    sqlx::query("ROLLBACK").execute(&mut *blocker).await?;
    migrations_through(102).run(&pool).await?;
    let ledger: Option<i64> =
        sqlx::query_scalar("SELECT max(version) FROM public._sqlx_migrations WHERE success")
            .fetch_one(&pool)
            .await?;
    assert_eq!(ledger, Some(102));
    drop(blocker);
    pool.close().await;
    drop(fixture);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reader_and_legacy_writer_lanes_cannot_race_0102() -> TestResult {
    assert_locking_lane_blocks_then_allows_upgrade(
        "SELECT id FROM public.abac_policies WHERE id='lock-proof'",
    )
    .await?;
    assert_locking_lane_blocks_then_allows_upgrade(
        "UPDATE public.abac_policies SET permission=permission WHERE id='lock-proof'",
    )
    .await
}
