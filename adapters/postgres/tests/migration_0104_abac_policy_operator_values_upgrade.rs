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

fn rules(operator: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "rules": [{
            "condition": {"attribute": "resource.owner", "operator": operator},
            "effect": "allow",
            "obligations": {"rowScope": null, "fieldMask": []}
        }]
    })
}

fn literal(value_type: &str, value: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "family":"equality", "predicate":"eq",
        "operand":{"kind":"literal", "valueType":value_type, "value":value}
    })
}

fn membership(value_type: &str, values: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "family":"membership", "predicate":"in",
        "operand":{"kind":"set", "valueType":value_type, "values":values}
    })
}

fn pattern(value: &str) -> serde_json::Value {
    serde_json::json!({
        "family":"string", "predicate":"glob",
        "operand":{"kind":"pattern", "valueType":"string", "value":value}
    })
}

async fn insert_policy(
    pool: &sqlx::PgPool,
    tenant: uuid::Uuid,
    id: &str,
    document: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO public.abac_policies
         (tenant_id,id,version,contract_id,permission,effective_from,rules)
         VALUES ($1::uuid,$2,1,'identity.account-status-get','identity:account-security:read',to_timestamp(0),$3)",
    )
    .bind(tenant.to_string())
    .bind(id)
    .bind(document)
    .execute(pool)
    .await?;
    Ok(())
}

async fn validator(pool: &sqlx::PgPool, operator: serde_json::Value) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT public.rss_abac_policy_operator_values_valid_v1($1)")
        .bind(rules(operator))
        .fetch_one(pool)
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn dirty_103_rows_abort_0104_atomically_then_fixed_rows_upgrade() -> TestResult {
    let fixture = testkit::owned_postgres().await?;
    let pool = connect(fixture.owner_params()).await?;
    migrations_through(103).run(&pool).await?;
    let tenant = uuid::Uuid::new_v4();
    let dirty_rows = [
        (
            "dirty-literal",
            rules(literal("string", serde_json::json!("a".repeat(257)))),
        ),
        ("dirty-pattern", rules(pattern(&"あ".repeat(86)))),
        (
            "dirty-set",
            rules(membership("string", serde_json::json!(["x", "x"]))),
        ),
    ];
    for (id, document) in &dirty_rows {
        insert_policy(&pool, tenant, id, document).await?;
    }

    let migration_error = migrations_through(104)
        .run(&pool)
        .await
        .expect_err("dirty operator rows must abort 0104");
    let diagnostic = format!("{migration_error:#}");
    for (id, _) in &dirty_rows {
        assert!(
            diagnostic.contains(&format!("{tenant}/{id}")),
            "preflight diagnostic omitted policy coordinates: {diagnostic}"
        );
    }
    assert!(
        !diagnostic.contains(&"a".repeat(257)) && !diagnostic.contains(&"あ".repeat(86)),
        "preflight diagnostic leaked operator values: {diagnostic}"
    );
    let ledger: Option<i64> =
        sqlx::query_scalar("SELECT max(version) FROM public._sqlx_migrations WHERE success")
            .fetch_one(&pool)
            .await?;
    assert_eq!(ledger, Some(103));
    for (id, document) in &dirty_rows {
        let unchanged: serde_json::Value = sqlx::query_scalar(
            "SELECT rules FROM public.abac_policies WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(tenant.to_string())
        .bind(id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(&unchanged, document);
    }
    let artifact_count: i64 = sqlx::query_scalar(
        "SELECT
             (SELECT count(*) FROM pg_constraint WHERE conname='abac_policies_operator_values_v1')
           + (SELECT count(*) FROM pg_proc WHERE proname='rss_abac_policy_operator_values_valid_v1')",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        artifact_count, 0,
        "failed migration must roll back its function/CHECK artifacts"
    );

    for (id, replacement) in [
        (
            "dirty-literal",
            rules(literal("string", serde_json::json!("a".repeat(256)))),
        ),
        ("dirty-pattern", rules(pattern("team-*"))),
        (
            "dirty-set",
            rules(membership("string", serde_json::json!(["x", "y"]))),
        ),
    ] {
        sqlx::query("UPDATE public.abac_policies SET rules=$1 WHERE tenant_id=$2::uuid AND id=$3")
            .bind(replacement)
            .bind(tenant.to_string())
            .bind(id)
            .execute(&pool)
            .await?;
    }
    migrations_through(104).run(&pool).await?;
    let validated: bool = sqlx::query_scalar(
        "SELECT convalidated FROM pg_constraint
         WHERE conrelid='public.abac_policies'::regclass AND conname='abac_policies_operator_values_v1'",
    )
    .fetch_one(&pool)
    .await?;
    assert!(validated);

    let rejected_insert = insert_policy(
        &pool,
        tenant,
        "new-invalid",
        &rules(pattern(&"あ".repeat(86))),
    )
    .await;
    assert!(
        rejected_insert.is_err(),
        "CHECK must reject new invalid inserts"
    );
    let rejected_update = sqlx::query(
        "UPDATE public.abac_policies SET rules=$1 WHERE tenant_id=$2::uuid AND id='dirty-literal'",
    )
    .bind(rules(membership("string", serde_json::json!(["x", "x"]))))
    .bind(tenant.to_string())
    .execute(&pool)
    .await;
    assert!(
        rejected_update.is_err(),
        "CHECK must reject invalid updates"
    );

    pool.close().await;
    drop(fixture);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn validator_covers_closed_type_shape_and_utf8_boundaries() -> TestResult {
    let fixture = testkit::owned_postgres().await?;
    let pool = connect(fixture.owner_params()).await?;
    migrations_through(104).run(&pool).await?;
    let server_encoding: String = sqlx::query_scalar("SHOW server_encoding")
        .fetch_one(&pool)
        .await?;
    assert_eq!(server_encoding, "UTF8");
    let exact = format!("{}a", "あ".repeat(85));
    let over = format!("{}aa", "あ".repeat(85));
    assert_eq!(exact.len(), 256);
    assert_eq!(over.len(), 257);
    let min_i64 = serde_json::Value::from(i64::MIN);
    let max_i64 = serde_json::Value::from(i64::MAX);
    let over_i64: serde_json::Value = serde_json::from_str("9223372036854775808")?;

    for (label, operator) in [
        (
            "literal exact utf8",
            literal("string", serde_json::json!(exact)),
        ),
        (
            "set exact utf8",
            membership("string", serde_json::json!([exact])),
        ),
        ("pattern exact utf8", pattern(&exact)),
        ("boolean", literal("boolean", serde_json::json!(true))),
        ("integer min", literal("integer", min_i64)),
        (
            "integer max",
            membership("integer", serde_json::json!([max_i64])),
        ),
        (
            "string set canonical",
            membership("string", serde_json::json!(["a", "あ"])),
        ),
        (
            "boolean set canonical",
            membership("boolean", serde_json::json!([false, true])),
        ),
        (
            "integer set canonical",
            membership("integer", serde_json::json!([-2, 0, 10])),
        ),
        (
            "decimal set canonical",
            membership("decimal", serde_json::json!(["-2", "1.5", "10"])),
        ),
        (
            "decimal canonical",
            literal("decimal", serde_json::json!("-12.5")),
        ),
        (
            "ordering numeric",
            serde_json::json!({"family":"ordering","predicate":"ge","operand":{"kind":"literal","valueType":"integer","value":0}}),
        ),
        (
            "PIP attribute",
            serde_json::json!({"family":"equality","predicate":"eq","operand":{"kind":"attribute","valueType":"string","attribute":"principal.id"}}),
        ),
    ] {
        assert!(
            validator(&pool, operator).await?,
            "validator rejected valid {label}"
        );
    }

    let mut extra_key = literal("string", serde_json::json!("ok"));
    extra_key["extra"] = serde_json::json!(true);
    for (label, operator) in [
        (
            "literal over utf8",
            literal("string", serde_json::json!(over)),
        ),
        (
            "set over utf8",
            membership("string", serde_json::json!([over])),
        ),
        ("pattern over utf8", pattern(&over)),
        ("empty pattern", pattern("")),
        ("control pattern", pattern("bad\npattern")),
        (
            "wrong scalar type",
            literal("boolean", serde_json::json!("true")),
        ),
        ("integer overflow", literal("integer", over_i64)),
        (
            "decimal noncanonical",
            literal("decimal", serde_json::json!("1.0")),
        ),
        (
            "decimal too long",
            literal(
                "decimal",
                serde_json::json!(format!("0.{}1", "0".repeat(63))),
            ),
        ),
        ("empty set", membership("string", serde_json::json!([]))),
        (
            "33 item set",
            membership("integer", serde_json::json!((0..33).collect::<Vec<_>>())),
        ),
        (
            "duplicate set",
            membership("string", serde_json::json!(["x", "x"])),
        ),
        (
            "unsorted string set",
            membership("string", serde_json::json!(["b", "a"])),
        ),
        (
            "unsorted boolean set",
            membership("boolean", serde_json::json!([true, false])),
        ),
        (
            "unsorted integer set",
            membership("integer", serde_json::json!([2, 1])),
        ),
        (
            "unsorted decimal set",
            membership("decimal", serde_json::json!(["2", "1.5"])),
        ),
        (
            "wrong set member type",
            membership("string", serde_json::json!([true])),
        ),
        (
            "unknown family",
            serde_json::json!({"family":"future","predicate":"eq","operand":{"kind":"literal","valueType":"string","value":"x"}}),
        ),
        (
            "non-PIP attribute",
            serde_json::json!({"family":"equality","predicate":"eq","operand":{"kind":"attribute","valueType":"string","attribute":"secret.probe"}}),
        ),
        ("extra operator key", extra_key),
    ] {
        assert!(
            !validator(&pool, operator).await?,
            "validator accepted invalid {label}"
        );
    }

    // 0102's independent resource attribute boundary remains active after 0104.
    let tenant = uuid::Uuid::new_v4();
    let insert_resource = |value: String| {
        sqlx::query(
            "INSERT INTO public.resource_attributes
             (tenant_id,contract_id,permission,resource_id,attribute_key,attribute_value,effective_from)
             VALUES ($1::uuid,'identity.account-status-get','identity:account-security:read',$2::uuid,'resource.owner',$3,to_timestamp(0))",
        )
        .bind(tenant.to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(serde_json::json!({"valueType":"string","value":value}))
    };
    assert!(insert_resource(exact).execute(&pool).await.is_ok());
    assert!(insert_resource(over).execute(&pool).await.is_err());

    pool.close().await;
    drop(fixture);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn dirty_preflight_reports_count_and_only_a_bounded_sample() -> TestResult {
    let fixture = testkit::owned_postgres().await?;
    let pool = connect(fixture.owner_params()).await?;
    migrations_through(103).run(&pool).await?;
    let tenant = uuid::Uuid::new_v4();
    let dirty = rules(pattern(&"z".repeat(257)));
    for index in 0..25 {
        insert_policy(&pool, tenant, &format!("dirty-{index:02}"), &dirty).await?;
    }

    let migration_error = migrations_through(104)
        .run(&pool)
        .await
        .expect_err("dirty rows must abort 0104");
    let diagnostic = format!("{migration_error:#}");
    assert!(
        diagnostic.contains("count=25"),
        "missing invalid count: {diagnostic}"
    );
    assert!(
        diagnostic.contains("truncated=true"),
        "missing truncation marker: {diagnostic}"
    );
    assert!(
        diagnostic.contains(&format!("{tenant}/dirty-00"))
            && diagnostic.contains(&format!("{tenant}/dirty-19")),
        "missing stable bounded sample: {diagnostic}"
    );
    assert!(
        !diagnostic.contains("dirty-20") && !diagnostic.contains("dirty-24"),
        "diagnostic exceeded sample bound: {diagnostic}"
    );

    pool.close().await;
    drop(fixture);
    Ok(())
}
