//! Capture actual runtime-role production plans independently of latency sampling.
use super::*;
use crate::federation_support::seed_inventory;

#[allow(clippy::unwrap_used, reason = "fixed experiment budgets")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "paired actual PG statement plans at fixed inventories"]
async fn plans() -> anyhow::Result<()> {
    let network = testkit::bridge_network("identity-work").await?;
    let pg = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "identity-pg",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let f = Fixture::new(&pg, rss_audit_postgres::Integrity::Plain).await?;
    f.bootstrap().await?;
    let initial = oidc::service(&f);
    let p = oidc::enabled(&f, &initial).await?;
    initial
        .begin_login(
            LoginRequest {
                binding: binding(f.key.tenant),
                provider: p.id,
                browser: BROWSER.into(),
                target: "home".into(),
                replacement: None,
                source: source(),
            },
            deadline(),
        )
        .await?;
    let template: serde_json::Value = sqlx::query_scalar(
        "SELECT to_jsonb(t) FROM identity_authority.oidc_transactions t LIMIT 1",
    )
    .fetch_one(&f.owner)
    .await?;
    initial
        .begin_link(
            LinkRequest {
                actor: f.actor().await?,
                target_provider: p.id,
                password: Some(password()),
                browser: BROWSER.into(),
                target: "home".into(),
                source: source(),
            },
            deadline(),
        )
        .await?;
    let intent: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(i) FROM identity_authority.link_intents i LIMIT 1")
            .fetch_one(&f.owner)
            .await?;
    f.reset_attempts().await?;
    sqlx::query("ALTER SYSTEM SET log_line_prefix='%n|%p|%d| '")
        .execute(&f.owner)
        .await?;
    sqlx::query("SELECT pg_reload_conf()")
        .execute(&f.owner)
        .await?;
    for setting in [
        "session_preload_libraries='auto_explain'",
        "auto_explain.log_min_duration=0",
        "auto_explain.log_analyze=on",
        "auto_explain.log_nested_statements=on",
        "auto_explain.log_buffers=on",
        "auto_explain.log_timing=off",
        "auto_explain.log_format=json",
        "auto_explain.log_parameter_max_length=0",
        "deadlock_timeout='1ms'",
        "log_lock_waits=on",
        "log_min_duration_statement=0",
        "log_parameter_max_length=0",
    ] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER ROLE identity_runtime IN DATABASE {} SET {setting}",
            f.database
        )))
        .execute(&f.owner)
        .await?;
    }
    let runtime = f.runtime_as("identity_runtime").await?;
    let window = AttemptWindow::new(100_000, 600)?;
    let config = f
        .config()
        .with_authentication_policy(AuthenticationPolicy::new(
            window,
            window,
            window,
            10000,
            128,
            Duration::from_secs(30),
        )?);
    let store = Authority::connect_runtime(
        runtime.clone(),
        Arc::new(PasswordKdf::new(
            NonZeroUsize::MIN,
            NonZeroU64::new(128 * 1024 * 1024).unwrap(),
        )?),
        config,
        binding(f.key.tenant),
        f.policy.clone(),
        deadline(),
    )
    .await?;
    let fed = oidc::service_for(store.clone(), oidc::settings().redirect_uri());
    controls::observe_oidc_changes(&f).await?;
    for n in [0, 5000, 9997] {
        f.reset_attempts().await?;
        seed_work(&f, n, &template, &intent).await?;
        sqlx::raw_sql("ANALYZE identity_authority.attempts; ANALYZE identity_authority.password_attempts; ANALYZE identity_authority.oidc_transactions; ANALYZE identity_authority.link_intents").execute(&f.owner).await?;
        let request = || LoginRequest {
            binding: binding(f.key.tenant),
            provider: p.id,
            browser: BROWSER.into(),
            target: "home".into(),
            replacement: None,
            source: source(),
        };
        for case in [
            "new",
            "reuse",
            "password-new",
            "password-reuse",
            "expired-batch",
        ] {
            if case == "expired-batch" {
                sqlx::query("UPDATE identity_authority.attempts SET expires_at=now()-interval '1 minute' WHERE key IN (SELECT 'warm:'||i FROM generate_series(1,20) i)").execute(&f.owner).await?;
                sqlx::query("UPDATE identity_authority.password_attempts SET window_until=now()-interval '1 minute' WHERE failures>0").execute(&f.owner).await?;
                sqlx::query("UPDATE identity_authority.link_intents SET created_at=1,expires_at=2")
                    .execute(&f.owner)
                    .await?;
                sqlx::query(
                    "UPDATE identity_authority.oidc_transactions SET created_at=1,expires_at=2",
                )
                .execute(&f.owner)
                .await?;
            }
            let start = clock_us(&f).await?;
            if case.starts_with("password") {
                let result = store
                    .login_local(
                        binding(f.key.tenant),
                        login("unknown"),
                        password(),
                        source(),
                        None,
                        deadline(),
                    )
                    .await;
                assert!(matches!(result, Err(AuthorityError::Rejected)));
            } else {
                let mut req = request();
                if case == "expired-batch" {
                    req.source = AttemptSource::parse("cold")?;
                }
                fed.begin_login(req, deadline()).await?;
            }
            println!(
                "AUTH_WORK {}",
                json!({"database":f.database,"rows":n,"case":case,"start_us":start,"end_us":clock_us(&f).await?})
            );
        }
    }
    runtime.close().await;
    f.close().await;
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/measure/locks.py"
        ))
        .arg(network.name())
        .arg("--plans")
        .status()?;
    anyhow::ensure!(status.success(), "plan extraction failed");
    Ok(())
}

async fn seed_work(
    f: &Fixture,
    n: i32,
    template: &serde_json::Value,
    intent: &serde_json::Value,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO identity_authority.attempts SELECT $1::uuid,'warm:'||i,1,now()+interval '1 hour' FROM generate_series(1,$2) i").bind(A).bind(n-n/4).execute(&f.owner).await?;
    sqlx::query("INSERT INTO identity_authority.password_attempts(tenant_id,login_digest,failures,window_until)
       SELECT $1::uuid,sha256(int4send(i)),1,now()+interval '1 hour' FROM generate_series(1,$2) i").bind(A).bind(n/4).execute(&f.owner).await?;
    seed_inventory(f, n, template).await?;
    sqlx::query("DELETE FROM identity_authority.link_intents WHERE tenant_id=$1::uuid")
        .bind(A)
        .execute(&f.owner)
        .await?;
    sqlx::query("INSERT INTO identity_authority.link_intents SELECT r.* FROM generate_series(1,$2) i
        CROSS JOIN LATERAL jsonb_populate_record(NULL::identity_authority.link_intents,$1::jsonb ||
        jsonb_build_object('intent_id',md5(i::text)::uuid,'created_at',extract(epoch FROM now())::bigint,'expires_at',extract(epoch FROM now())::bigint+300)) r")
        .bind(intent).bind(n).execute(&f.owner).await?;
    sqlx::query("UPDATE identity_authority.oidc_transactions t SET purpose=2,link_intent=md5(i::text)::uuid
        FROM generate_series(1,$2) i WHERE t.tenant_id=$1::uuid AND t.attempt_id=sha256(int4send(i))")
        .bind(A).bind(n/2).execute(&f.owner).await?;
    Ok(())
}
