//! Opt-in paired PG 17.6 experiment. Use the same test source on the epic baseline and candidate.
//! RSS_AUTH_TRACE=1 runs a shorter diagnostic lane, with server statement and wait logging.
#![allow(
    clippy::disallowed_methods,
    reason = "measurement clock and machine-readable results"
)]
use super::*;
use crate::federation_support::{self as oidc, BROWSER};
use futures::future::try_join_all;
use rss_identity_core::{
    account::PasswordKdf,
    federation::{ProviderCredentials, ProviderId},
};
use rss_identity_postgres::platform::PlatformPurpose;
use serde_json::json;
use std::num::{NonZeroU64, NonZeroUsize};
mod controls;
mod platform;
mod work;

struct Subject {
    key: AccountKey,
    name: String,
    provider: ProviderId,
}
struct Sample {
    local: u128,
    begin: u128,
    callback: u128,
    challenge: u128,
    issue: u128,
    local_profile: bool,
}

async fn subjects(
    f: &Fixture,
    store: &Authority,
    federation: &Federation,
    multi: bool,
) -> anyhow::Result<Vec<Subject>> {
    let mut result = vec![];
    let tenants = if multi {
        vec![(f.key, "admin"), (f.system_key, "platform")]
    } else {
        vec![(f.key, "admin")]
    };
    let per_tenant = 16 / tenants.len();
    for (root, admin_login) in tenants {
        let scope = binding(root.tenant);
        let session = store
            .login_local(
                scope,
                login(admin_login),
                password(),
                source(),
                None,
                deadline(),
            )
            .await?;
        let actor = || store.inspect_session(scope, oidc::secret(&session), deadline());
        let provider = federation
            .create_provider(
                actor().await?,
                oidc::settings(),
                ProviderCredentials::new("fixture-secret".into(), None)?,
                deadline(),
            )
            .await?;
        let provider = federation
            .enable_provider(
                actor().await?,
                provider.id,
                provider.version,
                true,
                deadline(),
            )
            .await?;
        for i in 0..per_tenant {
            let name = format!("bench-{i}");
            let account = store
                .create_local_account(actor().await?, login(&name), password(), deadline())
                .await?;
            result.push(Subject {
                key: account.key(),
                name,
                provider: provider.id,
            });
        }
        sqlx::query("INSERT INTO identity_authority.attempts SELECT $1::uuid,'warm:'||i,1,now()+interval '1 hour' FROM generate_series(1,5000) i")
            .bind(root.tenant.to_string()).execute(&f.owner).await?;
    }
    sqlx::raw_sql(
        "ANALYZE identity_authority.attempts; ANALYZE identity_authority.password_attempts",
    )
    .execute(&f.owner)
    .await?;
    Ok(result)
}
async fn once(
    store: &Authority,
    federation: &Federation,
    s: &Subject,
    local_profile: bool,
) -> anyhow::Result<Sample> {
    let scope = binding(s.key.tenant);
    let t = Instant::now();
    store
        .login_local(
            scope,
            login(&s.name),
            password(),
            source(),
            None,
            deadline(),
        )
        .await?;
    let local = t.elapsed().as_micros();
    let t = Instant::now();
    let redirect = federation
        .begin_login(
            LoginRequest {
                binding: scope,
                provider: s.provider,
                browser: BROWSER.into(),
                target: "home".into(),
                replacement: None,
                source: source(),
            },
            deadline(),
        )
        .await?;
    let begin = t.elapsed().as_micros();
    let state = oidc::state(redirect);
    let t = Instant::now();
    let _session = oidc::issued(oidc::finish(federation, state, &s.name).await?);
    let callback = t.elapsed().as_micros();
    let t = Instant::now();
    let challenge = store
        .begin_platform_login(
            scope,
            s.key.principal.as_uuid(),
            PlatformPurpose::BrowserLogin,
            BROWSER.into(),
            source(),
            deadline(),
        )
        .await?;
    let challenge_us = t.elapsed().as_micros();
    let mut evidence = vec![u8::from(local_profile)];
    evidence.extend(challenge.signing_payload);
    let t = Instant::now();
    store
        .complete_platform_login(
            scope,
            challenge.id,
            challenge.nonce,
            BROWSER.into(),
            evidence,
            deadline(),
        )
        .await?;
    Ok(Sample {
        local,
        begin,
        callback,
        challenge: challenge_us,
        issue: t.elapsed().as_micros(),
        local_profile,
    })
}
async fn run_group(
    store: &Authority,
    fed: &Federation,
    subjects: &[Subject],
    lanes: usize,
    calls: usize,
) -> anyhow::Result<Vec<Sample>> {
    let workers = (0..lanes).map(|lane| async move {
        let mut samples = vec![];
        for i in (lane..calls).step_by(lanes) {
            samples.push(once(store, fed, &subjects[i % subjects.len()], i % 2 == 0).await?);
        }
        anyhow::Ok(samples)
    });
    Ok(try_join_all(workers).await?.into_iter().flatten().collect())
}
async fn clock_us(f: &Fixture) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&f.owner)
            .await?,
    )
}

#[allow(clippy::unwrap_used, reason = "fixed positive experiment budgets")]
async fn run_fixture(
    pg: &testkit::PgTlsFixture,
    ledger: bool,
    multi: bool,
    trace: bool,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let integrity = if ledger {
        rss_audit_postgres::Integrity::Ledger(Arc::new(rss_ledger::Authenticator::new(
            rss_ledger::KeyId::parse("measure")?,
            vec![7; 32],
        )?))
    } else {
        rss_audit_postgres::Integrity::Plain
    };
    let f = Fixture::new(pg, integrity).await?;
    f.bootstrap().await?;
    let policy = AttemptWindow::new(1_000_000, 3600)?;
    let config = f
        .config()
        .with_platform(Arc::new(platform::FixturePlatform))
        .with_authentication_policy(AuthenticationPolicy::new(
            policy,
            policy,
            policy,
            10000,
            128,
            Duration::from_secs(30),
        )?);
    if trace {
        for setting in [
            "log_min_duration_statement=0",
            "log_parameter_max_length=0",
            "log_lock_waits=on",
            "deadlock_timeout='1ms'",
        ] {
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "ALTER ROLE identity_runtime IN DATABASE {} SET {setting}",
                f.database
            )))
            .execute(&f.owner)
            .await?;
        }
        sqlx::query("ALTER SYSTEM SET log_line_prefix='%n|%p|%d| '")
            .execute(&f.owner)
            .await?;
        sqlx::query("SELECT pg_reload_conf()")
            .execute(&f.owner)
            .await?;
    }
    let runtime = Arc::new(
        PgRuntime::connect_producer(
            PgConfig::new(
                &f.provider.host,
                f.provider.port,
                &f.database,
                "identity_runtime",
                PgPassword::new("fixture-only"),
                rss_transactional_messaging_postgres::PgPrivateCa::from_pem(
                    f.ca.as_bytes().to_vec(),
                )?,
            )
            .with_pool_limits(16, 16),
            Timer,
            StorageIdentity::new([1; 16], [2; 16])?,
        )
        .await?,
    );
    let store = Authority::connect_runtime(
        runtime.clone(),
        Arc::new(PasswordKdf::new(
            NonZeroUsize::new(16).unwrap(),
            NonZeroU64::new(512 * 1024 * 1024).unwrap(),
        )?),
        config,
        binding(f.key.tenant),
        f.policy.clone(),
        deadline(),
    )
    .await?;
    let federation = oidc::service_for(store.clone(), oidc::settings().redirect_uri());
    let subjects = subjects(&f, &store, &federation, multi).await?;
    for lanes in [1, 8, 16] {
        run_group(&store, &federation, &subjects, lanes, 16).await?;
        for round in 0..if trace { 1 } else { 3 } {
            let start = clock_us(&f).await?;
            let samples = run_group(
                &store,
                &federation,
                &subjects,
                lanes,
                if trace { 32 } else { 160 },
            )
            .await?;
            let end = clock_us(&f).await?;
            let times: Vec<_> = samples
                .iter()
                .map(|s| {
                    [
                        s.local,
                        s.begin,
                        s.callback,
                        s.challenge,
                        s.issue,
                        u128::from(s.local_profile),
                    ]
                })
                .collect();
            println!(
                "AUTH_MEASURE {}",
                json!({"database":f.database,"ledger":ledger,"multi":multi,"lanes":lanes,"round":round,"trace":trace,"start_us":start,"end_us":end,"samples_us":times})
            );
        }
    }
    let controls = if trace && !ledger && !multi {
        controls::collect(&f, &federation, subjects[0].provider).await?
    } else {
        vec![]
    };
    drop(store);
    drop(federation);
    runtime.close().await;
    f.close().await;
    Ok(controls)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "paired identity capacity and sequence contention experiment"]
#[allow(clippy::unwrap_used, reason = "fixed measurement parameters")]
async fn contention() -> anyhow::Result<()> {
    let network = testkit::bridge_network("identity-contention").await?;
    let pg = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "identity-pg",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let trace = std::env::var_os("RSS_AUTH_TRACE").is_some();
    let mut controls = vec![];
    for ledger in [false, true] {
        for multi in [false, true] {
            controls.extend(run_fixture(&pg, ledger, multi, trace).await?);
        }
    }
    if trace {
        let status = std::process::Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/support/measure/locks.py"
            ))
            .arg(network.name())
            .arg(serde_json::to_string(&controls)?)
            .status()?;
        anyhow::ensure!(status.success(), "PG trace extraction failed");
    }
    Ok(())
}
