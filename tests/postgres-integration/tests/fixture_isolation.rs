//! Real Docker regression for network-scoped fixture identity and TLS readiness.
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::time::Duration;
use testkit::{NetworkAttachment, PgTlsFixture, PgTlsServerIdentity};

async fn verify(fixture: &PgTlsFixture, network: &str) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), verify_inner(fixture, network))
        .await
        .map_err(|_| anyhow::anyhow!("fixture SQL/DNS/TLS probe deadline elapsed"))?
}

async fn verify_inner(fixture: &PgTlsFixture, network: &str) -> anyhow::Result<()> {
    let p = fixture.params();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(
            PgConnectOptions::new()
                .host(&p.host)
                .port(p.port)
                .database(&p.database)
                .username(&p.username)
                .password(&p.password)
                .ssl_mode(PgSslMode::VerifyFull)
                .ssl_root_cert_from_pem(fixture.ca_pem().as_bytes().to_vec()),
        )
        .await?;
    let value: i32 = sqlx::query_scalar("SELECT 1").fetch_one(&pool).await?;
    assert_eq!(value, 1);
    pool.close().await;
    let ids = tokio::process::Command::new("docker")
        .args([
            "ps",
            "--filter",
            &format!("network={network}"),
            "--format",
            "{{.ID}}",
        ])
        .kill_on_drop(true)
        .output()
        .await?;
    anyhow::ensure!(ids.status.success(), "fixture lookup failed");
    let id = String::from_utf8(ids.stdout)?;
    anyhow::ensure!(
        id.lines().count() == 1,
        "expected one fixture on isolated network"
    );
    // Resolving the original DNS alias and verifying its SAN proves that globally
    // unique identity did not silently change container-to-container TLS semantics.
    let probe = tokio::process::Command::new("docker")
        .args(["exec", "-e", "PGPASSWORD=postgres", id.trim(), "psql",
            "host=fixture-pg dbname=rss_test user=postgres sslmode=verify-full sslrootcert=/rss-tls/ca.pem connect_timeout=5",
            "-Atc", "SELECT 1"])
        .kill_on_drop(true).output().await?;
    anyhow::ensure!(probe.status.success(), "network DNS/TLS probe failed");
    assert_eq!(String::from_utf8(probe.stdout)?.trim(), "1");
    Ok(())
}

#[tokio::test]
async fn same_dns_on_independent_networks_keeps_tls_and_cleanup_isolated() -> anyhow::Result<()> {
    let first_network = testkit::bridge_network("fixture-first").await?;
    let second_network = testkit::bridge_network("fixture-second").await?;
    let start = |network| {
        testkit::postgres_tls(
            NetworkAttachment {
                network,
                dns_name: "fixture-pg",
            },
            PgTlsServerIdentity::MatchingHost,
        )
    };
    // join retains the successful fixture even when the other creation fails,
    // then ordinary scope drop cleans both outcomes.
    let (first, second) = tokio::join!(start(first_network.name()), start(second_network.name()));
    let first = first?;
    let second = second?;
    verify(&first, first_network.name()).await?;
    verify(&second, second_network.name()).await?;
    drop(first);
    drop(first_network);
    verify(&second, second_network.name()).await?;
    let missing = format!("missing-{}", second_network.name());
    let failure = testkit::postgres_tls(
        NetworkAttachment {
            network: &missing,
            dns_name: "fixture-pg",
        },
        PgTlsServerIdentity::MatchingHost,
    )
    .await;
    let failure = failure
        .err()
        .ok_or_else(|| anyhow::anyhow!("missing network must fail construction"))?;
    anyhow::ensure!(
        format!("{failure:#}").contains("reason=not-found"),
        "missing network must preserve its safe failure category"
    );
    // A failed attachment must not disconnect or clean up another fixture.
    verify(&second, second_network.name()).await?;
    Ok::<_, anyhow::Error>(())
}
