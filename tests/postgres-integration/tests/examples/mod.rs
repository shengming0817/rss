//! Fixture owner for real PG/AMQP example consumers.
use std::time::Duration;
use testkit::example_process::run_binary;

pub(super) async fn run(
    pg: &testkit::PgTlsFixture,
    network: &testkit::BridgeNetwork,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    let route = "rss.example";
    let broker = testkit::rabbitmq_tls(
        route,
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "example-broker",
        },
    )
    .await?;
    let params = pg.params();
    let binaries: Vec<String> = match std::env::var("RSS_EXAMPLE_CONSUMERS") {
        Ok(value) => {
            let values: Vec<String> = serde_json::from_str(&value)?;
            anyhow::ensure!(!values.is_empty(), "empty external example selection");
            values
        }
        Err(std::env::VarError::NotPresent) => vec![String::new()],
        Err(error) => return Err(error.into()),
    };
    for (index, binary) in binaries.iter().enumerate() {
        let id = format!("external-example-{index}");
        let input = serde_json::json!({
            "host": params.host, "port": params.port, "database": params.database,
            "username": "tmsg_runtime", "password": "fixture-only", "pg_ca": pg.ca_pem(),
            "tenant": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "target": ([1; 16]), "lineage": ([2; 16]), "epoch": 1,
            "id": id, "route": route, "publisher_url": broker.publisher_url(), "subscriber_url": broker.subscriber_url(), "amqp_ca": broker.ca_pem(),
        });
        if binary.is_empty() {
            rss_examples::providers::run(serde_json::from_value(input)?).await?;
        } else {
            run_binary(binary, &input, Duration::from_secs(60)).await?;
        }
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public.business_effects WHERE id=$1")
                .bind(id)
                .fetch_one(owner)
                .await?;
        assert_eq!(count, 1, "real business effect committed once");
        if !binary.is_empty() {
            eprintln!("external-provider-consumer PASS {binary}");
        }
    }
    Ok(())
}
