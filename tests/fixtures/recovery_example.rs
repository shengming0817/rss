//! Shared provisioning for the two recovery artifact scenarios; never a library dependency.
use crate::fence_fixture as fence;
use std::time::Duration;
pub const TENANT: &str = "11111111-1111-1111-1111-111111111111";
pub struct Fixture {
    pub _pg: testkit::PgTlsFixture,
    pub admin: sqlx::PgPool,
    pub input: serde_json::Value,
}
impl Fixture {
    pub async fn new(network: &testkit::BridgeNetwork) -> anyhow::Result<Self> {
        let pg = testkit::postgres_tls(
            testkit::NetworkAttachment {
                network: network.name(),
                dns_name: "recovery-example",
            },
            testkit::PgTlsServerIdentity::MatchingHost,
        )
        .await?;
        let p = pg.params();
        let mut input = testkit::example_process::pg_input(&pg, &p.username, TENANT);
        input["password"] = serde_json::json!(p.password);
        let admin = serde_json::from_value::<rss_examples::pg::Input>(input)?
            .pool()
            .await?;
        sqlx::raw_sql("CREATE ROLE example_owner LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; CREATE ROLE recovery_runtime LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; CREATE ROLE recovery_operator LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; CREATE ROLE archive_worker LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS; GRANT rss_tmsg_relay TO example_owner; GRANT CREATE ON DATABASE rss_test TO example_owner;").execute(&admin).await?;
        use ring::rand::SecureRandom;
        let mut hot = [0u8; 32];
        let mut cold = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut hot)
            .map_err(|_| anyhow::anyhow!("example key generation failed"))?;
        ring::rand::SystemRandom::new()
            .fill(&mut cold)
            .map_err(|_| anyhow::anyhow!("example key generation failed"))?;
        let mut input = testkit::example_process::pg_input(&pg, "example_owner", TENANT);
        input["hot_key"] = serde_json::json!(hot);
        input["cold_key"] = serde_json::json!(cold);
        input["dead_letter"] = serde_json::json!("00000000-0000-0000-0000-000000000091");
        match std::env::var("RSS_RECOVERY_INSTALL") {
            Ok(binary) => {
                testkit::example_process::run_binary(&binary, &input, Duration::from_secs(45))
                    .await?;
                eprintln!("external-provider-consumer PASS {binary}");
            }
            Err(std::env::VarError::NotPresent) => {
                rss_examples::recovery::install(serde_json::from_value(input.clone())?).await?
            }
            Err(e) => return Err(e.into()),
        }
        sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO recovery_operator; GRANT SELECT ON rss_transactional_messaging.policy TO recovery_operator; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO recovery_operator; GRANT SELECT,UPDATE(status,recovery_version,lease_token,lease_until,retry_after) ON rss_transactional_messaging.outbox TO recovery_operator; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(text,text,text,jsonb,bytea) TO recovery_operator; GRANT SELECT,INSERT,UPDATE(recovery_version) ON rss_transactional_messaging.consumer_dead_letter TO recovery_operator; GRANT SELECT,INSERT ON rss_transactional_messaging.recovery_operations TO recovery_operator; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) TO recovery_operator;").execute(&admin).await?;
        sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO archive_worker; GRANT SELECT ON rss_transactional_messaging.consumer_dead_letter,rss_transactional_messaging.archive_jobs,rss_transactional_messaging.archive_objects TO archive_worker; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.archive_claim(uuid,uuid,bigint,bytea,bigint,bigint,boolean,bigint),rss_transactional_messaging.archive_prepare(uuid,uuid,bytea,jsonb,bytea),rss_transactional_messaging.archive_record(uuid,uuid,bytea,uuid,jsonb),rss_transactional_messaging.archive_purge(uuid,uuid,bytea,jsonb),rss_transactional_messaging.archive_missing(uuid,uuid,bytea,uuid,jsonb),rss_transactional_messaging.archive_fault(uuid,uuid,bytea,text) TO archive_worker;").execute(&admin).await?;
        anyhow::ensure!(
            fence::binding().storage()
                == rss_transactional_messaging::fence::StorageIdentity::new([1; 16], [2; 16])?,
            "example storage authority drift"
        );
        sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO recovery_runtime; GRANT SELECT ON rss_transactional_messaging.policy TO recovery_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO recovery_runtime; GRANT SELECT ON rss_transactional_messaging.outbox TO recovery_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(text,text,text,jsonb,bytea) TO recovery_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) TO recovery_runtime;").execute(&admin).await?;
        fence::provision(&admin).await?;
        Ok(Self {
            _pg: pg,
            admin,
            input,
        })
    }
    pub fn input(&self, role: &str) -> serde_json::Value {
        let mut input = self.input.clone();
        input["username"] = serde_json::json!(role);
        input
    }
}
