//! Single-object archive proof using real PostgreSQL and a verified Object Lock bucket.
use crate::recovery::{Input as RecoveryInput, Timer, binding, config, deadline, settled};
use aws_sdk_s3::{
    Client,
    config::{Credentials, Region},
};
use aws_smithy_http_client::tls::{self, TrustStore};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::{ExecutionBudget, ExecutionDeadlines, OperationDeadline};
use rss_transactional_messaging_postgres::PgArchiveRepository;
use rss_transactional_messaging_recovery::{DeadLetterId, OperationId, Version, archive::*};
use rss_transactional_messaging_recovery_s3::{Clock, Unverified};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[derive(serde::Deserialize)]
pub struct Input {
    #[serde(flatten)]
    pub recovery: RecoveryInput,
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    pub s3_ca: String,
    pub bucket: String,
}
struct Wall;
impl Clock for Wall {
    #[allow(clippy::disallowed_methods)] // reason: concrete Object Lock wall-clock source supplied by the host.
    fn unix_seconds(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64)
    }
}
struct Allow;
impl Authorizer for Allow {
    async fn authorize(
        &self,
        c: Challenge<'_>,
        _: OperationDeadline,
    ) -> Result<Authorization, Error> {
        // reason: fixture authorizes its single supplied tenant/record, not a product policy.
        Ok(c.authorized())
    }
}
struct Observe;
impl Observer for Observe {
    fn observe(&self, _: Event) {} // reason: fixture uses durable state assertions, not telemetry.
}
pub async fn run(input: Input) -> anyhow::Result<()> {
    let tls = tls::TlsContext::builder()
        .with_trust_store(TrustStore::empty().with_pem_certificate(input.s3_ca.into_bytes()))
        .build()?;
    let http = aws_smithy_http_client::Builder::new()
        .tls_provider(tls::Provider::Rustls(
            tls::rustls_provider::CryptoMode::Ring,
        ))
        .tls_context(tls)
        .build_https();
    let client = Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .endpoint_url(input.endpoint)
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new(
                input.access_key,
                input.secret_key,
                None,
                None,
                "example",
            ))
            .force_path_style(true)
            .http_client(http)
            .build(),
    );
    let store = Unverified::new(client, input.bucket)?
        .verify(&Wall, deadline()?)
        .await?;
    let pg = &input.recovery.pg;
    let repository = PgArchiveRepository::connect(config(pg)?, Timer, binding(pg)?).await?;
    let hot = HotKey(crate::ephemeral::EphemeralKey::from_bytes(
        &input.recovery.hot_key,
        "example-hot",
    )?);
    let cold = ArchiveKey(crate::ephemeral::EphemeralKey::from_bytes(
        &input.recovery.cold_key,
        "example-cold",
    )?);
    let request = authorize(
        &Allow,
        Request::new(
            TenantId::parse(&pg.tenant)?,
            DeadLetterId::parse(&input.recovery.dead_letter)?,
            OperationId::new(),
            Version::new(1)?,
            Retention::new(172800, 604800)?,
            Hold::Release,
        ),
        &Timer,
        rss_request_context::Deadline::from_timeout(&Timer, Duration::from_secs(30))?,
    )
    .await?;
    let budgets = ExecutionDeadlines::from_budget(
        &Timer,
        ExecutionBudget::new(Duration::from_secs(30), Duration::from_secs(5))?,
    )?;
    anyhow::ensure!(
        settled(
            execute(
                &repository,
                &store,
                &hot,
                &cold,
                &request,
                &Timer,
                budgets,
                &Observe
            )
            .await
        )? == Outcome::Purged,
        "archive did not purge HOT"
    );
    let pool = pg.pool().await?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(&pg.tenant)
        .execute(&mut *tx)
        .await?;
    let object:serde_json::Value=sqlx::query_scalar("SELECT object FROM rss_transactional_messaging.archive_objects WHERE verified AND prepared IS NULL").fetch_one(&mut *tx).await?;
    let object: Object = serde_json::from_value(object)?;
    anyhow::ensure!(object.version.is_some(), "archive version missing");
    anyhow::ensure!(
        store
            .inspect(&object, true, deadline()?)
            .await?
            .is_some_and(|actual| actual.object == object
                && actual.compliance
                && actual.bytes.is_some()),
        "archive exact-object readback mismatch"
    );
    tx.commit().await?;
    pool.close().await;
    repository.close().await;
    Ok(())
}
