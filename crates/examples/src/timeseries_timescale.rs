//! Same public behavior as PostgreSQL, with explicit Timescale deployment inputs.
use rss_request_context::TenantId;
use rss_timeseries_postgres::{
    StorageProfile,
    timescale::{DedicatedTenant, Hypertable},
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::num::NonZeroU64;
#[derive(serde::Deserialize)]
pub struct Input {
    #[serde(flatten)]
    pub common: crate::timeseries_pg::Input,
    pub deployment: Deployment,
}
#[derive(serde::Deserialize)]
#[serde(tag = "profile", rename_all = "camelCase")]
pub enum Deployment {
    Shared,
    Dedicated { maintenance: crate::pg::Input },
}
fn profile(input: &Input) -> anyhow::Result<StorageProfile> {
    let chunk = Hypertable::new(NonZeroU64::new(100).ok_or_else(|| anyhow::anyhow!("chunk"))?)?;
    Ok(match input.deployment {
        Deployment::Shared => StorageProfile::TimescaleSharedRls(chunk),
        Deployment::Dedicated { .. } => {
            StorageProfile::TimescaleDedicatedTenant(DedicatedTenant::new(
                TenantId::parse(&input.common.pg.tenant)?,
                chunk,
                &[NonZeroU64::new(100).ok_or_else(|| anyhow::anyhow!("resolution"))?],
            )?)
        }
    })
}
pub async fn install(input: Input) -> anyhow::Result<()> {
    let profile = profile(&input)?;
    let pool = input.common.pg.pool().await?;
    let mut c = pool.acquire().await?;
    sqlx::query("SET ROLE ts_owner").execute(&mut *c).await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(profile.installation_sql()?.as_str()))
        .execute(&mut *c)
        .await?;
    drop(c);
    pool.close().await;
    Ok(())
}
pub async fn run(input: Input) -> anyhow::Result<()> {
    let profile = profile(&input)?;
    let maintenance = match &input.deployment {
        Deployment::Shared => None,
        Deployment::Dedicated { maintenance: p } => Some(
            PgPoolOptions::new()
                .max_connections(2)
                .after_connect(|c, _| {
                    Box::pin(async move {
                        sqlx::query("SET ROLE ts_owner").execute(c).await?;
                        Ok(())
                    })
                })
                .connect_with(
                    PgConnectOptions::new()
                        .host(&p.host)
                        .port(p.port)
                        .database(&p.database)
                        .username(&p.username)
                        .password(&p.password)
                        .ssl_mode(PgSslMode::VerifyFull)
                        .ssl_root_cert_from_pem(p.pg_ca.as_bytes().to_vec()),
                )
                .await?,
        ),
    };
    crate::timeseries_pg::run_on(input.common, profile, maintenance).await
}
