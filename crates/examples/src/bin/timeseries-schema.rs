//! Emit a fresh installation for review and owner execution; never connects to a database.
use rss_timeseries_postgres::StorageProfile;
use std::io::Write;
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let profile = match args.first().map(String::as_str) {
        Some("pg") => StorageProfile::PostgreSQL,
        #[cfg(feature = "timeseries-timescaledb")]
        Some("shared") => StorageProfile::TimescaleSharedRls(hypertable()?),
        #[cfg(feature = "timeseries-timescaledb")]
        Some("dedicated") => StorageProfile::TimescaleDedicatedTenant(
            rss_timeseries_postgres::timescale::DedicatedTenant::new(
                rss_request_context::TenantId::parse(
                    args.get(1)
                        .ok_or_else(|| anyhow::anyhow!("tenant required"))?,
                )?,
                hypertable()?,
                &[std::num::NonZeroU64::new(10).ok_or_else(|| anyhow::anyhow!("resolution"))?],
            )?,
        ),
        _ => anyhow::bail!("usage: timeseries-schema pg|shared|dedicated [tenant]"),
    };
    std::io::stdout().write_all(profile.installation_sql()?.as_bytes())?;
    Ok(())
}
#[cfg(feature = "timeseries-timescaledb")]
fn hypertable() -> anyhow::Result<rss_timeseries_postgres::timescale::Hypertable> {
    Ok(rss_timeseries_postgres::timescale::Hypertable::new(
        std::num::NonZeroU64::new(100).ok_or_else(|| anyhow::anyhow!("chunk interval"))?,
    )?)
}
