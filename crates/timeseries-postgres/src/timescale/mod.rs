//! Explicit TimescaleDB 2.30.2 deployment support; no implicit extension installation.
// ref: timescale/timescaledb tsl/src/continuous_aggs/common.c@2.30.2
use rss_request_context::TenantId;
use rss_timeseries::Error;
use std::num::NonZeroU64;
mod columnstore;
pub(crate) mod install;
pub(crate) mod probe;
pub use columnstore::StorageFormat;

pub const EXTENSION_VERSION: &str = "2.30.2";
/// Bigint microsecond hypertable configuration.
#[derive(Clone, Debug)]
pub struct Hypertable {
    pub(crate) chunk_micros: i64,
}
impl Hypertable {
    pub fn new(chunk_micros: NonZeroU64) -> Result<Self, Error> {
        Ok(Self {
            chunk_micros: i64::try_from(chunk_micros.get()).map_err(|_| Error::NumericRange)?,
        })
    }
}
/// A fixed tenant and finite materialization manifest.
#[derive(Clone)]
pub struct DedicatedTenant {
    pub(crate) tenant: TenantId,
    pub(crate) hypertable: Hypertable,
    pub(crate) resolutions: Vec<i64>,
}
impl DedicatedTenant {
    pub fn new(
        tenant: TenantId,
        hypertable: Hypertable,
        resolutions: &[NonZeroU64],
    ) -> Result<Self, Error> {
        if resolutions.is_empty() || resolutions.len() > 32 {
            return Err(Error::InvalidInput);
        }
        let mut resolutions: Vec<i64> = resolutions
            .iter()
            .map(|r| i64::try_from(r.get()).map_err(|_| Error::NumericRange))
            .collect::<Result<_, _>>()?;
        resolutions.sort_unstable();
        if resolutions.windows(2).any(|v| v[0] == v[1]) {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            tenant,
            hypertable,
            resolutions,
        })
    }
}
