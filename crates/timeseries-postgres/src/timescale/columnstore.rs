use crate::{PgStore, StorageProfile, transaction::sql_error};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::{Error, Interval, Outcome};
use sqlx::Row;
use std::num::NonZeroU32;

#[derive(Clone, Copy, Debug)]
pub enum StorageFormat {
    Rowstore,
    Columnstore,
}
impl<C: Clock> PgStore<C> {
    /// Host-owned physical administration for a dedicated tenant installation.
    /// Converts at most `max_chunks` complete raw chunks within the explicit window.
    /// This changes no logical visibility or retention policy. Repetition is idempotent;
    /// cancellation may leave a subset converted and therefore returns Unknown.
    pub async fn convert_raw_chunks(
        &self,
        window: Interval,
        max_chunks: NonZeroU32,
        format: StorageFormat,
        deadline: Deadline,
    ) -> Result<Outcome<u32>, Error> {
        if !matches!(self.profile, StorageProfile::TimescaleDedicatedTenant(_)) {
            return Err(Error::Unsupported);
        }
        if max_chunks.get() > 32 || window.width_micros() == 0 {
            return Err(Error::InvalidInput);
        }
        let pool = self.maintenance.as_ref().ok_or(Error::Invariant)?;
        let mut connection = tokio::time::timeout(
            deadline
                .remaining(self.clock.now())
                .ok_or(Error::Deadline)?,
            pool.acquire(),
        )
        .await
        .map_err(|_| Error::Deadline)?
        .map_err(sql_error)?;
        connection.close_on_drop();
        let remaining = deadline
            .remaining(self.clock.now())
            .ok_or(Error::Deadline)?;
        let ms = remaining.as_millis().clamp(1, i32::MAX as u128);
        tokio::time::timeout(remaining,sqlx::query("SELECT set_config('statement_timeout',$1,false),set_config('lock_timeout',$1,false)").bind(format!("{ms}ms")).execute(&mut *connection)).await.map_err(|_|Error::Deadline)?.map_err(sql_error)?;
        let rows=tokio::time::timeout(deadline.remaining(self.clock.now()).ok_or(Error::Deadline)?,sqlx::query("SELECT format('%I.%I',chunk_schema,chunk_name) AS name FROM timescaledb_information.chunks WHERE hypertable_schema='rss_timeseries' AND hypertable_name='samples' AND range_start_integer >= $1 AND range_end_integer <= $2 AND is_compressed=$3 ORDER BY range_start_integer,chunk_name LIMIT $4")
            .bind(window.start().micros()).bind(window.end().micros()).bind(matches!(format,StorageFormat::Rowstore)).bind(i64::from(max_chunks.get())).fetch_all(&mut *connection)).await.map_err(|_|Error::Deadline)?.map_err(sql_error)?;
        let sql = match format {
            StorageFormat::Rowstore => {
                "CALL public.convert_to_rowstore($1::text::regclass,if_columnstore=>true)"
            }
            StorageFormat::Columnstore => {
                "CALL public.convert_to_columnstore($1::text::regclass,if_not_columnstore=>true)"
            }
        };
        let mut converted = 0;
        for row in rows {
            let name: String = row.try_get("name").map_err(sql_error)?;
            let Some(remaining) = deadline.remaining(self.clock.now()) else {
                return Ok(Outcome::Unknown);
            };
            let ms = remaining.as_millis().clamp(1, i32::MAX as u128);
            let operation = async {
                sqlx::query("SELECT set_config('statement_timeout',$1,false),set_config('lock_timeout',$1,false)").bind(format!("{ms}ms")).execute(&mut *connection).await?;
                sqlx::query(sql).bind(name).execute(&mut *connection).await
            };
            match tokio::time::timeout(remaining, operation).await {
                Ok(Ok(_)) => converted += 1,
                // reason: conversion is physical and idempotent; a lost response is not rollback proof.
                _ => return Ok(Outcome::Unknown),
            }
        }
        Ok(Outcome::Accepted(converted))
    }
}
