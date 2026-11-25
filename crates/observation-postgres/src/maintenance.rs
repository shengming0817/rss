use crate::{
    PgStore,
    transaction::{Stage, sql_error},
};
use rss_observation::{
    Clock, Error, ErrorKind, MaintenanceGrant, ObservationMaintenance, RetentionPage, ScanWindow,
};
use rss_request_context::Deadline;
use sqlx::{PgPool, Row};

/// Dedicated tenant-scoped maintenance credential; admission, settlement and close
/// use the same deadline/clock engine as the reception store.
pub struct PgMaintenance<C>(PgStore<C>);
impl<C: Clock> PgMaintenance<C> {
    /// Adopt a dedicated maintenance pool after checking its privileges and schema.
    pub async fn new(pool: PgPool, clock: C, deadline: Deadline) -> Result<Self, Error> {
        PgStore::admit(pool, clock, deadline, None, true)
            .await
            .map(Self)
    }
    /// Close admission and await outstanding operations under this deadline.
    pub async fn close(&self, deadline: Deadline) -> Result<(), Error> {
        self.0.close(deadline).await
    }
    #[cfg(feature = "integration")]
    /// Apply a one-shot fixture fault to the next operation.
    pub fn inject_next_fault(&self, fault: crate::Fault) {
        self.0.inject_next_fault(fault);
    }
}
impl<C: Clock> ObservationMaintenance for PgMaintenance<C> {
    async fn reclaim(
        &self,
        grant: &MaintenanceGrant,
        window: ScanWindow,
        deadline: Deadline,
    ) -> Result<RetentionPage, Error> {
        let scope = grant.scope().encode()?;
        let cutoff = grant.cutoff();
        let through = grant.release_through();
        self.0.transact(grant.scope().tenant(),deadline,self.0.take_fault(),move |connection,progress|Box::pin(async move {
            progress.set(Stage::Effects);
            let row=sqlx::query("SELECT last_examined::text,scanned,reclaimed,released_bytes FROM rss_observation.reclaim($1,$2,$3,$4::numeric,$5)")
                .bind(scope).bind(cutoff).bind(through).bind(window.after().map(|v|v.to_string())).bind(i32::from(window.limit()))
                .fetch_one(connection).await.map_err(sql_error)?;
            let scanned:i32=row.try_get("scanned").map_err(sql_error)?;
            let reclaimed:i32=row.try_get("reclaimed").map_err(sql_error)?;
            let bytes:i64=row.try_get("released_bytes").map_err(sql_error)?;
            let last:Option<String>=row.try_get("last_examined").map_err(sql_error)?;
            Ok(RetentionPage {
                last_examined:last.map(|v|v.parse().map_err(|_|ErrorKind::Invariant)).transpose()?,
                finished:scanned<i32::from(window.limit()), scanned:scanned.try_into().map_err(|_|ErrorKind::Invariant)?,
                reclaimed:reclaimed.try_into().map_err(|_|ErrorKind::Invariant)?, released_bytes:bytes.try_into().map_err(|_|ErrorKind::Invariant)?,
            })
        })).await
    }
}
