use super::*;
use rss_projection::EventWith;
use rss_projection_postgres::PgTransaction;
use sqlx::ValueRef;

// Evaluate the current bytes even when the durable fingerprint column is unchanged.
// A changed row returns its body in this same READ COMMITTED statement for normal recovery.
const RECHECK: &str = "SELECT raw IS NULL AS expired, scope,batch_id,fingerprint,received_at,policy,
 decision,sequence::text AS sequence,applicable,log_position,
 CASE WHEN pg_catalog.sha256($3::bytea || raw)=$4 THEN
   CASE WHEN fingerprint=$4 AND scope COLLATE \"C\"=$5 AND batch_id COLLATE \"C\"=$6
     AND sequence::text COLLATE \"C\"=$7 AND received_at=$8 AND policy COLLATE \"C\"=$9
     AND decision COLLATE \"C\"=$10 THEN NULL ELSE raw END
 ELSE raw END AS raw FROM rss_observation.batches WHERE tenant_id=$1::uuid AND log_position=$2 AND applicable";

/// Same-database source mode. The byte bound applies to canonical reports in one atomic page.
pub struct LocalPages;

/// Observation evidence held by a page item. The adapter alone constructs this value;
/// use the borrowed transaction resolver to access the underlying record.
pub struct VerifiedObservation {
    fingerprint: [u8; 32],
    record: Arc<ApplicableRecord>,
}

impl<C: Clock> PgSource<C> {
    /// Select typed same-database handoff using this source's canonical-byte budget.
    pub fn into_local(self) -> PgSource<C, LocalPages> {
        PgSource {
            store: self.store,
            scope: self.scope,
            grant: self.grant,
            page_bytes: self.page_bytes,
            mode: std::marker::PhantomData,
        }
    }
}

impl<C: Clock> Source for PgSource<C, LocalPages> {
    type Item = EventWith<VerifiedObservation>;
    async fn high_water<T: Timer>(
        &self,
        scope: &SourceScope,
        control: &Control<'_, T>,
    ) -> Result<Option<Position>, rss_projection::Error> {
        self.check(scope).map_err(source_error)?;
        Ok(self.bounds(control).await?.high_water)
    }
    async fn read<T: Timer>(
        &self,
        scope: &SourceScope,
        after: Option<Position>,
        limit: BatchLimit,
        control: &Control<'_, T>,
    ) -> Result<Vec<Self::Item>, rss_projection::Error> {
        self.read_page(
            scope,
            after,
            limit,
            control,
            |source, pos, record, fingerprint| {
                let reference = reference_event(
                    source,
                    pos,
                    record.record().scope(),
                    record.record().batch().id(),
                    fingerprint,
                )?;
                Ok(reference.with_data(VerifiedObservation {
                    fingerprint,
                    record: Arc::new(record),
                }))
            },
        )
        .await
    }
}

impl<C: Clock> PgSource<C, LocalPages> {
    /// Recheck the page item at this callback's statement snapshot on the effect transaction.
    /// A matching row reuses the page's immutable record. Missing, released or changed rows
    /// retain the same restoration diagnostics as exact reference resolution.
    pub async fn resolve_in_transaction(
        &self,
        tx: &mut PgTransaction<'_>,
        item: &EventWith<VerifiedObservation>,
    ) -> Result<Arc<ApplicableRecord>, rss_projection::Error> {
        self.check(item.as_ref().source()).map_err(source_error)?;
        if tx.tenant() != self.grant.tenant() {
            return Err(source_error(ErrorKind::Unauthorized.into()));
        }
        if !tx.has_statement_snapshots() {
            return Err(rss_projection::Error::provider(
                rss_projection::ErrorKind::InvalidInput,
                Phase::Admission,
                None,
                None,
                ErrorKind::InvalidInput,
            ));
        }
        let tenant = self.grant.tenant().to_string();
        let item = item.clone();
        tx.with_connection(move |connection| {
            Box::pin(async move { Ok(recheck(connection, &tenant, item).await) })
        })
        .await
        .map_err(rss_projection::Error::from)?
        .map_err(|e| e.0)
    }
}

async fn recheck(
    connection: &mut sqlx::PgConnection,
    tenant: &str,
    item: EventWith<VerifiedObservation>,
) -> Result<Arc<ApplicableRecord>, BridgeError> {
    let record = item.data().record.record();
    let batch = record.batch();
    let pos = item.as_ref().position();
    let row = sqlx::query(RECHECK)
        .bind(tenant)
        .bind(pos.get() as i64)
        .bind(batch.fingerprint_prefix(record.scope())?)
        .bind(item.data().fingerprint.as_slice())
        .bind(record.scope().encode()?)
        .bind(batch.id().as_str())
        .bind(batch.sequence().to_string())
        .bind(record.received_at() as i64)
        .bind(record.policy().encode()?)
        .bind(record.decision().encode()?)
        .fetch_optional(connection)
        .await
        .map_err(sql_error)?;
    #[cfg(feature = "integration")]
    if let Some(row) = &row {
        crate::read_profile::row(row);
    }
    if let Some(row) = &row
        && !row.try_get::<bool, _>("expired").map_err(sql_error)?
    {
        #[cfg(feature = "integration")]
        crate::read_profile::count(|cost| {
            cost.database_fingerprints
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });
        if row.try_get_raw("raw").map_err(sql_error)?.is_null() {
            return Ok(item.data().record.clone());
        }
    }
    resolve_row(row, item.as_ref()).map(Arc::new)
}
