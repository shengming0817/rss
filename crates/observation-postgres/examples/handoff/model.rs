//! Example consumer mapping. Coverage IDs define disjoint regions in this example only.
use rss_observation::{Body, Clock};
use rss_observation_postgres::PgSource;
use rss_projection::{Event, ProjectionScope};
use rss_projection_postgres::{PgEffect, PgEffectOutcome, PgOperationError, PgTransaction};
use std::sync::Arc;
// SHA-256 of the application declaration "observation-facts:coverage-regions:reference-v1:schema-v1".
// Change this declaration when the mapping/schema changes; use a new generation.
pub const DEFINITION: rss_projection::DefinitionIdentity =
    rss_projection::DefinitionIdentity::new([
        54, 81, 75, 83, 140, 245, 111, 193, 132, 112, 84, 184, 169, 178, 250, 111, 122, 139, 158,
        212, 11, 198, 217, 90, 50, 161, 94, 154, 152, 245, 186, 190,
    ]);
pub struct Facts<C> {
    source: Arc<PgSource<C>>,
}
impl<C> Facts<C> {
    pub fn new(source: Arc<PgSource<C>>) -> Self {
        Self { source }
    }
}
impl<C: Clock + 'static> PgEffect for Facts<C> {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        projection: &ProjectionScope,
        event: &Event,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        let applicable = self
            .source
            .resolve_in_transaction(tx, event)
            .await
            .map_err(operation_error)?;
        let record = applicable.record();
        let scope = record.scope().encode().map_err(operation_error)?;
        let coverage = record.batch().coverage().id().as_str().to_owned();
        let projection = projection.clone();
        let body = record.batch().body().clone();
        tx.with_connection(move|conn|Box::pin(async move{
            if matches!(body,Body::Snapshot(_)){
                sqlx::query("DELETE FROM public.observation_facts WHERE tenant_id=$1::uuid AND journal=$2 AND projection=$3 AND generation=$4 AND scope=$5 AND coverage=$6")
                    .bind(projection.source().tenant().to_string()).bind(projection.source().source()).bind(projection.projection()).bind(projection.generation()).bind(&scope).bind(&coverage).execute(&mut *conn).await?;
            }
            for change in body.changes(){
                if let Some(value)=change.value(){
                    sqlx::query("INSERT INTO public.observation_facts(tenant_id,journal,projection,generation,scope,coverage,fact_key,value) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,journal,projection,generation,scope,coverage,fact_key) DO UPDATE SET value=excluded.value")
                        .bind(projection.source().tenant().to_string()).bind(projection.source().source()).bind(projection.projection()).bind(projection.generation()).bind(&scope).bind(&coverage).bind(change.key().as_str()).bind(value).execute(&mut *conn).await?;
                }else{
                    sqlx::query("DELETE FROM public.observation_facts WHERE tenant_id=$1::uuid AND journal=$2 AND projection=$3 AND generation=$4 AND scope=$5 AND coverage=$6 AND fact_key=$7")
                        .bind(projection.source().tenant().to_string()).bind(projection.source().source()).bind(projection.projection()).bind(projection.generation()).bind(&scope).bind(&coverage).bind(change.key().as_str()).execute(&mut *conn).await?;
                }
            }
            Ok(())
        })).await?;
        Ok(PgEffectOutcome::Applied)
    }
}

fn operation_error(error: rss_observation::Error) -> PgOperationError {
    use rss_observation::ErrorKind;
    match error.kind() {
        ErrorKind::Storage
        | ErrorKind::Closed
        | ErrorKind::Deadline
        | ErrorKind::CommitUnknown
        | ErrorKind::RollbackFailed => PgOperationError::unavailable(error),
        ErrorKind::InvalidInput
        | ErrorKind::Unauthorized
        | ErrorKind::Conflict
        | ErrorKind::LifecycleConflict
        | ErrorKind::StaleEpoch
        | ErrorKind::UnknownStream
        | ErrorKind::Invariant => PgOperationError::rejected(),
    }
}
