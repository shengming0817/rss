use crate::{
    ChStore,
    transaction::{bytes, decode, flatten, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use sqlx::{PgConnection, Row, postgres::PgRow};
fn record(r: PgRow) -> Result<DefinitionRecord, Error> {
    let d: Definition = decode(&r.try_get::<Vec<u8>, _>("raw").map_err(sql_error)?)?;
    if d.digest()?.as_bytes().as_slice() != r.try_get::<Vec<u8>, _>("digest").map_err(sql_error)? {
        return Err(Error::Invariant);
    }
    Ok(DefinitionRecord {
        definition: d,
        state: if r.try_get("retired").map_err(sql_error)? {
            DefinitionState::Retired
        } else {
            DefinitionState::Active
        },
    })
}
pub(crate) async fn exact(
    c: &mut PgConnection,
    id: &DefinitionId,
) -> Result<Option<DefinitionRecord>, Error> {
    sqlx::query("SELECT raw,digest,retired FROM rss_ts_ch.definitions WHERE tenant_id=$1::text::uuid AND namespace=$2 AND key=$3 AND version=$4::text::numeric")
        .bind(id.scope.tenant().to_string()).bind(id.scope.namespace().as_str()).bind(id.key.as_str()).bind(id.version.to_string()).fetch_optional(c).await.map_err(sql_error)?.map(record).transpose()
}
async fn change(
    c: &mut PgConnection,
    r: &DefinitionMutation,
) -> Result<Outcome<DefinitionRecord>, Error> {
    match r {
        DefinitionMutation::Register {
            definition: d,
            expected_latest,
        } => {
            let spec = d.spec();
            let id = DefinitionId {
                scope: spec.scope.clone(),
                key: spec.key.clone(),
                version: std::num::NonZeroU64::new(spec.version).ok_or(Error::Invariant)?,
            };
            if let Some(old) = exact(c, &id).await? {
                d.compare(&old.definition)?;
                return Ok(Outcome::Replay(old));
            }
            let old=sqlx::query("SELECT raw,digest,retired FROM rss_ts_ch.definitions WHERE tenant_id=$1::text::uuid AND namespace=$2 AND key=$3 ORDER BY version DESC LIMIT 1")
                .bind(spec.scope.tenant().to_string()).bind(spec.scope.namespace().as_str()).bind(spec.key.as_str()).fetch_optional(&mut *c).await.map_err(sql_error)?.map(record).transpose()?;
            if old.as_ref().map(|v| v.definition.digest()).transpose()? != *expected_latest {
                return Err(Error::Conflict);
            }
            if let Some(old) = old {
                d.compare(&old.definition)?;
            }
            sqlx::query("INSERT INTO rss_ts_ch.definitions(tenant_id,namespace,key,version,raw,digest) VALUES($1::text::uuid,$2,$3,$4::text::numeric,$5,$6)")
                .bind(spec.scope.tenant().to_string()).bind(spec.scope.namespace().as_str()).bind(spec.key.as_str()).bind(spec.version.to_string()).bind(bytes(d)?).bind(d.digest()?.as_bytes().as_slice()).execute(c).await.map_err(sql_error)?;
            Ok(Outcome::Accepted(DefinitionRecord {
                definition: d.clone(),
                state: DefinitionState::Active,
            }))
        }
        DefinitionMutation::Retire { id, expected } => {
            let mut old = exact(c, id).await?.ok_or(Error::InvalidInput)?;
            if old.definition.digest()? != *expected {
                return Err(Error::Conflict);
            }
            if old.state == DefinitionState::Retired {
                return Ok(Outcome::Replay(old));
            }
            sqlx::query("UPDATE rss_ts_ch.definitions SET retired=true WHERE tenant_id=$1::text::uuid AND namespace=$2 AND key=$3 AND version=$4::text::numeric")
                .bind(id.scope.tenant().to_string()).bind(id.scope.namespace().as_str()).bind(id.key.as_str()).bind(id.version.to_string()).execute(c).await.map_err(sql_error)?;
            old.state = DefinitionState::Retired;
            Ok(Outcome::Accepted(old))
        }
    }
}
impl<C: Clock> DefinitionStore for ChStore<C> {
    async fn read(
        &self,
        request: &Authorized<DefinitionId>,
        deadline: Deadline,
    ) -> Result<Lookup<DefinitionRecord>, Error> {
        let r = request.request();
        let _guard = self.operation(&r.scope, deadline).await?;
        self.bounded(deadline, async {
            let mut tx = self.begin(&r.scope, false, deadline).await?;
            let result = exact(tx.connection(), r)
                .await
                .map(|v| v.map_or(Lookup::NotVisible, Lookup::Found));
            tx.read(result).await
        })
        .await
    }
    async fn change(
        &self,
        request: &Authorized<DefinitionMutation>,
        deadline: Deadline,
    ) -> Result<Outcome<DefinitionRecord>, Error> {
        let r = request.request();
        let scope = match r {
            DefinitionMutation::Register { definition, .. } => &definition.spec().scope,
            DefinitionMutation::Retire { id, .. } => &id.scope,
        };
        let _guard = self.operation(scope, deadline).await?;
        self.mutation(deadline, async {
            let mut tx = self.begin(scope, true, deadline).await?;
            let result = change(tx.connection(), r).await;
            tx.finish(result, true).await.map(flatten)
        })
        .await
    }
}
