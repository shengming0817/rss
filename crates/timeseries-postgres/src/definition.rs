use crate::{
    PgStore,
    transaction::{certain, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use sqlx::{PgConnection, Row, postgres::PgRow};
pub(crate) fn definition(row: &PgRow) -> Result<DefinitionRecord, Error> {
    let raw: Vec<u8> = row.try_get("raw").map_err(sql_error)?;
    let definition: Definition = serde_json::from_slice(&raw).map_err(|_| Error::Invariant)?;
    let digest: Vec<u8> = row.try_get("digest").map_err(sql_error)?;
    if definition.digest()?.as_bytes().as_slice() != digest {
        return Err(Error::Invariant);
    }
    Ok(DefinitionRecord {
        definition,
        state: if row.try_get("retired").map_err(sql_error)? {
            DefinitionState::Retired
        } else {
            DefinitionState::Active
        },
    })
}
pub(crate) async fn exact(
    c: &mut PgConnection,
    id: &DefinitionId,
    lock: bool,
) -> Result<Option<DefinitionRecord>, Error> {
    let sql = if lock {
        "SELECT raw,digest,retired FROM rss_timeseries.lock_definition($1::text::uuid,$2,$3,$4::text::numeric)"
    } else {
        "SELECT raw,digest,retired FROM rss_timeseries.definitions WHERE tenant_id=$1::text::uuid AND namespace=$2 AND key=$3 AND version=$4::text::numeric"
    };
    sqlx::query(sql)
        .bind(id.scope.tenant().to_string())
        .bind(id.scope.namespace().as_str())
        .bind(id.key.as_str())
        .bind(id.version.to_string())
        .fetch_optional(c)
        .await
        .map_err(sql_error)?
        .as_ref()
        .map(definition)
        .transpose()
}
async fn lock_key(c: &mut PgConnection, scope: &Scope, key: &Id) -> Result<(), Error> {
    sqlx::query("SELECT rss_timeseries.lock_key($1::text::uuid,$2,$3)")
        .bind(scope.tenant().to_string())
        .bind(scope.namespace().as_str())
        .bind(key.as_str())
        .execute(c)
        .await
        .map_err(sql_error)?;
    Ok(())
}
async fn put(c: &mut PgConnection, d: &Definition, retire: bool) -> Result<(), Error> {
    let s = d.spec();
    sqlx::query(
        "SELECT rss_timeseries.put_definition($1::text::uuid,$2,$3,$4::text::numeric,$5,$6,$7)",
    )
    .bind(s.scope.tenant().to_string())
    .bind(s.scope.namespace().as_str())
    .bind(s.key.as_str())
    .bind(s.version.to_string())
    .bind(serde_json::to_vec(d).map_err(|_| Error::Invariant)?)
    .bind(d.digest()?.as_bytes().as_slice())
    .bind(retire)
    .execute(c)
    .await
    .map_err(sql_error)?;
    Ok(())
}
async fn register(
    c: &mut PgConnection,
    d: Definition,
    expected: Option<Digest>,
) -> Result<Outcome<DefinitionRecord>, Error> {
    let s = d.spec();
    lock_key(c, &s.scope, &s.key).await?;
    let id = DefinitionId {
        scope: s.scope.clone(),
        key: s.key.clone(),
        version: std::num::NonZeroU64::new(s.version).ok_or(Error::Invariant)?,
    };
    if let Some(old) = exact(c, &id, false).await? {
        d.compare(&old.definition)?;
        return Ok(Outcome::Replay(old));
    }
    let row=sqlx::query("SELECT d.raw,d.digest,d.retired FROM rss_timeseries.definition_heads h JOIN rss_timeseries.definitions d USING(tenant_id,namespace,key,version) WHERE h.tenant_id=$1::text::uuid AND h.namespace=$2 AND h.key=$3")
        .bind(s.scope.tenant().to_string()).bind(s.scope.namespace().as_str()).bind(s.key.as_str()).fetch_optional(&mut *c).await.map_err(sql_error)?;
    let old = row.as_ref().map(definition).transpose()?;
    if old.as_ref().map(|o| o.definition.digest()).transpose()? != expected {
        return Err(Error::Conflict);
    }
    if let Some(old) = old {
        d.compare(&old.definition)?;
    }
    put(c, &d, false).await?;
    Ok(Outcome::Accepted(DefinitionRecord {
        definition: d,
        state: DefinitionState::Active,
    }))
}
impl<C: Clock> DefinitionStore for PgStore<C> {
    async fn read(
        &self,
        request: &Authorized<DefinitionId>,
        deadline: Deadline,
    ) -> Result<Lookup<DefinitionRecord>, Error> {
        let id = request.request().clone();
        certain(
            self.transaction(id.scope.tenant(), deadline, false, move |c, _| {
                Box::pin(async move {
                    Ok(match exact(c, &id, false).await? {
                        Some(v) => Lookup::Found(v),
                        None => Lookup::NotVisible,
                    })
                })
            })
            .await?,
        )
    }
    async fn change(
        &self,
        request: &Authorized<DefinitionMutation>,
        deadline: Deadline,
    ) -> Result<Outcome<DefinitionRecord>, Error> {
        let request = request.request().clone();
        let tenant = match &request {
            DefinitionMutation::Register { definition, .. } => definition.spec().scope.tenant(),
            DefinitionMutation::Retire { id, .. } => id.scope.tenant(),
        };
        let out = self
            .transaction(tenant, deadline, true, move |c, _| {
                Box::pin(async move {
                    match request {
                        DefinitionMutation::Register {
                            definition,
                            expected_latest,
                        } => register(c, definition, expected_latest).await,
                        DefinitionMutation::Retire { id, expected } => {
                            lock_key(c, &id.scope, &id.key).await?;
                            let mut old = exact(c, &id, false).await?.ok_or(Error::InvalidInput)?;
                            if old.definition.digest()? != expected {
                                return Err(Error::Conflict);
                            }
                            if old.state == DefinitionState::Retired {
                                return Ok(Outcome::Replay(old));
                            }
                            put(c, &old.definition, true).await?;
                            old.state = DefinitionState::Retired;
                            Ok(Outcome::Accepted(old))
                        }
                    }
                })
            })
            .await?;
        Ok(flatten(out))
    }
}
pub(crate) fn flatten<T>(outcome: Outcome<Outcome<T>>) -> Outcome<T> {
    match outcome {
        Outcome::Accepted(v) | Outcome::Replay(v) => v,
        Outcome::Unknown => Outcome::Unknown,
    }
}
