use crate::{
    PgStore,
    definition::flatten,
    transaction::{certain, check, db_now, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use sqlx::{PgConnection, Row};
pub(crate) async fn lookup(
    c: &mut PgConnection,
    q: &ReceiptQuery,
) -> Result<Lookup<Receipt>, Error> {
    let stream = &q.stream;
    let row=sqlx::query("SELECT digest,received_at,new_samples,replayed_samples,replay_until,expired FROM rss_timeseries.batches WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 AND batch_id=$5")
        .bind(stream.scope().tenant().to_string()).bind(stream.scope().namespace().as_str()).bind(stream.source().as_str()).bind(stream.generation().as_str()).bind(q.batch_id.as_str())
        .fetch_optional(&mut *c).await.map_err(sql_error)?;
    let Some(row) = row else {
        return crate::lifecycle::absent_receipt(c, stream).await;
    };
    let digest: Vec<u8> = row.try_get("digest").map_err(sql_error)?;
    if digest != q.digest.as_bytes() {
        return Err(Error::Conflict);
    }
    if row.try_get::<bool, _>("expired").map_err(sql_error)? {
        return Ok(Lookup::Expired);
    }
    let count = |key| -> Result<u32, Error> {
        u32::try_from(row.try_get::<i32, _>(key).map_err(sql_error)?).map_err(|_| Error::Invariant)
    };
    Ok(Lookup::Found(Receipt::from_durable(ReceiptSnapshot {
        identity: q.clone(),
        received_at: Timestamp::new(row.try_get("received_at").map_err(sql_error)?)?,
        new_samples: count("new_samples")?,
        replayed_samples: count("replayed_samples")?,
        replay_until: Timestamp::new(row.try_get("replay_until").map_err(sql_error)?)?,
    })?))
}
async fn lock(c: &mut PgConnection, s: &Stream) -> Result<(), Error> {
    sqlx::query("SELECT rss_timeseries.lock_stream($1::text::uuid,$2,$3,$4)")
        .bind(s.scope().tenant().to_string())
        .bind(s.scope().namespace().as_str())
        .bind(s.source().as_str())
        .bind(s.generation().as_str())
        .execute(c)
        .await
        .map_err(sql_error)?;
    Ok(())
}
async fn admit(
    c: &mut PgConnection,
    clock: &impl Clock,
    deadline: Deadline,
    batch: Batch,
    horizon: u64,
) -> Result<Outcome<Receipt>, Error> {
    let s = batch.stream();
    lock(c, s).await?;
    let q = ReceiptQuery {
        stream: s.clone(),
        batch_id: batch.id().clone(),
        digest: batch.digest()?,
    };
    match lookup(c, &q).await? {
        Lookup::Found(old) => return Ok(Outcome::Replay(old)),
        Lookup::Expired => return Err(Error::HistoryExpired),
        Lookup::NotVisible => {} // reason: new identity still passes lifecycle admission below.
    }
    crate::lifecycle::admit_stream(c, s).await?;
    // Share-lock definitions in one order before any sample writes; retirement takes UPDATE.
    let mut definitions = std::collections::BTreeMap::new();
    for sample in batch.samples() {
        let d = sample.input().series.definition();
        definitions.insert((d.spec().key.clone(), d.spec().version), d);
    }
    for ((key, version), d) in definitions {
        check(clock, deadline)?;
        let id = DefinitionId {
            scope: s.scope().clone(),
            key,
            version: std::num::NonZeroU64::new(version).ok_or(Error::Invariant)?,
        };
        let stored = crate::definition::exact(c, &id, true)
            .await?
            .ok_or(Error::InvalidInput)?;
        if stored.definition.digest()? != d.digest()? {
            return Err(Error::Conflict);
        }
    }
    let received = db_now(c).await?;
    let until = received
        .checked_add(i64::try_from(horizon).map_err(|_| Error::NumericRange)?)
        .ok_or(Error::NumericRange)?;
    let mut added = 0i32;
    for sample in batch.samples() {
        check(clock, deadline)?;
        let inserted: bool = sqlx::query_scalar("SELECT rss_timeseries.put_sample($1,$2,$3,$4)")
            .bind(serde_json::to_vec(sample).map_err(|_| Error::Invariant)?)
            .bind(sample.digest()?.as_bytes().as_slice())
            .bind(sample.input().series.digest()?.as_bytes().as_slice())
            .bind(received)
            .fetch_one(&mut *c)
            .await
            .map_err(sql_error)?;
        added += i32::from(inserted);
    }
    let total = i32::try_from(batch.samples().len()).map_err(|_| Error::Invariant)?;
    sqlx::query("SELECT rss_timeseries.put_batch($1::text::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(s.scope().tenant().to_string())
        .bind(s.scope().namespace().as_str())
        .bind(s.source().as_str())
        .bind(s.generation().as_str())
        .bind(batch.id().as_str())
        .bind(q.digest.as_bytes().as_slice())
        .bind(received)
        .bind(added)
        .bind(total - added)
        .bind(until)
        .execute(&mut *c)
        .await
        .map_err(sql_error)?;
    let Lookup::Found(result) = lookup(c, &q).await? else {
        return Err(Error::Invariant);
    };
    if result.new_samples() + result.replayed_samples() != total as u32 {
        return Err(Error::Invariant);
    }
    Ok(Outcome::Accepted(result))
}
impl<C: Clock> Writer for PgStore<C> {
    fn guarantees(&self) -> &Guarantees {
        &self.guarantees
    }
    async fn write(
        &self,
        request: &Authorized<Batch>,
        deadline: Deadline,
    ) -> Result<Outcome<Receipt>, Error> {
        let batch = request.request().clone();
        let horizon = self.limits.replay_micros.get();
        let out = self
            .transaction(
                batch.stream().scope().tenant(),
                deadline,
                true,
                move |c, clock| Box::pin(admit(c, clock, deadline, batch, horizon)),
            )
            .await?;
        Ok(flatten(out))
    }
    async fn receipt(
        &self,
        request: &Authorized<ReceiptQuery>,
        deadline: Deadline,
    ) -> Result<Lookup<Receipt>, Error> {
        let q = request.request().clone();
        certain(
            self.transaction(q.stream.scope().tenant(), deadline, false, move |c, _| {
                Box::pin(async move { lookup(c, &q).await })
            })
            .await?,
        )
    }
}
