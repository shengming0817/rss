use crate::{
    PgStore,
    definition::flatten,
    transaction::{Mode, certain, check, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use sqlx::{PgConnection, Row, postgres::PgRow};
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
    Ok(Lookup::Found(receipt(&row, q)?))
}

fn receipt(row: &PgRow, q: &ReceiptQuery) -> Result<Receipt, Error> {
    let count = |key| -> Result<u32, Error> {
        u32::try_from(row.try_get::<i32, _>(key).map_err(sql_error)?).map_err(|_| Error::Invariant)
    };
    Receipt::from_durable(ReceiptSnapshot {
        identity: q.clone(),
        received_at: Timestamp::new(row.try_get("received_at").map_err(sql_error)?)?,
        new_samples: count("new_samples")?,
        replayed_samples: count("replayed_samples")?,
        replay_until: Timestamp::new(row.try_get("replay_until").map_err(sql_error)?)?,
    })
}
async fn admit(
    c: &mut PgConnection,
    clock: &impl Clock,
    deadline: Deadline,
    batch: Batch,
    horizon: u64,
) -> Result<Outcome<Receipt>, Error> {
    let stream = batch.stream();
    let identity = ReceiptQuery {
        stream: stream.clone(),
        batch_id: batch.id().clone(),
        digest: batch.digest()?,
    };
    let mut payloads = Vec::with_capacity(batch.samples().len());
    let mut sample_digests = Vec::with_capacity(payloads.capacity());
    let mut series_digests = Vec::with_capacity(payloads.capacity());
    let mut definition_digests = Vec::with_capacity(payloads.capacity());
    for sample in batch.samples() {
        check(clock, deadline)?;
        let series = &sample.input().series;
        payloads.push(crate::lifecycle::bytes(sample)?);
        sample_digests.push(sample.digest()?.as_bytes().to_vec());
        series_digests.push(series.digest()?.as_bytes().to_vec());
        definition_digests.push(series.definition().digest()?.as_bytes().to_vec());
    }
    let row = sqlx::query(
        "SELECT * FROM rss_timeseries.admit_batch($1::text::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(stream.scope().tenant().to_string())
    .bind(stream.scope().namespace().as_str())
    .bind(stream.source().as_str())
    .bind(stream.generation().as_str())
    .bind(batch.id().as_str())
    .bind(identity.digest.as_bytes().as_slice())
    .bind(payloads)
    .bind(sample_digests)
    .bind(series_digests)
    .bind(definition_digests)
    .bind(i64::try_from(horizon).map_err(|_| Error::NumericRange)?)
    .fetch_one(c)
    .await
    .map_err(sql_error)?;
    let result = receipt(&row, &identity)?;
    if (result.new_samples() + result.replayed_samples()) as usize != batch.samples().len() {
        return Err(Error::Invariant);
    }
    Ok(if row.try_get("replay").map_err(sql_error)? {
        Outcome::Replay(result)
    } else {
        Outcome::Accepted(result)
    })
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
                Mode::Write,
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
            self.transaction(
                q.stream.scope().tenant(),
                deadline,
                Mode::Snapshot,
                move |c, _| Box::pin(async move { lookup(c, &q).await }),
            )
            .await?,
        )
    }
}
