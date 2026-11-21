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
struct PreparedBatch {
    identity: ReceiptQuery,
    payloads: Vec<Vec<u8>>,
    sample_digests: Vec<Vec<u8>>,
    series_digests: Vec<Vec<u8>>,
    definitions: Vec<Vec<u8>>,
    definition_digests: Vec<Vec<u8>>,
}

impl PreparedBatch {
    fn new(batch: &Batch, clock: &impl Clock, deadline: Deadline) -> Result<Self, Error> {
        check(clock, deadline)?;
        let identity = ReceiptQuery {
            stream: batch.stream().clone(),
            batch_id: batch.id().clone(),
            digest: batch.digest()?,
        };
        let mut payloads = Vec::with_capacity(batch.samples().len());
        let mut sample_digests = Vec::with_capacity(payloads.capacity());
        let mut series_digests = Vec::with_capacity(payloads.capacity());
        // A repeated ID binds to its last occurrence before individual samples are checked.
        let mut bindings = std::collections::BTreeMap::new();
        for sample in batch.samples() {
            check(clock, deadline)?;
            let series = &sample.input().series;
            let def = series.definition();
            bindings.insert((&def.spec().key, def.spec().version), def);
            payloads.push(crate::lifecycle::bytes(sample)?);
            sample_digests.push(sample.digest()?.as_bytes().to_vec());
            series_digests.push(series.digest()?.as_bytes().to_vec());
        }
        let mut definitions = Vec::with_capacity(bindings.len());
        let mut definition_digests = Vec::with_capacity(bindings.len());
        for def in bindings.into_values() {
            check(clock, deadline)?;
            definitions.push(crate::lifecycle::bytes(def)?);
            definition_digests.push(def.digest()?.as_bytes().to_vec());
        }
        check(clock, deadline)?;
        Ok(Self {
            identity,
            payloads,
            sample_digests,
            series_digests,
            definitions,
            definition_digests,
        })
    }

    async fn admit(self, c: &mut PgConnection, horizon: u64) -> Result<Outcome<Receipt>, Error> {
        let stream = &self.identity.stream;
        let count = self.payloads.len();
        let row = sqlx::query(
            "SELECT * FROM rss_timeseries.admit_batch($1::text::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(stream.scope().tenant().to_string())
        .bind(stream.scope().namespace().as_str())
        .bind(stream.source().as_str())
        .bind(stream.generation().as_str())
        .bind(self.identity.batch_id.as_str())
        .bind(self.identity.digest.as_bytes().as_slice())
        .bind(self.payloads)
        .bind(self.sample_digests)
        .bind(self.series_digests)
        .bind(self.definitions)
        .bind(self.definition_digests)
        .bind(i64::try_from(horizon).map_err(|_| Error::NumericRange)?)
        .fetch_one(c)
        .await
        .map_err(sql_error)?;
        if let Some(raw) = row
            .try_get::<Option<&[u8]>, _>("suspect_raw")
            .map_err(sql_error)?
        {
            crate::definition::verified(raw, row.try_get("suspect_digest").map_err(sql_error)?)?;
            return Err(Error::Conflict);
        }
        let result = receipt(&row, &self.identity)?;
        if (result.new_samples() + result.replayed_samples()) as usize != count {
            return Err(Error::Invariant);
        }
        Ok(if row.try_get("replay").map_err(sql_error)? {
            Outcome::Replay(result)
        } else {
            Outcome::Accepted(result)
        })
    }
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
        let tenant = request.request().stream().scope().tenant();
        self.profile.check_tenant(tenant)?;
        let batch = PreparedBatch::new(request.request(), &self.clock, deadline)?;
        let horizon = self.limits.replay_micros.get();
        let out = self
            .transaction(tenant, deadline, Mode::Write, move |c, _| {
                Box::pin(batch.admit(c, horizon))
            })
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
