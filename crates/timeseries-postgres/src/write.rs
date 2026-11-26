#[cfg(feature = "integration")]
mod measurement;
use crate::{
    PgStore,
    definition::flatten,
    transaction::{Budget, Mode, certain, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use sqlx::{
    PgConnection, Postgres, Row,
    postgres::{PgArguments, PgRow},
    query::Query as SqlQuery,
};
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
    #[cfg(feature = "integration")]
    _buffers: measurement::Buffers,
    identity: ReceiptQuery,
    count: usize,
    query: SqlQuery<'static, Postgres, PgArguments>,
}

impl PreparedBatch {
    async fn new(
        batch: &Batch,
        clock: &impl Clock,
        budget: Budget,
        horizon: u64,
    ) -> Result<Self, Error> {
        budget.remaining(clock)?;
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
        for (index, sample) in batch.samples().iter().enumerate() {
            if index > 0 && index % 32 == 0 { tokio::task::yield_now().await; }
            budget.remaining(clock)?;
            let series = &sample.input().series;
            let def = series.definition();
            bindings.insert((&def.spec().key, def.spec().version), def);
            #[cfg(feature = "integration")]
            payloads.push(measurement::raw("sample_payload", sample)?);
            #[cfg(not(feature = "integration"))]
            payloads.push(crate::lifecycle::bytes(sample)?);
            sample_digests.push(sample.digest()?.as_bytes().to_vec());
            series_digests.push(series.digest()?.as_bytes().to_vec());
        }
        let mut definitions = Vec::with_capacity(bindings.len());
        let mut definition_digests = Vec::with_capacity(bindings.len());
        for (index, def) in bindings.into_values().enumerate() {
            if index > 0 && index % 32 == 0 { tokio::task::yield_now().await; }
            budget.remaining(clock)?;
            #[cfg(feature = "integration")]
            definitions.push(measurement::raw("definition_payload", def)?);
            #[cfg(not(feature = "integration"))]
            definitions.push(crate::lifecycle::bytes(def)?);
            definition_digests.push(def.digest()?.as_bytes().to_vec());
        }
        budget.remaining(clock)?;
        let stream = &identity.stream;
        let count = payloads.len();
        let horizon = i64::try_from(horizon).map_err(|_| Error::NumericRange)?;
        #[cfg(feature = "integration")]
        let buffers = measurement::Buffers::default();
        #[cfg(feature = "integration")]
        let (payloads, sample_digests, series_digests, definitions, definition_digests, horizon) = {
            use measurement::{Observed, nested};
            let e = nested(&definition_digests);
            let d = e + nested(&definitions);
            let c = d + nested(&series_digests);
            let b = c + nested(&sample_digests);
            let a = b + nested(&payloads);
            buffers.set(a);
            (
                Observed {
                    value: payloads,
                    buffers: &buffers,
                    scratch: a,
                    final_arg: false,
                },
                Observed {
                    value: sample_digests,
                    buffers: &buffers,
                    scratch: b,
                    final_arg: false,
                },
                Observed {
                    value: series_digests,
                    buffers: &buffers,
                    scratch: c,
                    final_arg: false,
                },
                Observed {
                    value: definitions,
                    buffers: &buffers,
                    scratch: d,
                    final_arg: false,
                },
                Observed {
                    value: definition_digests,
                    buffers: &buffers,
                    scratch: e,
                    final_arg: false,
                },
                Observed {
                    value: horizon,
                    buffers: &buffers,
                    scratch: 0,
                    final_arg: true,
                },
            )
        };
        let query = sqlx::query(
            "SELECT * FROM rss_timeseries.admit_batch($1::text::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(stream.scope().tenant().to_string())
        .bind(stream.scope().namespace().as_str())
        .bind(stream.source().as_str())
        .bind(stream.generation().as_str())
        .bind(identity.batch_id.as_str())
        .bind(identity.digest.as_bytes().as_slice())
        .bind(payloads)
        .bind(sample_digests)
        .bind(series_digests)
        .bind(definitions)
        .bind(definition_digests)
        .bind(horizon);
        Ok(Self {
            #[cfg(feature = "integration")]
            _buffers: buffers,
            identity,
            count,
            query,
        })
    }

    async fn admit(self, c: &mut PgConnection) -> Result<Outcome<Receipt>, Error> {
        let row = self.query.fetch_one(c).await.map_err(sql_error)?;
        if let Some(raw) = row
            .try_get::<Option<&[u8]>, _>("suspect_raw")
            .map_err(sql_error)?
        {
            crate::definition::verified(raw, row.try_get("suspect_digest").map_err(sql_error)?)?;
            return Err(Error::Conflict);
        }
        let result = receipt(&row, &self.identity)?;
        if (result.new_samples() + result.replayed_samples()) as usize != self.count {
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
        let out = self
            .prepared_transaction(
                tenant,
                deadline,
                Mode::Write,
                |budget| async move {
                    let permit = self.preparation.acquire(request.request()).await?;
                    #[cfg(feature = "integration")]
                    let start = rss_timeseries::measurement::timer();
                    let prepared = PreparedBatch::new(request.request(), &self.clock, budget, self.limits.replay_micros.get()).await?;
                    #[cfg(feature = "integration")]
                    rss_timeseries::measurement::record("prepare", start, 0, 0);
                    Ok((prepared, permit))
                },
                |c, _, (batch, permit)| Box::pin(async move {
                    let result = batch.admit(c).await;
                    drop(permit);
                    result
                }),
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
