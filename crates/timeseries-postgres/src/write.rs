mod encoding;
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
    _permit: crate::prepare::Permit,
}

impl PreparedBatch {
    async fn admit(self, c: &mut PgConnection) -> Result<Outcome<Receipt>, Error> {
        // The connection now owns transport and driver buffers.
        #[cfg(feature = "integration")]
        self._buffers.submit();
        let row = self.query.fetch_one(c).await;
        #[cfg(feature = "integration")]
        self._buffers.set(0);
        let row = row.map_err(sql_error)?;
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
                    let prepared =
                        encoding::prepare(request.request(), self, budget, permit).await?;
                    #[cfg(feature = "integration")]
                    rss_timeseries::measurement::record("prepare", start, 0, 0);
                    Ok(prepared)
                },
                |c, _, batch| Box::pin(batch.admit(c)),
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
