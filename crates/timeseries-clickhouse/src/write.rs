use crate::{
    ChStore, Operation, control,
    projection::{self, Raw},
    transaction::{bytes, decode, now, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use sqlx::{PgConnection, Row, postgres::PgRow};
mod admission;
mod publication;

/// Provider progress is separate from the immutable successful admission receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionProgress {
    NotVisible,
    Prepared,
    /// ClickHouse verified the batch while an earlier revision still blocks visibility.
    Verified,
    Published,
    Expired,
}
/// One-shot interruptions at real provider boundaries; production has no injection surface.
#[cfg(feature = "integration")]
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Fault {
    AfterPrepare = 1,
    AfterInsert = 2,
    AfterPublish = 3,
}
impl<C: Clock> ChStore<C> {
    #[cfg(feature = "integration")]
    pub fn inject_next_fault(&self, fault: Fault) {
        self.fault
            .store(fault as u8, std::sync::atomic::Ordering::SeqCst);
    }
}
impl<C: Clock> Operation<'_, C> {
    pub(crate) fn fault(&self, stage: u8) -> bool {
        #[cfg(feature = "integration")]
        {
            self.fault
                .compare_exchange(
                    stage,
                    0,
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                )
                .is_ok()
        }
        #[cfg(not(feature = "integration"))]
        {
            let _ = stage;
            false
        } // reason: fault injection is absent in production.
    }
}
enum Admission {
    Published(Receipt),
    Verified,
    Prepared(Prepared),
}
#[derive(clickhouse::Row, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct ProjectionProof {
    series: String,
    source: String,
    generation: String,
    observed_at: i64,
    sequence: u64,
    sample_id: String,
    digest: String,
    received_at: i64,
    subject: String,
    resource: String,
    metric_key: String,
    payload_hash: String,
}
struct Prepared {
    rows: Vec<Raw>,
    revision: i64,
    receipt: Receipt,
}
impl Prepared {
    fn validate(&self, batch: &Batch) -> Result<(), Error> {
        if self.rows.len() != self.receipt.new_samples() as usize {
            return Err(Error::Invariant);
        }
        // Projection is the ordered subset admitted as new in the original batch.
        let mut samples = batch.samples().iter();
        for row in &self.rows {
            let original = samples
                .find(|s| s.input().id.as_str() == row.sample_id)
                .ok_or(Error::Invariant)?;
            if row.revision != self.revision
                || row.received_at != self.receipt.received_at().micros()
                || &row.sample()? != original
            {
                return Err(Error::Invariant);
            }
        }
        Ok(())
    }
}
fn receipt(r: &PgRow, q: &ReceiptQuery) -> Result<Receipt, Error> {
    if r.try_get::<Vec<u8>, _>("digest").map_err(sql_error)? != q.digest.as_bytes() {
        return Err(Error::Conflict);
    }
    Receipt::from_durable(ReceiptSnapshot {
        identity: q.clone(),
        received_at: Timestamp::new(r.try_get("received_at").map_err(sql_error)?)?,
        replay_until: Timestamp::new(r.try_get("replay_until").map_err(sql_error)?)?,
        new_samples: u32::try_from(r.try_get::<i32, _>("new_samples").map_err(sql_error)?)
            .map_err(|_| Error::Invariant)?,
        replayed_samples: u32::try_from(
            r.try_get::<i32, _>("replayed_samples").map_err(sql_error)?,
        )
        .map_err(|_| Error::Invariant)?,
    })
}
fn identity(b: &Batch) -> Result<ReceiptQuery, Error> {
    Ok(ReceiptQuery {
        stream: b.stream().clone(),
        batch_id: b.id().clone(),
        digest: b.digest()?,
    })
}
async fn lookup(c: &mut PgConnection, q: &ReceiptQuery) -> Result<Option<PgRow>, Error> {
    sqlx::query("SELECT digest,received_at,replay_until,new_samples,replayed_samples,revision,projection,phase FROM rss_ts_ch.batches WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 AND batch_id=$5")
        .bind(q.stream.scope().tenant().to_string()).bind(q.stream.scope().namespace().as_str()).bind(q.stream.source().as_str()).bind(q.stream.generation().as_str()).bind(q.batch_id.as_str()).fetch_optional(c).await.map_err(sql_error)
}
impl<C: Clock> Operation<'_, C> {
    async fn prepare(&self, b: &Batch, deadline: Deadline) -> Result<Outcome<Admission>, Error> {
        let scope = b.stream().scope();
        let mut tx = self.begin(scope, true, deadline).await?;
        #[cfg(feature = "integration")]
        let locked = self.clock.now();
        let result = self.prepare_in(tx.connection(), b).await;
        let settled = tx.finish(result, true).await;
        #[cfg(feature = "integration")]
        crate::measurement::record(|m| m.locked += self.clock.now() - locked);
        settled
    }
    async fn prepare_in(&self, c: &mut PgConnection, b: &Batch) -> Result<Admission, Error> {
        let q = identity(b)?;
        if let Some(r) = lookup(c, &q).await? {
            let receipt = receipt(&r, &q)?;
            return match r.try_get::<&str, _>("phase").map_err(sql_error)? {
                "expired" => Err(Error::HistoryExpired),
                "published" => Ok(Admission::Published(receipt)),
                "verified" => Ok(Admission::Verified),
                "prepared" => Ok(Admission::Prepared(Prepared {
                    rows: decode(&r.try_get::<Vec<u8>, _>("projection").map_err(sql_error)?)?,
                    revision: r.try_get("revision").map_err(sql_error)?,
                    receipt,
                })),
                _ => Err(Error::Invariant),
            };
        }
        let s = b.stream();
        let scope = s.scope();
        let revision = sqlx::query_scalar::<_, i64>(
            "UPDATE rss_ts_ch.namespaces n SET allocated=allocated+1
            FROM rss_ts_ch.installation i WHERE n.tenant_id=$1::text::uuid AND n.namespace=$2
              AND n.allocated-n.published<i.max_pending_batches AND NOT EXISTS (
                SELECT FROM rss_ts_ch.batches WHERE tenant_id=n.tenant_id AND namespace=n.namespace
                  AND source=$3 AND generation=$4 AND phase IN ('prepared','verified'))
            RETURNING n.allocated",
        )
        .bind(scope.tenant().to_string())
        .bind(scope.namespace().as_str())
        .bind(s.source().as_str())
        .bind(s.generation().as_str())
        .fetch_optional(&mut *c)
        .await
        .map_err(sql_error)?
        .ok_or(Error::Unavailable)?;
        sqlx::query("INSERT INTO rss_ts_ch.streams(tenant_id,namespace,source,generation) VALUES($1::text::uuid,$2,$3,$4) ON CONFLICT DO NOTHING")
            .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).execute(&mut *c).await.map_err(sql_error)?;
        let max = self.limits.max_fences.get();
        let (closed, count): (bool, i64) = sqlx::query_as(concat!(
            "SELECT closed, (",
            include_str!("fence_count.sql"),
            ") FROM rss_ts_ch.streams WHERE tenant_id=$1::text::uuid AND namespace=$2
               AND source=$4 AND generation=$5"
        ))
        .bind(scope.tenant().to_string())
        .bind(scope.namespace().as_str())
        .bind(i64::from(max) + 1)
        .bind(s.source().as_str())
        .bind(s.generation().as_str())
        .fetch_one(&mut *c)
        .await
        .map_err(sql_error)?;
        if closed {
            return Err(Error::HistoryExpired);
        }
        let has_fences = control::has_fences(count, max)?;
        #[cfg(feature = "integration")]
        crate::measurement::record(|m| {
            // tenant and namespace are already bound for the stream-state read.
            m.fence_input_bytes += 8;
            m.fence_bytes += 8;
        });
        let received = now(c).await?;
        let rows = admission::admit(
            c,
            b,
            has_fences,
            received,
            revision,
            self.limits.max_points.get(),
        )
        .await?;
        let replay_until = received
            .checked_add(
                i64::try_from(self.limits.replay_micros.get()).map_err(|_| Error::NumericRange)?,
            )
            .ok_or(Error::NumericRange)?;
        let new_samples = u32::try_from(rows.len()).map_err(|_| Error::Invariant)?;
        let replayed_samples =
            u32::try_from(b.samples().len() - rows.len()).map_err(|_| Error::Invariant)?;
        sqlx::query("INSERT INTO rss_ts_ch.batches(tenant_id,namespace,source,generation,batch_id,digest,revision,received_at,replay_until,new_samples,replayed_samples,payload,projection) VALUES($1::text::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
            .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).bind(b.id().as_str()).bind(b.digest()?.as_bytes().as_slice()).bind(revision).bind(received).bind(replay_until).bind(i64::from(new_samples) as i32).bind(i64::from(replayed_samples) as i32).bind(bytes(b)?).bind(bytes(&rows)?).execute(c).await.map_err(sql_error)?;
        Ok(Admission::Prepared(Prepared {
            rows,
            revision,
            receipt: Receipt::from_durable(ReceiptSnapshot {
                identity: q,
                received_at: Timestamp::new(received)?,
                replay_until: Timestamp::new(replay_until)?,
                new_samples,
                replayed_samples,
            })?,
        }))
    }
    async fn verify_projection(
        &self,
        b: &Batch,
        p: &Prepared,
        deadline: Deadline,
    ) -> Result<(), Error> {
        // These columns complete the raw sorting key after the fixed tenant, namespace and
        // revision. Only exact retries collapse; a conflicting digest or receipt survives merges.
        use sha2::{Digest, Sha256};
        let sql="SELECT DISTINCT series,source,generation,observed_at,sequence,sample_id,digest,received_at,
                    subject,resource,metric_key,lower(hex(SHA256(payload))) AS payload_hash
                 FROM rss_ts_ch.raw WHERE tenant=? AND namespace=? AND revision=? LIMIT ?";
        let mut rows = self
            .ch_query(self.reader.query(sql), deadline)?
            .bind(self.tenant.to_string())
            .bind(b.stream().scope().namespace().as_str())
            .bind(p.revision)
            .bind(p.rows.len() as u64 + 1)
            .fetch_all::<ProjectionProof>()
            .await
            .map_err(|e| projection::provider_error("projection-verification", e))?;
        let mut expected = p
            .rows
            .iter()
            .map(|r| ProjectionProof {
                series: r.series.clone(),
                source: r.source.clone(),
                generation: r.generation.clone(),
                observed_at: r.observed_at,
                sequence: r.sequence,
                sample_id: r.sample_id.clone(),
                digest: r.digest.clone(),
                received_at: r.received_at,
                subject: r.subject.clone(),
                resource: r.resource.clone(),
                metric_key: r.metric_key.clone(),
                payload_hash: projection::hex(&Sha256::digest(r.payload.as_bytes())),
            })
            .collect::<Vec<_>>();
        rows.sort_unstable();
        expected.sort_unstable();
        if rows != expected {
            return Err(Error::Invariant);
        }
        Ok(())
    }
    async fn advance(&self, b: &Batch, deadline: Deadline) -> Result<Outcome<Receipt>, Error> {
        let p = match self.prepare(b, deadline).await? {
            Outcome::Accepted(Admission::Published(r))
            | Outcome::Replay(Admission::Published(r)) => return Ok(Outcome::Replay(r)),
            Outcome::Accepted(Admission::Verified) | Outcome::Replay(Admission::Verified) => {
                return Ok(Outcome::Unknown);
            }
            Outcome::Accepted(Admission::Prepared(p)) | Outcome::Replay(Admission::Prepared(p)) => {
                p
            }
            Outcome::Unknown => return Ok(Outcome::Unknown),
        };
        if self.fault(1) {
            return Ok(Outcome::Unknown);
        }
        let projected: Result<Outcome<Receipt>, Error> = async {
            p.validate(b)?;
            let a = match self.raw_attempt(b.stream().scope(), &p, deadline).await? {
                Outcome::Accepted(a) | Outcome::Replay(a) => a,
                Outcome::Unknown => return Ok(Outcome::Unknown),
            };
            self.insert(&a, &p.rows, deadline).await?;
            if self.fault(2) {
                return Ok(Outcome::Unknown);
            }
            self.verify_projection(b, &p, deadline).await?;
            let outcome = self.confirm(b.stream().scope(), p, &a, deadline).await?;
            if self.fault(3) {
                return Ok(Outcome::Unknown);
            }
            Ok(outcome)
        }
        .await;
        match projected {
            Ok(v) => Ok(v),
            Err(error) => {
                #[cfg(feature = "integration")]
                eprintln!("projection stage failed: {error}");
                #[cfg(not(feature = "integration"))]
                let _ = error;
                Ok(Outcome::Unknown)
            }
        }
    }
}
impl<C: Clock> ChStore<C> {
    pub async fn progress(
        &self,
        request: &Authorized<ReceiptQuery>,
        deadline: Deadline,
    ) -> Result<ProjectionProgress, Error> {
        let q = request.request();
        let owner = self.owner.upgrade().ok_or(Error::Unavailable)?;
        let operation = owner.operation(self, q.stream.scope(), deadline).await?;
        operation
            .bounded(deadline, async {
                let mut tx = operation.begin(q.stream.scope(), false, deadline).await?;
                let result = async {
                    Ok(match lookup(tx.connection(), q).await? {
                        None => ProjectionProgress::NotVisible,
                        Some(r) => {
                            receipt(&r, q)?;
                            match r.try_get::<&str, _>("phase").map_err(sql_error)? {
                                "expired" => ProjectionProgress::Expired,
                                "published" => ProjectionProgress::Published,
                                "verified" => ProjectionProgress::Verified,
                                "prepared" => ProjectionProgress::Prepared,
                                _ => return Err(Error::Invariant),
                            }
                        }
                    })
                }
                .await;
                tx.read(result).await
            })
            .await
    }
    /// Recover one fixed pending batch; no background task or retained authorization.
    pub async fn recover(
        &self,
        scope: &Scope,
        authority: &impl Authority,
        deadline: Deadline,
    ) -> Result<Outcome<Option<Receipt>>, Error> {
        let owner = self.owner.upgrade().ok_or(Error::Unavailable)?;
        let operation = owner.operation(self, scope, deadline).await?;
        operation.mutation(deadline,async {
            let mut tx=operation.begin(scope,false,deadline).await?;
            // At the largest published revision there can be no pending successor.
            let head = tx.published.checked_add(1);
            let raw=sqlx::query_scalar::<_,Vec<u8>>("SELECT payload FROM rss_ts_ch.batches WHERE tenant_id=$1::text::uuid AND namespace=$2 AND revision=$3 AND phase='prepared'")
                .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(head).fetch_optional(tx.connection()).await.map_err(sql_error);
            let Some(raw)=tx.read(raw).await? else {return Ok(Outcome::Accepted(None));};
            let b=Authorized::<Batch>::verify(authority,Batch::decode(&raw)?)?;
            Ok(match operation.advance(b.request(),deadline).await? {Outcome::Accepted(r)=>Outcome::Accepted(Some(r)),Outcome::Replay(r)=>Outcome::Replay(Some(r)),Outcome::Unknown=>Outcome::Unknown})
        }).await
    }
}
impl<C: Clock> Writer for ChStore<C> {
    fn guarantees(&self) -> &Guarantees {
        &self.guarantees
    }
    async fn write(
        &self,
        b: &Authorized<Batch>,
        deadline: Deadline,
    ) -> Result<Outcome<Receipt>, Error> {
        let owner = self.owner.upgrade().ok_or(Error::Unavailable)?;
        let operation = owner
            .operation(self, b.request().stream().scope(), deadline)
            .await?;
        operation
            .mutation(deadline, operation.advance(b.request(), deadline))
            .await
    }
    async fn receipt(
        &self,
        request: &Authorized<ReceiptQuery>,
        deadline: Deadline,
    ) -> Result<Lookup<Receipt>, Error> {
        let q = request.request();
        let owner = self.owner.upgrade().ok_or(Error::Unavailable)?;
        let operation = owner.operation(self, q.stream.scope(), deadline).await?;
        operation.bounded(deadline,async {
            let mut tx=operation.begin(q.stream.scope(),false,deadline).await?;
            let result=async {Ok(match lookup(tx.connection(),q).await? {
                None=>{
                    let reclaimed:Option<bool>=sqlx::query_scalar("SELECT reclaimed FROM rss_ts_ch.streams WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4").bind(q.stream.scope().tenant().to_string()).bind(q.stream.scope().namespace().as_str()).bind(q.stream.source().as_str()).bind(q.stream.generation().as_str()).fetch_optional(tx.connection()).await.map_err(sql_error)?;
                    if reclaimed==Some(true) {Lookup::Expired} else {Lookup::NotVisible}
                },
                Some(r)=>{let value=receipt(&r,q)?;match r.try_get::<&str,_>("phase").map_err(sql_error)? {
                        "expired" => Lookup::Expired, "published" => Lookup::Found(value),
                        "prepared" | "verified" => Lookup::NotVisible, _ => return Err(Error::Invariant),
                    }}
            })}.await;tx.read(result).await
        }).await
    }
}
