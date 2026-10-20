use crate::{
    ChStore, control, definition,
    projection::{self, Attempt, Raw},
    transaction::{bytes, decode, now, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use sqlx::{PgConnection, Row, postgres::PgRow};
/// Provider progress is separate from the immutable successful admission receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionProgress {
    NotVisible,
    Prepared,
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
    BeforeInsertEnd = 4,
}
impl<C: Clock> ChStore<C> {
    #[cfg(feature = "integration")]
    pub fn inject_next_fault(&self, fault: Fault) {
        self.fault
            .store(fault as u8, std::sync::atomic::Ordering::SeqCst);
    }
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
struct Prepared {
    rows: Vec<Raw>,
    revision: i64,
    receipt: Receipt,
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
    sqlx::query("SELECT digest,received_at,replay_until,new_samples,replayed_samples,revision,projection,published,expired FROM rss_ts_ch.batches WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 AND batch_id=$5")
        .bind(q.stream.scope().tenant().to_string()).bind(q.stream.scope().namespace().as_str()).bind(q.stream.source().as_str()).bind(q.stream.generation().as_str()).bind(q.batch_id.as_str()).fetch_optional(c).await.map_err(sql_error)
}
impl<C: Clock> ChStore<C> {
    async fn prepare(
        &self,
        b: &Batch,
        deadline: Deadline,
    ) -> Result<Outcome<Result<Receipt, Prepared>>, Error> {
        let scope = b.stream().scope();
        let mut tx = self.begin(scope, true, deadline).await?;
        let revision = tx.published.checked_add(1).ok_or(Error::NumericRange)?;
        let result = self.prepare_in(tx.connection(), b, revision).await;
        tx.finish(result, true).await
    }
    async fn prepare_in(
        &self,
        c: &mut PgConnection,
        b: &Batch,
        revision: i64,
    ) -> Result<Result<Receipt, Prepared>, Error> {
        let q = identity(b)?;
        if let Some(r) = lookup(c, &q).await? {
            let receipt = receipt(&r, &q)?;
            if r.try_get("expired").map_err(sql_error)? {
                return Err(Error::HistoryExpired);
            }
            if r.try_get("published").map_err(sql_error)? {
                return Ok(Ok(receipt));
            }
            return Ok(Err(Prepared {
                rows: decode(&r.try_get::<Vec<u8>, _>("projection").map_err(sql_error)?)?,
                revision: r.try_get("revision").map_err(sql_error)?,
                receipt,
            }));
        }
        let s = b.stream();
        let scope = s.scope();
        if control::pending(c, scope).await? {
            return Err(Error::Unavailable);
        }
        sqlx::query("INSERT INTO rss_ts_ch.streams(tenant_id,namespace,source,generation) VALUES($1::text::uuid,$2,$3,$4) ON CONFLICT DO NOTHING")
            .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).execute(&mut *c).await.map_err(sql_error)?;
        let closed:bool=sqlx::query_scalar("SELECT closed FROM rss_ts_ch.streams WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4")
            .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).fetch_one(&mut *c).await.map_err(sql_error)?;
        if closed {
            return Err(Error::HistoryExpired);
        }
        let fences = control::fences(c, scope, self.limits.max_points.get()).await?;
        let received = now(c).await?;
        let mut rows = Vec::new();
        for sample in b.samples() {
            if self.admit_sample(c, sample, &fences, received).await? {
                rows.push(Raw::new(sample, received, revision)?);
            }
        }
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
        Ok(Err(Prepared {
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
    async fn admit_sample(
        &self,
        c: &mut PgConnection,
        sample: &Sample,
        fences: &[control::Fence],
        received: i64,
    ) -> Result<bool, Error> {
        let i = sample.input();
        let scope = i.stream.scope();
        let digest = sample.digest()?;
        let old:Option<Vec<u8>>=sqlx::query_scalar("SELECT digest FROM rss_ts_ch.identities WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 AND sample_id=$5")
            .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(i.stream.source().as_str()).bind(i.stream.generation().as_str()).bind(i.id.as_str()).fetch_optional(&mut *c).await.map_err(sql_error)?;
        if let Some(old) = old {
            return if old == digest.as_bytes() {
                Ok(false)
            } else {
                Err(Error::Conflict)
            };
        }
        if fences.iter().any(|f| f.matches(sample)) {
            return Err(Error::HistoryExpired);
        }
        let spec = i.series.definition().spec();
        let d = definition::exact(
            c,
            &DefinitionId {
                scope: scope.clone(),
                key: spec.key.clone(),
                version: std::num::NonZeroU64::new(spec.version).ok_or(Error::Invariant)?,
            },
        )
        .await?
        .ok_or(Error::InvalidInput)?;
        if d.definition != *i.series.definition() {
            return Err(Error::Conflict);
        }
        if d.state == DefinitionState::Retired {
            return Err(Error::Retired);
        }
        sqlx::query("INSERT INTO rss_ts_ch.identities(tenant_id,namespace,source,generation,sample_id,digest,received_at) VALUES($1::text::uuid,$2,$3,$4,$5,$6,$7)")
            .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(i.stream.source().as_str()).bind(i.stream.generation().as_str()).bind(i.id.as_str()).bind(digest.as_bytes().as_slice()).bind(received).execute(c).await.map_err(sql_error)?;
        Ok(true)
    }
    async fn attempt(
        &self,
        b: &Batch,
        revision: i64,
        deadline: Deadline,
    ) -> Result<Outcome<(Attempt, Vec<String>)>, Error> {
        let scope = b.stream().scope();
        let mut tx = self.begin(scope, true, deadline).await?;
        let result=async {
            let ids=sqlx::query_scalar::<_,String>("UPDATE rss_ts_ch.attempts SET allowed=false WHERE tenant_id=$1::text::uuid AND namespace=$2 AND target='raw' AND NOT drained RETURNING query_id::text")
                .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).fetch_all(tx.connection()).await.map_err(sql_error)?;
            let attempt=projection::permit(tx.connection(),scope,"raw",&projection::hex(b.digest()?.as_bytes()),revision).await?;
            let count=sqlx::query("UPDATE rss_ts_ch.batches SET attempt=$6::text::uuid WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 AND batch_id=$5 AND NOT published")
                .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(b.stream().source().as_str()).bind(b.stream().generation().as_str()).bind(b.id().as_str()).bind(&attempt.id).execute(tx.connection()).await.map_err(sql_error)?.rows_affected();
            if count!=1 {return Err(Error::Unavailable);}
            Ok((attempt,ids))
        }.await;
        tx.finish(result, true).await
    }
    async fn verify_projection(
        &self,
        b: &Batch,
        p: &Prepared,
        deadline: Deadline,
    ) -> Result<(), Error> {
        let rows=self.ch_query(&self.ch.reader,"SELECT sample_id,digest,received_at FROM rss_ts_ch.raw FINAL WHERE tenant=? AND namespace=? AND revision=? ORDER BY sample_id",deadline)?
            .bind(self.tenant.to_string()).bind(b.stream().scope().namespace().as_str()).bind(p.revision).fetch_all::<(String,String,i64)>().await.map_err(|_|Error::Unavailable)?;
        let mut expected = p
            .rows
            .iter()
            .map(|r| (r.sample_id.clone(), r.digest.clone(), r.received_at))
            .collect::<Vec<_>>();
        expected.sort();
        if rows != expected {
            return Err(Error::Invariant);
        }
        Ok(())
    }
    async fn publish(
        &self,
        b: &Batch,
        p: Prepared,
        a: &Attempt,
        deadline: Deadline,
    ) -> Result<Outcome<Receipt>, Error> {
        let scope = b.stream().scope();
        let mut tx = self.begin(scope, true, deadline).await?;
        let result=async {
            let count=sqlx::query("UPDATE rss_ts_ch.batches SET published=true,payload=NULL,projection=NULL WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 AND batch_id=$5 AND attempt=$6::text::uuid AND NOT published")
                .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(b.stream().source().as_str()).bind(b.stream().generation().as_str()).bind(b.id().as_str()).bind(&a.id).execute(tx.connection()).await.map_err(sql_error)?.rows_affected();
            if count!=1 {return Err(Error::Unavailable);}
            sqlx::query("UPDATE rss_ts_ch.attempts SET allowed=false WHERE tenant_id=$1::text::uuid AND namespace=$2 AND target='raw'")
                .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).execute(tx.connection()).await.map_err(sql_error)?;
            sqlx::query("UPDATE rss_ts_ch.namespaces SET published=$3 WHERE tenant_id=$1::text::uuid AND namespace=$2")
                .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).bind(p.revision).execute(tx.connection()).await.map_err(sql_error)?;
            for row in &p.rows {
                let sample=row.sample()?;
                let selection=Selection::Exact {stream:sample.input().stream.clone(),series:sample.input().series.clone()};
                control::invalidate(tx.connection(),scope,&selection,row.observed_at,self.limits.max_points.get()).await?;
            }
            Ok(p.receipt)
        }.await;
        // A prior INSERT has possible durable effects, even if this transaction rolls back.
        match tx.finish(result, true).await {
            Ok(v) => Ok(v),
            Err(_) => Ok(Outcome::Unknown),
        }
    }
    async fn advance(&self, b: &Batch, deadline: Deadline) -> Result<Outcome<Receipt>, Error> {
        let p = match self.prepare(b, deadline).await? {
            Outcome::Accepted(Ok(r)) | Outcome::Replay(Ok(r)) => return Ok(Outcome::Replay(r)),
            Outcome::Accepted(Err(p)) | Outcome::Replay(Err(p)) => p,
            Outcome::Unknown => return Ok(Outcome::Unknown),
        };
        if self.fault(1) {
            return Ok(Outcome::Unknown);
        }
        let projected: Result<Outcome<Receipt>,Error> = async {
            let (a, old) = match self.attempt(b, p.revision, deadline).await? {
                Outcome::Accepted(v) | Outcome::Replay(v) => v,
                Outcome::Unknown => return Ok(Outcome::Unknown),
            };
            self.drain(&old, deadline).await?;
            let mut drained=self.begin(b.stream().scope(),true,deadline).await?;
            let deletion=sqlx::query("DELETE FROM rss_ts_ch.attempts WHERE tenant_id=$1::text::uuid AND namespace=$2 AND query_id::text=ANY($3) AND NOT allowed")
                .bind(self.tenant.to_string()).bind(b.stream().scope().namespace().as_str()).bind(&old).execute(drained.connection()).await.map(|_|()).map_err(sql_error);
            if matches!(drained.finish(deletion,true).await?,Outcome::Unknown) {return Ok(Outcome::Unknown);}
            self.insert(&a, &p.rows, deadline).await?;
            if self.fault(2) {
                return Ok(Outcome::Unknown);
            }
            self.verify_projection(b, &p, deadline).await?;
            let outcome = self.publish(b, p, &a, deadline).await?;
            if self.fault(3) {
                return Ok(Outcome::Unknown);
            }
            Ok(outcome)
        }
        .await;
        match projected {
            Ok(v) => Ok(v),
            Err(_) => Ok(Outcome::Unknown),
        }
    }
    pub async fn progress(
        &self,
        request: &Authorized<ReceiptQuery>,
        deadline: Deadline,
    ) -> Result<ProjectionProgress, Error> {
        let q = request.request();
        let _guard = self.operation(q.stream.scope(), deadline).await?;
        self.bounded(deadline, async {
            let mut tx = self.begin(q.stream.scope(), false, deadline).await?;
            let result = async {
                Ok(match lookup(tx.connection(), q).await? {
                    None => ProjectionProgress::NotVisible,
                    Some(r) => {
                        receipt(&r, q)?;
                        if r.try_get("expired").map_err(sql_error)? {
                            ProjectionProgress::Expired
                        } else if r.try_get("published").map_err(sql_error)? {
                            ProjectionProgress::Published
                        } else {
                            ProjectionProgress::Prepared
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
        let _guard = self.operation(scope, deadline).await?;
        self.mutation(deadline,async {
            let mut tx=self.begin(scope,false,deadline).await?;
            let raw=sqlx::query_scalar::<_,Vec<u8>>("SELECT payload FROM rss_ts_ch.batches WHERE tenant_id=$1::text::uuid AND namespace=$2 AND NOT published")
                .bind(scope.tenant().to_string()).bind(scope.namespace().as_str()).fetch_optional(tx.connection()).await.map_err(sql_error);
            let Some(raw)=tx.read(raw).await? else {return Ok(Outcome::Accepted(None));};
            let b=Authorized::<Batch>::verify(authority,Batch::decode(&raw)?)?;
            Ok(match self.advance(b.request(),deadline).await? {Outcome::Accepted(r)=>Outcome::Accepted(Some(r)),Outcome::Replay(r)=>Outcome::Replay(Some(r)),Outcome::Unknown=>Outcome::Unknown})
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
        let _guard = self
            .operation(b.request().stream().scope(), deadline)
            .await?;
        self.mutation(deadline, self.advance(b.request(), deadline))
            .await
    }
    async fn receipt(
        &self,
        request: &Authorized<ReceiptQuery>,
        deadline: Deadline,
    ) -> Result<Lookup<Receipt>, Error> {
        let q = request.request();
        let _guard = self.operation(q.stream.scope(), deadline).await?;
        self.bounded(deadline,async {
            let mut tx=self.begin(q.stream.scope(),false,deadline).await?;
            let result=async {Ok(match lookup(tx.connection(),q).await? {
                None=>{
                    let reclaimed:Option<bool>=sqlx::query_scalar("SELECT reclaimed FROM rss_ts_ch.streams WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4").bind(q.stream.scope().tenant().to_string()).bind(q.stream.scope().namespace().as_str()).bind(q.stream.source().as_str()).bind(q.stream.generation().as_str()).fetch_optional(tx.connection()).await.map_err(sql_error)?;
                    if reclaimed==Some(true) {Lookup::Expired} else {Lookup::NotVisible}
                },
                Some(r)=>{let value=receipt(&r,q)?;if r.try_get("expired").map_err(sql_error)? {Lookup::Expired} else if r.try_get("published").map_err(sql_error)? {Lookup::Found(value)} else {Lookup::NotVisible}}
            })}.await;tx.read(result).await
        }).await
    }
}
