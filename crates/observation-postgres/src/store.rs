use crate::{
    probe,
    transaction::{Fault, Lease, Progress, Stage, runtime_budget, sql_error, watchdog, within},
};
use rss_observation::{
    Batch, Clock, Decision, Error, ErrorKind, Id, LifecycleGrant, LookupOutcome, ObservationStore,
    Policy, ReadGrant, ReceiveOutcome, Record, Scope, State, VerifiedBatch,
};
use rss_request_context::{Deadline, TenantId};
use sqlx::{Connection, PgConnection, PgPool, Row, postgres::PgRow};
#[cfg(feature = "integration")]
use std::sync::Mutex;
/// Adopted, dedicated pool. The host configures TLS/authentication before construction.
/// Dropping an operation quarantines its unconfirmed transaction. Close stops pool admission.
pub struct PgStore<C> {
    pool: PgPool,
    pub(crate) clock: C,
    #[cfg(feature = "integration")]
    fault: Mutex<Option<Fault>>,
}
impl<C: Clock> PgStore<C> {
    /// Adopt a dedicated pool after validating the PostgreSQL storage and effective-permission contract.
    /// The host configures TLS and credentials and supplies a clock sharing the Deadline domain.
    /// Admission is bounded, executes no migrations and quarantines unconfirmed probe transactions.
    pub async fn new(pool: PgPool, clock: C, deadline: Deadline) -> Result<Self, Error> {
        Self::admit(pool, clock, deadline, None, false).await
    }
    /// Integration-only admission fault; only RollbackPending is valid for this boundary.
    #[cfg(feature = "integration")]
    pub async fn new_with_fault(
        pool: PgPool,
        clock: C,
        deadline: Deadline,
        fault: crate::Fault,
    ) -> Result<Self, Error> {
        if !matches!(&fault, Fault::RollbackPending(_)) {
            return Err(ErrorKind::InvalidInput.into());
        }
        Self::admit(pool, clock, deadline, Some(fault), false).await
    }
    pub(crate) async fn admit(
        pool: PgPool,
        clock: C,
        deadline: Deadline,
        _fault: Option<Fault>,
        maintenance: bool,
    ) -> Result<Self, Error> {
        let progress = Progress::new();
        within(&clock, deadline, &progress, async {
            let mut lease = Lease {
                connection: pool.acquire().await.map_err(sql_error)?,
                settled: false,
            };
            let mut tx = lease.connection.begin().await.map_err(sql_error)?;
            let result = async {
                let budget = watchdog(deadline.remaining(clock.now()).ok_or(ErrorKind::Deadline)?);
                sqlx::query("SELECT set_config('statement_timeout',$1,true)")
                    .bind(budget)
                    .execute(&mut *tx)
                    .await
                    .map_err(sql_error)?;
                probe::validate(&mut tx, maintenance).await
            }
            .await;
            progress.set(Stage::Rollback);
            #[cfg(feature = "integration")]
            if let Some(Fault::RollbackPending(entered)) = _fault {
                Fault::hold_rollback(entered).await;
            }
            tx.rollback()
                .await
                .map_err(|e| Error::provider(ErrorKind::RollbackFailed, e))?;
            lease.settled = true;
            result
        })
        .await??;
        Ok(Self {
            pool,
            clock,
            #[cfg(feature = "integration")]
            fault: Mutex::default(),
        })
    }
    /// Close pool admission immediately and await borrowers within the original deadline.
    /// This closes all clones of the adopted pool. A timed-out drain remains closed and can be awaited
    /// again; existing borrowers still own their settlement. The host must stop/join workers first.
    pub async fn close(&self, deadline: Deadline) -> Result<(), Error> {
        within(&self.clock, deadline, &Progress::new(), self.pool.close()).await?;
        Ok(())
    }
    /// Whether pool admission has stopped; this does not prove that every borrower has drained.
    pub fn is_closed(&self) -> bool {
        self.pool.is_closed()
    }
    #[cfg(feature = "integration")]
    /// Inject one fault into the next eligible fixture operation on this handle.
    /// Readback deliberately uses a clean transaction. Admission faults use new_with_fault instead.
    pub fn inject_next_fault(&self, fault: crate::Fault) {
        *self
            .fault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(fault);
    }
    /// Arm a pending rollback and observe when that transaction has actually entered rollback.
    #[cfg(feature = "integration")]
    pub fn inject_pending_rollback(&self) -> futures::channel::oneshot::Receiver<()> {
        let (entered, waiting) = futures::channel::oneshot::channel();
        self.inject_next_fault(Fault::RollbackPending(Some(entered)));
        waiting
    }
    pub(crate) fn take_fault(&self) -> Option<Fault> {
        #[cfg(feature = "integration")]
        {
            self.fault
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
        }
        #[cfg(not(feature = "integration"))]
        {
            None
        }
    }
    async fn setup(
        &self,
        connection: &mut PgConnection,
        tenant: TenantId,
        remaining: std::time::Duration,
    ) -> Result<(), Error> {
        let remaining = remaining.as_nanos().div_ceil(1_000_000).to_string();
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true)")
            .bind(tenant.to_string()).bind(remaining).execute(connection).await.map_err(sql_error)?;
        Ok(())
    }
    pub(crate) async fn transact<T, E, F>(
        &self,
        tenant: TenantId,
        deadline: Deadline,
        fault: Option<Fault>,
        operation: F,
    ) -> Result<T, E>
    where
        T: Send,
        E: From<Error> + Send,
        F: for<'a> FnOnce(
                &'a mut PgConnection,
                &'a Progress,
            ) -> futures::future::BoxFuture<'a, Result<T, E>>
            + Send,
    {
        let progress = Progress::new();
        let budget = || {
            deadline
                .remaining(self.clock.now())
                .ok_or_else(|| Error::new(ErrorKind::Deadline))
                .and_then(runtime_budget)
                .map_err(E::from)
        };
        budget()?;
        within(
            &self.clock,
            deadline,
            &progress,
            self.transact_inner(
                tenant,
                fault,
                &progress,
                &budget,
                |connection, progress, _| operation(connection, progress),
            ),
        )
        .await
        .map_err(E::from)?
    }
    pub(crate) async fn transact_inner<T, E, F, B>(
        &self,
        tenant: TenantId,
        _fault: Option<Fault>,
        progress: &Progress,
        budget: &B,
        operation: F,
    ) -> Result<T, E>
    where
        T: Send,
        E: From<Error> + Send,
        B: Fn() -> Result<std::time::Duration, E> + Sync,
        F: for<'a> FnOnce(
                &'a mut PgConnection,
                &'a Progress,
                &'a B,
            ) -> futures::future::BoxFuture<'a, Result<T, E>>
            + Send,
    {
        #[cfg(feature = "integration")]
        let fault = _fault;
        budget()?;
        let mut lease = Lease {
            connection: self.pool.acquire().await.map_err(sql_error)?,
            settled: false,
        };
        budget()?;
        let mut tx = lease.connection.begin().await.map_err(sql_error)?;
        let result = async {
            self.setup(&mut tx, tenant, budget()?).await?;
            #[cfg(feature = "integration")]
            crate::transaction::watchdog_fault(&mut tx, fault.as_ref()).await?;
            budget()?;
            let result = operation(&mut tx, progress, budget).await;
            budget()?;
            #[cfg(feature = "integration")]
            let result =
                crate::transaction::after_write_fault(&mut tx, fault.as_ref(), result).await;
            result
        }
        .await;
        #[cfg(feature = "integration")]
        let result = Fault::before_settlement(fault.as_ref(), result);
        match result {
            Ok(value) => {
                progress.set(Stage::Effects);
                #[cfg(feature = "integration")]
                if matches!(fault, Some(Fault::CommitPending)) {
                    std::future::pending::<()>().await;
                }
                tx.commit()
                    .await
                    .map_err(|e| Error::provider(ErrorKind::CommitUnknown, e))?;
                #[cfg(feature = "integration")]
                if matches!(
                    fault,
                    Some(Fault::CommitAckLost | Fault::CommitAckAndReadLost)
                ) {
                    return Err(Error::new(ErrorKind::CommitUnknown).into());
                }
                lease.settled = true;
                Ok(value)
            }
            Err(error) => {
                progress.set(Stage::Rollback);
                #[cfg(feature = "integration")]
                if let Some(Fault::RollbackPending(entered)) = fault {
                    Fault::hold_rollback(entered).await;
                }
                tx.rollback()
                    .await
                    .map_err(|e| Error::provider(ErrorKind::RollbackFailed, e))?;
                #[cfg(feature = "integration")]
                if matches!(fault, Some(Fault::RollbackAckLost)) {
                    return Err(Error::new(ErrorKind::RollbackFailed).into());
                }
                lease.settled = true;
                // The original failure is now backed by an acknowledged rollback.
                progress.set(Stage::Waiting);
                Err(error)
            }
        }
    }
    async fn receive_once(
        &self,
        input: &VerifiedBatch,
        deadline: Deadline,
        fault: Option<Fault>,
    ) -> Result<ReceiveOutcome, Error> {
        let input_scope = input.scope().clone();
        let batch = input.batch().clone();
        let fingerprint = input.fingerprint();
        self.transact(input.scope().tenant(),deadline,fault,move |connection,progress|Box::pin(async move{
            if let Some(outcome)=read(connection,&input_scope,batch.id()).await?.retry(&batch, &fingerprint)? {return Ok(outcome);}
            let row=sqlx::query("SELECT state,policy FROM rss_observation.lock_stream($1)").bind(input_scope.encode()?).fetch_one(&mut *connection).await.map_err(sql_error)?;
            // A concurrent exact retry may have committed while we waited for the stream lock.
            if let Some(outcome)=read(connection,&input_scope,batch.id()).await?.retry(&batch, &fingerprint)? {return Ok(outcome);}
            let state=durable(State::decode(row.try_get("state").map_err(sql_error)?))?;
            let policy=durable(Policy::decode(row.try_get("policy").map_err(sql_error)?))?;
            let received:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").fetch_one(&mut *connection).await.map_err(sql_error)?;
            let received_at=u64::try_from(received).map_err(|_|ErrorKind::Invariant)?;
            let decision=state.advance(&batch,received_at,&policy)?;
            progress.set(Stage::Effects);
            sqlx::query("SELECT rss_observation.commit_batch($1,$2,$3::numeric,$4,$5,$6,$7,$8,$9::numeric,$10)")
                .bind(input_scope.encode()?).bind(batch.id().as_str()).bind(batch.sequence().to_string()).bind(batch.encode()).bind(fingerprint.as_slice()).bind(received)
                .bind(policy.encode()?).bind(decision.encode()?).bind(state.revision().to_string()).bind(decision.outcome().is_applicable()).execute(connection).await.map_err(sql_error)?;
            Ok(ReceiveOutcome::Accepted(Record::from_durable(input_scope,batch,received_at,policy,decision)?))
        })).await
    }
}
impl<C: Clock> ObservationStore for PgStore<C> {
    async fn activate(
        &self,
        grant: &LifecycleGrant,
        expected: Option<u64>,
        policy: &Policy,
        deadline: Deadline,
    ) -> Result<u64, Error> {
        let scope = grant.scope().encode()?;
        let policy = policy.encode()?;
        let initial = State::initial().encode()?;
        let fault = self.take_fault();
        let readback_lost = fault.as_ref().is_some_and(Fault::hides_readback);
        let encoded_scope = scope.clone();
        let encoded_policy = policy.clone();
        let result: Result<u64, Error> = self
            .transact(
                grant.scope().tenant(),
                deadline,
                fault,
                move |connection, progress| {
                    Box::pin(async move {
                        progress.set(Stage::Effects);
                        let revision: String = sqlx::query_scalar(
                            "SELECT rss_observation.activate($1,$2::numeric,$3,$4)::text",
                        )
                        .bind(encoded_scope)
                        .bind(expected.map(|n| n.to_string()))
                        .bind(encoded_policy)
                        .bind(initial)
                        .fetch_one(connection)
                        .await
                        .map_err(sql_error)?;
                        revision.parse().map_err(|_| ErrorKind::Invariant.into())
                    })
                },
            )
            .await;
        match result {
            Err(error) if error.kind() == ErrorKind::CommitUnknown && !readback_lost => {
                let found=self.transact(grant.scope().tenant(),deadline,None,move |connection,_|Box::pin(async move {
                    let revision:Option<String>=sqlx::query_scalar("SELECT activation_revision::text FROM rss_observation.streams WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND scope=$1 AND activation_previous IS NOT DISTINCT FROM $2::numeric AND policy::jsonb=$3::jsonb")
                        .bind(scope).bind(expected.map(|n|n.to_string())).bind(policy).fetch_optional(connection).await.map_err(sql_error)?;
                    revision.map(|r|r.parse::<u64>().map_err(|_|Error::new(ErrorKind::Invariant))).transpose()
                })).await;
                match found {
                    Ok(Some(revision)) => Ok(revision),
                    _ => Err(error),
                }
            }
            other => other,
        }
    }

    async fn receive(
        &self,
        input: &VerifiedBatch,
        deadline: Deadline,
    ) -> Result<ReceiveOutcome, Error> {
        let fault = self.take_fault();
        let readback_lost = fault.as_ref().is_some_and(Fault::hides_readback);
        match self.receive_once(input, deadline, fault).await {
            // A retry may have seen Missing before it queued behind the original
            // receive and a concurrent retirement. Recheck the durable identity.
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::CommitUnknown | ErrorKind::StaleEpoch
                ) =>
            {
                if readback_lost {
                    return Err(error);
                }
                let scope = input.scope().clone();
                let id = input.batch().id().clone();
                let found = self
                    .transact(
                        input.scope().tenant(),
                        deadline,
                        None,
                        move |connection, _| {
                            Box::pin(async move { read(connection, &scope, &id).await })
                        },
                    )
                    .await;
                match found {
                    Ok(identity) => identity
                        .retry(input.batch(), &input.fingerprint())?
                        .ok_or(error),
                    Err(e) if matches!(e.kind(), ErrorKind::Invariant | ErrorKind::Conflict) => {
                        Err(e)
                    }
                    Err(e) if error.kind() == ErrorKind::StaleEpoch => Err(e),
                    _ => Err(error),
                }
            }
            result => result,
        }
    }
    async fn lookup(
        &self,
        grant: &ReadGrant,
        id: &Id,
        deadline: Deadline,
    ) -> Result<LookupOutcome, Error> {
        let scope = grant.scope().clone();
        let id = id.clone();
        self.transact(
            grant.scope().tenant(),
            deadline,
            self.take_fault(),
            move |connection, _| {
                Box::pin(async move { Ok(read(connection, &scope, &id).await?.lookup()) })
            },
        )
        .await
    }
    async fn state(&self, grant: &ReadGrant, deadline: Deadline) -> Result<State, Error> {
        let scope = grant.scope().encode()?;
        self.transact(grant.scope().tenant(),deadline,None,move |connection,_|Box::pin(async move{
            let raw:Option<String>=sqlx::query_scalar("SELECT state FROM rss_observation.streams WHERE scope=$1 AND tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid").bind(scope).fetch_optional(connection).await.map_err(sql_error)?;
            durable(State::decode(&raw.ok_or(ErrorKind::UnknownStream)?))
        })).await
    }
}
fn replay(record: Record, batch: &Batch) -> Result<ReceiveOutcome, Error> {
    if record.batch() != batch {
        return Err(ErrorKind::Conflict.into());
    }
    Ok(ReceiveOutcome::Replay(record))
}
enum StoredBatch {
    Found(Box<Record>),
    Expired([u8; 32]),
    Missing,
}
impl StoredBatch {
    fn lookup(self) -> LookupOutcome {
        match self {
            Self::Found(record) => LookupOutcome::Found(record),
            Self::Missing => LookupOutcome::NotFound,
            Self::Expired(_) => LookupOutcome::Expired,
        }
    }
    fn retry(self, batch: &Batch, fingerprint: &[u8; 32]) -> Result<Option<ReceiveOutcome>, Error> {
        match self {
            Self::Missing => Ok(None),
            Self::Found(record) => replay(*record, batch).map(Some),
            Self::Expired(original) if &original == fingerprint => {
                Err(ErrorKind::HistoryExpired.into())
            }
            Self::Expired(_) => Err(ErrorKind::Conflict.into()),
        }
    }
}
async fn read(connection: &mut PgConnection, scope: &Scope, id: &Id) -> Result<StoredBatch, Error> {
    let row=sqlx::query("SELECT raw IS NULL AS expired,raw,fingerprint,received_at,policy,decision,sequence::text AS sequence,applicable,log_position FROM rss_observation.batches WHERE tenant_id=$1::uuid AND scope=$2 AND batch_id=$3")
        .bind(scope.tenant().to_string()).bind(scope.encode()?).bind(id.as_str()).fetch_optional(connection).await.map_err(sql_error)?;
    match row {
        None => Ok(StoredBatch::Missing),
        Some(row) if row.try_get("expired").map_err(sql_error)? => {
            let fingerprint: Vec<u8> = row.try_get("fingerprint").map_err(sql_error)?;
            Ok(StoredBatch::Expired(
                fingerprint.try_into().map_err(|_| ErrorKind::Invariant)?,
            ))
        }
        Some(row) => restore(row, scope, id)
            .map(Box::new)
            .map(StoredBatch::Found),
    }
}
pub(crate) fn restore(row: PgRow, scope: &Scope, id: &Id) -> Result<Record, Error> {
    let restore = || -> Result<Record, Error> {
        let raw: Vec<u8> = row.try_get("raw").map_err(sql_error)?;
        #[cfg(all(feature = "projection", feature = "integration"))]
        crate::read_profile::count(|cost| {
            use std::sync::atomic::Ordering::Relaxed;
            cost.raw_bytes.fetch_add(raw.len() as u64, Relaxed);
            cost.decodes.fetch_add(1, Relaxed);
            cost.fingerprints.fetch_add(1, Relaxed);
        });
        let batch = Batch::decode(&raw)?;
        let fingerprint: Vec<u8> = row.try_get("fingerprint").map_err(sql_error)?;
        let sequence: String = row.try_get("sequence").map_err(sql_error)?;
        if batch.id() != id
            || batch.encode() != raw
            || batch.fingerprint(scope)?.as_slice() != fingerprint
            || batch.sequence().to_string() != sequence
        {
            return Err(ErrorKind::Invariant.into());
        }
        let received: i64 = row.try_get("received_at").map_err(sql_error)?;
        let received_at = u64::try_from(received).map_err(|_| ErrorKind::Invariant)?;
        let policy = durable(Policy::decode(row.try_get("policy").map_err(sql_error)?))?;
        let decision = Decision::restore(
            row.try_get("decision").map_err(sql_error)?,
            &batch,
            received_at,
            &policy,
        )?;
        if decision.outcome().is_applicable()
            != row.try_get::<bool, _>("applicable").map_err(sql_error)?
        {
            return Err(ErrorKind::Invariant.into());
        }
        let position: Option<i64> = row.try_get("log_position").map_err(sql_error)?;
        if decision.outcome().is_applicable() != position.is_some()
            || position.is_some_and(|p| p <= 0)
        {
            return Err(ErrorKind::Invariant.into());
        }
        Record::from_durable(scope.clone(), batch, received_at, policy, decision)
    };
    restore().map_err(|e| Error::provider(ErrorKind::Invariant, e))
}

fn durable<T>(value: Result<T, Error>) -> Result<T, Error> {
    value.map_err(|e| Error::provider(ErrorKind::Invariant, e))
}
