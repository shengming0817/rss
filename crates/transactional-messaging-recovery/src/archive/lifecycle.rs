use super::*;
use rss_data_protection::Aead;
use rss_transactional_messaging::{
    policy::{ExecutionDeadlines, ExecutionTimer, OperationDeadline, within},
    transaction::LocalTxAttempt,
};
use std::sync::atomic::{AtomicBool, Ordering};
/// PG owns leases, exact-request retries, durable progress and all cleanup predicates.
pub trait ArchiveRepository: Send + Sync {
    /// Read durable progress for the exact request after uncertain settlement; absence proves nothing.
    fn receipt(
        &self,
        request: &AuthorizedRequest,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<Option<Outcome>, Error>> + Send;
    /// Acquire or resume a generation, fencing previous workers. Held requests persist their decision too.
    fn claim(
        &self,
        request: &AuthorizedRequest,
        deadline: OperationDeadline,
    ) -> impl Future<Output = LocalTxAttempt<Claim, Error>> + Send;
    /// Persist encryption bytes before any external write.
    fn prepare(
        &self,
        request: &AuthorizedRequest,
        claim: &Claim,
        prepared: &Prepared,
        deadline: OperationDeadline,
    ) -> impl Future<Output = LocalTxAttempt<(), Error>> + Send;
    /// Persist the verifier's receipt and discard temporary ciphertext atomically.
    fn record(
        &self,
        request: &AuthorizedRequest,
        claim: &Claim,
        proof: &Verified,
        deadline: OperationDeadline,
    ) -> impl Future<Output = LocalTxAttempt<(), Error>> + Send;
    /// Recheck current policy, source revision and lease under lock before removing HOT.
    fn purge(
        &self,
        request: &AuthorizedRequest,
        claim: &Claim,
        proof: &Verified,
        deadline: OperationDeadline,
    ) -> impl Future<Output = LocalTxAttempt<(), Error>> + Send;
    /// Mark an expired exact version missing, preserving the source and operation evidence.
    fn reconcile(
        &self,
        request: &AuthorizedRequest,
        claim: &Claim,
        proof: &Missing,
        deadline: OperationDeadline,
    ) -> impl Future<Output = LocalTxAttempt<(), Error>> + Send;
    /// Persist a closed integrity fault; never delete evidence.
    fn fault(
        &self,
        request: &AuthorizedRequest,
        claim: &Claim,
        error: Error,
        deadline: OperationDeadline,
    ) -> impl Future<Output = LocalTxAttempt<(), Error>> + Send;
}
/// Narrow trusted object provider. No delete, listing or administrative capability.
pub trait ArchiveObjectStore: Send + Sync {
    /// Create-only upload. Return the observed immutable version even after a matching duplicate.
    fn put(
        &self,
        prepared: &Prepared,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<Object, Error>> + Send;
    /// Inspect an exact version, or resolve a prepared key to an immutable version before reading its body.
    /// Unknown authorization or transport outcomes must not become None.
    fn inspect(
        &self,
        object: &Object,
        body: bool,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<Option<Observation>, Error>> + Send;
}
/// Closed lifecycle outcome, separate from transaction settlement certainty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Product hold persisted.
    Held,
    /// Verified but HOT age has not elapsed.
    Archived,
    /// HOT bytes removed with durable evidence.
    Purged,
    /// Expired object still exists.
    Retained,
    /// Exact expired version is absent.
    Reconciled,
}
/// Low-cardinality completion observation.
#[derive(Clone, Copy, Debug)]
pub struct Event {
    /// Transaction settlement certainty; unknown commit never appears as rollback.
    pub status: crate::AttemptStatus,
    /// Successful phase, if committed.
    pub outcome: Option<Outcome>,
    /// Closed error, never provider text.
    pub error: Option<Error>,
}
/// Product-owned observation sink.
pub trait Observer {
    /// Emit a payload-free result.
    fn observe(&self, event: Event);
}
fn settled<T>(attempt: LocalTxAttempt<T, Error>) -> Result<T, LocalTxAttempt<Outcome, Error>> {
    attempt.fold(
        Ok,
        |e| Err(LocalTxAttempt::not_started(e)),
        |e| Err(LocalTxAttempt::rolled_back(e)),
        |e| Err(LocalTxAttempt::rollback_failed(e)),
        |e| Err(LocalTxAttempt::commit_unknown(e)),
        |e| Err(LocalTxAttempt::fenced(e)),
    )
}
/// Execute one bounded archive attempt. An expired outer budget conservatively preserves uncertainty.
#[allow(clippy::too_many_arguments)] // reason: required provider, crypto, clock and observation capabilities.
pub async fn execute<
    R: ArchiveRepository,
    S: ArchiveObjectStore,
    H: Aead + Send + Sync,
    K: Aead + Send + Sync,
    C: ExecutionTimer,
    O: Observer,
>(
    repository: &R,
    store: &S,
    hot: &HotKey<H>,
    archive: &ArchiveKey<K>,
    request: &AuthorizedRequest,
    clock: &C,
    deadlines: ExecutionDeadlines,
    observer: &O,
) -> LocalTxAttempt<Outcome, Error> {
    let integrity_observed = AtomicBool::new(false);
    let result = if deadlines.operation().remaining(clock).is_zero() {
        LocalTxAttempt::not_started(Error::Deadline)
    } else {
        match within(clock, deadlines.operation(), |deadline| {
            run(
                repository,
                store,
                hot,
                archive,
                request,
                deadline,
                &integrity_observed,
            )
        })
        .await
        {
            Ok(result) => result,
            Err(_) => LocalTxAttempt::commit_unknown(Error::Deadline),
        }
    };
    let (unknown, result) = result.fold(
        |v| (false, LocalTxAttempt::committed(v)),
        |e| (false, LocalTxAttempt::not_started(e)),
        |e| (false, LocalTxAttempt::rolled_back(e)),
        |e| (false, LocalTxAttempt::rollback_failed(e)),
        |e| (true, LocalTxAttempt::commit_unknown(e)),
        |e| (false, LocalTxAttempt::fenced(e)),
    );
    // An older successful receipt cannot settle an integrity fault whose write was interrupted.
    let result = if unknown && !integrity_observed.load(Ordering::Relaxed) {
        match within(clock, deadlines.settlement(), |deadline| {
            repository.receipt(request, deadline)
        })
        .await
        {
            Ok(Ok(Some(outcome))) => LocalTxAttempt::committed(outcome),
            _ => result,
        }
    } else {
        result
    };
    result.fold(
        |v| {
            observer.observe(Event {
                status: crate::AttemptStatus::Committed,
                outcome: Some(v),
                error: None,
            });
            LocalTxAttempt::committed(v)
        },
        |e| {
            observer.observe(Event {
                status: crate::AttemptStatus::NotStarted,
                outcome: None,
                error: Some(e),
            });
            LocalTxAttempt::not_started(e)
        },
        |e| {
            observer.observe(Event {
                status: crate::AttemptStatus::RolledBack,
                outcome: None,
                error: Some(e),
            });
            LocalTxAttempt::rolled_back(e)
        },
        |e| {
            observer.observe(Event {
                status: crate::AttemptStatus::RollbackFailed,
                outcome: None,
                error: Some(e),
            });
            LocalTxAttempt::rollback_failed(e)
        },
        |e| {
            observer.observe(Event {
                status: crate::AttemptStatus::CommitUnknown,
                outcome: None,
                error: Some(e),
            });
            LocalTxAttempt::commit_unknown(e)
        },
        |e| {
            observer.observe(Event {
                status: crate::AttemptStatus::Fenced,
                outcome: None,
                error: Some(e),
            });
            LocalTxAttempt::fenced(e)
        },
    )
}
async fn run<
    R: ArchiveRepository,
    S: ArchiveObjectStore,
    H: Aead + Send + Sync,
    K: Aead + Send + Sync,
>(
    repository: &R,
    store: &S,
    hot: &HotKey<H>,
    archive: &ArchiveKey<K>,
    request: &AuthorizedRequest,
    deadline: OperationDeadline,
    integrity_observed: &AtomicBool,
) -> LocalTxAttempt<Outcome, Error> {
    let claim = match settled(repository.claim(request, deadline).await) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if request.request().hold() == Hold::Retain {
        return LocalTxAttempt::committed(Outcome::Held);
    }
    let result = advance(repository, store, hot, archive, request, &claim, deadline).await;
    match result {
        Ok(outcome) => LocalTxAttempt::committed(outcome),
        Err(attempt) => {
            let fault = |error| matches!(error, Error::Missing | Error::Evidence).then_some(error);
            let (integrity, attempt) = attempt.fold(
                |value| (None, LocalTxAttempt::committed(value)),
                |e| (fault(e), LocalTxAttempt::not_started(e)),
                |e| (fault(e), LocalTxAttempt::rolled_back(e)),
                |e| (fault(e), LocalTxAttempt::rollback_failed(e)),
                |e| (fault(e), LocalTxAttempt::commit_unknown(e)),
                |e| (fault(e), LocalTxAttempt::fenced(e)),
            );
            if let Some(error) = integrity {
                integrity_observed.store(true, Ordering::Relaxed);
                if let Err(failure) =
                    settled(repository.fault(request, &claim, error, deadline).await)
                {
                    return failure;
                }
            }
            attempt
        }
    }
}
async fn advance<
    R: ArchiveRepository,
    S: ArchiveObjectStore,
    H: Aead + Send + Sync,
    K: Aead + Send + Sync,
>(
    repository: &R,
    store: &S,
    hot: &HotKey<H>,
    archive: &ArchiveKey<K>,
    request: &AuthorizedRequest,
    claim: &Claim,
    deadline: OperationDeadline,
) -> Result<Outcome, LocalTxAttempt<Outcome, Error>> {
    let failure = LocalTxAttempt::not_started;
    reconcile_retired(repository, store, request, claim, deadline).await?;
    let object = if let Some(object) = &claim.object {
        object.clone()
    } else {
        let prepared = if let Some(prepared) = &claim.prepared {
            prepared.clone()
        } else {
            let candidate = claim
                .candidate
                .as_ref()
                .ok_or_else(|| failure(Error::Evidence))?;
            let prepared =
                super::crypto::prepare(hot, archive, request.request(), claim, candidate)
                    .map_err(failure)?;
            settled(
                repository
                    .prepare(request, claim, &prepared, deadline)
                    .await,
            )?;
            prepared
        };
        let uploaded = store
            .put(&prepared, deadline)
            .await
            .map_err(LocalTxAttempt::commit_unknown)?;
        if uploaded.key != prepared.object.key
            || uploaded.checksum != prepared.object.checksum
            || uploaded.length != prepared.object.length
        {
            return Err(failure(Error::Evidence));
        }
        uploaded
    };
    let observed = store
        .inspect(&object, true, deadline)
        .await
        .map_err(failure)?;
    let Some(observed) = observed else {
        if claim.purged && claim.now >= object.retain_until {
            let proof = Missing {
                object,
                digest: request.request().digest(),
                generation: claim.generation.clone(),
            };
            settled(repository.reconcile(request, claim, &proof, deadline).await)?;
            return Ok(Outcome::Reconciled);
        }
        return Err(failure(Error::Missing));
    };
    if claim.purged {
        validate_object(&object, &observed).map_err(failure)?;
        return Ok(if claim.now >= object.retain_until {
            Outcome::Retained
        } else {
            Outcome::Purged
        });
    }
    let proof = verify(archive, request.request(), claim, &object, observed).map_err(failure)?;
    settled(repository.record(request, claim, &proof, deadline).await)?;
    if claim.now < claim.hot_until {
        return Ok(Outcome::Archived);
    }
    settled(repository.purge(request, claim, &proof, deadline).await)?;
    Ok(Outcome::Purged)
}
fn validate_object(expected: &Object, observed: &Observation) -> Result<(), Error> {
    let actual = &observed.object;
    if actual.key != expected.key
        || (expected.version.is_some() && actual.version != expected.version)
        || actual
            .version
            .as_deref()
            .is_none_or(|s| s.is_empty() || s == "null")
        || actual.checksum != expected.checksum
        || actual.length != expected.length
        || !observed.compliance
        || actual.retain_until < expected.retain_until
    {
        return Err(Error::Evidence);
    }
    let bytes = observed.bytes.as_ref().ok_or(Error::Evidence)?;
    if bytes.len() as u64 != expected.length || super::model::checksum(bytes) != expected.checksum {
        return Err(Error::Evidence);
    }
    Ok(())
}
fn verify<K: Aead>(
    archive: &ArchiveKey<K>,
    request: &Request,
    claim: &Claim,
    expected: &Object,
    observed: Observation,
) -> Result<Verified, Error> {
    validate_object(expected, &observed)?;
    super::crypto::validate(
        archive,
        request,
        claim.candidate.as_ref().ok_or(Error::Evidence)?,
        &expected.key,
        observed.bytes.as_deref().ok_or(Error::Evidence)?,
    )?;
    if observed.object.retain_until
        <= request
            .retention()
            .minimum_lock_until(claim.now, claim.receipt_seconds)?
    {
        return Err(Error::Retention);
    }
    Ok(Verified {
        object: observed.object,
        digest: request.digest(),
        generation: claim.generation.clone(),
    })
}

fn object_generation(object: &Object) -> Result<String, Error> {
    object
        .key
        .rsplit('/')
        .next()
        .and_then(|s| s.strip_suffix(super::crypto::OBJECT_SUFFIX))
        .map(str::to_owned)
        .ok_or(Error::Evidence)
}

async fn reconcile_retired<R: ArchiveRepository, S: ArchiveObjectStore>(
    repository: &R,
    store: &S,
    request: &AuthorizedRequest,
    claim: &Claim,
    deadline: OperationDeadline,
) -> Result<(), LocalTxAttempt<Outcome, Error>> {
    let failure = LocalTxAttempt::not_started;
    for object in &claim.retired {
        if object.retain_until > claim.now {
            return Err(failure(Error::Evidence));
        }
        match store
            .inspect(object, true, deadline)
            .await
            .map_err(failure)?
        {
            Some(observed) => {
                validate_object(object, &observed).map_err(failure)?;
                if object.version.is_none() {
                    let generation = object_generation(object).map_err(failure)?;
                    let proof = Verified {
                        object: observed.object,
                        digest: request.request().digest(),
                        generation,
                    };
                    settled(repository.record(request, claim, &proof, deadline).await)?;
                }
            }
            None if object.version.is_some() => {
                let generation = object_generation(object).map_err(failure)?;
                let proof = Missing {
                    object: object.clone(),
                    digest: request.request().digest(),
                    generation,
                };
                settled(repository.reconcile(request, claim, &proof, deadline).await)?;
            }
            // An unknown PUT with no known version is not exact-version missing evidence.
            None => {}
        }
    }
    Ok(())
}
