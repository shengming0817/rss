use super::{PgArchiveRepository, attempt};
use crate::PgError;
use rss_transactional_messaging::{
    inbox::{ConsumerGroup, ConsumerIdentity},
    message::{ContractIdentity, MessageFingerprint, MessageId},
    policy::OperationDeadline,
    transaction::{LocalTxAttempt, RejectKind},
};
use rss_transactional_messaging_recovery::{
    archive::*,
    protection::{Capsule, CaptureContext},
};
use serde_json::Value;
use sqlx::Row;
fn invalid() -> PgError {
    PgError::Archive(Error::Evidence)
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str, PgError> {
    v.get(k).and_then(Value::as_str).ok_or_else(invalid)
}
fn integer(v: &Value, k: &str) -> Result<i64, PgError> {
    v.get(k).and_then(Value::as_i64).ok_or_else(invalid)
}
fn unhex(s: &str) -> Result<Vec<u8>, PgError> {
    if !s.len().is_multiple_of(2) {
        return Err(invalid());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| {
            let raw = std::str::from_utf8(b).map_err(|_| invalid())?;
            u8::from_str_radix(raw, 16).map_err(|_| invalid())
        })
        .collect()
}
fn candidate(v: &Value, r: &Request) -> Result<Option<Candidate>, PgError> {
    let Some(raw) = v.get("capsule").and_then(Value::as_str) else {
        return Ok(None);
    };
    let s = &v["source"];
    let contract = ContractIdentity::new(
        rss_contract::ContractId::parse(string(s, "contract")?).map_err(|_| invalid())?,
        rss_contract::ContractVersion::parse(string(s, "contract_version")?)
            .map_err(|_| invalid())?,
        rss_contract::SchemaDigest::parse(string(s, "schema_digest")?).map_err(|_| invalid())?,
    );
    let consumer = ConsumerIdentity::new(
        r.tenant(),
        ConsumerGroup::parse(string(s, "consumer_group")?).map_err(|_| invalid())?,
        MessageId::parse(string(s, "message_id")?).map_err(|_| invalid())?,
        contract,
    );
    let fingerprint = unhex(
        string(s, "fingerprint")?
            .strip_prefix("\\x")
            .ok_or_else(invalid)?,
    )?;
    let fingerprint =
        MessageFingerprint::from_bytes(fingerprint.try_into().map_err(|_| invalid())?);
    Ok(Some(Candidate {
        context: CaptureContext::from_provider(r.id(), consumer, fingerprint),
        capsule: Capsule::from_provider(unhex(raw)?).map_err(|_| invalid())?,
        captured_at: integer(v, "captured")?,
        reason: match string(s, "reason")? {
            "rejected_permanent" => RejectKind::Permanent,
            "rejected_invariant" => RejectKind::Invariant,
            _ => return Err(invalid()),
        },
    }))
}
impl ArchiveRepository for PgArchiveRepository {
    async fn receipt(
        &self,
        request: &AuthorizedRequest,
        deadline: OperationDeadline,
    ) -> Result<Option<Outcome>, Error> {
        let r = request.request();
        attempt(self.runtime.local_tx_with_context(r.tenant(),deadline,r,|r,tx|Box::pin(async move {
            let row=sqlx::query("SELECT j.request_digest,j.held,j.purged,j.fault,o.verified,o.reconciled FROM rss_transactional_messaging.archive_jobs j LEFT JOIN rss_transactional_messaging.archive_objects o ON o.tenant_id=j.tenant_id AND o.generation=j.generation WHERE j.tenant_id=$1::uuid AND j.operation_id=$2::uuid AND j.claim_epoch=current_setting('rss.execution_epoch')::bigint AND j.claim_lineage=decode(current_setting('rss.storage_lineage'),'hex')")
                .bind(r.tenant().to_string()).bind(r.operation().to_string()).fetch_optional(&mut *tx.connection).await.map_err(super::sql_error)?;
            let Some(row)=row else {return Ok(None)};
            if row.try_get::<Vec<u8>,_>("request_digest")?!=r.digest(){return Err(invalid())}
            if let Some(fault)=row.try_get::<Option<String>,_>("fault")? {
                return Err(PgError::Archive(match fault.as_str() {"missing"=>Error::Missing,"evidence"=>Error::Evidence,_=>Error::StorageContract}));
            }
            Ok(if row.try_get::<bool,_>("held")? {Some(Outcome::Held)} else if row.try_get::<Option<bool>,_>("reconciled")?==Some(true) {Some(Outcome::Reconciled)} else if row.try_get::<bool,_>("purged")? {Some(Outcome::Purged)} else if row.try_get::<Option<bool>,_>("verified")?==Some(true) {Some(Outcome::Archived)} else {None})
        })).await).fold(Ok,Err,Err,Err,Err,Err)
    }

    async fn claim(
        &self,
        request: &AuthorizedRequest,
        deadline: OperationDeadline,
    ) -> LocalTxAttempt<Claim, Error> {
        let ttl = deadline.timeout().as_nanos().div_ceil(1_000_000);
        if ttl == 0 {
            return LocalTxAttempt::not_started(Error::Deadline);
        }
        if ttl > 300_000 {
            return LocalTxAttempt::not_started(Error::Invalid);
        }
        let ttl = ttl as i64;
        let r = request.request();
        attempt(self.runtime.local_tx_with_context(r.tenant(),deadline,(r,ttl),|(r,ttl),tx|Box::pin(async move {
            let v:Value=sqlx::query_scalar("SELECT rss_transactional_messaging.archive_claim($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8)")
                .bind(r.operation().to_string()).bind(r.id().to_string()).bind(r.version().get()).bind(r.digest().as_slice()).bind(r.retention().hot_seconds()).bind(r.retention().cold_seconds()).bind(r.hold()==Hold::Retain).bind(*ttl).fetch_one(&mut *tx.connection).await.map_err(super::sql_error)?;
            let j=&v["job"];
            let generation=string(j,"generation")?.to_owned();
            let row=sqlx::query("SELECT object,prepared,verified FROM rss_transactional_messaging.archive_objects WHERE tenant_id=$1::uuid AND generation=$2::uuid")
                .bind(r.tenant().to_string()).bind(&generation).fetch_optional(&mut *tx.connection).await.map_err(super::sql_error)?;
            let mut prepared=None; let mut object=None;
            if let Some(row)=row {
                let facts:Object=serde_json::from_value(row.try_get("object")?).map_err(|_|invalid())?;
                if row.try_get::<bool,_>("verified")? {object=Some(facts)} else {
                    prepared=Some(Prepared{object:facts,bytes:row.try_get::<Option<Vec<u8>>,_>("prepared")?.ok_or_else(invalid)?});
                }
            }
            let captured=integer(&v,"captured")?.div_euclid(1_000_000);
            let retired=serde_json::from_value::<Vec<Object>>(v["retired"].clone()).map_err(|_|invalid())?;
            Ok(Claim{retired,generation,token:string(j,"lease_token")?.to_owned(),request_digest:r.digest(),candidate:candidate(&v,r)?,prepared,object,now:integer(&v,"now")?,hot_until:captured.checked_add(r.retention().hot_seconds()).ok_or_else(invalid)?,receipt_seconds:integer(&v,"receipt")?,purged:j.get("purged").and_then(Value::as_bool).ok_or_else(invalid)?})
        })).await)
    }
    async fn prepare(
        &self,
        r: &AuthorizedRequest,
        c: &Claim,
        p: &Prepared,
        d: OperationDeadline,
    ) -> LocalTxAttempt<(), Error> {
        self.apply(r, c, d, Command::Prepare(p)).await
    }
    async fn record(
        &self,
        r: &AuthorizedRequest,
        c: &Claim,
        p: &Verified,
        d: OperationDeadline,
    ) -> LocalTxAttempt<(), Error> {
        if p.request_digest() != r.request().digest() {
            return LocalTxAttempt::not_started(Error::Evidence);
        }
        self.apply(r, c, d, Command::Record(p)).await
    }
    async fn purge(
        &self,
        r: &AuthorizedRequest,
        c: &Claim,
        p: &Verified,
        d: OperationDeadline,
    ) -> LocalTxAttempt<(), Error> {
        if p.request_digest() != r.request().digest() || p.generation() != c.generation {
            return LocalTxAttempt::not_started(Error::Evidence);
        }
        self.apply(r, c, d, Command::Purge(p)).await
    }
    async fn reconcile(
        &self,
        r: &AuthorizedRequest,
        c: &Claim,
        p: &Missing,
        d: OperationDeadline,
    ) -> LocalTxAttempt<(), Error> {
        if p.request_digest() != r.request().digest() {
            return LocalTxAttempt::not_started(Error::Evidence);
        }
        self.apply(r, c, d, Command::Reconcile(p)).await
    }
    async fn fault(
        &self,
        r: &AuthorizedRequest,
        c: &Claim,
        error: Error,
        d: OperationDeadline,
    ) -> LocalTxAttempt<(), Error> {
        let command = match error {
            Error::Missing => Command::FaultMissing,
            Error::Evidence => Command::FaultEvidence,
            _ => return LocalTxAttempt::not_started(Error::Invalid),
        };
        self.apply(r, c, d, command).await
    }
}
// Each variant fixes both the SQL signature and its parameter shape; no optional bind positions.
enum Command<'a> {
    Prepare(&'a Prepared),
    Record(&'a Verified),
    Purge(&'a Verified),
    Reconcile(&'a Missing),
    FaultMissing,
    FaultEvidence,
}
impl Command<'_> {
    fn query<'a>(
        &'a self,
        r: &Request,
        c: &Claim,
    ) -> Result<sqlx::query::Query<'a, sqlx::Postgres, sqlx::postgres::PgArguments>, PgError> {
        let base=|sql:&'static str| -> sqlx::query::Query<'a,sqlx::Postgres,sqlx::postgres::PgArguments> {
            sqlx::query(sql).bind(r.operation().to_string()).bind(c.token.clone()).bind(r.digest().to_vec())
        };
        let json = |object: &Object| serde_json::to_value(object).map_err(|_| invalid());
        Ok(match self {
            Self::Prepare(p)=>base("SELECT rss_transactional_messaging.archive_prepare($1::uuid,$2::uuid,$3,$4,$5)").bind(json(&p.object)?).bind(p.bytes.as_slice()),
            Self::Record(p)=>base("SELECT rss_transactional_messaging.archive_record($1::uuid,$2::uuid,$3,$4::uuid,$5)").bind(p.generation()).bind(json(p.object())?),
            Self::Purge(p)=>base("SELECT rss_transactional_messaging.archive_purge($1::uuid,$2::uuid,$3,$4)").bind(json(p.object())?),
            Self::Reconcile(p)=>base("SELECT rss_transactional_messaging.archive_missing($1::uuid,$2::uuid,$3,$4::uuid,$5)").bind(p.generation()).bind(json(p.object())?),
            Self::FaultMissing=>base("SELECT rss_transactional_messaging.archive_fault($1::uuid,$2::uuid,$3,'missing')"),
            Self::FaultEvidence=>base("SELECT rss_transactional_messaging.archive_fault($1::uuid,$2::uuid,$3,'evidence')"),
        })
    }
}
impl PgArchiveRepository {
    async fn apply(
        &self,
        r: &AuthorizedRequest,
        c: &Claim,
        d: OperationDeadline,
        command: Command<'_>,
    ) -> LocalTxAttempt<(), Error> {
        attempt(
            self.runtime
                .local_tx_with_context(
                    r.request().tenant(),
                    d,
                    (r.request(), c, command),
                    |(r, c, command), tx| {
                        Box::pin(async move {
                            command
                                .query(r, c)?
                                .execute(&mut *tx.connection)
                                .await
                                .map_err(super::sql_error)?;
                            Ok(())
                        })
                    },
                )
                .await,
        )
    }
}
