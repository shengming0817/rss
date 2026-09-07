//! Narrow DR operator. The raw transaction/pool is deliberately private.
use crate::{PgConfig, PgError, PgRuntime, fence::hex};
use rss_request_context::ExecutionTimer;
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding},
    policy::OperationDeadline,
    transaction::LocalTxAttempt,
};
use rss_transactional_messaging_recovery::{Error, StoreFailureKind, dr::*};
use sqlx::Row;

/// PostgreSQL atomic DR application and exact durable readback.
pub struct PgDrStore {
    runtime: PgRuntime,
}
impl PgDrStore {
    /// Validate a dedicated DR operator; execution bindings are immutable even after applying a plan.
    pub async fn connect<C: ExecutionTimer + 'static>(
        config: PgConfig,
        timer: C,
        binding: ExecutionBinding,
    ) -> Result<Self, Error> {
        let runtime =
            PgRuntime::connect_profile(config, timer, binding, crate::transaction::Profile::Dr)
                .await
                .map_err(error)?;
        Ok(Self { runtime })
    }
    /// Stop admissions and drain the private pool under the caller's shutdown budget.
    pub async fn close(&self) {
        self.runtime.close().await;
    }
    /// Integration-only fault at the real transaction boundary.
    #[cfg(feature = "integration")]
    pub fn inject_next_transaction_fault(&self, fault: crate::PgTransactionFault) {
        self.runtime.inject_next_transaction_fault(fault);
    }
    fn validate(&self, plan: &Plan) -> Result<(), Error> {
        if self.runtime.binding.storage() != plan.storage()
            || self.runtime.binding.epoch(plan.tenant()).is_none()
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
fn error(e: PgError) -> Error {
    match e {
        PgError::Recovery(e) => e,
        PgError::IncompatibleStorageContract(_) | PgError::StorageContractProbe(_) => {
            Error::StorageContract
        }
        _ => match e.kind() {
            rss_transactional_messaging::error::MessagingErrorKind::Conflict => Error::Conflict,
            rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost => {
                Error::Store(StoreFailureKind::OwnershipLost)
            }
            rss_transactional_messaging::error::MessagingErrorKind::DeadlineElapsed => {
                Error::Deadline
            }
            rss_transactional_messaging::error::MessagingErrorKind::Transient => {
                Error::Store(StoreFailureKind::Transient)
            }
            rss_transactional_messaging::error::MessagingErrorKind::Permanent => {
                Error::Store(StoreFailureKind::Permanent)
            }
            rss_transactional_messaging::error::MessagingErrorKind::Invariant => {
                Error::Store(StoreFailureKind::Invariant)
            }
        },
    }
}
fn sql_error(e: sqlx::Error) -> PgError {
    if let sqlx::Error::Database(ref db) = e {
        match db.code().as_deref() {
            Some("PZ004") => return PgError::Recovery(Error::Expired),
            Some("P0002") => return PgError::Recovery(Error::NotFound),
            _ => {}
        }
    }
    e.into()
}
fn map<T>(v: LocalTxAttempt<T, PgError>) -> LocalTxAttempt<T, Error> {
    v.fold(
        LocalTxAttempt::committed,
        |e| LocalTxAttempt::not_started(error(e)),
        |e| LocalTxAttempt::rolled_back(error(e)),
        |e| LocalTxAttempt::rollback_failed(error(e)),
        |e| LocalTxAttempt::commit_unknown(error(e)),
        |e| LocalTxAttempt::fenced(error(e)),
    )
}
fn members(plan: &Plan) -> Result<serde_json::Value, PgError> {
    let members = plan.members().iter().map(|member| {
        Ok(match member {
            Member::Outbox { message, fingerprint, version } => serde_json::json!({
                "message": message.as_str(), "fingerprint": hex(fingerprint.as_bytes()), "version": version.get()
            }),
            Member::Consumer { identity, fingerprint } => serde_json::json!({
                "message": identity.message_id().as_str(), "group": identity.group().as_str(),
                "contract": crate::inbox::contract_key(identity.contract())?, "fingerprint": hex(fingerprint.as_bytes())
            }),
        })
    }).collect::<Result<Vec<_>, PgError>>()?;
    Ok(serde_json::Value::Array(members))
}
impl Store for PgDrStore {
    async fn apply(
        &self,
        authorized: &AuthorizedPlan,
        deadline: OperationDeadline,
    ) -> LocalTxAttempt<Receipt, Error> {
        let plan = authorized.request();
        if let Err(e) = self.validate(plan) {
            return LocalTxAttempt::not_started(e);
        }
        let attempt = self
            .runtime
            .transaction_with_context(plan.tenant(), deadline, plan, false, |plan, tx| {
                Box::pin(async move {
                    let (direction, evidence) = match plan.action() {
                        PlanAction::Recover {direction, evidence,..} => (
                            match direction {Direction::DatabaseAhead => "database", Direction::BrokerAhead => "broker"},
                            serde_json::json!({"database": hex(&evidence.database()), "broker": hex(&evidence.broker())}),
                        ),
                        PlanAction::Terminate {operation,digest} => ("terminate", serde_json::json!({"operation": operation.to_string(), "digest": hex(digest)})),
                    };
                    let epoch: i64 = sqlx::query_scalar(
                        "SELECT rss_transactional_messaging.apply_dr($1::uuid,$2,$3,$4,$5,$6)",
                    )
                    .bind(plan.operation().to_string())
                    .bind(plan.digest().as_slice())
                    .bind(direction)
                    .bind(evidence)
                    .bind(members(plan)?)
                    .bind(plan.expected().get())
                    .fetch_one(&mut *tx.connection)
                    .await
                    .map_err(sql_error)?;
                    if epoch != plan.next().get() {
                        return Err(PgError::invariant());
                    }
                    Ok(Receipt {
                        operation: plan.operation(),
                        digest: plan.digest(),
                        epoch: plan.next(),
                    })
                })
            })
            .await;
        map(attempt)
    }

    async fn receipt(
        &self,
        plan: &AuthorizedPlan,
        deadline: OperationDeadline,
    ) -> Result<Option<Receipt>, Error> {
        self.progress(plan, deadline)
            .await
            .map(|v| v.map(|p| p.receipt))
    }
    async fn progress(
        &self,
        authorized: &AuthorizedPlan,
        deadline: OperationDeadline,
    ) -> Result<Option<Progress>, Error> {
        let plan = authorized.request();
        self.validate(plan)?;
        map(self
            .runtime
            .transaction_with_context(plan.tenant(), deadline, plan, false, |plan, tx| {
                Box::pin(async move {
                    let row = sqlx::query(
                        "SELECT * FROM rss_transactional_messaging.read_dr($1::uuid,$2)",
                    )
                    .bind(plan.operation().to_string())
                    .bind(plan.digest().as_slice())
                    .fetch_optional(&mut *tx.connection)
                    .await?;
                    row.map(|r| {
                        let epoch =
                            Epoch::new(r.try_get("epoch")?).map_err(|_| PgError::invariant())?;
                        let statuses: Vec<String> = r.try_get("statuses")?;
                        let reasons: Vec<Option<String>> = r.try_get("reasons")?;
                        if reasons.len() != statuses.len() {
                            return Err(PgError::invariant());
                        }
                        let members = statuses
                            .iter()
                            .zip(reasons.iter())
                            .map(|(status, reason)| member_status(status, reason.as_deref()))
                            .collect::<Result<Vec<_>, _>>()?;
                        if epoch != plan.next() || members.len() != plan.members().len() {
                            return Err(PgError::invariant());
                        }
                        Ok(Progress {
                            receipt: Receipt {
                                operation: plan.operation(),
                                digest: plan.digest(),
                                epoch,
                            },
                            members,
                        })
                    })
                    .transpose()
                })
            })
            .await)
        .fold(Ok, Err, Err, Err, Err, Err)
    }
}

fn member_status(status: &str, reason: Option<&str>) -> Result<MemberStatus, PgError> {
    let reason = match reason {
        None => None,
        Some("deadline_expired") => Some(BlockReason::DeadlineExpired),
        Some("permanent_publish_failure") => Some(BlockReason::PermanentPublishFailure),
        _ => return Err(PgError::invariant()),
    };
    match (status, reason) {
        ("pending", None) => Ok(MemberStatus::Pending),
        ("publishing", None) => Ok(MemberStatus::Publishing),
        ("completed", None) => Ok(MemberStatus::Completed),
        ("blocked", Some(reason)) => Ok(MemberStatus::Blocked(reason)),
        ("superseded", reason) => Ok(MemberStatus::Superseded(reason)),
        ("terminated", reason) => Ok(MemberStatus::Terminated(reason)),
        _ => Err(PgError::invariant()),
    }
}
