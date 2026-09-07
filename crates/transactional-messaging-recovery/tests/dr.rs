use rss_request_context::TenantId;
use rss_request_context::{Deadline, ExecutionTimer};
use rss_transactional_messaging::{
    fence::{Epoch, StorageIdentity},
    message::{MessageFingerprint, MessageId},
};
use rss_transactional_messaging_recovery::{
    OperationId, Version,
    dr::{Member, Plan, RestoreEvidence},
};
#[test]
fn plans_bind_exact_facts_and_canonical_members() -> Result<(), Box<dyn std::error::Error>> {
    let tenant = TenantId::parse("11111111-1111-1111-1111-111111111111")?;
    let storage = StorageIdentity::new([1; 16], [2; 16])?;
    let evidence = RestoreEvidence::new([3; 32], [4; 32])?;
    let operation = OperationId::new();
    let a = Member::Outbox {
        message: MessageId::parse("a")?,
        fingerprint: MessageFingerprint::from_bytes([5; 32]),
        version: Version::new(1)?,
    };
    let b = Member::Outbox {
        message: MessageId::parse("b")?,
        fingerprint: MessageFingerprint::from_bytes([6; 32]),
        version: Version::new(1)?,
    };
    let epoch = Epoch::new(1)?;
    let make = |members| Plan::new(tenant, operation, storage, epoch, evidence, members);
    assert!(make(vec![]).is_err());
    assert!(make(vec![a.clone(), a.clone()]).is_err());
    assert_eq!(
        make(vec![a.clone(), b.clone()])?.digest(),
        make(vec![b, a.clone()])?.digest()
    );
    assert_ne!(
        make(vec![a.clone()])?.digest(),
        Plan::new(
            tenant,
            operation,
            storage,
            Epoch::new(2)?,
            evidence,
            vec![a]
        )?
        .digest()
    );
    Ok(())
}

fn member(id: &str) -> Result<Member, Box<dyn std::error::Error>> {
    Ok(Member::Outbox {
        message: MessageId::parse(id)?,
        fingerprint: MessageFingerprint::from_bytes([5; 32]),
        version: Version::new(1)?,
    })
}
fn bounded_plan(members: Vec<Member>) -> Result<Plan, Box<dyn std::error::Error>> {
    Ok(Plan::new(
        TenantId::parse("11111111-1111-1111-1111-111111111111")?,
        OperationId::new(),
        StorageIdentity::new([1; 16], [2; 16])?,
        Epoch::new(1)?,
        RestoreEvidence::new([3; 32], [4; 32])?,
        members,
    )?)
}
#[test]
fn plan_bounds_and_consumer_scope_are_closed() -> Result<(), Box<dyn std::error::Error>> {
    use rss_transactional_messaging::{
        inbox::{ConsumerGroup, ConsumerIdentity},
        message::ContractIdentity,
    };
    let members = (0..Plan::MAX_MEMBERS)
        .map(|n| member(&format!("message-{n}")))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(bounded_plan(members.clone())?.members().len(), 500);
    let mut too_many = members;
    too_many.push(member("excess")?);
    assert!(bounded_plan(too_many).is_err());
    let contract = ContractIdentity::new(
        rss_contract::ContractId::from_static("orders.created"),
        rss_contract::ContractVersion::from_static_major(1),
        rss_contract::SchemaDigest::from_static(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    );
    let consumer = |tenant| -> Result<Member, Box<dyn std::error::Error>> {
        Ok(Member::Consumer {
            identity: ConsumerIdentity::new(
                TenantId::parse(tenant)?,
                ConsumerGroup::parse("orders")?,
                MessageId::parse("message")?,
                contract.clone(),
            ),
            fingerprint: MessageFingerprint::from_bytes([5; 32]),
        })
    };
    let own = consumer("11111111-1111-1111-1111-111111111111")?;
    assert!(bounded_plan(vec![own.clone()]).is_ok());
    assert!(bounded_plan(vec![own, member("message")?]).is_err());
    assert!(bounded_plan(vec![consumer("22222222-2222-2222-2222-222222222222")?]).is_err());
    assert!(RestoreEvidence::new([0; 32], [1; 32]).is_err());
    assert!(Epoch::new(i64::MAX)?.next().is_err());
    Ok(())
}

use rss_transactional_messaging::policy::*;
use rss_transactional_messaging_recovery::{
    Authorization, Authorizer, Challenge, Error, authorize_dr,
};
struct Clock;
impl rss_request_context::Clock for Clock {
    fn now(&self) -> std::time::Instant {
        {
            #[allow(
                clippy::disallowed_methods,
                reason = "the fixed injected test clock owns its epoch"
            )]
            fn epoch() -> std::time::Instant {
                std::time::Instant::now()
            }
            static ORIGIN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
            *ORIGIN.get_or_init(epoch)
        }
    }
}
impl ExecutionTimer for Clock {
    async fn sleep_until(&self, _: Deadline) {
        std::future::pending::<()>().await;
    }
}
struct StaleProof(std::sync::Mutex<Option<Authorization>>);
impl Authorizer for StaleProof {
    async fn authorize(
        &self,
        c: Challenge<'_>,
        _: OperationDeadline,
    ) -> Result<Authorization, Error> {
        let mut slot = self.0.lock().map_err(|_| Error::Unauthorized)?;
        match slot.take() {
            Some(proof) => Ok(proof),
            None => {
                *slot = Some(c.authorized());
                Err(Error::Unauthorized)
            }
        }
    }
}
#[tokio::test]
async fn authorization_cannot_move_between_exact_plans() -> Result<(), Box<dyn std::error::Error>> {
    let stale = StaleProof(std::sync::Mutex::new(None));
    let cutoff = Deadline::from_timeout(&Clock, std::time::Duration::from_secs(1))?;
    assert!(
        authorize_dr(
            &stale,
            bounded_plan(vec![member("first")?])?,
            &Clock,
            cutoff
        )
        .await
        .is_err()
    );
    assert!(matches!(
        authorize_dr(
            &stale,
            bounded_plan(vec![member("second")?])?,
            &Clock,
            cutoff
        )
        .await,
        Err(Error::Unauthorized)
    ));
    Ok(())
}

struct Allow;
impl Authorizer for Allow {
    async fn authorize(
        &self,
        c: Challenge<'_>,
        _: OperationDeadline,
    ) -> Result<Authorization, Error> {
        Ok(c.authorized())
    }
}
struct UnknownStore(bool);
impl rss_transactional_messaging_recovery::dr::Store for UnknownStore {
    async fn apply(
        &self,
        _: &rss_transactional_messaging_recovery::dr::AuthorizedPlan,
        _: OperationDeadline,
    ) -> rss_transactional_messaging::transaction::LocalTxAttempt<
        rss_transactional_messaging_recovery::dr::Receipt,
        Error,
    > {
        rss_transactional_messaging::transaction::LocalTxAttempt::commit_unknown(Error::Deadline)
    }
    async fn receipt(
        &self,
        p: &rss_transactional_messaging_recovery::dr::AuthorizedPlan,
        _: OperationDeadline,
    ) -> Result<Option<rss_transactional_messaging_recovery::dr::Receipt>, Error> {
        Ok(self
            .0
            .then(|| rss_transactional_messaging_recovery::dr::Receipt {
                operation: p.request().operation(),
                digest: p.request().digest(),
                epoch: p.request().next(),
            }))
    }
    async fn progress(
        &self,
        _: &rss_transactional_messaging_recovery::dr::AuthorizedPlan,
        _: OperationDeadline,
    ) -> Result<Option<rss_transactional_messaging_recovery::dr::Progress>, Error> {
        Ok(None)
    }
}
struct Observed(std::cell::RefCell<Vec<rss_transactional_messaging_recovery::Observation>>);
impl rss_transactional_messaging_recovery::Observer for Observed {
    fn observe(&self, o: rss_transactional_messaging_recovery::Observation) {
        self.0.borrow_mut().push(o);
    }
}
#[tokio::test]
async fn unknown_application_requires_exact_readback_and_closed_observation()
-> Result<(), Box<dyn std::error::Error>> {
    use rss_transactional_messaging_recovery::{ActionKind, AttemptStatus};
    let deadlines = ExecutionDeadlines::from_budget(&Clock, ExecutionBudget::STANDARD)?;
    let p = authorize_dr(
        &Allow,
        bounded_plan(vec![member("unknown")?])?,
        &Clock,
        deadlines.operation(),
    )
    .await?;
    for (readback, expected) in [
        (false, AttemptStatus::CommitUnknown),
        (true, AttemptStatus::Committed),
    ] {
        let observed = Observed(std::cell::RefCell::new(Vec::new()));
        let result = rss_transactional_messaging_recovery::dr::execute(
            &UnknownStore(readback),
            &p,
            &Clock,
            deadlines,
            &observed,
        )
        .await;
        assert_eq!(
            result.fold(
                |_| AttemptStatus::Committed,
                |_| AttemptStatus::NotStarted,
                |_| AttemptStatus::RolledBack,
                |_| AttemptStatus::RollbackFailed,
                |_| AttemptStatus::CommitUnknown,
                |_| AttemptStatus::Fenced
            ),
            expected
        );
        let events = observed.0.borrow();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, ActionKind::DrApply);
        assert_eq!(events[0].status, expected);
    }
    Ok(())
}

#[tokio::test]
async fn recovery_authorization_cannot_authorize_termination()
-> Result<(), Box<dyn std::error::Error>> {
    let original = bounded_plan(vec![member("prior")?])?;
    let terminate = Plan::terminate(
        original.tenant(),
        OperationId::new(),
        original.storage(),
        original.next(),
        original.operation(),
        original.digest(),
    )?;
    let stale = StaleProof(std::sync::Mutex::new(None));
    let cutoff = Deadline::from_timeout(&Clock, std::time::Duration::from_secs(1))?;
    assert!(
        authorize_dr(&stale, original, &Clock, cutoff)
            .await
            .is_err()
    );
    assert!(matches!(
        authorize_dr(&stale, terminate, &Clock, cutoff).await,
        Err(Error::Unauthorized)
    ));
    Ok(())
}

#[tokio::test]
async fn uncertain_termination_uses_exact_readback_and_its_own_observation()
-> Result<(), Box<dyn std::error::Error>> {
    let original = bounded_plan(vec![member("prior")?])?;
    let terminate = Plan::terminate(
        original.tenant(),
        OperationId::new(),
        original.storage(),
        original.next(),
        original.operation(),
        original.digest(),
    )?;
    let deadlines = ExecutionDeadlines::from_budget(&Clock, ExecutionBudget::STANDARD)?;
    let authorized = authorize_dr(&Allow, terminate, &Clock, deadlines.operation()).await?;
    let observed = Observed(std::cell::RefCell::new(Vec::new()));
    let result = rss_transactional_messaging_recovery::dr::execute(
        &UnknownStore(true),
        &authorized,
        &Clock,
        deadlines,
        &observed,
    )
    .await;
    assert!(result.fold(
        |r| r.digest == authorized.request().digest(),
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false
    ));
    let events = observed.0.borrow();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].action,
        rss_transactional_messaging_recovery::ActionKind::DrTerminate
    );
    assert_eq!(
        events[0].status,
        rss_transactional_messaging_recovery::AttemptStatus::Committed
    );
    Ok(())
}
