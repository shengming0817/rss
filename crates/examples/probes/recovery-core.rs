use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    fence::{Epoch, StorageIdentity},
    message::MessageId,
    policy::OperationDeadline,
};
use rss_transactional_messaging_recovery::*;
use std::time::Duration;
struct Timer;
impl Clock for Timer {
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, d: Deadline) {
        tokio::time::sleep_until(d.instant().into()).await;
    }
}
struct Deny;
impl Authorizer for Deny {
    async fn authorize(
        &self,
        _: Challenge<'_>,
        _: OperationDeadline,
    ) -> Result<Authorization, Error> {
        Err(Error::Unauthorized)
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tenant = TenantId::parse("00000000-0000-0000-0000-000000000001")?;
    let operation = OperationId::new();
    let request = Mutation::new(
        tenant,
        operation,
        Target::Outbox(MessageId::parse("one")?),
        Version::new(1)?,
        Action::Redrive,
    )?;
    assert_ne!(request.digest(), [0; 32]);
    assert!(matches!(
        authorize_mutation(
            &Deny,
            request,
            &Timer,
            Deadline::from_timeout(&Timer, Duration::from_secs(1))?
        )
        .await,
        Err(Error::Unauthorized)
    ));
    let plan = dr::Plan::terminate(
        tenant,
        OperationId::new(),
        StorageIdentity::new([1; 16], [2; 16])?,
        Epoch::new(1)?,
        operation,
        [3; 32],
    )?;
    assert_eq!(plan.tenant(), tenant);
    assert!(plan.members().is_empty());
    assert_ne!(plan.digest(), [0; 32]);
    assert!(matches!(plan.action(), dr::PlanAction::Terminate { .. }));
    assert!(
        Mutation::new(
            tenant,
            OperationId::new(),
            Target::DeadLetter(DeadLetterId::new()),
            Version::new(1)?,
            Action::Redrive
        )
        .is_err()
    );
    Ok(())
}
