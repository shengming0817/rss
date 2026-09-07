mod support;
use rss_transactional_messaging_recovery::protection::{Capsule, open, seal};
use support::*;

#[test]
fn real_aead_rejects_each_coordinate_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    use rss_data_protection::{Aead, AeadError, ProtectionContext};
    use rss_request_context::TenantId;
    let tenant_a = tenant();
    let tenant_b = TenantId::parse("22222222-2222-4222-8222-222222222222")?;
    let original = ProtectionContext::new(tenant_a, "key", "field", 1)?.derive();
    let encrypted = Key(1).seal(b"SENSITIVE_2326", &original)?;
    // Matching coordinates are sufficient for cryptographic verification, not proof of authority.
    let same = ProtectionContext::new(tenant_a, "key", "field", 1)?.derive();
    assert_eq!(Key(1).open(&encrypted, &same)?.expose(), b"SENSITIVE_2326");
    for (tenant, key, field, version) in [
        (tenant_b, "key", "field", 1),
        (tenant_a, "other-key", "field", 1),
        (tenant_a, "key", "other-field", 1),
        (tenant_a, "key", "field", 2),
    ] {
        let changed = ProtectionContext::new(tenant, key, field, version)?.derive();
        assert!(matches!(
            Key(1).open(&encrypted, &changed),
            Err(AeadError::Open)
        ));
    }
    assert!(matches!(
        Key(2).open(&encrypted, &same),
        Err(AeadError::Open)
    ));
    Ok(())
}

#[test]
#[allow(clippy::expect_used)] // reason: successful fixtures and negative assertions.
fn capsule_is_authenticated_authored_only_and_redacted() {
    let message = message("secret-id");
    let context = context(&message);
    let capsule = seal(&Key(1), &context, &message).expect("seal");
    let decoded = open(&Key(1), &context, &capsule).expect("open");
    assert_eq!(decoded.payload().as_ref(), message.payload());
    assert!(decoded.transport_context().tenant_authority().is_none());
    assert!(decoded.transport_context().trace().is_none());
    assert!(!String::from_utf8_lossy(capsule.bytes()).contains("secret"));
    assert!(!format!("{capsule:?}").contains("secret"));
    assert!(open(&Key(2), &context, &capsule).is_err());
    assert!(open(&Key(1), &support::context(&message), &capsule).is_err());
    let mut tampered = capsule.bytes().to_vec();
    tampered[0] ^= 1;
    assert!(
        open(
            &Key(1),
            &context,
            &Capsule::from_provider(tampered).expect("bytes")
        )
        .is_err()
    );
    assert!(seal(&Key(1), &context, &support::message("another-id")).is_err());
}
use rss_transactional_messaging::{message::MessageId, policy::OperationDeadline};
use rss_transactional_messaging_recovery::*;
use std::sync::Mutex;
struct Stale(Mutex<Option<Authorization>>);
impl Authorizer for Stale {
    async fn authorize(
        &self,
        challenge: Challenge<'_>,
        _: OperationDeadline,
    ) -> Result<Authorization, Error> {
        let mut saved = self.0.lock().map_err(|_| Error::Unauthorized)?;
        match saved.take() {
            Some(proof) => Ok(proof),
            None => {
                *saved = Some(challenge.authorized());
                Err(Error::Unauthorized)
            }
        }
    }
}
#[tokio::test]
#[allow(clippy::expect_used)] // reason: controlled test inputs.
async fn different_request_cannot_consume_stale_authorization() {
    let clock = support::Timer::new();
    let authorizer = Stale(Mutex::new(None));
    let mutation = Mutation::new(
        support::tenant(),
        OperationId::new(),
        Target::Outbox(MessageId::parse("original").expect("id")),
        Version::new(1).expect("version"),
        Action::Redrive,
    )
    .expect("mutation");
    assert!(
        authorize_mutation(&authorizer, mutation.clone(), &clock, clock.cutoff())
            .await
            .is_err()
    );
    let other = Mutation::new(
        mutation.tenant(),
        mutation.operation(),
        mutation.target().clone(),
        mutation.version(),
        Action::Resolve(Resolution::AcceptedGap),
    )
    .expect("mutation");
    assert!(matches!(
        authorize_mutation(&authorizer, other, &clock, clock.cutoff()).await,
        Err(Error::Unauthorized)
    ));
}
#[test]
#[allow(clippy::expect_used)] // reason: fixed pagination fixtures.
fn cursor_cannot_cross_tenant_or_source() {
    let query = Query::list(support::tenant(), Source::Consumer, 10, None).expect("query");
    let cursor = query.cursor("last-key");
    assert!(Query::list(support::tenant(), Source::Consumer, 10, Some(&cursor)).is_ok());
    assert!(Query::list(support::tenant(), Source::Outbox, 10, Some(&cursor)).is_err());
    let other = rss_request_context::TenantId::parse("22222222-2222-2222-2222-222222222222")
        .expect("tenant");
    assert!(Query::list(other, Source::Consumer, 10, Some(&cursor)).is_err());
}

use rss_transactional_messaging::{
    policy::{AbsoluteDeadline, ExecutionBudget, ExecutionDeadlines},
    transaction::LocalTxAttempt,
};
use std::sync::atomic::{AtomicUsize, Ordering};
struct UncertainStore {
    calls: AtomicUsize,
    persisted: bool,
}
impl RecoveryStore for UncertainStore {
    async fn query(&self, _: &AuthorizedQuery, _: OperationDeadline) -> Result<Page, Error> {
        Err(Error::Store(StoreFailureKind::Transient))
    }
    async fn mutate(
        &self,
        _: &AuthorizedMutation,
        _: OperationDeadline,
    ) -> LocalTxAttempt<Receipt, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        LocalTxAttempt::commit_unknown(Error::Store(StoreFailureKind::Transient))
    }
    #[allow(clippy::expect_used)] // reason: fixed persisted provider revision.
    async fn receipt(
        &self,
        request: &AuthorizedMutation,
        _: OperationDeadline,
    ) -> Result<Option<Receipt>, Error> {
        Ok(self.persisted.then(|| Receipt {
            request: request.request().clone(),
            outcome: Outcome::Redriven,
            version: Version::new(2).expect("fixture version"),
        }))
    }
}
struct Permit;
impl Authorizer for Permit {
    async fn authorize(
        &self,
        c: Challenge<'_>,
        _: OperationDeadline,
    ) -> Result<Authorization, Error> {
        Ok(c.authorized())
    }
}
struct Observations(AtomicUsize);
impl Observer for Observations {
    fn observe(&self, _: Observation) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
#[tokio::test]
#[allow(clippy::expect_used)] // reason: fixture requests and durable readback assertions.
async fn uncertain_commit_reads_receipt_without_repeating_mutation() {
    let clock = Timer::new();
    let request = Mutation::new(
        tenant(),
        OperationId::new(),
        Target::Outbox(MessageId::parse("head").expect("id")),
        Version::new(1).expect("version"),
        Action::Redrive,
    )
    .expect("request");
    let permit = authorize_mutation(&Permit, request, &clock, clock.cutoff())
        .await
        .expect("permit");
    for persisted in [false, true] {
        let store = UncertainStore {
            calls: AtomicUsize::new(0),
            persisted,
        };
        let observer = Observations(AtomicUsize::new(0));
        let result = execute(
            &store,
            &permit,
            &clock,
            ExecutionDeadlines::from_budget(&clock, ExecutionBudget::STANDARD).expect("deadlines"),
            &observer,
        )
        .await;
        assert_eq!(
            result.fold(
                |_| "committed",
                |_| "not_started",
                |_| "rollback",
                |_| "rollback_failed",
                |_| "unknown",
                |_| "fenced"
            ),
            if persisted { "committed" } else { "unknown" }
        );
        assert_eq!(store.calls.load(Ordering::SeqCst), 1);
        assert_eq!(observer.0.load(Ordering::SeqCst), 1);
    }
}
struct PendingAuthorization;
impl Authorizer for PendingAuthorization {
    async fn authorize(
        &self,
        _: Challenge<'_>,
        _: OperationDeadline,
    ) -> Result<Authorization, Error> {
        std::future::pending().await
    }
}
#[tokio::test]
#[allow(clippy::expect_used)] // reason: bounded timeout fixture.
async fn authorization_is_bounded_before_any_storage_access() {
    let clock = Timer::new();
    let cutoff = AbsoluteDeadline::from_timeout(&clock, std::time::Duration::from_millis(1))
        .expect("deadline");
    let query = Query::list(tenant(), Source::Consumer, 1, None).expect("query");
    assert!(matches!(
        authorize_query(&PendingAuthorization, query, &clock, cutoff).await,
        Err(Error::Deadline)
    ));
}
