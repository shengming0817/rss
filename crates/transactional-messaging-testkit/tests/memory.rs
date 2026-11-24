use rss_request_context::{Clock, Deadline, ExecutionTimer};
use rss_transactional_messaging::policy::OperationDeadline;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::time::Duration;

use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_transactional_messaging::error::MessagingErrorKind;
use rss_transactional_messaging::inbox::{
    ConsumerGroup, IdempotencyDisposition, InboxStore, LeaseStatus,
};
use rss_transactional_messaging::message::{
    AuthoredMessageMetadata, ContractIdentity, MessageEnvelope, MessageFingerprint, MessageId,
    MessageMetadata, MessageMetadataExtensions, MessageRoute, MessagingDomain, PartitionKey,
};
use rss_transactional_messaging::outbox::{
    AppendOutcome, OutboxLeaseStatus, OutboxRelayStore, OutboxSettlement, OutboxWriter,
    PendingMessage,
};

use rss_transactional_messaging::transaction::{
    SettlementDecision, SettlementKind, TerminalDisposition,
};
use rss_transactional_messaging::transport::{
    DeliverySettlement, PublishFailure, PublishFailureKind, PublishFailureReason,
    PublishFailureStage, PublishOutcome, Publisher,
};
use rss_transactional_messaging_testkit::memory::{
    FakeClock, MemoryInboxStore, MemoryOutboxStore, MemoryPublisher, RecordingSettlement,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn envelope(
    id: &str,
    payload: &[u8],
) -> Result<MessageEnvelope<Vec<u8>>, Box<dyn std::error::Error>> {
    envelope_for_tenant(
        id,
        payload,
        TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
    )
}
fn envelope_for_tenant(
    id: &str,
    payload: &[u8],
    tenant: TenantId,
) -> Result<MessageEnvelope<Vec<u8>>, Box<dyn std::error::Error>> {
    let metadata = MessageMetadata::new(
        AuthoredMessageMetadata::new(
            tenant,
            Timepoint::try_from(1_700_000_000_i64)?,
            MessagingDomain::parse("orders")?,
            MessageRoute::parse("orders.created")?,
            ContractIdentity::new(
                ContractId::parse("orders.created")?,
                ContractVersion::from_major(1)?,
                SchemaDigest::parse(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )?,
            ),
        ),
        MessageMetadataExtensions::new(
            None,
            Some(PartitionKey::parse("customer-7")?),
            None,
            BTreeMap::new(),
        ),
    );
    Ok(MessageEnvelope::new(
        MessageId::parse(id)?,
        metadata,
        payload.to_vec(),
    ))
}

fn verified(
    message: &MessageEnvelope<Vec<u8>>,
    group: &str,
) -> Result<
    rss_transactional_messaging::transaction::VerifiedConsumerBinding,
    Box<dyn std::error::Error>,
> {
    use rss_transactional_messaging::{message::SubscriptionIdentity, transaction::*};
    struct Validator;
    impl IngressValidator<Vec<u8>> for Validator {
        fn validate(
            &self,
            input: IngressChallenge<'_, Vec<u8>>,
        ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
            let execution = crate::execution(input.message().metadata().tenant_id(), 1);
            Ok(input.verified(execution))
        }
    }
    let meta = message.metadata();
    verify_ingress(
        &Validator,
        ConsumerGroup::parse(group)?,
        &SubscriptionIdentity::new(
            meta.domain().clone(),
            meta.route().clone(),
            meta.contract().clone(),
        ),
        message,
    )
    .map_err(|_| "fixture ingress".into())
}

fn deadline(
    clock: &FakeClock,
) -> Result<rss_transactional_messaging::policy::OperationDeadline, Box<dyn std::error::Error>> {
    Ok(OperationDeadline::from_cutoff(
        Deadline::from_timeout(clock, Duration::from_secs(30))?,
        clock,
    ))
}

fn expired_deadline(
    clock: &FakeClock,
) -> Result<rss_transactional_messaging::policy::OperationDeadline, Box<dyn std::error::Error>> {
    Ok(OperationDeadline::from_cutoff(
        Deadline::from_timeout(clock, Duration::ZERO)?,
        clock,
    ))
}

#[tokio::test]
async fn fake_clock_releases_deadlines_only_after_advance() -> TestResult {
    let clock = FakeClock::new();
    let origin = clock.now();
    clock.advance(Duration::from_nanos(1))?;
    clock.advance(Duration::from_micros(1))?;
    assert_eq!(clock.now(), origin + Duration::from_nanos(1_001));
    let cutoff = Deadline::from_timeout(&clock, Duration::from_secs(5))?;
    let waiter_clock = clock.clone();
    let handle = tokio::spawn(async move { waiter_clock.sleep_until(cutoff).await });
    tokio::task::yield_now().await;
    assert!(!handle.is_finished());
    clock.advance(Duration::from_secs(5))?;
    handle.await?;
    assert_eq!(
        clock.now(),
        origin + Duration::from_secs(5) + Duration::from_nanos(1_001)
    );
    let before_overflow = clock.now();
    assert!(clock.advance(Duration::MAX).is_err());
    assert_eq!(
        clock.now(),
        before_overflow,
        "overflow cannot alter the injected clock"
    );
    for _ in 0..64 {
        let racing_clock = FakeClock::new();
        let cutoff = Deadline::from_timeout(&racing_clock, Duration::from_millis(1))?;
        let waiter_clock = racing_clock.clone();
        let waiter = tokio::spawn(async move { waiter_clock.sleep_until(cutoff).await });
        racing_clock.advance(Duration::from_millis(1))?;
        tokio::time::timeout(Duration::from_secs(1), waiter).await??;
    }
    Ok(())
}

#[tokio::test]
async fn publisher_script_exhaustion_is_an_explicit_fixture_failure() -> TestResult {
    let clock = FakeClock::new();
    let publisher = MemoryPublisher::<()>::new([]);
    let message = envelope("script-exhausted", b"payload")?;
    let outcome = publisher.publish(&message, deadline(&clock)?).await;
    assert!(publisher.script_exhausted());
    assert!(matches!(
        outcome,
        PublishOutcome::DefinitelyNotPublished(failure)
            if failure.kind() == PublishFailureKind::Permanent
                && failure.reason() == PublishFailureReason::InvalidMessage
    ));
    Ok(())
}

#[tokio::test]
async fn memory_outbox_uses_core_identity_and_fencing() -> TestResult {
    let clock = FakeClock::new();
    let store = MemoryOutboxStore::<Vec<u8>>::new();
    let mut tx = ();
    assert_eq!(
        store
            .append(
                &mut tx,
                PendingMessage::new(envelope("message-1", b"payload")?)
            )
            .await?,
        AppendOutcome::Inserted
    );
    assert_eq!(
        store
            .append(
                &mut tx,
                PendingMessage::new(envelope("message-1", b"payload")?)
            )
            .await?,
        AppendOutcome::AlreadyPresent
    );
    let conflict = match store
        .append(
            &mut tx,
            PendingMessage::new(envelope("message-1", b"changed")?),
        )
        .await
    {
        Ok(_) => return Err("same id with changed facts must conflict".into()),
        Err(error) => error,
    };
    assert_eq!(conflict.kind(), MessagingErrorKind::Conflict);

    store
        .append(
            &mut tx,
            PendingMessage::new(envelope("message-2", b"payload")?),
        )
        .await?;
    let claims = store
        .claim_partition_heads(
            crate::execution(crate::fixture_tenant(), 1),
            NonZeroUsize::new(8).ok_or("limit")?,
            deadline(&clock)?,
        )
        .await?;
    assert_eq!(
        claims.len(),
        1,
        "same partition successor must remain blocked"
    );
    let mut claims = claims.into_iter();
    let claim = claims.next().ok_or("claim")?;
    let claimed_id = MemoryOutboxStore::message(&claim).message_id().clone();
    assert!(
        store
            .claim_partition_heads(
                crate::execution(crate::fixture_tenant(), 1),
                NonZeroUsize::new(8).ok_or("limit")?,
                deadline(&clock)?
            )
            .await?
            .is_empty(),
        "an in-flight partition head must block its successor across claim calls"
    );
    store.fence_claims();
    assert_eq!(
        store.extend(&claim, deadline(&clock)?).await?,
        OutboxLeaseStatus::Lost
    );
    let error = match store
        .settle(claim, OutboxSettlement::Published(()), deadline(&clock)?)
        .await
    {
        Ok(()) => return Err("stale claim must not settle".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), MessagingErrorKind::OwnershipLost);
    let reclaimed = store
        .claim_partition_heads(
            crate::execution(crate::fixture_tenant(), 1),
            NonZeroUsize::new(8).ok_or("limit")?,
            deadline(&clock)?,
        )
        .await?
        .into_iter()
        .next()
        .ok_or("fenced head must be reclaimable")?;
    assert_eq!(
        MemoryOutboxStore::message(&reclaimed).message_id(),
        &claimed_id
    );

    let store = MemoryOutboxStore::<Vec<u8>>::new();
    let mut tx = ();
    store
        .append(
            &mut tx,
            PendingMessage::new(envelope("message-expired", b"payload")?),
        )
        .await?;
    let claim = store
        .claim_partition_heads(
            crate::execution(crate::fixture_tenant(), 1),
            NonZeroUsize::MIN,
            deadline(&clock)?,
        )
        .await?
        .into_iter()
        .next()
        .ok_or("expired claim")?;
    assert_eq!(
        store.extend(&claim, expired_deadline(&clock)?).await?,
        OutboxLeaseStatus::Lost
    );
    let error = match store
        .settle(
            claim,
            OutboxSettlement::Published(()),
            expired_deadline(&clock)?,
        )
        .await
    {
        Ok(()) => return Err("expired claim must not settle".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), MessagingErrorKind::DeadlineElapsed);
    let reclaimed = store
        .claim_partition_heads(
            crate::execution(crate::fixture_tenant(), 1),
            NonZeroUsize::MIN,
            deadline(&clock)?,
        )
        .await?
        .into_iter()
        .next()
        .ok_or("expired head must be reclaimable")?;
    assert_eq!(
        MemoryOutboxStore::message(&reclaimed).message_id().as_str(),
        "message-expired"
    );

    let store = MemoryOutboxStore::<Vec<u8>>::new();
    let mut tx = ();
    let first = PendingMessage::new(envelope("dead-letter-head", b"payload")?);
    let partition = first.partition().cloned().ok_or("partition")?;
    store.append(&mut tx, first).await?;
    store
        .append(
            &mut tx,
            PendingMessage::new(envelope("blocked-successor", b"payload")?),
        )
        .await?;
    let head = store
        .claim_partition_heads(
            crate::execution(crate::fixture_tenant(), 1),
            NonZeroUsize::MIN,
            deadline(&clock)?,
        )
        .await?
        .into_iter()
        .next()
        .ok_or("dead-letter head")?;
    store
        .settle(head, OutboxSettlement::DeadLetter, deadline(&clock)?)
        .await?;
    assert!(
        store
            .claim_partition_heads(
                crate::execution(crate::fixture_tenant(), 1),
                NonZeroUsize::MIN,
                deadline(&clock)?
            )
            .await?
            .is_empty(),
        "an unresolved dead-letter head must block its partition successor"
    );
    store.resolve_partition(&partition);
    assert_eq!(
        store
            .claim_partition_heads(
                crate::execution(crate::fixture_tenant(), 1),
                NonZeroUsize::MIN,
                deadline(&clock)?
            )
            .await?
            .len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn memory_inbox_reclaims_and_returns_core_terminal_receipts() -> TestResult {
    let clock = FakeClock::new();
    let store = MemoryInboxStore::new();
    let message = envelope("message-inbox", b"payload")?;
    let binding = verified(&message, "orders-worker")?;
    let identity = binding.identity().clone();
    let claim = match store.claim(&binding, deadline(&clock)?).await? {
        IdempotencyDisposition::Acquired(claim) => claim,
        _ => return Err("first claim must acquire".into()),
    };
    assert!(matches!(
        store.claim(&binding, deadline(&clock)?).await?,
        IdempotencyDisposition::InProgress
    ));
    assert!(matches!(
        store.extend(&claim, deadline(&clock)?).await?,
        LeaseStatus::Held { .. }
    ));
    store.expire(&identity);
    assert_eq!(
        store.extend(&claim, deadline(&clock)?).await?,
        LeaseStatus::Lost
    );

    let successor = match store.claim(&binding, deadline(&clock)?).await? {
        IdempotencyDisposition::Acquired(claim) => claim,
        _ => return Err("successor must acquire".into()),
    };
    assert_eq!(
        store
            .release(claim.clone(), deadline(&clock)?)
            .await
            .err()
            .map(|e| e.kind()),
        Some(MessagingErrorKind::OwnershipLost)
    );
    assert!(matches!(
        store.extend(&successor, deadline(&clock)?).await?,
        LeaseStatus::Held { .. }
    ));
    store.store_terminal(
        identity.clone(),
        MessageFingerprint::of(&message),
        TerminalDisposition::Succeeded,
    );
    assert!(matches!(
        store.claim(&binding, deadline(&clock)?).await?,
        IdempotencyDisposition::Terminal(_)
    ));
    assert_eq!(
        store
            .release(claim, deadline(&clock)?)
            .await
            .err()
            .map(|e| e.kind()),
        Some(MessagingErrorKind::OwnershipLost)
    );
    store.expire(&identity);
    let IdempotencyDisposition::Terminal(receipt) =
        store.claim(&binding, deadline(&clock)?).await?
    else {
        return Err("terminal lost".into());
    };
    assert!(receipt.matches(&identity, MessageFingerprint::of(&message)));
    assert_eq!(receipt.disposition(), TerminalDisposition::Succeeded);
    let other_message = envelope_for_tenant(
        "message-inbox",
        b"payload",
        TenantId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")?,
    )?;
    let other_binding = verified(&other_message, "orders-worker")?;
    let other = other_binding.identity().clone();
    assert!(matches!(
        store.claim(&other_binding, deadline(&clock)?).await?,
        IdempotencyDisposition::Acquired(_)
    ));
    store.store_terminal(
        other.clone(),
        MessageFingerprint::of(&other_message),
        TerminalDisposition::Succeeded,
    );
    assert!(matches!(
        store.claim(&binding, deadline(&clock)?).await?,
        IdempotencyDisposition::Terminal(_)
    ));
    assert!(matches!(
        store.claim(&other_binding, deadline(&clock)?).await?,
        IdempotencyDisposition::Terminal(_)
    ));

    let releasable = MemoryInboxStore::new();
    let claim = match releasable.claim(&binding, deadline(&clock)?).await? {
        IdempotencyDisposition::Acquired(claim) => claim,
        _ => return Err("release fixture must acquire".into()),
    };
    releasable.release(claim, deadline(&clock)?).await?;
    assert!(matches!(
        releasable.claim(&binding, deadline(&clock)?).await?,
        IdempotencyDisposition::Acquired(_)
    ));

    let collision_store = MemoryInboxStore::new();
    let first_message = envelope("c", b"payload")?;
    let first = verified(&first_message, "a:b")?;
    let second_message = envelope("b:c", b"payload")?;
    let second = verified(&second_message, "a")?;
    assert!(matches!(
        collision_store.claim(&first, deadline(&clock)?).await?,
        IdempotencyDisposition::Acquired(_)
    ));
    assert!(matches!(
        collision_store.claim(&second, deadline(&clock)?).await?,
        IdempotencyDisposition::Acquired(_)
    ));

    // A different message in this group's occupied partition must wait.
    let successor = verified(&envelope("later", b"payload")?, "a")?;
    assert!(matches!(
        collision_store.claim(&successor, deadline(&clock)?).await?,
        IdempotencyDisposition::PartitionBlocked
    ));
    Ok(())
}

#[tokio::test]
async fn publisher_and_settlement_record_only_core_values() -> TestResult {
    let clock = FakeClock::new();
    let transient = PublishFailure::new(
        PublishFailureKind::Transient,
        PublishFailureStage::Confirm,
        PublishFailureReason::TransportUnavailable,
    );
    let publisher = MemoryPublisher::new([
        PublishOutcome::Ambiguous(transient),
        PublishOutcome::Confirmed(()),
    ]);
    let message = envelope("message-publish", b"payload")?;
    assert!(
        publisher
            .publish(&message, deadline(&clock)?)
            .await
            .is_ambiguous()
    );
    assert!(matches!(
        publisher.publish(&message, deadline(&clock)?).await,
        PublishOutcome::Confirmed(())
    ));
    let ids = publisher.message_ids();
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0], ids[1]);

    let settlement = RecordingSettlement::new();
    settlement
        .clone()
        .settle(SettlementDecision::requeue(), deadline(&clock)?)
        .await?;
    assert_eq!(settlement.settlements(), [SettlementKind::Requeue]);
    assert_eq!(settlement.abandon_count(), 0);
    Ok(())
}

#[tokio::test]
async fn outbox_same_message_id_is_independent_across_tenants() -> TestResult {
    let clock = FakeClock::new();
    let store = MemoryOutboxStore::<Vec<u8>>::new();
    let tenants = [
        TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
        TenantId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")?,
    ];
    for tenant in tenants {
        assert_eq!(
            store
                .append(
                    &mut (),
                    PendingMessage::new(envelope_for_tenant("shared-id", b"payload", tenant)?)
                )
                .await?,
            AppendOutcome::Inserted
        );
    }
    let a = store
        .claim_partition_heads(
            execution(tenants[0], 1),
            NonZeroUsize::MIN,
            deadline(&clock)?,
        )
        .await?
        .into_iter()
        .next()
        .ok_or("tenant A claim")?;
    let b = store
        .claim_partition_heads(
            execution(tenants[1], 1),
            NonZeroUsize::MIN,
            deadline(&clock)?,
        )
        .await?
        .into_iter()
        .next()
        .ok_or("tenant B claim")?;
    store
        .settle(a, OutboxSettlement::Published(()), deadline(&clock)?)
        .await?;
    assert!(matches!(
        store.extend(&b, deadline(&clock)?).await?,
        OutboxLeaseStatus::Held { .. }
    ));
    store
        .settle(b, OutboxSettlement::Published(()), deadline(&clock)?)
        .await?;
    assert_eq!(store.pending_len(), 0);
    for tenant in tenants {
        assert_eq!(
            store
                .append(
                    &mut (),
                    PendingMessage::new(envelope_for_tenant("shared-id", b"payload", tenant)?)
                )
                .await?,
            AppendOutcome::AlreadyPresent
        );
    }
    Ok(())
}
#[tokio::test]
async fn outbox_old_attempt_cannot_change_successor_or_terminal() -> TestResult {
    for retry in [false, true] {
        let clock = FakeClock::new();
        let store = MemoryOutboxStore::<Vec<u8>>::new();
        store
            .append(
                &mut (),
                PendingMessage::new(envelope("retry-id", b"payload")?),
            )
            .await?;
        let limit = NonZeroUsize::new(1).ok_or("limit")?;
        let old = store
            .claim_partition_heads(
                crate::execution(crate::fixture_tenant(), 1),
                limit,
                deadline(&clock)?,
            )
            .await?
            .into_iter()
            .next()
            .ok_or("old")?;
        if retry {
            store
                .settle(old.clone(), OutboxSettlement::Retry, deadline(&clock)?)
                .await?;
            store.clock().advance(Duration::from_secs(1))?;
        } else {
            store.fence_claims();
        }
        let current = store
            .claim_partition_heads(
                crate::execution(crate::fixture_tenant(), 1),
                limit,
                deadline(&clock)?,
            )
            .await?
            .into_iter()
            .next()
            .ok_or("successor")?;
        for (budget, expected) in [
            (deadline(&clock)?, MessagingErrorKind::OwnershipLost),
            (
                expired_deadline(&clock)?,
                MessagingErrorKind::DeadlineElapsed,
            ),
        ] {
            let result = store
                .settle(old.clone(), OutboxSettlement::Published(()), budget)
                .await;
            assert_eq!(result.err().map(|error| error.kind()), Some(expected));
            assert!(matches!(
                store.extend(&current, deadline(&clock)?).await?,
                OutboxLeaseStatus::Held { .. }
            ));
        }
        store
            .settle(current, OutboxSettlement::DeadLetter, deadline(&clock)?)
            .await?;
        assert_eq!(
            store
                .settle(old, OutboxSettlement::Retry, deadline(&clock)?)
                .await
                .err()
                .map(|error| error.kind()),
            Some(MessagingErrorKind::OwnershipLost)
        );
        assert!(
            store
                .claim_partition_heads(
                    crate::execution(crate::fixture_tenant(), 1),
                    limit,
                    deadline(&clock)?
                )
                .await?
                .is_empty()
        );
        assert_eq!(
            store.settlements().last(),
            Some(&rss_transactional_messaging::outbox::OutboxDisposition::DeadLetter)
        );
    }
    Ok(())
}

#[allow(clippy::expect_used)] // reason: explicit fixture coordinates are validated before exercising the provider.
fn execution(
    tenant: rss_request_context::TenantId,
    epoch: i64,
) -> rss_transactional_messaging::fence::ExecutionBinding {
    use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
    ExecutionBinding::new(
        StorageIdentity::new([1; 16], [2; 16]).expect("fixture storage"),
        tenant,
        Epoch::new(epoch).expect("fixture epoch"),
    )
}

#[allow(clippy::expect_used)] // reason: independently selected fixture tenant, not envelope authority.
fn fixture_tenant() -> rss_request_context::TenantId {
    rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
        .expect("fixture tenant")
}
