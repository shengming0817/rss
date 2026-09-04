use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::time::Duration;

use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_transactional_messaging::error::MessagingErrorKind;
use rss_transactional_messaging::inbox::{
    ConsumerGroup, ConsumerIdentity, IdempotencyDisposition, InboxStore, LeaseStatus,
};
use rss_transactional_messaging::message::{
    AuthoredMessageMetadata, ContractIdentity, MessageEnvelope, MessageFingerprint, MessageId,
    MessageMetadata, MessageMetadataExtensions, MessageRoute, MessagingDomain, PartitionKey,
};
use rss_transactional_messaging::outbox::{
    AppendOutcome, OutboxLeaseStatus, OutboxSettlement, OutboxStore, PendingMessage,
};
use rss_transactional_messaging::policy::{AbsoluteDeadline, Clock, ExecutionTimer};
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
    let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
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

fn deadline(
    clock: &FakeClock,
) -> Result<rss_transactional_messaging::policy::OperationDeadline, Box<dyn std::error::Error>> {
    Ok(AbsoluteDeadline::from_timeout(clock, Duration::from_secs(30))?.operation(clock))
}

fn expired_deadline(
    clock: &FakeClock,
) -> Result<rss_transactional_messaging::policy::OperationDeadline, Box<dyn std::error::Error>> {
    Ok(AbsoluteDeadline::from_timeout(clock, Duration::ZERO)?.operation(clock))
}

#[tokio::test]
async fn fake_clock_releases_deadlines_only_after_advance() -> TestResult {
    let clock = FakeClock::new();
    clock.advance(Duration::from_nanos(1));
    clock.advance(Duration::from_micros(1));
    assert_eq!(clock.now().elapsed(), Duration::from_nanos(1_001));
    let cutoff = AbsoluteDeadline::from_timeout(&clock, Duration::from_secs(5))?;
    let waiter_clock = clock.clone();
    let handle = tokio::spawn(async move { waiter_clock.sleep_until(cutoff).await });
    tokio::task::yield_now().await;
    assert!(!handle.is_finished());
    clock.advance(Duration::from_secs(5));
    handle.await?;
    assert_eq!(
        clock.now().elapsed(),
        Duration::from_secs(5) + Duration::from_nanos(1_001)
    );
    clock.advance(Duration::MAX);
    let saturated = clock.now();
    clock.advance(Duration::MAX);
    assert_eq!(
        clock.now(),
        saturated,
        "monotonic time must saturate, not wrap"
    );
    for _ in 0..64 {
        let racing_clock = FakeClock::new();
        let cutoff = AbsoluteDeadline::from_timeout(&racing_clock, Duration::from_millis(1))?;
        let waiter_clock = racing_clock.clone();
        let waiter = tokio::spawn(async move { waiter_clock.sleep_until(cutoff).await });
        racing_clock.advance(Duration::from_millis(1));
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
        .claim_partition_heads(NonZeroUsize::new(8).ok_or("limit")?, deadline(&clock)?)
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
            .claim_partition_heads(NonZeroUsize::new(8).ok_or("limit")?, deadline(&clock)?)
            .await?
            .is_empty(),
        "an in-flight partition head must block its successor across claim calls"
    );
    store.fence_claims();
    assert_eq!(
        store.lease_status(&claim, deadline(&clock)?).await?,
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
        .claim_partition_heads(NonZeroUsize::new(8).ok_or("limit")?, deadline(&clock)?)
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
        .claim_partition_heads(NonZeroUsize::MIN, deadline(&clock)?)
        .await?
        .into_iter()
        .next()
        .ok_or("expired claim")?;
    assert_eq!(
        store
            .lease_status(&claim, expired_deadline(&clock)?)
            .await?,
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
        .claim_partition_heads(NonZeroUsize::MIN, deadline(&clock)?)
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
        .claim_partition_heads(NonZeroUsize::MIN, deadline(&clock)?)
        .await?
        .into_iter()
        .next()
        .ok_or("dead-letter head")?;
    store
        .settle(head, OutboxSettlement::DeadLetter, deadline(&clock)?)
        .await?;
    assert!(
        store
            .claim_partition_heads(NonZeroUsize::MIN, deadline(&clock)?)
            .await?
            .is_empty(),
        "an unresolved dead-letter head must block its partition successor"
    );
    store.resolve_partition(&partition);
    assert_eq!(
        store
            .claim_partition_heads(NonZeroUsize::MIN, deadline(&clock)?)
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
    let identity = ConsumerIdentity::new(
        message.metadata().tenant_id(),
        ConsumerGroup::parse("orders-worker")?,
        message.id().clone(),
        message.metadata().contract().clone(),
    );
    let claim = match store.claim(&identity, deadline(&clock)?).await? {
        IdempotencyDisposition::Acquired(claim) => claim,
        _ => return Err("first claim must acquire".into()),
    };
    assert!(matches!(
        store.claim(&identity, deadline(&clock)?).await?,
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

    store.store_terminal(
        identity.clone(),
        MessageFingerprint::of(&message),
        TerminalDisposition::Succeeded,
    );
    assert!(matches!(
        store.claim(&identity, deadline(&clock)?).await?,
        IdempotencyDisposition::Terminal(_)
    ));
    store.expire(&identity);
    assert!(matches!(
        store.claim(&identity, deadline(&clock)?).await?,
        IdempotencyDisposition::Terminal(_)
    ));

    let releasable = MemoryInboxStore::new();
    let claim = match releasable.claim(&identity, deadline(&clock)?).await? {
        IdempotencyDisposition::Acquired(claim) => claim,
        _ => return Err("release fixture must acquire".into()),
    };
    releasable.release(claim, deadline(&clock)?).await?;
    assert!(matches!(
        releasable.claim(&identity, deadline(&clock)?).await?,
        IdempotencyDisposition::Acquired(_)
    ));

    let collision_store = MemoryInboxStore::new();
    let first_message = envelope("c", b"payload")?;
    let first_identity = ConsumerIdentity::new(
        first_message.metadata().tenant_id(),
        ConsumerGroup::parse("a:b")?,
        first_message.id().clone(),
        first_message.metadata().contract().clone(),
    );
    let second_message = envelope("b:c", b"payload")?;
    let second_identity = ConsumerIdentity::new(
        second_message.metadata().tenant_id(),
        ConsumerGroup::parse("a")?,
        second_message.id().clone(),
        second_message.metadata().contract().clone(),
    );
    assert!(matches!(
        collision_store
            .claim(&first_identity, deadline(&clock)?)
            .await?,
        IdempotencyDisposition::Acquired(_)
    ));
    assert!(matches!(
        collision_store
            .claim(&second_identity, deadline(&clock)?)
            .await?,
        IdempotencyDisposition::Acquired(_)
    ));

    let changed_schema_identity = ConsumerIdentity::new(
        second_message.metadata().tenant_id(),
        ConsumerGroup::parse("a")?,
        second_message.id().clone(),
        ContractIdentity::new(
            second_message.metadata().contract().id().clone(),
            second_message.metadata().contract().version(),
            SchemaDigest::parse(
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )?,
        ),
    );
    assert!(matches!(
        collision_store
            .claim(&changed_schema_identity, deadline(&clock)?)
            .await?,
        IdempotencyDisposition::Acquired(_)
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
