#![allow(clippy::expect_used, clippy::cognitive_complexity)]

use std::num::NonZeroU32;
use std::time::Duration;

use rss_eventing::delivery::{
    ConsumerTxOutcome, DELIVERY_BUDGET_MAX, DeliveryBudget, DeliveryBudgetError, PublishErrorKind,
    RejectKind,
};
use rss_eventing::envelope::{EventEnvelope, EventId, EventIdError};
use rss_eventing::lifecycle::{
    ConsumerTxAction, ConsumerTxLifecycle, RETRY_ATTEMPTS_MAX, RetryPolicy, RetryPolicyError,
    SHUTDOWN_BUDGET_MAX, ShutdownBudget, ShutdownBudgetError,
};
use rss_eventing::metadata::EventMetadata;

fn tenant() -> rss_request_context::TenantId {
    rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
        .expect("valid tenant")
}

fn metadata() -> EventMetadata {
    EventMetadata::new(
        tenant(),
        rss_contract::Timepoint::try_from_duration(Duration::from_millis(1_700_000_000_000))
            .expect("valid timepoint"),
        Some(rss_diag_context::CorrelationId::parse("corr-2159").expect("valid correlation")),
    )
}

#[test]
fn envelope_binds_identity_metadata_and_generic_payload() {
    let expected_time =
        rss_contract::Timepoint::try_from_duration(Duration::from_millis(1_700_000_000_000))
            .expect("valid timepoint");
    let descriptor = rss_contract::ContractDescriptor::from_static_version(
        "runtime.fact-updated",
        "v1",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let envelope = EventEnvelope::new(
        descriptor,
        EventId::parse("event-2159").expect("valid event id"),
        metadata(),
        String::from("payload"),
    );

    assert_eq!(envelope.contract(), descriptor);
    assert_eq!(envelope.event_id().as_str(), "event-2159");
    assert_eq!(envelope.metadata().tenant_id(), tenant());
    assert_eq!(envelope.metadata().occurred_at(), expected_time);
    assert_eq!(
        envelope
            .metadata()
            .correlation()
            .map(rss_diag_context::CorrelationId::as_str),
        Some("corr-2159")
    );
    assert_eq!(envelope.payload(), "payload");

    let mapped = envelope.map_payload(String::into_bytes);
    let (contract, event_id, metadata, payload) = mapped.into_parts();
    assert_eq!(contract, descriptor);
    assert_eq!(event_id.as_str(), "event-2159");
    assert_eq!(metadata.tenant_id(), tenant());
    assert_eq!(metadata.occurred_at(), expected_time);
    assert_eq!(
        metadata
            .correlation()
            .map(rss_diag_context::CorrelationId::as_str),
        Some("corr-2159")
    );
    assert_eq!(payload, b"payload");
}

#[test]
fn event_id_enforces_the_shared_transport_boundary_and_clones_stably() {
    assert!(matches!(EventId::parse(""), Err(EventIdError::Empty)));
    assert!(matches!(
        EventId::parse(&"x".repeat(256)),
        Err(EventIdError::TooLong)
    ));
    for invalid in [
        " stable-id",
        "stable-id ",
        "line\nbreak",
        "event/id",
        "事件",
    ] {
        assert!(matches!(
            EventId::parse(invalid),
            Err(EventIdError::InvalidChar)
        ));
    }

    let id = EventId::parse(&"x".repeat(255)).expect("boundary-length id is valid");
    assert!(id.clone() == id);
    assert_eq!(id.as_str().len(), 255);
    assert_eq!(
        EventId::parse("urn:event.stable_42")
            .expect("transport-safe alphabet")
            .as_str(),
        "urn:event.stable_42"
    );
}

#[test]
fn delivery_outcomes_and_publish_failures_are_closed() {
    let outcomes = [
        ConsumerTxOutcome::<u8>::Committed(1),
        ConsumerTxOutcome::HandlerTransient,
        ConsumerTxOutcome::InfrastructureTransient,
        ConsumerTxOutcome::Rejected(RejectKind::Permanent),
        ConsumerTxOutcome::Rejected(RejectKind::Invariant),
        ConsumerTxOutcome::CommitUnknown,
        ConsumerTxOutcome::RollbackFailed,
        ConsumerTxOutcome::Fenced,
    ];
    assert_eq!(
        outcomes.map(|outcome| outcome.as_label()),
        [
            "committed",
            "handler_transient",
            "infrastructure_transient",
            "rejected_permanent",
            "rejected_invariant",
            "commit_unknown",
            "rollback_failed",
            "fenced",
        ]
    );

    for (kind, retryable, ambiguous, permanent) in [
        (PublishErrorKind::Transient, true, false, false),
        (PublishErrorKind::Permanent, false, false, true),
        (PublishErrorKind::Ambiguous, true, true, false),
    ] {
        assert_eq!(kind.is_retryable(), retryable);
        assert_eq!(kind.is_ambiguous(), ambiguous);
        assert_eq!(kind.is_permanent(), permanent);
    }
}

#[test]
fn delivery_budget_preserves_existing_bounds_without_provider_projection() {
    let budget = DeliveryBudget::new(
        Duration::from_secs(60),
        Duration::from_secs(30),
        Duration::from_secs(10),
        Duration::from_secs(5),
    )
    .expect("valid delivery budget");
    assert_eq!(budget.required_budget(), Duration::from_secs(45));
    assert_eq!(budget.publisher_watchdog_timeout(), Duration::from_secs(35));
    assert_eq!(budget.lease_ttl(), Duration::from_secs(60));
    assert_eq!(budget.publish_timeout(), Duration::from_secs(30));
    assert_eq!(budget.settle_timeout(), Duration::from_secs(10));
    assert_eq!(budget.safety_margin(), Duration::from_secs(5));
    assert!(!budget.can_start_attempt(Duration::from_secs(45)));
    assert!(budget.can_start_attempt(Duration::from_secs(45) + Duration::from_millis(1)));

    let valid = Duration::from_millis(10);
    for (field, [lease, publish, settle, safety]) in [
        ("lease_ttl", [Duration::ZERO, valid, valid, valid]),
        ("publish_timeout", [valid, Duration::ZERO, valid, valid]),
        ("settle_timeout", [valid, valid, Duration::ZERO, valid]),
        ("safety_margin", [valid, valid, valid, Duration::ZERO]),
    ] {
        assert_eq!(
            DeliveryBudget::new(lease, publish, settle, safety),
            Err(DeliveryBudgetError::Zero { field })
        );
    }

    let sub_millisecond = Duration::from_micros(1);
    for (field, [lease, publish, settle, safety]) in [
        ("lease_ttl", [sub_millisecond, valid, valid, valid]),
        ("publish_timeout", [valid, sub_millisecond, valid, valid]),
        ("settle_timeout", [valid, valid, sub_millisecond, valid]),
        ("safety_margin", [valid, valid, valid, sub_millisecond]),
    ] {
        assert_eq!(
            DeliveryBudget::new(lease, publish, settle, safety),
            Err(DeliveryBudgetError::NonIntegralMilliseconds { field })
        );
    }

    assert!(matches!(
        DeliveryBudget::new(
            Duration::from_secs(3),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        ),
        Err(DeliveryBudgetError::RequiredBudgetNotBelowLease { .. })
    ));
    assert!(
        DeliveryBudget::new(
            Duration::from_millis(4),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .is_ok()
    );

    assert_eq!(DELIVERY_BUDGET_MAX, Duration::from_secs(24 * 60 * 60));
    assert!(
        DeliveryBudget::new(
            DELIVERY_BUDGET_MAX,
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .is_ok()
    );
    let above_max = DELIVERY_BUDGET_MAX + Duration::from_millis(1);
    assert!(matches!(
        DeliveryBudget::new(
            above_max,
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
        ),
        Err(DeliveryBudgetError::OperationalRangeExceeded {
            field: "lease_ttl",
            max: DELIVERY_BUDGET_MAX,
        })
    ));
    for (field, [lease, publish, settle, safety]) in [
        (
            "publish_timeout",
            [DELIVERY_BUDGET_MAX, above_max, valid, valid],
        ),
        (
            "settle_timeout",
            [DELIVERY_BUDGET_MAX, valid, above_max, valid],
        ),
        (
            "safety_margin",
            [DELIVERY_BUDGET_MAX, valid, valid, above_max],
        ),
    ] {
        assert_eq!(
            DeliveryBudget::new(lease, publish, settle, safety),
            Err(DeliveryBudgetError::OperationalRangeExceeded {
                field,
                max: DELIVERY_BUDGET_MAX,
            })
        );
    }
    assert!(matches!(
        DeliveryBudget::new(
            Duration::MAX,
            Duration::new(u64::MAX, 0),
            Duration::from_secs(1),
            Duration::from_secs(1),
        ),
        Err(DeliveryBudgetError::RequiredBudgetOverflow)
    ));
}

#[tokio::test(start_paused = true)]
async fn consumer_tx_lifecycle_closes_retry_and_terminal_decisions() {
    let mut cancelled = ConsumerTxLifecycle::new(RetryPolicy::STANDARD);
    {
        let future = cancelled.finish_attempt(
            &ConsumerTxOutcome::<()>::HandlerTransient,
            tokio::time::sleep,
        );
        tokio::pin!(future);
        tokio::select! {
            biased;
            result = &mut future => panic!("retry became ready before delay: {result:?}"),
            () = tokio::task::yield_now() => {}
        }
    }
    assert_eq!(
        cancelled.current_attempt(),
        NonZeroU32::new(1),
        "dropping the retry wait must not expose the next attempt"
    );

    let mut lifecycle = ConsumerTxLifecycle::new(RetryPolicy::STANDARD);
    assert_eq!(lifecycle.current_attempt(), NonZeroU32::new(1));
    let first = {
        let future = lifecycle.finish_attempt(
            &ConsumerTxOutcome::<()>::HandlerTransient,
            tokio::time::sleep,
        );
        tokio::pin!(future);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        future.await
    };
    assert_eq!(
        first,
        Ok(ConsumerTxAction::RetryReady {
            failed_attempt: NonZeroU32::new(1).expect("non-zero"),
            delay: Duration::from_secs(1),
        })
    );
    assert_eq!(lifecycle.current_attempt(), NonZeroU32::new(2));
    assert_eq!(
        lifecycle
            .finish_attempt(&ConsumerTxOutcome::<()>::CommitUnknown, tokio::time::sleep,)
            .await,
        Ok(ConsumerTxAction::Requeue)
    );
    assert!(lifecycle.current_attempt().is_none());
    assert!(
        lifecycle
            .finish_attempt(&ConsumerTxOutcome::<()>::Committed(()), tokio::time::sleep,)
            .await
            .is_err()
    );

    let mut exhausted = ConsumerTxLifecycle::new(RetryPolicy::STANDARD);
    let first = {
        let future = exhausted.finish_attempt(
            &ConsumerTxOutcome::<()>::HandlerTransient,
            tokio::time::sleep,
        );
        tokio::pin!(future);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        future.await
    };
    assert!(matches!(first, Ok(ConsumerTxAction::RetryReady { .. })));
    let second = {
        let future = exhausted.finish_attempt(
            &ConsumerTxOutcome::<()>::HandlerTransient,
            tokio::time::sleep,
        );
        tokio::pin!(future);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        future.await
    };
    assert!(matches!(second, Ok(ConsumerTxAction::RetryReady { .. })));
    assert_eq!(
        exhausted
            .finish_attempt(
                &ConsumerTxOutcome::<()>::HandlerTransient,
                tokio::time::sleep,
            )
            .await,
        Ok(ConsumerTxAction::Exhausted)
    );
    assert!(exhausted.current_attempt().is_none());
}

#[test]
fn retry_and_shutdown_lifecycle_are_bounded() {
    let standard = RetryPolicy::STANDARD;
    assert_eq!(standard.max_attempts().get(), 3);
    assert!(standard.allows_attempt(NonZeroU32::new(3).expect("non-zero")));
    assert!(!standard.allows_attempt(NonZeroU32::new(4).expect("non-zero")));
    assert_eq!(
        standard.delay_after(NonZeroU32::new(1).expect("non-zero")),
        Duration::from_secs(1)
    );
    assert_eq!(
        standard.delay_after(NonZeroU32::new(2).expect("non-zero")),
        Duration::from_secs(2)
    );
    assert_eq!(
        standard.delay_after(NonZeroU32::new(3).expect("non-zero")),
        Duration::from_secs(4)
    );
    assert_eq!(
        standard.delay_after(NonZeroU32::new(7).expect("non-zero")),
        Duration::from_secs(60)
    );
    assert_eq!(
        standard.delay_after(NonZeroU32::new(99).expect("non-zero")),
        Duration::from_secs(60)
    );
    assert!(matches!(
        RetryPolicy::new(
            NonZeroU32::new(1).expect("non-zero"),
            Duration::from_secs(2),
            Duration::from_secs(1),
        ),
        Err(RetryPolicyError::BaseExceedsCap { .. })
    ));
    let long_exponent = RetryPolicy::new(
        NonZeroU32::new(40).expect("non-zero"),
        Duration::from_nanos(1),
        Duration::from_secs(8),
    )
    .expect("valid long retry policy");
    assert_eq!(
        long_exponent.delay_after(NonZeroU32::new(32).expect("non-zero")),
        Duration::from_nanos(1_u64 << 31)
    );
    assert_eq!(
        long_exponent.delay_after(NonZeroU32::new(33).expect("non-zero")),
        Duration::from_nanos(1_u64 << 32)
    );
    assert_eq!(
        long_exponent.delay_after(NonZeroU32::new(34).expect("non-zero")),
        Duration::from_secs(8)
    );
    assert!(matches!(
        RetryPolicy::new(
            NonZeroU32::MAX,
            Duration::from_secs(1),
            Duration::from_secs(1)
        ),
        Err(RetryPolicyError::AttemptsExceeded { .. })
    ));
    assert!(matches!(
        RetryPolicy::new(
            NonZeroU32::new(3).expect("non-zero"),
            Duration::ZERO,
            Duration::from_secs(1),
        ),
        Err(RetryPolicyError::ZeroBackoff)
    ));
    assert!(
        RetryPolicy::new(
            RETRY_ATTEMPTS_MAX,
            Duration::from_nanos(1),
            Duration::from_secs(1),
        )
        .is_ok()
    );

    assert_eq!(ShutdownBudget::STANDARD.timeout(), Duration::from_secs(45));
    assert!(matches!(
        ShutdownBudget::new(Duration::ZERO),
        Err(ShutdownBudgetError::Zero)
    ));
    assert!(matches!(
        ShutdownBudget::new(SHUTDOWN_BUDGET_MAX + Duration::from_nanos(1)),
        Err(ShutdownBudgetError::OperationalRangeExceeded)
    ));
    assert!(ShutdownBudget::new(SHUTDOWN_BUDGET_MAX).is_ok());
}
