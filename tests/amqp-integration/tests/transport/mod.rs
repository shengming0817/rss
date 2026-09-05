//! Real broker implementations of the public transport suites.
use super::*;
use rss_transactional_messaging::transaction::verify_ingress;
use rss_transactional_messaging_testkit::transport::{
    CancellationEvidence, DeliveryEvidence, DeliveryTransportDriver, PublishAttempt,
    PublisherTransportDriver, run_delivery_transport_conformance,
    run_publisher_transport_conformance,
};

struct BrokerDriver<'a> {
    url: String,
    rabbit: &'a testkit::RabbitFixture,
}
fn evidence_error<T>(error: T) -> ConformanceError {
    let _ = error;
    ConformanceError::delivery(MessagingErrorKind::Invariant)
}
fn terminal_decision(
    message: &MessageEnvelope<Vec<u8>>,
    subscription: &SubscriptionIdentity,
    rejected: bool,
) -> Result<SettlementDecision, ConformanceError> {
    let binding = verify_ingress(
        &LiveIngress,
        ConsumerGroup::parse("transport-proof").map_err(evidence_error)?,
        subscription,
        message,
    )
    .map_err(evidence_error)?;
    let disposition = if rejected {
        TerminalDisposition::Rejected(
            rss_transactional_messaging::transaction::RejectKind::Permanent,
        )
    } else {
        TerminalDisposition::Succeeded
    };
    binding.receipt_intent().committed((), disposition).fold(
        |committed| Ok(committed.into_parts().1.into_decision()),
        |_| Err(evidence_error(())),
        |_| Err(evidence_error(())),
        || Err(evidence_error(())),
        || Err(evidence_error(())),
        || Err(evidence_error(())),
    )
}
async fn close(resource: &impl ManagedResource) -> Result<(), ConformanceError> {
    shutdown_bounded(resource)
        .await
        .map_err(LiveConformanceFailure::into_conformance)
}
impl BrokerDriver<'_> {
    async fn cancellation_case(&self) -> Result<CancellationEvidence, ConformanceError> {
        let route = MessageRoute::parse("rss.transport.cancel").map_err(evidence_error)?;
        let (subscriber, resource) =
            prepared_subscriber(&self.url, &route, "transport-cancel", true)
                .await
                .map_err(LiveConformanceFailure::into_conformance)?;
        let (publisher, publisher_resource) =
            connected_publisher(&self.url, "transport-cancel-pub")
                .await
                .map_err(LiveConformanceFailure::into_conformance)?;
        let first = envelope(&route, "cancel-inflight");
        let pending = envelope(&route, "cancel-pending");
        let subscription = subscription_for(&first, &route);
        let mut stream = subscriber
            .deliveries(&subscription)
            .await
            .map_err(|e| ConformanceError::delivery(e.kind()))?;
        publish_confirmed(&publisher, &first).await?;
        publish_confirmed(&publisher, &pending).await?;
        let delivery = next_valid_delivery(&mut stream, "inflight", "invalid")
            .await
            .map_err(LiveConformanceFailure::into_conformance)?;
        let (drained, settlement) = (*delivery).into_parts();
        cancel_and_drain(self, settlement, &drained, &subscription).await?;
        let received_id = observe_cancel_successor(&self.url, &subscription).await?;
        drop(stream);
        close(&resource).await?;
        close(&publisher_resource).await?;
        Ok(CancellationEvidence {
            drained_id: drained.id().clone(),
            pending_id: pending.id().clone(),
            replacement_ids: vec![received_id],
        })
    }

    async fn publish_case(&self, routed: bool) -> Result<PublishAttempt, ConformanceError> {
        let route = MessageRoute::parse(if routed {
            "rss.transport.confirmed"
        } else {
            "rss.transport.unroutable"
        })
        .map_err(evidence_error)?;
        let subscriber = if routed {
            Some(
                prepared_subscriber(&self.url, &route, "transport-publish-sub", true)
                    .await
                    .map_err(LiveConformanceFailure::into_conformance)?,
            )
        } else {
            None
        };
        let (publisher, resource) = connected_publisher(&self.url, "transport-publish")
            .await
            .map_err(LiveConformanceFailure::into_conformance)?;
        let message = envelope(&route, "transport-publish");
        let outcome = publisher.publish(&message, provider_deadline()).await;
        close(&resource).await?;
        if let Some((_, resource)) = subscriber {
            close(&resource).await?;
        }
        Ok(PublishAttempt {
            message_id: message.id().clone(),
            outcome,
        })
    }
    async fn settlement_case(&self, kind: Case) -> Result<DeliveryEvidence, ConformanceError> {
        let route = MessageRoute::parse(&format!("rss.transport.{}", kind.name()))
            .map_err(evidence_error)?;
        let (subscriber, resource) =
            prepared_subscriber(&self.url, &route, "transport-settle", true)
                .await
                .map_err(LiveConformanceFailure::into_conformance)?;
        let (publisher, publisher_resource) =
            connected_publisher(&self.url, "transport-settle-pub")
                .await
                .map_err(LiveConformanceFailure::into_conformance)?;
        let message = envelope(&route, kind.name());
        let subscription = subscription_for(&message, &route);
        let mut stream = subscriber
            .deliveries(&subscription)
            .await
            .map_err(|e| ConformanceError::delivery(e.kind()))?;
        publish_confirmed(&publisher, &message).await?;
        let delivered = next_valid_delivery(&mut stream, "delivery", "invalid")
            .await
            .map_err(LiveConformanceFailure::into_conformance)?;
        let (received, settlement) = (*delivered).into_parts();
        if received.id() != message.id()
            || MessageFingerprint::of(&received) != MessageFingerprint::of(&message)
        {
            return Err(evidence_error(()));
        }
        apply_settlement(kind, settlement, &received, &subscription).await?;
        let redelivered_ids = self
            .observe_settled(kind, stream, &subscriber, &resource, &subscription)
            .await?;
        close(&resource).await?;
        close(&publisher_resource).await?;
        Ok(DeliveryEvidence {
            message_id: received.id().clone(),
            redelivered_ids,
        })
    }
    async fn observe_settled(
        &self,
        kind: Case,
        mut stream: ManagedDeliveryStream<AmqpDeliveries>,
        subscriber: &AmqpSubscriber,
        resource: &AmqpSubscriberResource,
        subscription: &SubscriptionIdentity,
    ) -> Result<Vec<MessageId>, ConformanceError> {
        let redelivered_ids = if matches!(kind, Case::Requeue) {
            // Only the actual NACK may reopen the original prefetch window.
            let ids = observe_redelivery(&mut stream, subscription, kind).await?;
            drop(stream);
            ids
        } else if matches!(kind, Case::Ack | Case::Reject) {
            // Closing makes an omitted ACK observable as a redelivery, including unacked messages.
            drop(stream);
            close(resource).await?;
            let (replacement, replacement_resource) = prepared_subscriber(
                &self.url,
                subscription.route(),
                "transport-replacement",
                false,
            )
            .await
            .map_err(LiveConformanceFailure::into_conformance)?;
            let mut stream = replacement
                .deliveries(subscription)
                .await
                .map_err(|e| ConformanceError::delivery(e.kind()))?;
            let ids = observe_redelivery(&mut stream, subscription, kind).await?;
            close(&replacement_resource).await?;
            ids
        } else {
            // Abandon/timeout must retire the old channel themselves. Keep both the old stream
            // and resource alive while a fresh channel on this exact resource observes requeue.
            let mut replacement = subscriber
                .deliveries(subscription)
                .await
                .map_err(|e| ConformanceError::delivery(e.kind()))?;
            let ids = observe_redelivery(&mut replacement, subscription, kind).await?;
            drop(stream);
            ids
        };
        Ok(redelivered_ids)
    }
}
#[derive(Clone, Copy)]
enum Case {
    Ack,
    Requeue,
    Reject,
    Abandon,
    Failure,
}
impl Case {
    fn name(self) -> &'static str {
        match self {
            Self::Ack => "ack",
            Self::Requeue => "requeue",
            Self::Reject => "reject",
            Self::Abandon => "abandon",
            Self::Failure => "failure",
        }
    }
}

impl PublisherTransportDriver for BrokerDriver<'_> {
    async fn confirmed(&self) -> Result<PublishAttempt, ConformanceError> {
        self.publish_case(true).await
    }
    async fn transient(&self) -> Result<PublishAttempt, ConformanceError> {
        self.publish_case(false).await
    }
    async fn permanent(&self) -> Result<PublishAttempt, ConformanceError> {
        let network = testkit::bridge_network("rss-amqp-publisher-permission")
            .await
            .map_err(|_| ConformanceError::fixture(MessagingErrorKind::Transient))?;
        let dns = format!("{}-node", network.name());
        let fixture = testkit::rabbitmq_tls(
            "rss.transport.allowed",
            testkit::NetworkAttachment {
                network: network.name(),
                dns_name: &dns,
            },
        )
        .await
        .map_err(|_| ConformanceError::fixture(MessagingErrorKind::Transient))?;
        let ca = AmqpPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())
            .map_err(|_| ConformanceError::connect(MessagingErrorKind::Permanent))?;
        let endpoint = AmqpPublisherEndpoint::parse(fixture.publisher_url())
            .map_err(|_| ConformanceError::connect(MessagingErrorKind::Permanent))?;
        let (publisher, resource) =
            AmqpPublisher::connect(&endpoint, "transport-permission", &ca, TIMEOUT)
                .await
                .map_err(|_| ConformanceError::connect(MessagingErrorKind::Transient))?;
        let message = envelope(
            &MessageRoute::parse("rss.transport.forbidden").map_err(evidence_error)?,
            "permission-refusal",
        );
        let outcome = publisher.publish(&message, provider_deadline()).await;
        close(&resource).await?;
        Ok(PublishAttempt {
            message_id: message.id().clone(),
            outcome,
        })
    }
    async fn ambiguous_retry(&self) -> Result<Vec<PublishAttempt>, ConformanceError> {
        let (ids, outcomes, _) = run_ambiguous_publish_retries_the_same_message_identity()
            .await
            .map_err(LiveConformanceFailure::into_conformance)?;
        Ok(ids
            .into_iter()
            .zip(outcomes)
            .map(|(message_id, outcome)| PublishAttempt {
                message_id,
                outcome,
            })
            .collect())
    }
}
impl DeliveryTransportDriver for BrokerDriver<'_> {
    async fn acknowledged(&self) -> Result<DeliveryEvidence, ConformanceError> {
        self.settlement_case(Case::Ack).await
    }
    async fn requeued(&self) -> Result<DeliveryEvidence, ConformanceError> {
        self.settlement_case(Case::Requeue).await
    }
    async fn rejected(&self) -> Result<DeliveryEvidence, ConformanceError> {
        self.settlement_case(Case::Reject).await
    }
    async fn abandoned(&self) -> Result<DeliveryEvidence, ConformanceError> {
        self.settlement_case(Case::Abandon).await
    }
    async fn settlement_failed(&self) -> Result<DeliveryEvidence, ConformanceError> {
        self.settlement_case(Case::Failure).await
    }
    async fn cancelled(&self) -> Result<CancellationEvidence, ConformanceError> {
        // Management evidence must belong to an owned broker, even when ordinary transport
        // conformance uses an externally provisioned endpoint.
        let rabbit = testkit::managed_rabbitmq().await.map_err(evidence_error)?;
        let url = rabbit
            .vhost_url(&isolated_vhost("rss_transport_cancel"))
            .await
            .map_err(evidence_error)?;
        BrokerDriver {
            url,
            rabbit: &rabbit,
        }
        .cancellation_case()
        .await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn publisher_transport_conformance() -> anyhow::Result<()> {
    let (_rabbit, url) = isolated_rabbit("rss_transport_publish").await?;
    run_publisher_transport_conformance(
        &BrokerDriver {
            url,
            rabbit: &_rabbit,
        },
        &TokioClock::new(),
        ExecutionBudget::new(Duration::from_secs(90), Duration::from_secs(5))?,
    )
    .await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread")]
async fn delivery_transport_conformance() -> anyhow::Result<()> {
    let (_rabbit, url) = isolated_rabbit("rss_transport_delivery").await?;
    run_delivery_transport_conformance(
        &BrokerDriver {
            url,
            rabbit: &_rabbit,
        },
        &TokioClock::new(),
        ExecutionBudget::new(Duration::from_secs(90), Duration::from_secs(5))?,
    )
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_publish_retires_generation_and_owner_cannot_revive() -> anyhow::Result<()> {
    let (_rabbit, url) = isolated_rabbit("rss_transport_cancel_publish").await?;
    let route = MessageRoute::parse("rss.transport.cancel-publish")?;
    let (_subscriber, subscriber_resource) =
        prepared_subscriber(&url, &route, "cancel-publish-sub", true).await?;
    let (publisher, resource) = connected_publisher(&url, "cancel-publish").await?;
    let generation = publisher
        .transport_generation_for_test()
        .expect("ready generation");
    let message = envelope(&route, "cancelled-at-confirm");
    let (entered, _release) = publisher.pause_next_confirmation_for_test();
    {
        let publishing = publisher.publish(&message, provider_deadline());
        tokio::pin!(publishing);
        tokio::select! {
            result = &mut publishing => { let _ = result; anyhow::bail!("publication must pause before returning confirmation"); },
            ready = tokio::time::timeout(TIMEOUT, entered) => { ready??; },
        }
    } // Drop the in-flight provider future, exactly as core's outer deadline does.
    assert!(publisher.wait_until_publish_ready_for_test().await);
    assert!(
        publisher
            .transport_generation_for_test()
            .is_some_and(|new| new > generation)
    );
    assert!(matches!(
        publisher.publish(&message, provider_deadline()).await,
        PublishOutcome::Confirmed(())
    ));
    drop(resource);
    assert!(matches!(
        publisher.publish(&message, provider_deadline()).await,
        PublishOutcome::DefinitelyNotPublished(_)
    ));
    assert!(publisher.transport_generation_for_test().is_none());
    close(&subscriber_resource).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_settlement_never_acks_and_redelivers() -> anyhow::Result<()> {
    let (_rabbit, url) = isolated_rabbit("rss_transport_expired_settle").await?;
    let route = MessageRoute::parse("rss.transport.expired-settle")?;
    let (subscriber, resource) =
        prepared_subscriber(&url, &route, "expired-settle-sub", true).await?;
    let (publisher, publisher_resource) = connected_publisher(&url, "expired-settle-pub").await?;
    let message = envelope(&route, "expired-settle-message");
    let subscription = subscription_for(&message, &route);
    let mut stream = subscriber.deliveries(&subscription).await?;
    let clock = FakeClock::new();
    let expired = AbsoluteDeadline::from_timeout(&clock, Duration::ZERO)?.operation(&clock);
    let generation = publisher.transport_generation_for_test();
    assert!(
        matches!(publisher.publish(&message, expired).await, PublishOutcome::DefinitelyNotPublished(failure) if failure.stage() == rss_transactional_messaging::transport::PublishFailureStage::Admission)
    );
    assert_eq!(publisher.transport_generation_for_test(), generation);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), stream.next())
            .await
            .is_err()
    );
    assert!(matches!(
        publisher.publish(&message, provider_deadline()).await,
        PublishOutcome::Confirmed(())
    ));
    let delivery = next_valid_delivery(&mut stream, "expired delivery", "invalid").await?;
    let (received, settlement) = (*delivery).into_parts();
    let clock = FakeClock::new();
    let expired = AbsoluteDeadline::from_timeout(&clock, Duration::ZERO)?.operation(&clock);
    assert!(
        settlement
            .settle(terminal_decision(&received, &subscription, false)?, expired)
            .await
            .is_err()
    );
    assert_same_id_redelivery(&url, &route, &subscription, message.id()).await?;
    drop(stream);
    close(&resource).await?;
    close(&publisher_resource).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn headers_roundtrip_and_subscription_cancel_is_isolated() -> anyhow::Result<()> {
    use rss_transactional_messaging::message::TransportContext;
    let (_rabbit, url) = isolated_rabbit("rss_transport_headers").await?;
    let route = MessageRoute::parse("rss.transport.headers")?;
    let other_route = MessageRoute::parse("rss.transport.adjacent")?;
    let (subscriber, resource) = prepared_subscriber(&url, &route, "headers-sub", true).await?;
    topology::provision(&url, &other_route, true).await?;
    let (publisher, publisher_resource) = connected_publisher(&url, "headers-pub").await?;
    let template = envelope(&route, "headers-message");
    let metadata = template.metadata();
    let message = MessageEnvelope::new(
        template.id().clone(),
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                metadata.tenant_id(),
                metadata.occurred_at(),
                metadata.domain().clone(),
                route.clone(),
                metadata.contract().clone(),
            ),
            MessageMetadataExtensions::new(
                Some(rss_diag_context::CorrelationId::parse("correlation-value")?),
                Some(PartitionKey::parse("partition-key")?),
                Some(MessageId::parse("causing-message")?),
                BTreeMap::from([("extension".into(), "opaque-value".into())]),
            ),
        ),
        vec![0, 1, 127, 255],
    )
    .with_transport_context(TransportContext::new(
        Some("trace-context".into()),
        Some("tenant-authority".into()),
    ));
    let other = envelope(&other_route, "adjacent-message");
    let subscription = subscription_for(&message, &route);
    let other_subscription = subscription_for(&other, &other_route);
    let mut first_stream = subscriber.deliveries(&subscription).await?;
    let mut other_stream = subscriber.deliveries(&other_subscription).await?;
    assert!(matches!(
        publisher.publish(&message, provider_deadline()).await,
        PublishOutcome::Confirmed(())
    ));
    let delivery = next_valid_delivery(&mut first_stream, "headers", "invalid").await?;
    let (received, settlement) = (*delivery).into_parts();
    assert_eq!(
        MessageFingerprint::of(&received),
        MessageFingerprint::of(&message)
    );
    assert_eq!(
        received.transport_context().trace(),
        message.transport_context().trace()
    );
    assert_eq!(
        received.transport_context().tenant_authority(),
        message.transport_context().tenant_authority()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), other_stream.next())
            .await
            .is_err(),
        "exact route bindings must not deliver an adjacent route"
    );
    drop(first_stream);
    settlement
        .settle(
            terminal_decision(&received, &subscription, false)?,
            provider_deadline(),
        )
        .await?;
    assert!(matches!(
        publisher.publish(&other, provider_deadline()).await,
        PublishOutcome::Confirmed(())
    ));
    let delivery = next_valid_delivery(&mut other_stream, "adjacent", "invalid").await?;
    let (received, settlement) = (*delivery).into_parts();
    assert_eq!(received.id(), other.id());
    settlement
        .settle(
            terminal_decision(&received, &other_subscription, false)?,
            provider_deadline(),
        )
        .await?;
    drop(resource);
    assert!(
        subscriber.deliveries(&subscription).await.is_err(),
        "dropping the unique owner must fence surviving handles"
    );
    close(&publisher_resource).await?;
    Ok(())
}

async fn apply_settlement(
    kind: Case,
    mut settlement: rss_transactional_messaging_amqp::AmqpSettlement,
    received: &MessageEnvelope<Vec<u8>>,
    subscription: &SubscriptionIdentity,
) -> Result<(), ConformanceError> {
    match kind {
        Case::Ack | Case::Reject => settlement
            .settle(
                terminal_decision(received, subscription, matches!(kind, Case::Reject))?,
                provider_deadline(),
            )
            .await
            .map_err(|e| ConformanceError::settlement(e.kind()))?,
        Case::Requeue => settlement
            .settle(SettlementDecision::requeue(), provider_deadline())
            .await
            .map_err(|e| ConformanceError::settlement(e.kind()))?,
        Case::Abandon => settlement
            .abandon(provider_deadline())
            .await
            .map_err(|e| ConformanceError::settlement(e.kind()))?,
        Case::Failure => {
            let (mut entered, _resume) = settlement.pause_before_settlement_for_test();
            let clock = FakeClock::new();
            let deadline = AbsoluteDeadline::from_timeout(&clock, Duration::from_millis(100))
                .map_err(evidence_error)?
                .operation(&clock);
            if settlement
                .settle(terminal_decision(received, subscription, false)?, deadline)
                .await
                .is_ok()
            {
                return Err(evidence_error(()));
            }
            entered
                .try_recv()
                .expect("real settlement must enter the pause barrier");
        }
    }
    Ok(())
}

async fn publish_confirmed(
    publisher: &AmqpPublisher,
    message: &MessageEnvelope<Vec<u8>>,
) -> Result<(), ConformanceError> {
    match publisher.publish(message, provider_deadline()).await {
        PublishOutcome::Confirmed(()) => Ok(()),
        _ => Err(ConformanceError::publish(MessagingErrorKind::Transient)),
    }
}

async fn observe_redelivery(
    stream: &mut ManagedDeliveryStream<AmqpDeliveries>,
    subscription: &SubscriptionIdentity,
    kind: Case,
) -> Result<Vec<MessageId>, ConformanceError> {
    let mut redelivered_ids = Vec::new();
    let wait = if matches!(kind, Case::Ack | Case::Reject) {
        Duration::from_millis(300)
    } else {
        Duration::from_secs(5)
    };
    match tokio::time::timeout(wait, stream.next()).await {
        Ok(Some(IncomingDelivery::Valid(delivery))) => {
            let (received, settlement) = (*delivery).into_parts();
            redelivered_ids.push(received.id().clone());
            settlement
                .settle(
                    terminal_decision(&received, subscription, false)?,
                    provider_deadline(),
                )
                .await
                .map_err(|e| ConformanceError::settlement(e.kind()))?;
        }
        Err(_) => {}
        Ok(_) => return Err(ConformanceError::delivery(MessagingErrorKind::Transient)),
    }
    Ok(redelivered_ids)
}

#[tokio::test(flavor = "multi_thread")]
async fn subscription_cannot_register_after_resource_shutdown() -> anyhow::Result<()> {
    let (_rabbit, url) = isolated_rabbit("rss_transport_register_shutdown").await?;
    let route = MessageRoute::parse("rss.transport.register-shutdown")?;
    let (subscriber, resource) =
        prepared_subscriber(&url, &route, "register-shutdown", true).await?;
    let subscription = subscription_for(&envelope(&route, "register-shutdown"), &route);
    let (entered, resume) = subscriber.pause_next_subscription_registration_for_test();
    let registration = subscriber.deliveries(&subscription);
    tokio::pin!(registration);
    tokio::select! {
        _ = &mut registration => anyhow::bail!("subscription must pause before registration"),
        ready = tokio::time::timeout(TIMEOUT, entered) => { ready??; },
    }
    close(&resource).await?;
    let _ = resume.send(());
    assert!(
        registration.await.is_err(),
        "closed resource must reject late registration"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn confirmation_deadline_retires_generation_and_preserves_retry_identity()
-> anyhow::Result<()> {
    use rss_transactional_messaging::transport::{PublishFailureReason, PublishFailureStage};
    let (_rabbit, url) = isolated_rabbit("rss_transport_confirm_deadline").await?;
    let route = MessageRoute::parse("rss.transport.confirm-deadline")?;
    let (_subscriber, subscriber_resource) =
        prepared_subscriber(&url, &route, "confirm-deadline-sub", true).await?;
    let (publisher, resource) = connected_publisher(&url, "confirm-deadline-pub").await?;
    let generation = publisher
        .transport_generation_for_test()
        .expect("ready generation");
    let message = envelope(&route, "confirm-deadline-message");
    let (entered, _resume) = publisher.pause_next_confirmation_for_test();
    let clock = FakeClock::new();
    let deadline =
        AbsoluteDeadline::from_timeout(&clock, Duration::from_millis(500))?.operation(&clock);
    let publishing = publisher.publish(&message, deadline);
    tokio::pin!(publishing);
    tokio::select! {
        _ = &mut publishing => anyhow::bail!("publication must reach confirm barrier"),
        ready = tokio::time::timeout(TIMEOUT, entered) => { ready??; },
    }
    assert!(
        matches!(tokio::time::timeout(Duration::from_secs(2), publishing).await?, PublishOutcome::Ambiguous(failure) if failure.stage() == PublishFailureStage::Confirm && failure.reason() == PublishFailureReason::DeadlineElapsed)
    );
    assert!(publisher.wait_until_publish_ready_for_test().await);
    assert!(
        publisher
            .transport_generation_for_test()
            .is_some_and(|new| new > generation)
    );
    publish_confirmed(&publisher, &message).await?;
    close(&resource).await?;
    close(&subscriber_resource).await?;
    Ok(())
}

async fn assert_live_consumer(
    driver: &BrokerDriver<'_>,
    route: &MessageRoute,
) -> Result<(), ConformanceError> {
    let count = driver
        .rabbit
        .broker_consumer_count(
            driver.url.rsplit('/').next().expect("fixture vhost"),
            route.as_str(),
        )
        .await
        .map_err(evidence_error)?;
    assert_eq!(count, 1, "broker must own one original consumer");
    Ok(())
}
async fn await_broker_cancel(
    driver: &BrokerDriver<'_>,
    route: &MessageRoute,
) -> Result<(), ConformanceError> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while driver
            .rabbit
            .broker_consumer_count(
                driver.url.rsplit('/').next().expect("fixture vhost"),
                route.as_str(),
            )
            .await
            .map_err(evidence_error)?
            != 0
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<(), ConformanceError>(())
    })
    .await
    .map_err(|_| ConformanceError::delivery(MessagingErrorKind::DeadlineElapsed))??;
    Ok(())
}

pub(super) async fn acknowledge(
    settlement: rss_transactional_messaging_amqp::AmqpSettlement,
    received: &MessageEnvelope<Vec<u8>>,
    subscription: &SubscriptionIdentity,
) -> Result<(), ConformanceError> {
    settlement
        .settle(
            terminal_decision(received, subscription, false)?,
            provider_deadline(),
        )
        .await
        .map_err(|e| ConformanceError::settlement(e.kind()))
}

async fn observe_cancel_successor(
    url: &str,
    subscription: &SubscriptionIdentity,
) -> Result<MessageId, ConformanceError> {
    let (replacement, replacement_resource) = prepared_subscriber(
        url,
        subscription.route(),
        "transport-cancel-replacement",
        false,
    )
    .await
    .map_err(LiveConformanceFailure::into_conformance)?;
    let mut replacement_stream = replacement
        .deliveries(subscription)
        .await
        .map_err(|e| ConformanceError::delivery(e.kind()))?;
    let delivery = next_valid_delivery(&mut replacement_stream, "successor", "invalid")
        .await
        .map_err(LiveConformanceFailure::into_conformance)?;
    let (received, settlement) = (*delivery).into_parts();
    acknowledge(settlement, &received, subscription).await?;
    close(&replacement_resource).await?;
    Ok(received.id().clone())
}

async fn cancel_and_drain(
    driver: &BrokerDriver<'_>,
    mut settlement: rss_transactional_messaging_amqp::AmqpSettlement,
    drained: &MessageEnvelope<Vec<u8>>,
    subscription: &SubscriptionIdentity,
) -> Result<(), ConformanceError> {
    assert_live_consumer(driver, subscription.route()).await?;
    let (ack_entered, ack_resume) = settlement.pause_before_settlement_for_test();
    let (cancel_entered, cancel_resume) = settlement.pause_subscription_cancel_for_test();
    cancel_entered.await.map_err(evidence_error)?;
    let settling = acknowledge(settlement, drained, subscription);
    tokio::pin!(settling);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut settling)
            .await
            .is_err(),
        "ACK cannot complete while cancel is paused"
    );
    let mut ack_entered = ack_entered;
    assert!(
        matches!(
            ack_entered.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "ACK must not enter its RPC before cancel-ok"
    );
    assert_live_consumer(driver, subscription.route()).await?;
    cancel_resume.send(()).map_err(evidence_error)?;
    tokio::select! {
        _ = &mut settling => return Err(evidence_error(())),
        entered = &mut ack_entered => entered.map_err(evidence_error)?,
    }
    // Keep ACK paused and the original stream alive: neither settlement Drop nor lapin Consumer
    // Drop can make a missing managed basic.cancel look successful.
    await_broker_cancel(driver, subscription.route()).await?;
    ack_resume.send(()).map_err(evidence_error)?;
    settling.await
}

#[tokio::test(flavor = "multi_thread")]
async fn subscriber_recovers_after_broker_connection_loss() -> anyhow::Result<()> {
    let rabbit = testkit::managed_rabbitmq().await?;
    let url = rabbit
        .vhost_url(&isolated_vhost("rss_transport_subscriber_recovery"))
        .await?;
    let route = MessageRoute::parse("rss.transport.subscriber-recovery")?;
    let (subscriber, resource) = prepared_subscriber(&url, &route, "recovering-sub", true).await?;
    let message = envelope(&route, "subscriber-recovered-message");
    let subscription = subscription_for(&message, &route);
    let mut old = subscriber.deliveries(&subscription).await?;
    rabbit
        .broker_force_close_one_connection(
            url.rsplit('/').next().expect("fixture vhost"),
            "subscriber recovery proof",
        )
        .await?;
    assert!(tokio::time::timeout(TIMEOUT, old.next()).await?.is_none());
    let mut recovered =
        tokio::time::timeout(TIMEOUT, subscriber.deliveries(&subscription)).await??;
    let (publisher, publisher_resource) = connected_publisher(&url, "recovery-publisher").await?;
    publish_confirmed(&publisher, &message).await?;
    let delivery = next_valid_delivery(&mut recovered, "recovered delivery", "invalid").await?;
    let (received, settlement) = (*delivery).into_parts();
    assert_eq!(received.id(), message.id());
    acknowledge(settlement, &received, &subscription).await?;
    close(&publisher_resource).await?;
    close(&resource).await?;
    assert!(subscriber.deliveries(&subscription).await.is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn delivery_conformance_accepts_external_broker_configuration() -> anyhow::Result<()> {
    let rabbit = testkit::managed_rabbitmq().await?;
    let url = rabbit.vhost_url("rss_transport_delivery_0").await?;
    let (base, _) = url.rsplit_once('/').expect("fixture vhost");
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "transport::delivery_transport_conformance",
            "--nocapture",
        ])
        .env("RSS_AMQP_TEST_URL", base)
        .kill_on_drop(true)
        .spawn()?;
    let status = tokio::time::timeout(Duration::from_secs(90), child.wait()).await??;
    anyhow::ensure!(status.success(), "external broker conformance failed");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn subscriber_recovery_cancellation_and_shutdown_fence_installation() -> anyhow::Result<()> {
    let rabbit = testkit::managed_rabbitmq().await?;
    let vhost = isolated_vhost("rss_transport_recovery_fence");
    let url = rabbit.vhost_url(&vhost).await?;
    let route = MessageRoute::parse("rss.transport.recovery-fence")?;
    let (subscriber, resource) = prepared_subscriber(&url, &route, "fenced-sub", true).await?;
    let message = envelope(&route, "recovery-fence");
    let subscription = subscription_for(&message, &route);
    let mut old = subscriber.deliveries(&subscription).await?;
    rabbit
        .broker_force_close_one_connection(&vhost, "recovery fence proof")
        .await?;
    assert!(tokio::time::timeout(TIMEOUT, old.next()).await?.is_none());
    let (entered, resume) = subscriber.pause_next_recovery_installation_for_test();
    let mut first = Box::pin(subscriber.deliveries(&subscription));
    tokio::select! {
        result = &mut first => anyhow::bail!("recovery completed before barrier: {}", result.is_ok()),
        result = tokio::time::timeout(TIMEOUT, entered) => { result??; }
    }
    let mut waiter = Box::pin(subscriber.deliveries(&subscription));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut waiter)
            .await
            .is_err(),
        "replacement must be single-flight"
    );
    drop(first);
    drop(resume);
    // Cancelling the lock owner releases the lock and retires its uninstalled connection.
    let (entered, resume) = subscriber.pause_next_recovery_installation_for_test();
    tokio::select! {
        result = &mut waiter => anyhow::bail!("waiter completed before barrier: {}", result.is_ok()),
        result = tokio::time::timeout(TIMEOUT, entered) => { result??; }
    }
    close(&resource).await?;
    drop(resume);
    let result = tokio::time::timeout(TIMEOUT, waiter).await?;
    assert!(matches!(result, Err(error) if error.kind() == MessagingErrorKind::Permanent));
    assert!(subscriber.deliveries(&subscription).await.is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn subscriber_never_provisions_a_missing_queue() -> anyhow::Result<()> {
    let rabbit = testkit::managed_rabbitmq().await?;
    let url = rabbit
        .vhost_url(&isolated_vhost("rss_external_topology"))
        .await?;
    let (subscriber, resource) = AmqpSubscriber::connect_for_test(
        &AmqpSubscriberEndpoint::for_test(&url)?,
        "external-topology",
        TIMEOUT,
    )
    .await?;
    let route = MessageRoute::parse("rss.transport.not-provisioned")?;
    let subscription = subscription_for(&envelope(&route, "missing-queue"), &route);
    let result = subscriber.deliveries(&subscription).await;
    assert!(
        result.is_err(),
        "production delivery must not create an absent broker queue"
    );
    close(&resource).await?;
    Ok(())
}
