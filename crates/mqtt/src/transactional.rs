//! Protocol capabilities stay private behind core-issued transaction decisions.
//! ref: rumqtt client.rs@aa7a694f9b76b17d4c31200cf73d79616acae9b3 (manual ACK).
use crate::{ConnectionState, MqttError, MqttReceiver, RejectReason, Settlement, codec};
use rss_transactional_messaging::{
    error::{MessagingError, MessagingErrorKind as Kind},
    message::SubscriptionIdentity,
    policy::OperationDeadline,
    transaction::{EnvelopeValidationFailure, SettlementDecision, SettlementKind},
    transport::{
        Delivery, DeliverySettlement, DeliverySource, IncomingDelivery, ManagedDeliveryStream,
    },
};
use std::{
    pin::Pin,
    sync::{Arc, Mutex, atomic::Ordering},
};

/// One exclusive MQTT session adapted to one exact RSS subscription.
///
/// Construction consumes the raw receiver. One stream leases it at a time. Dropping a stream
/// retires the connection and returns admission to this source; re-establishment waits for the
/// replacement generation. Dropping the last source/stream owner closes the receiver's driver.
/// Decoding is not authentication: use the normal core ingress validator and transaction pipeline.
pub struct MqttDeliverySource {
    inner: Arc<SourceInner>,
    subscription: SubscriptionIdentity,
    filter: String,
}
struct Admission {
    receiver: MqttReceiver,
    retired: Option<u64>,
}
struct SourceInner {
    admission: Mutex<Option<Admission>>,
    shared: Arc<crate::handles::Shared>,
}
struct StreamLease {
    admission: Option<Admission>,
    inner: Arc<SourceInner>,
}
impl StreamLease {
    async fn ready(&self) -> Result<(), MessagingError> {
        let retired = self.admission.as_ref().and_then(|a| a.retired);
        let Some(retired) = retired else {
            return Ok(());
        };
        let mut state = self.inner.shared.state.subscribe();
        loop {
            match *state.borrow_and_update() {
                ConnectionState::Failed(error) => {
                    return Err(MessagingError::new(Kind::Permanent, error));
                }
                ConnectionState::Closed => return Err(messaging(MqttError::Closed)),
                ConnectionState::Ready { generation, .. } if generation > retired => return Ok(()),
                _ => {}
            }
            state
                .changed()
                .await
                .map_err(|_| messaging(MqttError::Closed))?;
        }
    }
    async fn next(&mut self) -> Result<Option<crate::Delivery>, MqttError> {
        self.admission
            .as_mut()
            .ok_or(MqttError::Closed)?
            .receiver
            .next()
            .await
    }
}
impl Drop for StreamLease {
    fn drop(&mut self) {
        if let Some(mut admission) = self.admission.take() {
            let generation = self.inner.shared.generation.load(Ordering::Acquire);
            self.inner.shared.abandon(generation);
            admission.retired = Some(generation);
            // Poison can only occur in trusted synchronous admission ownership code. Restore the
            // sole receiver so resource Drop still closes it; never mint a broker acknowledgement.
            *self
                .inner
                .admission
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(admission);
        }
    }
}
impl MqttDeliverySource {
    /// Consume exclusive admission authority and derive the filter from the actual connection.
    pub fn new(
        receiver: MqttReceiver,
        subscription: SubscriptionIdentity,
    ) -> Result<Self, MqttError> {
        let [filter] = receiver.shared.subscriptions.as_slice() else {
            return Err(MqttError::InvalidConfig);
        };
        let filter = filter.clone();
        let shared = receiver.shared.clone();
        Ok(Self {
            inner: Arc::new(SourceInner {
                shared,
                admission: Mutex::new(Some(Admission {
                    receiver,
                    retired: None,
                })),
            }),
            subscription,
            filter,
        })
    }
    /// Observe the retained closed diagnostic, including terminal failures encountered by a stream.
    pub fn connection_state(&self) -> tokio::sync::watch::Receiver<ConnectionState> {
        self.inner.shared.state.subscribe()
    }
}

/// Opaque protocol authority. Only a core-issued decision can authorize success or rejection.
/// INVARIANT: MQTT-TRANSACTION-SETTLEMENT-01: raw settlement is never extractable.
///
/// ```compile_fail
/// use rss_mqtt::MqttTransactionSettlement;
/// use rss_transactional_messaging::policy::OperationDeadline;
/// async fn bypass(value: MqttTransactionSettlement, deadline: OperationDeadline) {
///     value.ack_after_durable_handoff(deadline).await;
/// }
/// ```
pub struct MqttTransactionSettlement(Settlement);
impl DeliverySettlement for MqttTransactionSettlement {
    async fn settle(
        self,
        decision: SettlementDecision,
        deadline: OperationDeadline,
    ) -> Result<(), MessagingError> {
        match decision.kind() {
            SettlementKind::Acknowledge => self
                .0
                .ack_after_durable_handoff(deadline)
                .await
                .map_err(messaging),
            SettlementKind::Reject => self
                .0
                .reject_terminal(RejectReason::Unspecified, deadline)
                .await
                .map_err(messaging),
            SettlementKind::Requeue => self.retire(deadline),
        }
    }
    async fn abandon(self, deadline: OperationDeadline) -> Result<(), MessagingError> {
        self.retire(deadline)
    }
}
impl MqttTransactionSettlement {
    fn retire(self, deadline: OperationDeadline) -> Result<(), MessagingError> {
        let shared = self
            .0
            .shared
            .upgrade()
            .ok_or_else(|| messaging(MqttError::Closed))?;
        let cutoff = shared.deadline(deadline.timeout()).map_err(messaging)?;
        if cutoff.remaining(&shared.clock).is_zero() {
            return Err(messaging(MqttError::DeadlineElapsed));
        }
        if shared.generation.load(Ordering::Acquire) != self.0.generation {
            return Err(messaging(MqttError::StaleDelivery));
        }
        if shared.closing.load(Ordering::Acquire) {
            return Err(messaging(MqttError::Closed));
        }
        // Ok means the synchronous retirement request was recorded, not broker redelivery.
        // Every failure also drops raw authority, conservatively requesting retirement.
        self.0.abandon();
        Ok(())
    }
}

/// Managed stream item: decoded but unverified envelope, or explicit decode rejection authority.
pub type MqttDeliveries = Pin<
    Box<dyn futures::Stream<Item = IncomingDelivery<Vec<u8>, MqttTransactionSettlement>> + Send>,
>;
impl DeliverySource<Vec<u8>> for MqttDeliverySource {
    type Settlement = MqttTransactionSettlement;
    type Deliveries = MqttDeliveries;
    async fn deliveries(
        &self,
        subscription: &SubscriptionIdentity,
    ) -> Result<ManagedDeliveryStream<Self::Deliveries>, MessagingError> {
        if subscription != &self.subscription {
            return Err(messaging(MqttError::InvalidConfig));
        }
        match *self.inner.shared.state.borrow() {
            ConnectionState::Failed(error) => {
                return Err(MessagingError::new(Kind::Permanent, error));
            }
            ConnectionState::Closed => return Err(messaging(MqttError::Closed)),
            _ => {}
        }
        let admission = self
            .inner
            .admission
            .lock()
            .map_err(|_| messaging(MqttError::Closed))?
            .take()
            .ok_or_else(|| MessagingError::new(Kind::Conflict, MqttError::InvalidConfig))?;
        let lease = StreamLease {
            admission: Some(admission),
            inner: self.inner.clone(),
        };
        lease.ready().await?;
        let stream = futures::stream::unfold(
            (lease, self.subscription.clone(), self.filter.clone()),
            |(mut lease, subscription, filter)| async move {
                let delivery = match lease.next().await {
                    Ok(Some(value)) => value,
                    Ok(None) | Err(_) => return None,
                };
                let (publish, settlement) = delivery.into_parts();
                let decoded = std::str::from_utf8(&publish.topic)
                    .ok()
                    .filter(|topic| rumqttc::mqttbytes::matches(topic, &filter))
                    .ok_or(EnvelopeValidationFailure::UnsupportedContract)
                    .and_then(|_| codec::decode(&publish, &subscription));
                let settlement = MqttTransactionSettlement(settlement);
                let incoming = match decoded {
                    Ok(message) => {
                        IncomingDelivery::Valid(Box::new(Delivery::new(message, settlement)))
                    }
                    Err(reason) => IncomingDelivery::invalid_from_provider(reason, settlement),
                };
                Some((incoming, (lease, subscription, filter)))
            },
        );
        Ok(ManagedDeliveryStream::from_provider(
            Box::pin(stream) as MqttDeliveries
        ))
    }
}
#[deny(clippy::wildcard_enum_match_arm)]
fn messaging(error: MqttError) -> MessagingError {
    let kind = match error {
        MqttError::DeadlineElapsed => Kind::DeadlineElapsed,
        MqttError::StaleDelivery => Kind::OwnershipLost,
        MqttError::Unavailable
        | MqttError::ConnectionLost
        | MqttError::BrokerBusy
        | MqttError::SettlementUnknown => Kind::Transient,
        MqttError::InvalidConfig
        | MqttError::InvalidMessage
        | MqttError::Closed
        | MqttError::Authentication
        | MqttError::Protocol
        | MqttError::SubscriptionRejected
        | MqttError::SessionState
        | MqttError::SessionStore
        | MqttError::UnsupportedQos
        | MqttError::ReceiveCapacity => Kind::Permanent,
    };
    MessagingError::new(kind, error)
}
