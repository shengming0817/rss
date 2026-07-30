//! Generated event authoring boundary.
//!
//! A generated [`generated::event::EventContract`] binds its typed payload, topology spec and fact
//! identity. [`GeneratedEventEncoder`] is the only production constructor for [`ReviewedEvent`];
//! providers can consume the result but ordinary [`consistency::EventEntry`] values cannot be
//! promoted into this capability.

use consistency::{EventEntry, EventTopic, IdemKey, OutboxPayload};
use diport::{EnvelopeCausationId, EnvelopeSubjectId, OutboxActor, OutboxEnvelopeParts};

/// Parent-message provenance minted only after the consumer envelope and tenant authority pass.
#[derive(Clone)]
pub(crate) struct VerifiedEventOrigin(EnvelopeCausationId);

impl VerifiedEventOrigin {
    pub(crate) const fn new(causation_id: EnvelopeCausationId) -> Self {
        Self(causation_id)
    }
}

tokio::task_local! {
    static VERIFIED_EVENT_ORIGIN: VerifiedEventOrigin;
}

/// Bind one verified immediate parent while its consumer handler is executing.
pub(crate) fn scope_verified_event_origin<F>(
    origin: VerifiedEventOrigin,
    future: F,
) -> impl std::future::Future<Output = F::Output>
where
    F: std::future::Future,
{
    VERIFIED_EVENT_ORIGIN.scope(origin, future)
}

fn current_verified_causation() -> Option<EnvelopeCausationId> {
    VERIFIED_EVENT_ORIGIN
        .try_with(|origin| origin.0.clone())
        .ok()
}

/// Failure while converting a generated typed payload into a reviewed durable event.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EventEncodeError {
    /// Generated topology contained an invalid event topic.
    #[error("generated event topic is invalid")]
    Topic,
    /// Scoped actor tenant differs from the event tenant.
    #[error("event actor tenant does not match event tenant")]
    ActorTenant,
    /// Generated aggregate topology could not derive a canonical partition key.
    #[error("generated event partition key is invalid")]
    PartitionKey,
    /// Typed payload serialization failed.
    #[error("generated event payload serialization failed")]
    Serialization(#[source] serde_json::Error),
}

/// One generated, encoded event whose fact and envelope identity were bound atomically.
///
/// Fields and constructors are private. Provider ports accept this capability instead of parallel
/// `EventEntry` / `OutboxEnvelopeParts` arguments, eliminating topic, contract and envelope drift.
#[derive(Clone)]
pub struct ReviewedEvent {
    entry: EventEntry,
    envelope: OutboxEnvelopeParts,
    fact: vocab::EventFactBinding,
}

impl std::fmt::Debug for ReviewedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReviewedEvent")
            .field("contract_id", &self.fact.contract().contract_id())
            .field("topic", &self.fact.topic())
            .field("payload", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ReviewedEvent {
    /// Exact generated fact authorized by this capability.
    pub const fn fact(&self) -> vocab::EventFactBinding {
        self.fact
    }

    /// Encoded outbox entry for provider inspection.
    pub const fn entry(&self) -> &EventEntry {
        &self.entry
    }

    /// Contract-bound envelope identity for provider inspection.
    pub const fn envelope(&self) -> &OutboxEnvelopeParts {
        &self.envelope
    }

    /// Consume the capability at a persistence boundary.
    pub fn into_parts(self) -> (EventEntry, OutboxEnvelopeParts, vocab::EventFactBinding) {
        (self.entry, self.envelope, self.fact)
    }
}

/// Production persistence seam for a generated and fully reviewed event.
///
/// Implementations receive the single sealed capability, never parallel raw entry/envelope
/// coordinates. In-memory demo emitters may still implement the lower-level `diport` port, but
/// durable production adapters must implement this seam.
pub trait ReviewedEventWriter: Send + Sync {
    /// Persist one reviewed event through the provider-owned durable boundary.
    fn write(
        &self,
        event: ReviewedEvent,
    ) -> impl std::future::Future<Output = Result<(), diport::OutboxEmitError>> + Send;
}

/// Stateless encoder used by generated per-event emit wrappers.
#[derive(Debug, Default, Clone, Copy)]
pub struct GeneratedEventEncoder;

impl generated::event::EventEmit for GeneratedEventEncoder {
    type Error = EventEncodeError;
    type Output = ReviewedEvent;
    type SubjectId = EnvelopeSubjectId;
    type Actor = OutboxActor;
    type IdempotencyKey = IdemKey;

    async fn emit<C>(
        &self,
        payload: &C::Payload,
        tenant: vocab::TenantId,
        subject_id: Self::SubjectId,
        actor: Self::Actor,
        idempotency_key: Self::IdempotencyKey,
    ) -> Result<Self::Output, Self::Error>
    where
        C: generated::event::EventContract,
        C::Payload: Send + Sync,
    {
        let fact = C::FACT;
        let topic = EventTopic::parse(fact.topic()).map_err(|_| EventEncodeError::Topic)?;
        crate::command::validate_actor_tenant(tenant, &actor)
            .map_err(|()| EventEncodeError::ActorTenant)?;
        let partition_key = match C::SPEC.partition_key() {
            generated::event::PartitionKeyStrategy::None => None,
            generated::event::PartitionKeyStrategy::Aggregate => Some(
                consistency::PartitionKey::parse(subject_id.as_str())
                    .map_err(|_| EventEncodeError::PartitionKey)?,
            ),
        };
        let payload = serde_json::to_vec(payload).map_err(EventEncodeError::Serialization)?;
        let entry = EventEntry::new(
            topic,
            idempotency_key,
            OutboxPayload::from_reviewed_event_bytes(payload),
        );
        let mut envelope = OutboxEnvelopeParts::new(C::SPEC.contract(), tenant, subject_id, actor);
        if let Some(partition_key) = partition_key {
            envelope = envelope.with_partition_key(partition_key);
        }
        if let Some(causation_id) = current_verified_causation() {
            envelope = envelope.with_causation_id(causation_id);
        }
        Ok(ReviewedEvent {
            entry,
            envelope,
            fact,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generated_event_rejects_scoped_actor_from_another_tenant() {
        let tenant =
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
        let other =
            vocab::TenantId::parse("00000000-0000-4000-8000-000000000abc").expect("other tenant");
        let actor = diport::OutboxActor::scoped(
            vocab::PrincipalKind::Admin,
            diport::OpaqueActorId::from_opaque("other-tenant-actor").expect("actor"),
            other,
            vocab::ScopedTenant::Tenant,
        );
        let payload = generated::event::settings_v1::SettingsConfigVersionChangedPayload {
            change_kind: generated::event::settings_v1::SettingsConfigChangeKind::Published,
            key: "app.theme".to_owned(),
            occurred_at: 1,
            source_version: None,
            tenant_id: tenant.to_string(),
            version: 1,
        };

        let result = generated::event::settings_v1::emit(
            &GeneratedEventEncoder,
            payload,
            tenant,
            diport::EnvelopeSubjectId::from_opaque("app.theme").expect("subject"),
            actor,
            IdemKey::parse("event-actor-tenant-mismatch").expect("idempotency key"),
        )
        .await;

        assert!(matches!(result, Err(EventEncodeError::ActorTenant)));
    }

    #[tokio::test]
    async fn generated_root_event_has_no_causation() {
        let tenant =
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
        let payload = generated::event::settings_v1::SettingsConfigVersionChangedPayload {
            change_kind: generated::event::settings_v1::SettingsConfigChangeKind::Published,
            key: "root.event".to_owned(),
            occurred_at: 1,
            source_version: None,
            tenant_id: tenant.to_string(),
            version: 1,
        };
        let event = generated::event::settings_v1::emit(
            &GeneratedEventEncoder,
            payload,
            tenant,
            diport::EnvelopeSubjectId::from_opaque("root.event").expect("subject"),
            diport::OutboxActor::scoped(
                vocab::PrincipalKind::Service,
                diport::OpaqueActorId::from_opaque("root-service").expect("actor"),
                tenant,
                vocab::ScopedTenant::Tenant,
            ),
            IdemKey::parse("root-event-1").expect("idempotency key"),
        )
        .await
        .expect("generated event");

        assert!(event.envelope().causation_id().is_none());
    }

    #[test]
    fn serialization_error_retains_its_source() {
        let source = serde_json::from_str::<serde_json::Value>("{")
            .expect_err("fixture must be invalid JSON");
        let error = EventEncodeError::Serialization(source);

        assert!(std::error::Error::source(&error).is_some());
    }
}
