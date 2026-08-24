//! Assembly-private durable device-ingress settlement boundary.

#[cfg(test)]
use std::future::Future;

use identity::ports::device_certificate::{ArtifactEligibility, DeviceIngressDomainOutcome};

/// Provider-confirmed domain outcome paired with the provider's move-only commit proof.
///
/// The constructor is assembly-private. Runnable wiring may call it only while mapping the
/// concrete PostgreSQL commit/readback result; tests use a private proof below.
pub(crate) struct ProviderCommittedDeviceIngress<P> {
    outcome: DeviceIngressDomainOutcome,
    proof: P,
}

impl<P> ProviderCommittedDeviceIngress<P> {
    const fn from_provider(outcome: DeviceIngressDomainOutcome, proof: P) -> Self {
        Self { outcome, proof }
    }
}

/// Map the concrete PostgreSQL commit/readback result into the private settlement runner.
///
/// No generic repository result enters this function: the opaque proof's private constructor keeps
/// the runtime path tied to PostgreSQL's confirmed commit or exact readback.
fn confirm_postgres_device_ingress<E: ArtifactEligibility>(
    pending: identity::ports::device_certificate::PendingDeviceIngress,
    committed: postgres::PgDeviceIngressCommit<E>,
) -> Result<
    ProviderCommittedDeviceIngress<postgres::PgDeviceIngressCommitProof<E>>,
    identity::ports::device_certificate::DeviceIngressReceiptMismatch,
> {
    let (receipt, proof) = committed.into_parts();
    let outcome = pending.verify_receipt(receipt)?;
    Ok(ProviderCommittedDeviceIngress::from_provider(
        outcome, proof,
    ))
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DeviceIngressCompositionError<E> {
    Settlement(E),
}

/// Closed failure surface for durable MQTT settlement.
#[derive(Debug, PartialEq, Eq)]
pub enum PostgresDeviceIngressSettlementError {
    ReceiptMismatch(identity::ports::device_certificate::DeviceIngressReceiptMismatch),
    Transport(mqtt::MqttSessionError),
}

enum DeviceIngressTerminalProof<E: ArtifactEligibility> {
    Durable(postgres::PgDeviceIngressCommitProof<E>),
    Unaddressable(identity::ports::device_certificate::UnaddressableDeviceIngress),
}

struct DeviceIngressTerminalAuthority<T, E: ArtifactEligibility> {
    outcome: T,
    proof: DeviceIngressTerminalProof<E>,
}

impl std::fmt::Display for PostgresDeviceIngressSettlementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReceiptMismatch(_) => f.write_str("device ingress receipt mismatch"),
            Self::Transport(_) => f.write_str("device ingress transport settlement failed"),
        }
    }
}

impl std::error::Error for PostgresDeviceIngressSettlementError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReceiptMismatch(error) => Some(error),
            Self::Transport(error) => Some(error),
        }
    }
}

/// Consume the exact PostgreSQL commit proof and settle one authenticated MQTT delivery.
///
/// A generic repository receipt cannot enter this function. Failed settlement consumes both the
/// proof and delivery; broker redelivery must obtain a fresh exact-readback proof before retrying.
pub async fn acknowledge_postgres_device_ingress<E: ArtifactEligibility>(
    delivery: mqtt::AuthenticatedDeviceDelivery,
    pending: identity::ports::device_certificate::PendingDeviceIngress,
    committed: postgres::PgDeviceIngressCommit<E>,
) -> Result<DeviceIngressDomainOutcome, PostgresDeviceIngressSettlementError> {
    let verified = confirm_postgres_device_ingress(pending, committed)
        .map_err(PostgresDeviceIngressSettlementError::ReceiptMismatch)?;
    let ProviderCommittedDeviceIngress { outcome, proof } = verified;
    settle_terminal_delivery(
        delivery,
        DeviceIngressTerminalAuthority::<_, E> {
            outcome,
            proof: DeviceIngressTerminalProof::Durable(proof),
        },
    )
    .map_err(PostgresDeviceIngressSettlementError::Transport)
}

/// Settle an authenticated delivery that cannot carry a durable envelope identity.
pub(crate) fn acknowledge_unaddressable_device_ingress(
    delivery: mqtt::AuthenticatedDeviceDelivery,
    poison: identity::ports::device_certificate::UnaddressableDeviceIngress,
) -> Result<(), mqtt::MqttSessionError> {
    settle_terminal_delivery(
        delivery,
        DeviceIngressTerminalAuthority::<_, identity::ports::device_certificate::DraftEligibility> {
            outcome: (),
            proof: DeviceIngressTerminalProof::Unaddressable(poison),
        },
    )
    .map(|_| ())
}

fn settle_terminal_delivery<T, E: ArtifactEligibility>(
    delivery: mqtt::AuthenticatedDeviceDelivery,
    authority: DeviceIngressTerminalAuthority<T, E>,
) -> Result<T, mqtt::MqttSessionError> {
    let DeviceIngressTerminalAuthority { outcome, proof } = authority;
    match proof {
        DeviceIngressTerminalProof::Durable(proof) => {
            let _consumed_postgres_proof = proof;
        }
        DeviceIngressTerminalProof::Unaddressable(poison) => {
            let _consumed_identity_classification = poison;
        }
    }
    delivery.settle_terminal()?;
    Ok(outcome)
}

/// Consume one provider proof and attempt transport settlement exactly once.
///
/// Settlement failure intentionally returns no reusable proof. Broker redelivery must repeat the
/// provider's exact-readback path and obtain a fresh proof for the same envelope before retrying.
#[cfg(test)]
pub(crate) async fn settle_verified_ingress<P, F, Fut, E>(
    committed: ProviderCommittedDeviceIngress<P>,
    settle: F,
) -> Result<DeviceIngressDomainOutcome, DeviceIngressCompositionError<E>>
where
    F: FnOnce(&DeviceIngressDomainOutcome, P) -> Fut,
    Fut: Future<Output = Result<(), E>>,
{
    let ProviderCommittedDeviceIngress { outcome, proof } = committed;
    settle(&outcome, proof)
        .await
        .map_err(DeviceIngressCompositionError::Settlement)?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use deviceloop::{DeviceIngressDisposition, DeviceIngressReceipt};

    fn domain_outcome() -> identity::ports::device_certificate::DeviceIngressDomainOutcome {
        struct Delivery;
        impl identity::ports::device_certificate::DeviceIngressDelivery for Delivery {
            fn tenant(&self) -> rss_request_context::TenantId {
                rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000001")
                    .expect("tenant")
            }
            fn device(&self) -> ids::DeviceId {
                ids::DeviceId::parse("00000000-0000-4000-8000-000000000002").expect("device")
            }
            fn credential_generation(&self) -> u64 {
                1
            }
            fn contract(&self) -> identity::ports::device_certificate::DeviceIngressContract {
                identity::ports::device_certificate::DeviceIngressContract::CommandAcked
            }
            fn correlation_data(&self) -> Option<&[u8]> {
                Some(b"ingress-1")
            }
            fn payload(&self) -> &[u8] {
                br#"{"deviceId":"00000000-0000-4000-8000-000000000002","commandId":"command-1","desiredGeneration":1,"fenceEpoch":2,"deviceSequence":3,"result":"received","reason":"None","observedAt":10}"#
            }
        }
        let identity::ports::device_certificate::DeviceIngressPreparation::Accepted(prepared) =
            identity::ports::device_certificate::prepare_device_ingress(&Delivery)
        else {
            panic!("prepared");
        };
        let evidence = prepared.write().evidence().clone();
        let (_, pending) = prepared.into_parts();
        let receipt = DeviceIngressReceipt::restore(
            evidence,
            DeviceIngressDisposition::Advanced,
            std::time::SystemTime::UNIX_EPOCH,
            std::time::SystemTime::UNIX_EPOCH,
        )
        .expect("receipt");
        pending.verify_receipt(receipt).expect("outcome")
    }

    #[derive(Debug, PartialEq, Eq)]
    struct AckError;

    struct TestCommitProof;

    #[tokio::test]
    async fn settlement_failure_keeps_same_envelope_replayable_until_one_success() {
        let durable_commits = AtomicUsize::new(1);
        let exact_readbacks = AtomicUsize::new(0);
        let attempts = Arc::new(AtomicUsize::new(0));
        let successes = Arc::new(AtomicUsize::new(0));

        let first_attempts = Arc::clone(&attempts);
        let first_successes = Arc::clone(&successes);
        let first = settle_verified_ingress(
            ProviderCommittedDeviceIngress::from_provider(domain_outcome(), TestCommitProof),
            move |_, TestCommitProof| async move {
                first_attempts.fetch_add(1, Ordering::SeqCst);
                let _ = first_successes;
                Err(AckError)
            },
        )
        .await;
        assert!(matches!(
            first,
            Err(DeviceIngressCompositionError::Settlement(AckError))
        ));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(successes.load(Ordering::SeqCst), 0);

        // Broker redelivery re-enters the concrete provider. The stable envelope is found through
        // exact receipt + Outbox readback, so no second business commit occurs and a fresh
        // provider proof can authorize one more settlement attempt.
        exact_readbacks.fetch_add(1, Ordering::SeqCst);
        let retry_attempts = Arc::clone(&attempts);
        let retry_successes = Arc::clone(&successes);
        let replay = settle_verified_ingress(
            ProviderCommittedDeviceIngress::from_provider(domain_outcome(), TestCommitProof),
            move |_, TestCommitProof| async move {
                retry_attempts.fetch_add(1, Ordering::SeqCst);
                retry_successes.fetch_add(1, Ordering::SeqCst);
                Ok::<_, AckError>(())
            },
        )
        .await
        .expect("same envelope replay settles");
        assert_eq!(
            replay.receipt().evidence().envelope_id().as_str(),
            "ingress-1"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(successes.load(Ordering::SeqCst), 1);
        assert_eq!(durable_commits.load(Ordering::SeqCst), 1);
        assert_eq!(exact_readbacks.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn terminal_mqtt_ack_has_one_composition_callsite() {
        let source = include_str!("device_ingress.rs");
        let call = concat!("delivery.", "settle_terminal", "()");
        assert_eq!(source.matches(call).count(), 1);
    }
}
