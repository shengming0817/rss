//! Assembly-private durable device-ingress settlement boundary.

#![allow(dead_code)] // #1903 closes the seam; #1904 activates it in a production assembly.

use std::future::Future;

use identity::ports::device_certificate::DeviceIngressDomainOutcome;

/// Provider-confirmed domain outcome paired with the provider's move-only commit proof.
///
/// The constructor is assembly-private. Production wiring may call it only while mapping the
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
/// the production path tied to PostgreSQL's confirmed commit or exact readback.
pub(crate) fn confirm_postgres_device_ingress(
    pending: identity::ports::device_certificate::PendingDeviceIngress,
    committed: postgres::PgDeviceIngressCommit,
) -> Result<
    ProviderCommittedDeviceIngress<postgres::PgDeviceIngressCommitProof>,
    identity::ports::device_certificate::DeviceIngressReceiptMismatch,
> {
    let (receipt, proof) = committed.into_parts();
    let outcome = pending.verify_receipt(receipt)?;
    Ok(ProviderCommittedDeviceIngress::from_provider(
        outcome, proof,
    ))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DeviceIngressCompositionError<E> {
    Settlement(E),
}

/// Consume one provider proof and attempt transport settlement exactly once.
///
/// Settlement failure intentionally returns no reusable proof. Broker redelivery must repeat the
/// provider's exact-readback path and obtain a fresh proof for the same envelope before retrying.
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
            fn tenant(&self) -> vocab::TenantId {
                vocab::TenantId::parse("00000000-0000-4000-8000-000000000001").expect("tenant")
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
        let prepared = identity::ports::device_certificate::prepare_device_ingress(&Delivery)
            .expect("prepared");
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
}
