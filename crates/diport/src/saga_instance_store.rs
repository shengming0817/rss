//! `SagaInstanceStore` —— tenant-scoped saga instance + lease/CAS DI port.
//!
//! This port intentionally exposes only direct `run`/`resume` support: register one instance,
//! acquire/refresh/release a lease, and mark durable status. It is not a worker queue or listing
//! API.

use std::time::Duration;

use dynosaur::dynosaur;

use consistency::{
    SagaInstanceRecord, SagaInstanceRef, SagaInstanceStatus, SagaLease, SagaLeaseOutcome,
};

use crate::redacted::RedactedSource;

/// saga instance store operation failed.
#[derive(Debug, thiserror::Error)]
#[error("saga instance store operation failed")]
pub struct SagaInstanceStoreError {
    #[source]
    source: RedactedSource,
}

impl SagaInstanceStoreError {
    /// Wrap an adapter error without exposing its Display/debug contents through this public error.
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

/// Registration request for a saga instance row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaInstanceRegistration {
    instance: SagaInstanceRef,
    owner: String,
    contract_id: String,
}

/// Registration validation error.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaInstanceRegistrationError {
    /// Owner was empty or blank.
    #[error("saga instance owner is empty")]
    EmptyOwner,
    /// Contract id was empty or blank.
    #[error("saga instance contract id is empty")]
    EmptyContractId,
}

impl SagaInstanceRegistration {
    /// Build a validated registration request.
    pub fn new(
        instance: SagaInstanceRef,
        owner: impl Into<String>,
        contract_id: impl Into<String>,
    ) -> Result<Self, SagaInstanceRegistrationError> {
        let owner = owner.into();
        if owner.trim().is_empty() {
            return Err(SagaInstanceRegistrationError::EmptyOwner);
        }
        let contract_id = contract_id.into();
        if contract_id.trim().is_empty() {
            return Err(SagaInstanceRegistrationError::EmptyContractId);
        }
        Ok(Self {
            instance,
            owner,
            contract_id,
        })
    }

    /// Tenant-scoped instance identity.
    pub fn instance(&self) -> SagaInstanceRef {
        self.instance
    }

    /// Saga owner/domain.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Contract id.
    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }
}

/// saga instance store DI port.
#[trait_variant::make(SagaInstanceStore: Send)]
#[dynosaur(pub DynSagaInstanceStore = dyn(box) SagaInstanceStore, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: Send variant + dynosaur wrapper follow the async DI port pattern documented in lib.rs.
pub trait SagaInstanceStoreLocal {
    /// Register an instance if absent. Implementations must not overwrite owner/contract for an
    /// existing instance.
    async fn register(
        &self,
        registration: SagaInstanceRegistration,
    ) -> Result<SagaInstanceRecord, SagaInstanceStoreError>;

    /// Read one instance row.
    async fn get(
        &self,
        instance: &SagaInstanceRef,
    ) -> Result<Option<SagaInstanceRecord>, SagaInstanceStoreError>;

    /// Acquire a free or expired lease. `None` means another holder still owns it.
    async fn acquire_lease(
        &self,
        instance: &SagaInstanceRef,
        holder_id: &str,
        ttl: Duration,
    ) -> Result<Option<SagaLease>, SagaInstanceStoreError>;

    /// Extend a held lease by token+epoch CAS.
    async fn extend_lease(
        &self,
        lease: &SagaLease,
        ttl: Duration,
    ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError>;

    /// Release a held lease by token+epoch CAS.
    async fn release_lease(
        &self,
        lease: &SagaLease,
    ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError>;

    /// Mark durable instance status by token+epoch CAS.
    async fn mark_status(
        &self,
        lease: &SagaLease,
        status: SagaInstanceStatus,
    ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError>;

    /// Asynchronously release provider resources.
    async fn shutdown(&self) -> Result<(), SagaInstanceStoreError>;
}

#[cfg(test)]
mod smoke {
    use super::{
        DynSagaInstanceStore, SagaInstanceRegistration, SagaInstanceStore, SagaInstanceStoreError,
    };
    use consistency::{
        SagaId, SagaInstanceRecord, SagaInstanceRef, SagaInstanceStatus, SagaLease,
        SagaLeaseOutcome,
    };
    use std::time::Duration;

    struct NoopStore;

    impl SagaInstanceStore for NoopStore {
        async fn register(
            &self,
            registration: SagaInstanceRegistration,
        ) -> Result<SagaInstanceRecord, SagaInstanceStoreError> {
            Ok(SagaInstanceRecord::new(
                registration.instance(),
                SagaInstanceStatus::Ready,
            ))
        }

        async fn get(
            &self,
            _instance: &SagaInstanceRef,
        ) -> Result<Option<SagaInstanceRecord>, SagaInstanceStoreError> {
            Ok(None)
        }

        async fn acquire_lease(
            &self,
            _instance: &SagaInstanceRef,
            _holder_id: &str,
            _ttl: Duration,
        ) -> Result<Option<SagaLease>, SagaInstanceStoreError> {
            Ok(None)
        }

        async fn extend_lease(
            &self,
            _lease: &SagaLease,
            _ttl: Duration,
        ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError> {
            Ok(SagaLeaseOutcome::Lost)
        }

        async fn release_lease(
            &self,
            _lease: &SagaLease,
        ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError> {
            Ok(SagaLeaseOutcome::Lost)
        }

        async fn mark_status(
            &self,
            _lease: &SagaLease,
            _status: SagaInstanceStatus,
        ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError> {
            Ok(SagaLeaseOutcome::Lost)
        }

        async fn shutdown(&self) -> Result<(), SagaInstanceStoreError> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn saga_instance_store_is_dyn_injectable() {
        let store: Box<DynSagaInstanceStore> = DynSagaInstanceStore::new_box(NoopStore);
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let instance =
            SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::from_u128(1632))).unwrap();
        let registration =
            SagaInstanceRegistration::new(instance, "billing", "billing.checkout").unwrap();
        let joined = tokio::spawn(async move {
            store.register(registration).await.is_ok()
                && store.get(&instance).await.is_ok()
                && store
                    .acquire_lease(&instance, "runner-a", Duration::from_secs(30))
                    .await
                    .is_ok()
                && store.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }
}

#[cfg(test)]
mod error_redaction {
    use super::SagaInstanceStoreError;

    #[test]
    fn error_debug_redacts_source() {
        let secret = std::io::Error::other("postgres://user:hunter2@db.internal:5432/rss");
        assert!(format!("{secret:?}").contains("hunter2"), "前提失效");
        let err = SagaInstanceStoreError::new(secret);
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("hunter2") && !rendered.contains("postgres://"),
            "Debug 泄漏 source: {rendered}"
        );
    }
}
