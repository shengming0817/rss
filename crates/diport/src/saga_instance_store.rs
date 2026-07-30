//! `SagaInstanceStore` —— tenant-scoped saga instance + lease/CAS DI port.
//!
//! The same port also exposes the narrow runnable listing used by saga workers. Listing is
//! advisory: execution still goes through lease/runtime-lock CAS before any state transition.

use std::num::NonZeroUsize;
use std::time::Duration;

use dynosaur::dynosaur;

pub use consistency::{
    SagaContractId, SagaContractIdError, SagaWorkerIdentity, SagaWorkerIdentityError,
};
use consistency::{
    SagaDefinitionIdentity, SagaInstanceRecord, SagaInstanceRef, SagaInstanceStatus, SagaLease,
    SagaLeaseOutcome,
};

use crate::redacted::RedactedSource;

/// saga instance store operation failed.
#[derive(Debug, thiserror::Error)]
#[error("saga instance store operation failed")]
pub struct SagaInstanceStoreError {
    kind: SagaInstanceStoreErrorKind,
    #[source]
    source: RedactedSource,
}

/// Stable classification for saga instance store failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaInstanceStoreErrorKind {
    /// The requested instance UUID is already pinned to another owner or definition identity.
    IdentityConflict,
    /// Adapter/backend failure whose details remain redacted.
    Backend,
}

impl SagaInstanceStoreError {
    /// Wrap an adapter error without exposing its Display/debug contents through this public error.
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind: SagaInstanceStoreErrorKind::Backend,
            source: RedactedSource::new(source),
        }
    }

    /// Construct the fail-closed conflict returned when an existing row has another identity.
    pub fn identity_conflict<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind: SagaInstanceStoreErrorKind::IdentityConflict,
            source: RedactedSource::new(source),
        }
    }

    /// Stable error classification without exposing adapter details.
    pub fn kind(&self) -> SagaInstanceStoreErrorKind {
        self.kind
    }
}

/// Registration request for a saga instance row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaInstanceRegistration {
    instance: SagaInstanceRef,
    identity: SagaWorkerIdentity,
    definition: SagaDefinitionIdentity,
}

/// Invalid saga instance registration.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaInstanceRegistrationError {
    /// Worker contract and pinned definition contract differ.
    #[error("saga worker contract does not match pinned definition")]
    DefinitionContractMismatch,
}

impl SagaInstanceRegistration {
    /// Build a validated registration request.
    pub fn new(
        instance: SagaInstanceRef,
        identity: SagaWorkerIdentity,
        definition: SagaDefinitionIdentity,
    ) -> Result<Self, SagaInstanceRegistrationError> {
        if identity.contract_id().as_str() != definition.contract_id() {
            return Err(SagaInstanceRegistrationError::DefinitionContractMismatch);
        }
        Ok(Self {
            instance,
            identity,
            definition,
        })
    }

    /// Tenant-scoped instance identity.
    pub fn instance(&self) -> SagaInstanceRef {
        self.instance
    }

    /// Saga worker identity.
    pub fn identity(&self) -> &SagaWorkerIdentity {
        &self.identity
    }

    /// Saga owner/domain.
    pub fn owner(&self) -> &str {
        self.identity.owner()
    }

    /// Contract id.
    pub fn contract_id(&self) -> &str {
        self.identity.contract_id().as_str()
    }

    /// Exact generated definition pinned for the lifetime of this instance.
    pub fn definition(&self) -> &SagaDefinitionIdentity {
        &self.definition
    }
}

/// Runnable saga instance returned by worker discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaRunnableInstance {
    instance: SagaInstanceRef,
    status: SagaInstanceStatus,
    identity: SagaWorkerIdentity,
    definition: SagaDefinitionIdentity,
}

/// Runnable instance validation error.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaRunnableInstanceError {
    /// Terminal or degraded statuses must not enter worker discovery.
    #[error("saga instance status is not runnable")]
    NotRunnable,
    /// Worker contract and pinned definition contract differ.
    #[error("saga worker contract does not match pinned definition")]
    DefinitionContractMismatch,
}

impl SagaRunnableInstance {
    /// Build a runnable instance record, rejecting terminal/degraded statuses.
    pub fn new(
        instance: SagaInstanceRef,
        status: SagaInstanceStatus,
        identity: SagaWorkerIdentity,
        definition: SagaDefinitionIdentity,
    ) -> Result<Self, SagaRunnableInstanceError> {
        if !is_runnable_status(status) {
            return Err(SagaRunnableInstanceError::NotRunnable);
        }
        if identity.contract_id().as_str() != definition.contract_id() {
            return Err(SagaRunnableInstanceError::DefinitionContractMismatch);
        }
        Ok(Self {
            instance,
            status,
            identity,
            definition,
        })
    }

    /// Tenant-scoped instance identity.
    pub fn instance(&self) -> SagaInstanceRef {
        self.instance
    }

    /// Durable status observed when listed.
    pub fn status(&self) -> SagaInstanceStatus {
        self.status
    }

    /// Exact owner + contract identity pinned for this instance.
    pub fn identity(&self) -> &SagaWorkerIdentity {
        &self.identity
    }

    /// Exact pinned definition to use for resume.
    pub fn definition(&self) -> &SagaDefinitionIdentity {
        &self.definition
    }
}

/// saga instance store DI port.
#[trait_variant::make(SagaInstanceStore: Send)]
#[dynosaur(pub DynSagaInstanceStore = dyn(box) SagaInstanceStore, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: Send variant + dynosaur wrapper follow the async DI port pattern documented in lib.rs.
pub trait SagaInstanceStoreLocal {
    /// Register an instance if absent. An existing instance is idempotent only when owner and the
    /// complete definition identity match exactly; otherwise implementations return
    /// [`SagaInstanceStoreErrorKind::IdentityConflict`].
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

    /// List runnable instances for one tenant and one saga worker identity.
    async fn list_runnable(
        &self,
        identity: &SagaWorkerIdentity,
        tenant: vocab::TenantId,
        limit: NonZeroUsize,
    ) -> Result<Vec<SagaRunnableInstance>, SagaInstanceStoreError>;

    /// Asynchronously release provider resources.
    async fn shutdown(&self) -> Result<(), SagaInstanceStoreError>;
}

/// saga worker tenant candidate source DI port.
#[trait_variant::make(SagaTenantSource: Send)]
#[dynosaur(pub DynSagaTenantSource = dyn(box) SagaTenantSource, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: Send variant + dynosaur wrapper follow the async DI port pattern documented in lib.rs.
pub trait SagaTenantSourceLocal {
    /// List candidate tenants with runnable work for one saga worker identity.
    async fn list_candidate_tenants(
        &self,
        identity: &SagaWorkerIdentity,
        limit: NonZeroUsize,
    ) -> Result<Vec<vocab::TenantId>, SagaInstanceStoreError>;
}

fn is_runnable_status(status: SagaInstanceStatus) -> bool {
    matches!(
        status,
        SagaInstanceStatus::Ready | SagaInstanceStatus::Running | SagaInstanceStatus::Compensating
    )
}

#[cfg(test)]
mod smoke {
    use super::{
        DynSagaInstanceStore, DynSagaTenantSource, SagaContractId, SagaInstanceRegistration,
        SagaInstanceStore, SagaInstanceStoreError, SagaRunnableInstance, SagaTenantSource,
        SagaWorkerIdentity,
    };
    use consistency::{
        SagaDefinitionIdentity, SagaId, SagaInstanceRecord, SagaInstanceRef, SagaInstanceStatus,
        SagaLease, SagaLeaseOutcome,
    };
    use std::num::NonZeroUsize;
    use std::time::Duration;
    use vocab::TenantId;

    struct NoopStore;

    impl SagaInstanceStore for NoopStore {
        async fn register(
            &self,
            registration: SagaInstanceRegistration,
        ) -> Result<SagaInstanceRecord, SagaInstanceStoreError> {
            SagaInstanceRecord::new(
                registration.instance(),
                SagaInstanceStatus::Ready,
                registration.identity().clone(),
                registration.definition().clone(),
            )
            .map_err(SagaInstanceStoreError::new)
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

        async fn list_runnable(
            &self,
            _identity: &SagaWorkerIdentity,
            _tenant: TenantId,
            _limit: NonZeroUsize,
        ) -> Result<Vec<SagaRunnableInstance>, SagaInstanceStoreError> {
            Ok(Vec::new())
        }

        async fn shutdown(&self) -> Result<(), SagaInstanceStoreError> {
            Ok(())
        }
    }

    struct NoopTenantSource;

    impl SagaTenantSource for NoopTenantSource {
        async fn list_candidate_tenants(
            &self,
            _identity: &SagaWorkerIdentity,
            _limit: NonZeroUsize,
        ) -> Result<Vec<TenantId>, SagaInstanceStoreError> {
            Ok(Vec::new())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn saga_instance_store_is_dyn_injectable() {
        let store: Box<DynSagaInstanceStore> = DynSagaInstanceStore::new_box(NoopStore);
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let instance =
            SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::from_u128(1632))).unwrap();
        let identity = SagaWorkerIdentity::new(
            "billing",
            SagaContractId::parse("billing.checkout").unwrap(),
        )
        .unwrap();
        let definition = SagaDefinitionIdentity::new(
            "billing.checkout",
            "v1",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        let registration =
            SagaInstanceRegistration::new(instance, identity.clone(), definition).unwrap();
        let joined = tokio::spawn(async move {
            store.register(registration).await.is_ok()
                && store.get(&instance).await.is_ok()
                && store
                    .acquire_lease(&instance, "runner-a", Duration::from_secs(30))
                    .await
                    .is_ok()
                && store
                    .list_runnable(&identity, tenant, NonZeroUsize::new(8).unwrap())
                    .await
                    .is_ok()
                && store.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn saga_tenant_source_is_dyn_injectable() {
        let source: Box<DynSagaTenantSource> = DynSagaTenantSource::new_box(NoopTenantSource);
        let identity = SagaWorkerIdentity::new(
            "billing",
            SagaContractId::parse("billing.checkout").unwrap(),
        )
        .unwrap();
        let joined = tokio::spawn(async move {
            source
                .list_candidate_tenants(&identity, NonZeroUsize::new(4).unwrap())
                .await
                .is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn saga_identity_rejects_empty_owner_and_invalid_contract() {
        assert!(
            SagaWorkerIdentity::new("", SagaContractId::parse("billing.checkout").unwrap())
                .is_err()
        );
        assert!(SagaContractId::parse("billing checkout").is_err());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn registration_rejects_worker_definition_contract_drift() {
        let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let instance =
            SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::from_u128(1632))).unwrap();
        let worker = SagaWorkerIdentity::new(
            "billing",
            SagaContractId::parse("billing.checkout").unwrap(),
        )
        .unwrap();
        let definition = SagaDefinitionIdentity::new(
            "billing.refund",
            "v1",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        assert!(SagaInstanceRegistration::new(instance, worker, definition).is_err());
    }
}

#[cfg(test)]
mod error_redaction {
    use super::{SagaInstanceStoreError, SagaInstanceStoreErrorKind};

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
        assert_eq!(err.kind(), SagaInstanceStoreErrorKind::Backend);
    }

    #[test]
    fn identity_conflict_preserves_only_the_typed_kind() {
        let secret = std::io::Error::other("definition secret");
        let err = SagaInstanceStoreError::identity_conflict(secret);
        assert_eq!(err.kind(), SagaInstanceStoreErrorKind::IdentityConflict);
        assert!(!format!("{err:?}").contains("definition secret"));
    }
}
