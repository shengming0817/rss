//! `SagaInstanceStore` —— tenant-scoped saga instance + lease/CAS DI port.
//!
//! The same port also exposes the narrow runnable listing used by saga workers. Listing is
//! advisory: execution still goes through lease/runtime-lock CAS before any state transition.

use std::num::NonZeroUsize;
use std::time::Duration;

use dynosaur::dynosaur;

use consistency::{
    SagaInstanceRecord, SagaInstanceRef, SagaInstanceStatus, SagaLease, SagaLeaseOutcome,
};

use crate::redacted::RedactedSource;

/// Saga contract id newtype used by worker discovery and instance registration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SagaContractId(String);

/// Saga contract id parse error.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaContractIdError {
    /// Contract id was empty.
    #[error("saga contract id is empty")]
    Empty,
    /// Contract id does not use canonical dotted grammar.
    #[error("saga contract id is not a canonical dotted name")]
    Format,
}

impl SagaContractId {
    /// Parse a generated saga contract id.
    pub fn parse(raw: &str) -> Result<Self, SagaContractIdError> {
        if raw.is_empty() {
            return Err(SagaContractIdError::Empty);
        }
        if !is_canonical_dotted(raw) {
            return Err(SagaContractIdError::Format);
        }
        Ok(Self(raw.to_string()))
    }

    /// Borrow the canonical contract id string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Saga worker identity: owner + contract id, constructed once and passed through worker/store
/// APIs as a single value so the two strings cannot drift independently.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SagaWorkerIdentity {
    owner: String,
    contract_id: SagaContractId,
}

/// Saga worker identity validation error.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaWorkerIdentityError {
    /// Owner was empty or blank.
    #[error("saga worker owner is empty")]
    EmptyOwner,
}

impl SagaWorkerIdentity {
    /// Build a validated saga worker identity.
    pub fn new(
        owner: impl Into<String>,
        contract_id: SagaContractId,
    ) -> Result<Self, SagaWorkerIdentityError> {
        let owner = owner.into();
        if owner.trim().is_empty() {
            return Err(SagaWorkerIdentityError::EmptyOwner);
        }
        Ok(Self { owner, contract_id })
    }

    /// Saga owner/domain.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Saga contract id.
    pub fn contract_id(&self) -> &SagaContractId {
        &self.contract_id
    }
}

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
    identity: SagaWorkerIdentity,
}

impl SagaInstanceRegistration {
    /// Build a validated registration request.
    pub fn new(instance: SagaInstanceRef, identity: SagaWorkerIdentity) -> Self {
        Self { instance, identity }
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
}

/// Runnable saga instance returned by worker discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SagaRunnableInstance {
    instance: SagaInstanceRef,
    status: SagaInstanceStatus,
}

/// Runnable instance validation error.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaRunnableInstanceError {
    /// Terminal or degraded statuses must not enter worker discovery.
    #[error("saga instance status is not runnable")]
    NotRunnable,
}

impl SagaRunnableInstance {
    /// Build a runnable instance record, rejecting terminal/degraded statuses.
    pub fn new(
        instance: SagaInstanceRef,
        status: SagaInstanceStatus,
    ) -> Result<Self, SagaRunnableInstanceError> {
        if !is_runnable_status(status) {
            return Err(SagaRunnableInstanceError::NotRunnable);
        }
        Ok(Self { instance, status })
    }

    /// Tenant-scoped instance identity.
    pub fn instance(&self) -> SagaInstanceRef {
        self.instance
    }

    /// Durable status observed when listed.
    pub fn status(&self) -> SagaInstanceStatus {
        self.status
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

fn is_canonical_dotted(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|seg| {
            matches!(seg.bytes().next(), Some(b) if b.is_ascii_lowercase())
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

#[cfg(test)]
mod smoke {
    use super::{
        DynSagaInstanceStore, DynSagaTenantSource, SagaContractId, SagaInstanceRegistration,
        SagaInstanceStore, SagaInstanceStoreError, SagaRunnableInstance, SagaTenantSource,
        SagaWorkerIdentity,
    };
    use consistency::{
        SagaId, SagaInstanceRecord, SagaInstanceRef, SagaInstanceStatus, SagaLease,
        SagaLeaseOutcome,
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
        let registration = SagaInstanceRegistration::new(instance, identity.clone());
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
