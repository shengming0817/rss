//! PostgreSQL saga instance store + tenant-scoped journal adapter (#1632).
//!
//! All tenant-table access goes through distinct read/write capabilities. Journal writes are fenced by the
//! instance lease token+epoch and return typed idempotency/conflict outcomes.
//!
//! ref: oxidecomputer/steno src/store.rs@5b0d1be32fb3e3047ff4e4f972b59dc52f9c89ba
//! ref: apalis-postgres migrations/20220530084123_jobs_workers.sql@5a930218b6b4128fc4c9e191cecc7cd0e1cbbbed

use std::num::NonZeroUsize;
use std::time::Duration;

use consistency::{
    SagaDefinitionIdentity, SagaId, SagaInstanceRecord, SagaInstanceRef, SagaInstanceStatus,
    SagaJournalAppendOutcome, SagaJournalAppendRecord, SagaJournalRecord, SagaJournalStatus,
    SagaLease, SagaLeaseOutcome, StepName,
};
use diport::{
    SagaContractId, SagaInstanceRegistration, SagaInstanceStore, SagaInstanceStoreError,
    SagaJournal, SagaJournalError, SagaRunnableInstance, SagaTenantSource, SagaWorkerIdentity,
};

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;
use crate::cotx::eventing::{SagaLeaseMutation, SagaRunnableRow};
use crate::cotx::{ServingReadLane, ServingWriteLane, TenantDb, infra_tenant_scope};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};
use crate::saga_candidates::PgSagaCandidateSource;

const HOLDER_ID_MAX_BYTES: usize = 256;

/// PostgreSQL saga instance store.
pub struct PgSagaInstanceStore {
    read_pool: TenantDb<ServingReadLane>,
    write_pool: TenantDb<ServingWriteLane>,
    candidate_source: PgSagaCandidateSource,
}

/// PostgreSQL saga journal adapter.
pub struct PgSagaJournal {
    read_pool: TenantDb<ServingReadLane>,
    write_pool: TenantDb<ServingWriteLane>,
}

#[cfg(all(test, feature = "integration"))]
impl PgStore {
    /// Construct the tenant-scoped saga instance store.
    pub(crate) fn saga_instance_store(&self) -> PgSagaInstanceStore {
        PgSagaInstanceStore {
            read_pool: TenantDb::<ServingReadLane>::from_unverified_for_test(self),
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(self),
            candidate_source: PgSagaCandidateSource::from_unverified_for_test(self),
        }
    }

    /// Construct the tenant-scoped saga journal.
    pub(crate) fn saga_journal(&self) -> PgSagaJournal {
        PgSagaJournal {
            read_pool: TenantDb::<ServingReadLane>::from_unverified_for_test(self),
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(self),
        }
    }
}

impl PgSagaInstanceStore {
    pub(crate) fn new(reader: &VerifiedPgReadStore, writer: &VerifiedPgWriteStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::new(reader),
            write_pool: TenantDb::<ServingWriteLane>::new(writer),
            candidate_source: PgSagaCandidateSource::new(writer),
        }
    }
}

impl PgSagaJournal {
    pub(crate) fn new(reader: &VerifiedPgReadStore, writer: &VerifiedPgWriteStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::new(reader),
            write_pool: TenantDb::<ServingWriteLane>::new(writer),
        }
    }
}

impl SagaInstanceStore for PgSagaInstanceStore {
    async fn register(
        &self,
        registration: SagaInstanceRegistration,
    ) -> Result<SagaInstanceRecord, SagaInstanceStoreError> {
        let fields = RegistrationFields::from(registration);
        self.write_pool
            .saga_write(
                infra_tenant_scope(fields.instance.tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        tx.saga_register_instance(&fields)
                            .await
                            .map_err(SagaInstanceStoreError::new)?;
                        let row = tx
                            .saga_load_instance(&InstanceFields::from(fields.instance))
                            .await
                            .map_err(SagaInstanceStoreError::new)?;
                        let identity = parse_worker_identity(&row.owner, &row.contract_id)?;
                        let definition = parse_definition_identity(
                            &row.contract_id,
                            &row.definition_version,
                            &row.definition_schema_digest,
                            &row.action_registry_generation,
                        )?;
                        if identity != fields.identity || definition != fields.definition {
                            return Err(SagaInstanceStoreError::identity_conflict(InvariantError(
                                "saga instance definition identity conflict",
                            )));
                        }
                        let status = parse_instance_status(&row.status)?;
                        SagaInstanceRecord::new(fields.instance, status, identity, definition)
                            .map_err(SagaInstanceStoreError::new)
                    })
                },
                SagaInstanceStoreError::new,
            )
            .await
    }

    async fn get(
        &self,
        instance: &SagaInstanceRef,
    ) -> Result<Option<SagaInstanceRecord>, SagaInstanceStoreError> {
        let fields = InstanceFields::from(*instance);
        self.read_pool
            .saga_read_map(
                infra_tenant_scope(fields.instance.tenant()),
                move |mut conn| {
                    Box::pin(async move {
                        let row = conn
                            .saga_get_instance(&fields)
                            .await
                            .map_err(SagaInstanceStoreError::new)?;
                        row.map(|row| {
                            let identity = parse_worker_identity(&row.owner, &row.contract_id)?;
                            let definition = parse_definition_identity(
                                &row.contract_id,
                                &row.definition_version,
                                &row.definition_schema_digest,
                                &row.action_registry_generation,
                            )?;
                            let status = parse_instance_status(&row.status)?;
                            SagaInstanceRecord::new(fields.instance, status, identity, definition)
                                .map_err(SagaInstanceStoreError::new)
                        })
                        .transpose()
                    })
                },
                SagaInstanceStoreError::new,
            )
            .await
    }

    async fn acquire_lease(
        &self,
        instance: &SagaInstanceRef,
        holder_id: &str,
        ttl: Duration,
    ) -> Result<Option<SagaLease>, SagaInstanceStoreError> {
        validate_holder_id(holder_id)?;
        let fields = InstanceFields::from(*instance);
        let holder_id = holder_id.to_string();
        let ttl_secs = duration_secs(ttl).map_err(SagaInstanceStoreError::new)?;
        self.write_pool
            .saga_write(
                infra_tenant_scope(fields.instance.tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        let row = tx
                            .saga_acquire_lease(&fields, &holder_id, ttl_secs)
                            .await
                            .map_err(SagaInstanceStoreError::new)?;
                        row.map(|row| {
                            lease_from_row(fields.instance, holder_id, row.lease_token, row.epoch)
                                .map_err(SagaInstanceStoreError::new)
                        })
                        .transpose()
                    })
                },
                SagaInstanceStoreError::new,
            )
            .await
    }

    async fn extend_lease(
        &self,
        lease: &SagaLease,
        ttl: Duration,
    ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError> {
        let ttl_secs = duration_secs(ttl).map_err(SagaInstanceStoreError::new)?;
        self.cas_lease(lease, Some(ttl_secs), None).await
    }

    async fn release_lease(
        &self,
        lease: &SagaLease,
    ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError> {
        self.cas_lease(lease, None, Some("release")).await
    }

    async fn mark_status(
        &self,
        lease: &SagaLease,
        status: SagaInstanceStatus,
    ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError> {
        self.cas_lease(lease, None, Some(status.as_str())).await
    }

    async fn list_runnable(
        &self,
        identity: &SagaWorkerIdentity,
        tenant: vocab::TenantId,
        limit: NonZeroUsize,
    ) -> Result<Vec<SagaRunnableInstance>, SagaInstanceStoreError> {
        let owner = identity.owner().to_string();
        let contract_id = identity.contract_id().as_str().to_string();
        let limit = i64::try_from(limit.get()).map_err(SagaInstanceStoreError::new)?;
        self.read_pool
            .saga_read_map(
                infra_tenant_scope(tenant),
                move |mut conn| {
                    Box::pin(async move {
                        let rows = conn
                            .saga_list_runnable(&owner, &contract_id, limit)
                            .await
                            .map_err(SagaInstanceStoreError::new)?;
                        rows.into_iter()
                            .map(|row| runnable_from_row(tenant, row))
                            .collect()
                    })
                },
                SagaInstanceStoreError::new,
            )
            .await
    }

    async fn shutdown(&self) -> Result<(), SagaInstanceStoreError> {
        Ok(())
    }
}

impl SagaTenantSource for PgSagaInstanceStore {
    async fn list_candidate_tenants(
        &self,
        identity: &SagaWorkerIdentity,
        limit: NonZeroUsize,
    ) -> Result<Vec<vocab::TenantId>, SagaInstanceStoreError> {
        self.candidate_source.list(identity, limit).await
    }
}

impl PgSagaInstanceStore {
    async fn cas_lease(
        &self,
        lease: &SagaLease,
        extend_ttl_secs: Option<i64>,
        mark_status: Option<&'static str>,
    ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError> {
        let fields = LeaseFields::from(lease).map_err(SagaInstanceStoreError::new)?;
        self.write_pool
            .saga_write(
                infra_tenant_scope(fields.instance.tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        let mutation = if let Some(ttl_secs) = extend_ttl_secs {
                            SagaLeaseMutation::Extend { ttl_secs }
                        } else if mark_status == Some("release") {
                            SagaLeaseMutation::Release
                        } else {
                            SagaLeaseMutation::MarkStatus(mark_status.unwrap_or("running"))
                        };
                        let held = tx
                            .saga_cas_lease(&fields, mutation)
                            .await
                            .map_err(SagaInstanceStoreError::new)?;
                        Ok(if held {
                            SagaLeaseOutcome::Held
                        } else {
                            SagaLeaseOutcome::Lost
                        })
                    })
                },
                SagaInstanceStoreError::new,
            )
            .await
    }
}

impl SagaJournal for PgSagaJournal {
    async fn append(
        &self,
        lease: &SagaLease,
        entry: SagaJournalAppendRecord,
    ) -> Result<SagaJournalAppendOutcome, SagaJournalError> {
        let fields = LeaseFields::from(lease).map_err(SagaJournalError::new)?;
        let entry_fields = JournalEntryFields::from(entry)?;
        self.write_pool
            .saga_write(
                infra_tenant_scope(fields.instance.tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        if tx
                            .saga_insert_journal(&fields, &entry_fields)
                            .await
                            .map_err(SagaJournalError::new)?
                        {
                            return Ok(SagaJournalAppendOutcome::Appended);
                        }

                        if !tx
                            .saga_lease_is_held(&fields)
                            .await
                            .map_err(SagaJournalError::new)?
                        {
                            return Ok(SagaJournalAppendOutcome::LeaseLost);
                        }

                        let existing = tx
                            .saga_load_journal_entry(
                                &InstanceFields::from(fields.instance),
                                entry_fields.seq,
                            )
                            .await
                            .map_err(SagaJournalError::new)?;

                        let Some(existing) = existing else {
                            return Ok(SagaJournalAppendOutcome::AppendConflict);
                        };
                        if existing.step_name == entry_fields.step_name
                            && existing.status == entry_fields.status
                            && existing.error_summary.as_deref()
                                == entry_fields.error_summary.as_deref()
                        {
                            Ok(SagaJournalAppendOutcome::IdempotentDuplicate)
                        } else {
                            Ok(SagaJournalAppendOutcome::AppendConflict)
                        }
                    })
                },
                SagaJournalError::new,
            )
            .await
    }

    async fn read(
        &self,
        instance: &SagaInstanceRef,
    ) -> Result<Vec<SagaJournalRecord>, SagaJournalError> {
        let fields = InstanceFields::from(*instance);
        self.read_pool
            .saga_read_map(
                infra_tenant_scope(fields.instance.tenant()),
                move |mut conn| {
                    Box::pin(async move {
                        let rows = conn
                            .saga_read_journal(&fields)
                            .await
                            .map_err(SagaJournalError::new)?;
                        rows.into_iter()
                            .map(|row| {
                                let seq = u64::try_from(row.seq).map_err(SagaJournalError::new)?;
                                let step_name = StepName::parse(&row.step_name).map_err(|_| {
                                    SagaJournalError::new(InvariantError(
                                        "invalid step_name in saga_journal",
                                    ))
                                })?;
                                let status =
                                    SagaJournalStatus::parse(&row.status).ok_or_else(|| {
                                        SagaJournalError::new(InvariantError(
                                            "invalid status in saga_journal",
                                        ))
                                    })?;
                                Ok(SagaJournalRecord::replayed(seq, step_name, status))
                            })
                            .collect()
                    })
                },
                SagaJournalError::new,
            )
            .await
    }

    async fn shutdown(&self) -> Result<(), SagaJournalError> {
        Ok(())
    }
}

pub(crate) struct RegistrationFields {
    pub(crate) instance: SagaInstanceRef,
    pub(crate) saga_id: String,
    pub(crate) owner: String,
    pub(crate) contract_id: String,
    pub(crate) identity: SagaWorkerIdentity,
    pub(crate) definition: SagaDefinitionIdentity,
    pub(crate) definition_version: String,
    pub(crate) definition_schema_digest: String,
    pub(crate) action_registry_generation: String,
}

impl From<SagaInstanceRegistration> for RegistrationFields {
    fn from(registration: SagaInstanceRegistration) -> Self {
        let instance = registration.instance();
        let definition = registration.definition().clone();
        let identity = registration.identity().clone();
        Self {
            instance,
            saga_id: instance.saga_id().as_uuid().to_string(),
            owner: identity.owner().to_string(),
            contract_id: identity.contract_id().as_str().to_string(),
            identity,
            definition_version: definition.version().to_string(),
            definition_schema_digest: definition.schema_digest().to_string(),
            action_registry_generation: definition.action_registry_generation().to_string(),
            definition,
        }
    }
}

#[derive(Clone)]
pub(crate) struct InstanceFields {
    pub(crate) instance: SagaInstanceRef,
    pub(crate) saga_id: String,
}

impl From<SagaInstanceRef> for InstanceFields {
    fn from(instance: SagaInstanceRef) -> Self {
        Self {
            instance,
            saga_id: instance.saga_id().as_uuid().to_string(),
        }
    }
}

pub(crate) struct LeaseFields {
    pub(crate) instance: SagaInstanceRef,
    pub(crate) saga_id: String,
    pub(crate) lease_token: String,
    pub(crate) epoch: i64,
}

impl LeaseFields {
    fn from(lease: &SagaLease) -> Result<Self, InvariantError> {
        Ok(Self {
            instance: lease.instance(),
            saga_id: lease.instance().saga_id().as_uuid().to_string(),
            lease_token: lease.lease_token().to_string(),
            epoch: i64::try_from(lease.epoch())
                .map_err(|_| InvariantError("lease epoch overflow"))?,
        })
    }
}

pub(crate) struct JournalEntryFields {
    pub(crate) seq: i64,
    pub(crate) step_name: String,
    pub(crate) status: String,
    pub(crate) error_summary: Option<String>,
}

impl JournalEntryFields {
    fn from(entry: SagaJournalAppendRecord) -> Result<Self, SagaJournalError> {
        Ok(Self {
            seq: i64::try_from(entry.seq()).map_err(SagaJournalError::new)?,
            step_name: entry.step_name().as_str().to_string(),
            status: entry.status().as_str().to_string(),
            error_summary: entry.error_summary().map(str::to_string),
        })
    }
}

fn duration_secs(ttl: Duration) -> Result<i64, InvariantError> {
    if ttl.is_zero() {
        return Err(InvariantError("lease ttl is zero"));
    }
    i64::try_from(ttl.as_secs()).map_err(|_| InvariantError("lease ttl overflow"))
}

fn validate_holder_id(holder_id: &str) -> Result<(), SagaInstanceStoreError> {
    if holder_id.trim().is_empty() || holder_id.len() > HOLDER_ID_MAX_BYTES {
        return Err(SagaInstanceStoreError::new(InvariantError(
            "invalid saga lease holder_id",
        )));
    }
    Ok(())
}

fn parse_instance_status(raw: &str) -> Result<SagaInstanceStatus, SagaInstanceStoreError> {
    SagaInstanceStatus::parse(raw)
        .ok_or_else(|| SagaInstanceStoreError::new(InvariantError("invalid saga instance status")))
}

fn runnable_from_row(
    tenant: vocab::TenantId,
    row: SagaRunnableRow,
) -> Result<SagaRunnableInstance, SagaInstanceStoreError> {
    let saga_id = uuid::Uuid::parse_str(&row.saga_id)
        .map(SagaId::new)
        .map_err(SagaInstanceStoreError::new)?;
    let instance = SagaInstanceRef::new(tenant, saga_id).map_err(SagaInstanceStoreError::new)?;
    let status = parse_instance_status(&row.status)?;
    let identity = parse_worker_identity(&row.owner, &row.contract_id)?;
    let definition = parse_definition_identity(
        &row.contract_id,
        &row.definition_version,
        &row.definition_schema_digest,
        &row.action_registry_generation,
    )?;
    SagaRunnableInstance::new(instance, status, identity, definition)
        .map_err(SagaInstanceStoreError::new)
}

fn parse_worker_identity(
    owner: &str,
    contract_id: &str,
) -> Result<SagaWorkerIdentity, SagaInstanceStoreError> {
    let contract_id = SagaContractId::parse(contract_id).map_err(SagaInstanceStoreError::new)?;
    SagaWorkerIdentity::new(owner, contract_id).map_err(SagaInstanceStoreError::new)
}

fn parse_definition_identity(
    contract_id: &str,
    version: &str,
    schema_digest: &str,
    action_generation: &str,
) -> Result<SagaDefinitionIdentity, SagaInstanceStoreError> {
    SagaDefinitionIdentity::new(contract_id, version, schema_digest, action_generation)
        .map_err(SagaInstanceStoreError::new)
}

fn lease_from_row(
    instance: SagaInstanceRef,
    holder_id: String,
    token: String,
    epoch: i64,
) -> Result<SagaLease, InvariantError> {
    let token = uuid::Uuid::parse_str(&token).map_err(|_| InvariantError("invalid lease token"))?;
    let epoch = u64::try_from(epoch).map_err(|_| InvariantError("invalid lease epoch"))?;
    SagaLease::new(instance, holder_id, token, epoch)
        .map_err(|_| InvariantError("invalid saga lease row"))
}

#[derive(Debug)]
struct InvariantError(&'static str);

impl std::fmt::Display for InvariantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for InvariantError {}

#[cfg(all(test, feature = "integration"))]
mod integration_tests {
    use super::*;
    use consistency::{SagaId, SagaJournalAppendOutcome, SagaJournalAppendRecord};
    use diport::{
        ManagedResource, SagaContractId, SagaInstanceStore, SagaJournal, SagaTenantSource,
        SagaWorkerIdentity,
    };

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    #[test]
    fn saga_definition_identity_migration_is_fail_closed_and_has_no_defaults() {
        const MIGRATION: &str = include_str!("../migrations/0080_pin_saga_definition_identity.sql");

        assert!(MIGRATION.contains("IF EXISTS (SELECT 1 FROM saga_instances LIMIT 1)"));
        assert!(MIGRATION.contains("ADD COLUMN definition_version text NOT NULL"));
        assert!(MIGRATION.contains("ADD COLUMN definition_schema_digest text NOT NULL"));
        assert!(MIGRATION.contains("ADD COLUMN action_registry_generation text NOT NULL"));
        assert!(!MIGRATION.to_ascii_uppercase().contains("DEFAULT"));
        assert!(MIGRATION.contains("^v[1-9][0-9]*$"));
        assert_eq!(MIGRATION.matches("^sha256:[0-9a-f]{64}$").count(), 2);
    }

    fn saga_identity(
        contract_id: &str,
    ) -> Result<SagaWorkerIdentity, Box<dyn std::error::Error + Send + Sync>> {
        Ok(SagaWorkerIdentity::new(
            "billing",
            SagaContractId::parse(contract_id)?,
        )?)
    }

    fn saga_registration(
        instance: SagaInstanceRef,
        contract_id: &str,
    ) -> Result<SagaInstanceRegistration, Box<dyn std::error::Error + Send + Sync>> {
        let definition = SagaDefinitionIdentity::new(
            contract_id,
            "v1",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )?;
        Ok(SagaInstanceRegistration::new(
            instance,
            saga_identity(contract_id)?,
            definition,
        )?)
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn saga_instance_lease_and_journal_roundtrip() -> TestResult {
        let (_pg, store) = crate::test_pg::connect_pg().await?;
        store.run_migrations().await?;

        let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let instance = SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::new_v4()))?;
        let instances = store.saga_instance_store();
        let journal = store.saga_journal();
        let registration = saga_registration(instance, "billing.checkout")?;

        let registered = instances.register(registration).await?;
        assert_eq!(registered.status(), SagaInstanceStatus::Ready);
        assert_eq!(registered.identity().owner(), "billing");
        assert_eq!(
            registered.identity().contract_id().as_str(),
            "billing.checkout"
        );
        assert_eq!(registered.definition().version(), "v1");
        let duplicate = instances
            .register(saga_registration(instance, "billing.checkout")?)
            .await?;
        assert_eq!(duplicate.definition(), registered.definition());
        assert_eq!(duplicate.identity(), registered.identity());
        let fetched = instances
            .get(&instance)
            .await?
            .ok_or_else(|| std::io::Error::other("registered saga was not readable"))?;
        assert_eq!(fetched.identity(), registered.identity());
        assert_eq!(fetched.definition(), registered.definition());
        let foreign_owner = SagaInstanceRegistration::new(
            instance,
            SagaWorkerIdentity::new(
                "foreign-billing",
                SagaContractId::parse("billing.checkout")?,
            )?,
            registered.definition().clone(),
        )?;
        let foreign_owner_conflict = match instances.register(foreign_owner).await {
            Ok(_) => return Err(std::io::Error::other("foreign owner was accepted").into()),
            Err(error) => error,
        };
        assert_eq!(
            foreign_owner_conflict.kind(),
            diport::SagaInstanceStoreErrorKind::IdentityConflict
        );
        let conflicting_definition = SagaDefinitionIdentity::new(
            "billing.checkout",
            "v2",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )?;
        let conflicting = SagaInstanceRegistration::new(
            instance,
            saga_identity("billing.checkout")?,
            conflicting_definition,
        )?;
        let conflict = match instances.register(conflicting).await {
            Ok(_) => return Err(std::io::Error::other("identity conflict was accepted").into()),
            Err(error) => error,
        };
        assert_eq!(
            conflict.kind(),
            diport::SagaInstanceStoreErrorKind::IdentityConflict
        );
        let identity = saga_identity("billing.checkout")?;
        assert_eq!(
            instances
                .list_candidate_tenants(&identity, std::num::NonZeroUsize::new(8).unwrap())
                .await?,
            vec![tenant]
        );
        let runnable = instances
            .list_runnable(&identity, tenant, std::num::NonZeroUsize::new(8).unwrap())
            .await?;
        assert_eq!(runnable.len(), 1);
        assert_eq!(runnable[0].definition(), registered.definition());
        assert_eq!(runnable[0].identity(), registered.identity());
        let lease = instances
            .acquire_lease(&instance, "runner-a", Duration::from_secs(30))
            .await?
            .ok_or_else(|| std::io::Error::other("lease should be acquired"))?;
        assert!(
            instances
                .acquire_lease(&instance, "runner-b", Duration::from_secs(30))
                .await?
                .is_none(),
            "second holder must be fenced while lease is held"
        );

        let step = StepName::parse("reserve_funds").unwrap();
        let executing = SagaJournalAppendRecord::executing(0, step.clone());
        assert_eq!(
            journal.append(&lease, executing.clone()).await?,
            SagaJournalAppendOutcome::Appended
        );
        assert_eq!(
            journal.append(&lease, executing).await?,
            SagaJournalAppendOutcome::IdempotentDuplicate
        );
        assert_eq!(
            journal
                .append(&lease, SagaJournalAppendRecord::completed(0, step))
                .await?,
            SagaJournalAppendOutcome::AppendConflict
        );

        let rows = journal.read(&instance).await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status(), SagaJournalStatus::Executing);

        assert_eq!(
            instances.release_lease(&lease).await?,
            SagaLeaseOutcome::Held
        );
        let replacement = instances
            .acquire_lease(&instance, "runner-b", Duration::from_secs(30))
            .await?
            .ok_or_else(|| {
                std::io::Error::other("released lease should be acquirable by another holder")
            })?;
        assert_eq!(
            instances
                .extend_lease(&lease, Duration::from_secs(30))
                .await?,
            SagaLeaseOutcome::Lost,
            "old epoch must be fenced after reacquire"
        );
        assert_eq!(
            instances
                .mark_status(&lease, SagaInstanceStatus::Succeeded)
                .await?,
            SagaLeaseOutcome::Lost,
            "old epoch must not mark status after reacquire"
        );
        let next_step = StepName::parse("charge_card").unwrap();
        assert_eq!(
            journal
                .append(&lease, SagaJournalAppendRecord::executing(1, next_step))
                .await?,
            SagaJournalAppendOutcome::LeaseLost
        );
        assert_eq!(
            instances.release_lease(&replacement).await?,
            SagaLeaseOutcome::Held
        );

        let tenant_b = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let instance_b = SagaInstanceRef::new(tenant_b, instance.saga_id())?;
        instances
            .register(saga_registration(instance_b, "billing.checkout")?)
            .await?;
        let lease_b = instances
            .acquire_lease(&instance_b, "runner-b", Duration::from_secs(30))
            .await?
            .ok_or_else(|| {
                std::io::Error::other(
                    "same saga uuid in another tenant should acquire independently",
                )
            })?;
        let tenant_b_step = StepName::parse("tenant_b_step").unwrap();
        assert_eq!(
            journal
                .append(
                    &lease_b,
                    SagaJournalAppendRecord::executing(0, tenant_b_step.clone()),
                )
                .await?,
            SagaJournalAppendOutcome::Appended
        );
        let rows_a = journal.read(&instance).await?;
        let rows_b = journal.read(&instance_b).await?;
        assert_eq!(rows_a.len(), 1, "tenant A should not see tenant B row");
        assert_eq!(rows_b.len(), 1, "tenant B should not see tenant A row");
        assert_eq!(rows_b[0].step_name(), &tenant_b_step);

        let expiring = SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::new_v4()))?;
        instances
            .register(saga_registration(expiring, "billing.checkout")?)
            .await?;
        let expiring_lease = instances
            .acquire_lease(&expiring, "runner-expiring", Duration::from_secs(30))
            .await?
            .ok_or_else(|| std::io::Error::other("expiring lease should acquire"))?;
        sqlx::query(
            "UPDATE saga_instances \
             SET acquired_at = now() - interval '2 seconds', \
                 heartbeat_at = now() - interval '2 seconds', \
                 expires_at = now() - interval '1 second' \
             WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
        )
        .bind(expiring.tenant().to_string())
        .bind(expiring.saga_id().as_uuid().to_string())
        .execute(&store.pool)
        .await?;
        assert_eq!(
            instances
                .extend_lease(&expiring_lease, Duration::from_secs(30))
                .await?,
            SagaLeaseOutcome::Lost,
            "expired lease must be lost"
        );
        assert_eq!(
            journal
                .append(
                    &expiring_lease,
                    SagaJournalAppendRecord::executing(0, StepName::parse("expired_step").unwrap()),
                )
                .await?,
            SagaJournalAppendOutcome::LeaseLost,
            "expired lease must not append"
        );

        assert_saga_catalog_and_rls(&store).await?;

        journal.shutdown().await?;
        instances.shutdown().await?;
        store.shutdown().await?;
        Ok(())
    }

    #[allow(clippy::cognitive_complexity)]
    // reason: 表驱动 catalog/RLS 验收刻意在一个 helper 中并列全部权限事实，拆散会削弱矩阵可审计性。
    async fn assert_saga_catalog_and_rls(store: &crate::PgStore) -> TestResult {
        for (table, update_expected, delete_expected) in [
            ("saga_instances", false, false),
            ("saga_journal", false, false),
        ] {
            let (rls_enabled, rls_forced, can_select, can_insert, can_update, can_delete): (
                bool,
                bool,
                bool,
                bool,
                bool,
                bool,
            ) = sqlx::query_as(
                "SELECT c.relrowsecurity, c.relforcerowsecurity, \
                        has_table_privilege('rss_app', $1, 'SELECT'), \
                        has_table_privilege('rss_app', $1, 'INSERT'), \
                        has_table_privilege('rss_app', $1, 'UPDATE'), \
                        has_table_privilege('rss_app', $1, 'DELETE') \
                 FROM pg_class c \
                 JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE n.nspname = 'public' AND c.relname = $1",
            )
            .bind(table)
            .fetch_one(&store.pool)
            .await?;
            assert!(rls_enabled, "{table} must ENABLE RLS");
            assert!(rls_forced, "{table} must FORCE RLS");
            assert!(can_select, "rss_app must SELECT {table}");
            assert!(can_insert, "rss_app must INSERT {table}");
            assert_eq!(
                can_update, update_expected,
                "rss_app UPDATE privilege mismatch for {table}"
            );
            assert_eq!(
                can_delete, delete_expected,
                "rss_app DELETE privilege mismatch for {table}"
            );
        }

        let (can_update_status, can_update_owner, can_update_contract, can_update_definition): (
            bool,
            bool,
            bool,
            bool,
        ) = sqlx::query_as(
            "SELECT has_column_privilege('rss_app', 'saga_instances', 'status', 'UPDATE'), \
                    has_column_privilege('rss_app', 'saga_instances', 'owner', 'UPDATE'), \
                    has_column_privilege('rss_app', 'saga_instances', 'contract_id', 'UPDATE'), \
                    has_column_privilege('rss_app', 'saga_instances', \
                                         'definition_version', 'UPDATE')",
        )
        .fetch_one(&store.pool)
        .await?;
        assert!(
            can_update_status,
            "rss_app must update saga lifecycle state"
        );
        assert!(
            !can_update_definition,
            "rss_app must never mutate a pinned definition identity"
        );
        assert!(
            !can_update_owner && !can_update_contract,
            "rss_app must never mutate pinned owner/contract identity"
        );

        sqlx::query("GRANT rss_app TO CURRENT_USER")
            .execute(&store.pool)
            .await?;

        let tenant_a = uuid::Uuid::new_v4().to_string();
        let tenant_b = uuid::Uuid::new_v4().to_string();
        let saga_id = uuid::Uuid::new_v4().to_string();
        {
            let mut tx = store.pool.begin().await?;
            sqlx::query("SET LOCAL ROLE rss_app")
                .execute(&mut *tx)
                .await?;
            set_test_tenant(&mut tx, &tenant_a).await?;
            sqlx::query(
                "INSERT INTO saga_instances \
                    (tenant_id, saga_id, owner, contract_id, definition_version, \
                     definition_schema_digest, action_registry_generation) \
                 VALUES ($1::uuid, $2::uuid, 'billing', 'billing.checkout', 'v1', \
                    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
                    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')",
            )
            .bind(&tenant_a)
            .bind(&saga_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO saga_journal (tenant_id, saga_id, seq, step_name, status) \
                 VALUES ($1::uuid, $2::uuid, 0, 'rss_app_step', 'executing')",
            )
            .bind(&tenant_a)
            .bind(&saga_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }

        {
            let mut tx = store.pool.begin().await?;
            sqlx::query("SET LOCAL ROLE rss_app")
                .execute(&mut *tx)
                .await?;
            set_test_tenant(&mut tx, &tenant_a).await?;
            let mutation = sqlx::query(
                "UPDATE saga_instances SET definition_version = 'v2' \
                 WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
            )
            .bind(&tenant_a)
            .bind(&saga_id)
            .execute(&mut *tx)
            .await;
            assert!(
                mutation.is_err(),
                "pinned identity must be database-immutable"
            );
            tx.rollback().await?;
        }

        for sql in [
            "UPDATE saga_journal SET status = 'completed' \
             WHERE tenant_id = $1::uuid AND saga_id = $2::uuid AND seq = 0",
            "DELETE FROM saga_journal \
             WHERE tenant_id = $1::uuid AND saga_id = $2::uuid AND seq = 0",
        ] {
            let mut tx = store.pool.begin().await?;
            sqlx::query("SET LOCAL ROLE rss_app")
                .execute(&mut *tx)
                .await?;
            set_test_tenant(&mut tx, &tenant_a).await?;
            let result = sqlx::query(sql)
                .bind(&tenant_a)
                .bind(&saga_id)
                .execute(&mut *tx)
                .await;
            assert!(result.is_err(), "rss_app must not execute: {sql}");
            tx.rollback().await?;
        }

        for (tenant, expected, label) in
            [(&tenant_a, 1_i64, "tenant A"), (&tenant_b, 0, "tenant B")]
        {
            let mut tx = store.pool.begin().await?;
            sqlx::query("SET LOCAL ROLE rss_app")
                .execute(&mut *tx)
                .await?;
            set_test_tenant(&mut tx, tenant).await?;
            let count: (i64,) =
                sqlx::query_as("SELECT count(*) FROM saga_journal WHERE saga_id = $1::uuid")
                    .bind(&saga_id)
                    .fetch_one(&mut *tx)
                    .await?;
            assert_eq!(
                count.0, expected,
                "{label} saga_journal visibility mismatch"
            );
            tx.rollback().await?;
        }

        Ok(())
    }

    async fn set_test_tenant(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant: &str,
    ) -> Result<(), sqlx::Error> {
        let query = format!("SELECT set_config('{}', $1, true)", "rss.tenant_id");
        sqlx::query(&query).bind(tenant).execute(&mut **tx).await?;
        Ok(())
    }
}

#[cfg(test)]
mod smoke {
    use core::marker::PhantomData;

    use diport::{SagaInstanceStore, SagaJournal};

    #[test]
    fn pg_saga_ports_impl_frozen() {
        fn assert_instance_store<T: SagaInstanceStore>(_: PhantomData<T>) {}
        fn assert_journal<T: SagaJournal>(_: PhantomData<T>) {}

        assert_instance_store(PhantomData::<super::PgSagaInstanceStore>);
        assert_journal(PhantomData::<super::PgSagaJournal>);
    }

    #[test]
    fn saga_status_consts_match_migration_check() -> Result<(), &'static str> {
        const MIGRATION: &str = include_str!("../migrations/0043_create_saga_instance_store.sql");
        let values = extract_check_values(MIGRATION, "status IN (")?;
        let mut port_values: Vec<&str> = consistency::SagaInstanceStatus::ALL
            .map(|s| s.as_str())
            .to_vec();
        port_values.sort_unstable();
        assert_eq!(values, port_values);
        Ok(())
    }

    #[test]
    fn journal_status_consts_match_migration_check() -> Result<(), &'static str> {
        const MIGRATION: &str = include_str!("../migrations/0007_create_saga_journal.sql");
        let values = extract_check_values(MIGRATION, "status IN (")?;
        let mut port_values: Vec<&str> = consistency::SagaJournalStatus::ALL
            .map(|s| s.as_str())
            .to_vec();
        port_values.sort_unstable();
        assert_eq!(values, port_values);
        Ok(())
    }

    #[test]
    fn saga_worker_tenant_index_migration_is_narrow_and_function_gated() {
        const MIGRATION: &str =
            include_str!("../migrations/0050_create_saga_worker_tenant_index.sql");
        for needle in [
            "CREATE TABLE saga_worker_tenant_index",
            "FORCE ROW LEVEL SECURITY",
            "CREATE POLICY saga_worker_tenant_index_no_direct_app_access",
            "tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid",
            "AND false",
            "REVOKE ALL ON saga_worker_tenant_index FROM rss_app",
            "CREATE OR REPLACE FUNCTION rss_saga_candidate_tenants",
            "SECURITY DEFINER",
            "ALTER FUNCTION rss_saga_candidate_tenants(text, text, bigint) OWNER TO rss_saga_maintenance",
            "GRANT EXECUTE ON FUNCTION rss_saga_candidate_tenants(text, text, bigint) TO rss_app",
        ] {
            assert!(
                MIGRATION.contains(needle),
                "0050 migration missing `{needle}`"
            );
        }
        assert!(
            !MIGRATION.contains("GRANT SELECT ON saga_worker_tenant_index TO rss_app"),
            "rss_app must not receive direct saga worker tenant index SELECT"
        );
    }

    #[test]
    fn saga_worker_tenant_index_migration_has_poll_path_index() {
        const MIGRATION: &str =
            include_str!("../migrations/0050_create_saga_worker_tenant_index.sql");

        for needle in [
            "CREATE INDEX idx_saga_worker_tenant_index_owner_contract_updated",
            "ON saga_worker_tenant_index (owner, contract_id, updated_at, tenant_id)",
            "WHERE idx.owner = p_owner",
            "AND idx.contract_id = p_contract_id",
            "ORDER BY idx.updated_at, idx.tenant_id",
        ] {
            assert!(
                MIGRATION.contains(needle),
                "0050 migration missing `{needle}`"
            );
        }
    }

    fn extract_check_values<'a>(
        migration: &'a str,
        needle: &str,
    ) -> Result<Vec<&'a str>, &'static str> {
        let Some(in_pos) = migration.find(needle) else {
            return Err("CHECK IN clause");
        };
        let rest = &migration[in_pos..];
        let Some(open) = rest.find('(') else {
            return Err("IN clause needs '('");
        };
        let Some(close) = rest.find(')') else {
            return Err("IN clause needs ')'");
        };
        let mut values: Vec<&str> = rest[open + 1..close]
            .split(',')
            .map(|s| s.trim().trim_matches('\''))
            .collect();
        values.sort_unstable();
        Ok(values)
    }
}
