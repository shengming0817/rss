//! Persistent certificate-revocation store and its startup capability gate.

use diport::{CertNotAfter, CertScope, CertSerial, RevocationStore, RevocationStoreError};

use crate::cotx::{ServingWriteLane, TenantDb, infra_tenant_scope};
use crate::pool::{PgError, VerifiedPgWriteStore};

const REVOCATION_CAPABILITY_PROBE_TENANT: &str = "00000000-0000-0000-0000-000000000001";

/// Proof that the serving writer observed the exact revocation schema, RLS and ACL capability.
///
/// The type and field are crate-private. Production construction is confined to
/// [`VerifiedPgWriteStore::verify_revocation_capability`].
#[derive(Clone)]
pub(crate) struct RevocationCapabilityReceipt {
    _seal: (),
}

impl RevocationCapabilityReceipt {
    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)] // test-support mint; production mint stays behind capability gate
    pub(crate) fn for_test() -> Self {
        Self { _seal: () }
    }
}

/// PostgreSQL-backed certificate revocation provider.
///
/// The private typed writer pool makes an unscoped query or mutation unrepresentable. The receipt
/// proves that this value was constructed only after the exact startup capability gate succeeded.
#[derive(Clone)]
pub struct PgRevocationStore {
    pool: TenantDb<ServingWriteLane>,
    receipt: RevocationCapabilityReceipt,
}

impl PgRevocationStore {
    pub(crate) fn new(writer: &VerifiedPgWriteStore, receipt: RevocationCapabilityReceipt) -> Self {
        Self {
            pool: TenantDb::<ServingWriteLane>::new(writer),
            receipt,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RevocationOperationError {
    #[error("certificate is not active")]
    CertificateExpired,
    #[error("certificate revocation expiry conflicts with persisted evidence")]
    ExpiryConflict,
    #[error("certificate revocation write did not produce authoritative evidence")]
    EvidenceMissing,
    #[error("certificate scope tenant does not match transaction tenant")]
    ScopeMismatch,
}

pub(crate) fn operation_error(error: RevocationOperationError) -> RevocationStoreError {
    RevocationStoreError::new(error)
}

pub(crate) fn storage_error(error: sqlx::Error) -> RevocationStoreError {
    tracing::warn!(
        target: "postgres",
        error = %secure::redact_error(&error),
        "certificate revocation store operation failed"
    );
    RevocationStoreError::new(error)
}

impl RevocationStore for PgRevocationStore {
    #[tracing::instrument(
        name = "postgres.revocation.revoke",
        skip_all,
        fields(tenant = %scope.tenant(), device = %scope.device().as_uuid())
    )]
    async fn revoke(
        &self,
        serial: CertSerial,
        scope: CertScope,
        not_after: CertNotAfter,
    ) -> Result<(), RevocationStoreError> {
        self.pool
            .revocation_write(
                scope,
                move |mut tx| {
                    Box::pin(async move {
                        tx.revocations()
                            .revoke_certificate(scope, serial, not_after)
                            .await
                    })
                },
                storage_error,
            )
            .await
    }

    #[tracing::instrument(
        name = "postgres.revocation.is_revoked",
        skip_all,
        level = "debug",
        fields(tenant = %scope.tenant(), device = %scope.device().as_uuid())
    )]
    async fn is_revoked(
        &self,
        serial: CertSerial,
        scope: CertScope,
    ) -> Result<bool, RevocationStoreError> {
        self.pool
            .revocation_receipt_read(
                &self.receipt,
                scope,
                move |mut tx| {
                    Box::pin(
                        async move { tx.revocations().is_certificate_revoked(scope, serial).await },
                    )
                },
                storage_error,
            )
            .await
    }

    async fn shutdown(&self) -> Result<(), RevocationStoreError> {
        // The pool is shared and owned by PgRuntimeDeps; this provider has no independent resource.
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct RevocationSchemaProbe {
    rls_enabled: bool,
    rls_forced: bool,
    columns_exact: bool,
    primary_key_exact: bool,
    serial_check_exact: bool,
    time_check_exact: bool,
    default_exact: bool,
    retention_index_exact: bool,
    tenant_policy_exact: bool,
}

impl RevocationSchemaProbe {
    pub(crate) fn is_exact(&self) -> bool {
        self.rls_enabled
            && self.rls_forced
            && self.columns_exact
            && self.primary_key_exact
            && self.serial_check_exact
            && self.time_check_exact
            && self.default_exact
            && self.retention_index_exact
            && self.tenant_policy_exact
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct RelationAclProbe {
    no_unexpected_grants: bool,
    no_missing_grants: bool,
}

impl RelationAclProbe {
    pub(crate) fn is_exact(&self) -> bool {
        self.no_unexpected_grants && self.no_missing_grants
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct MaintenanceRoleProbe {
    attributes_exact: bool,
    no_memberships: bool,
    namespace_capabilities_exact: bool,
    no_extra_relation_capabilities: bool,
    no_extra_function_capabilities: bool,
}

impl MaintenanceRoleProbe {
    pub(crate) fn is_exact(&self) -> bool {
        self.attributes_exact
            && self.no_memberships
            && self.namespace_capabilities_exact
            && self.no_extra_relation_capabilities
            && self.no_extra_function_capabilities
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct MaintenanceFunctionProbe {
    exact_count: bool,
    security_definer: bool,
    owner_exact: bool,
    language_exact: bool,
    signature_exact: bool,
    search_path_exact: bool,
    body_exact: bool,
    no_unexpected_grants: bool,
    no_missing_grants: bool,
}

impl MaintenanceFunctionProbe {
    pub(crate) fn is_exact(&self) -> bool {
        self.exact_count
            && self.security_definer
            && self.owner_exact
            && self.language_exact
            && self.signature_exact
            && self.search_path_exact
            && self.body_exact
            && self.no_unexpected_grants
            && self.no_missing_grants
    }
}

impl VerifiedPgWriteStore {
    /// Mint the revocation receipt only after the exact schema/ACL/maintenance gate succeeds.
    pub(crate) async fn verify_revocation_capability(
        &self,
    ) -> Result<RevocationCapabilityReceipt, PgError> {
        let tenant = vocab::TenantId::parse(REVOCATION_CAPABILITY_PROBE_TENANT)
            .map_err(|_| PgError::RevocationSchema)?;
        TenantDb::<ServingWriteLane>::new(self)
            .revocation_write(
                infra_tenant_scope(tenant),
                |mut tx| {
                    Box::pin(async move {
                        let schema = tx.revocations().load_schema_probe().await?;
                        if schema.as_ref().is_none_or(|probe| !probe.is_exact()) {
                            return Err(PgError::RevocationSchema);
                        }
                        if !tx.revocations().load_relation_acl_probe().await?.is_exact() {
                            return Err(PgError::RevocationPrivileges);
                        }
                        if !tx
                            .revocations()
                            .load_maintenance_role_probe()
                            .await?
                            .is_exact()
                        {
                            return Err(PgError::RevocationMaintenanceRole);
                        }
                        let maintenance_functions =
                            tx.revocations().load_maintenance_function_probe().await?;
                        if !maintenance_functions.is_exact() {
                            return Err(PgError::RevocationMaintenanceFunction);
                        }
                        Ok(())
                    })
                },
                PgError::RevocationCapability,
            )
            .await?;
        Ok(RevocationCapabilityReceipt { _seal: () })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MaintenanceFunctionProbe, MaintenanceRoleProbe, PgRevocationStore, RelationAclProbe,
        RevocationCapabilityReceipt, RevocationSchemaProbe,
    };

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn postgres_revocation_store_and_receipt_are_send_sync() {
        assert_send_sync::<PgRevocationStore>();
        assert_send_sync::<RevocationCapabilityReceipt>();
    }

    #[test]
    fn postgres_revocation_schema_probe_fails_closed_on_each_missing_carrier() {
        let exact = RevocationSchemaProbe {
            rls_enabled: true,
            rls_forced: true,
            columns_exact: true,
            primary_key_exact: true,
            serial_check_exact: true,
            time_check_exact: true,
            default_exact: true,
            retention_index_exact: true,
            tenant_policy_exact: true,
        };
        let drifts: [fn(&mut RevocationSchemaProbe); 9] = [
            |probe| probe.rls_enabled = false,
            |probe| probe.rls_forced = false,
            |probe| probe.columns_exact = false,
            |probe| probe.primary_key_exact = false,
            |probe| probe.serial_check_exact = false,
            |probe| probe.time_check_exact = false,
            |probe| probe.default_exact = false,
            |probe| probe.retention_index_exact = false,
            |probe| probe.tenant_policy_exact = false,
        ];
        assert!(exact.is_exact());
        for drift in drifts {
            let mut probe = RevocationSchemaProbe { ..exact };
            drift(&mut probe);
            assert!(!probe.is_exact());
        }
    }

    #[test]
    fn postgres_revocation_acl_probe_fails_closed_on_extra_or_missing_grants() {
        let exact = RelationAclProbe {
            no_unexpected_grants: true,
            no_missing_grants: true,
        };
        assert!(exact.is_exact());
        assert!(
            !RelationAclProbe {
                no_unexpected_grants: false,
                ..exact
            }
            .is_exact()
        );
        assert!(
            !RelationAclProbe {
                no_missing_grants: false,
                ..exact
            }
            .is_exact()
        );
    }

    #[test]
    fn postgres_revocation_maintenance_role_probe_fails_closed_on_each_drift() {
        let exact = MaintenanceRoleProbe {
            attributes_exact: true,
            no_memberships: true,
            namespace_capabilities_exact: true,
            no_extra_relation_capabilities: true,
            no_extra_function_capabilities: true,
        };
        let drifts: [fn(&mut MaintenanceRoleProbe); 5] = [
            |probe| probe.attributes_exact = false,
            |probe| probe.no_memberships = false,
            |probe| probe.namespace_capabilities_exact = false,
            |probe| probe.no_extra_relation_capabilities = false,
            |probe| probe.no_extra_function_capabilities = false,
        ];
        assert!(exact.is_exact());
        for drift in drifts {
            let mut probe = MaintenanceRoleProbe { ..exact };
            drift(&mut probe);
            assert!(!probe.is_exact());
        }
    }

    #[test]
    fn postgres_revocation_maintenance_function_probe_fails_closed_on_each_drift() {
        let exact = MaintenanceFunctionProbe {
            exact_count: true,
            security_definer: true,
            owner_exact: true,
            language_exact: true,
            signature_exact: true,
            search_path_exact: true,
            body_exact: true,
            no_unexpected_grants: true,
            no_missing_grants: true,
        };
        let drifts: [fn(&mut MaintenanceFunctionProbe); 9] = [
            |probe| probe.exact_count = false,
            |probe| probe.security_definer = false,
            |probe| probe.owner_exact = false,
            |probe| probe.language_exact = false,
            |probe| probe.signature_exact = false,
            |probe| probe.search_path_exact = false,
            |probe| probe.body_exact = false,
            |probe| probe.no_unexpected_grants = false,
            |probe| probe.no_missing_grants = false,
        ];
        assert!(exact.is_exact());
        for drift in drifts {
            let mut probe = MaintenanceFunctionProbe { ..exact };
            drift(&mut probe);
            assert!(!probe.is_exact());
        }
    }
}
