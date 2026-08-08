use std::sync::Arc;

use diport::{ManagedResource, ShutdownError};

use super::{MaintenanceAuditOutcome, PgMaintenanceDeps, PgRuntimeDeps};
use crate::{PgConfig, PgDeviceCertificateStatusStore, PgError, PgStore, PgTenantReadConfig};

/// Fixed audit subject used before the maintenance service token is verified.
pub const UNVERIFIED_DEVICE_LATENT_OPERATOR: &str = "unverified-device-latent-operator";

/// Move-only PostgreSQL owner for the DeviceLatent inspection operator boundary.
///
/// The private maintenance owner is an implementation detail: callers can consume only the
/// service-token replay store, the two fixed identifier-free audit operations, and lifecycle
/// shutdown. General maintenance stores and parameterized audit methods are not projected.
///
/// INVARIANT: PG-DEVICE-LATENT-OPERATOR-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields, non-Clone owner, and purpose-specific method set; trybuild rejects clone and general maintenance access" }
pub struct PgDeviceLatentOperatorDeps {
    maintenance: PgMaintenanceDeps,
}

/// Dedicated read-only PostgreSQL owner for DeviceLatent status inspection.
///
/// This owner contains exactly one verified tenant reader. It cannot mint any writer, outbox,
/// reconcile, or command-mutation capability.
pub struct PgDeviceLatentInspectionDeps {
    reader: crate::pool::VerifiedPgReadStore,
}

/// Closed terminal outcome for the fixed DeviceLatent inspection audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceLatentInspectionAuditOutcome {
    /// The authorized read, payload-free projection, and stdout-ready output completed.
    Success,
    /// Operator token verifier configuration was invalid.
    OperatorProviderConfig,
    /// Operator service-token authentication failed.
    OperatorAuthentication,
    /// Exact tenant/permission/resource authorization failed.
    OperatorAuthorization,
    /// The read-only status store failed.
    Storage,
    /// The exact tenant/device status did not exist or was outside the RLS scope.
    NotFound,
    /// Validated domain evidence could not be represented by the frozen response.
    Projection,
    /// The closed JSON/Prometheus output surface failed after a successful read.
    Output,
    /// Inspection resources could not be closed before a durable Success outcome.
    Shutdown,
}

impl DeviceLatentInspectionAuditOutcome {
    const fn as_maintenance_outcome(self) -> MaintenanceAuditOutcome<'static> {
        match self {
            Self::Success => MaintenanceAuditOutcome::Success,
            Self::OperatorProviderConfig => MaintenanceAuditOutcome::Failure {
                reason: "operator_provider_config",
            },
            Self::OperatorAuthentication => MaintenanceAuditOutcome::Failure {
                reason: "operator_authentication",
            },
            Self::OperatorAuthorization => MaintenanceAuditOutcome::Failure {
                reason: "operator_authorization",
            },
            Self::Storage => MaintenanceAuditOutcome::Failure { reason: "storage" },
            Self::NotFound => MaintenanceAuditOutcome::Failure {
                reason: "not_found",
            },
            Self::Projection => MaintenanceAuditOutcome::Failure {
                reason: "projection",
            },
            Self::Output => MaintenanceAuditOutcome::Failure { reason: "output" },
            Self::Shutdown => MaintenanceAuditOutcome::Failure { reason: "shutdown" },
        }
    }
}

impl PgDeviceLatentInspectionDeps {
    /// Connect only the exact verified tenant-reader credential.
    pub async fn connect(config: &PgTenantReadConfig) -> Result<Self, PgError> {
        PgStore::connect_verified_read(config)
            .await
            .map(|reader| Self { reader })
    }

    /// Mint the sole business capability owned by this bundle.
    #[must_use]
    pub fn status_store(&self) -> PgDeviceCertificateStatusStore {
        PgDeviceCertificateStatusStore::new(&self.reader)
    }

    /// Close the dedicated tenant-reader pool.
    pub async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.reader.store_arc().shutdown().await
    }
}

impl PgDeviceLatentOperatorDeps {
    /// Connect the migrator credential behind the purpose-specific DeviceLatent operator owner.
    pub async fn connect(migrator_config: &PgConfig) -> Result<Self, PgError> {
        PgRuntimeDeps::connect_maintenance(migrator_config)
            .await
            .map(|maintenance| Self { maintenance })
    }

    /// Durable replay store for the one-shot inspection service token.
    #[must_use]
    pub fn service_token_replay_store(&self) -> Arc<diport::DynServiceTokenReplayStore<'static>> {
        self.maintenance.service_token_replay_store()
    }

    /// Record the fixed, identifier-free start audit.
    pub async fn record_start_audit(&self) -> Result<(), PgError> {
        self.maintenance
            .record_maintenance_audit(
                "device-certificate.status.inspection",
                UNVERIFIED_DEVICE_LATENT_OPERATOR,
                None,
                "device.latent.inspect.start",
                MaintenanceAuditOutcome::Success,
                "device-certificate-status",
                None,
            )
            .await
    }

    /// Record the fixed, identifier-free terminal audit.
    pub async fn record_finish_audit(
        &self,
        operator_subject: &str,
        outcome: DeviceLatentInspectionAuditOutcome,
    ) -> Result<(), PgError> {
        self.maintenance
            .record_maintenance_audit(
                "device-certificate.status.inspection",
                operator_subject,
                None,
                "device.latent.inspect.finish",
                outcome.as_maintenance_outcome(),
                "device-certificate-status",
                None,
            )
            .await
    }

    /// Close the sole maintenance connection pool owned by this boundary.
    pub async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.maintenance.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceLatentInspectionAuditOutcome, MaintenanceAuditOutcome};

    #[test]
    fn every_device_latent_outcome_has_one_fixed_audit_projection() {
        let cases = [
            (DeviceLatentInspectionAuditOutcome::Success, "success", None),
            (
                DeviceLatentInspectionAuditOutcome::OperatorProviderConfig,
                "failure",
                Some("operator_provider_config"),
            ),
            (
                DeviceLatentInspectionAuditOutcome::OperatorAuthentication,
                "failure",
                Some("operator_authentication"),
            ),
            (
                DeviceLatentInspectionAuditOutcome::OperatorAuthorization,
                "failure",
                Some("operator_authorization"),
            ),
            (
                DeviceLatentInspectionAuditOutcome::Storage,
                "failure",
                Some("storage"),
            ),
            (
                DeviceLatentInspectionAuditOutcome::NotFound,
                "failure",
                Some("not_found"),
            ),
            (
                DeviceLatentInspectionAuditOutcome::Projection,
                "failure",
                Some("projection"),
            ),
            (
                DeviceLatentInspectionAuditOutcome::Output,
                "failure",
                Some("output"),
            ),
            (
                DeviceLatentInspectionAuditOutcome::Shutdown,
                "failure",
                Some("shutdown"),
            ),
        ];

        for (outcome, expected_result, expected_reason) in cases {
            let (result, reason) = match outcome.as_maintenance_outcome() {
                MaintenanceAuditOutcome::Success => ("success", None),
                MaintenanceAuditOutcome::Failure { reason } => ("failure", Some(reason)),
            };
            assert_eq!((result, reason), (expected_result, expected_reason));
        }
    }
}
