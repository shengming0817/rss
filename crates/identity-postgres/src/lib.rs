//! Embeddable account/session services over a host-owned PostgreSQL runtime.
mod attempts;
mod audit;
mod auth_facts;
mod credentials;
mod department;
mod entra;
mod password_attempts;
pub use entra::{EntraAuthority, RevalidatedAccount, VerifiedExternalSubject};
mod account_directory;
mod directory_window;
mod federation;
mod federation_state;
mod session_checks;
pub use federation_state::StateSigner;
pub(crate) use federation_state::{Purpose, StateLocator};
mod federation_link;
mod federation_login;
mod federation_storage;
mod groups;
mod maintenance;
mod management;
mod operations;
pub use account_directory::{AccountDirectoryRow, AccountPage};
mod personnel;
pub mod personnel_facts;
pub mod platform;
mod profiles;
pub use personnel::{PersonnelProfileScope, PersonnelRead, PersonnelRevision};
pub use profiles::{
    LocalProfileView, ProfileChange, ProfileOperationId, ProfileReceipt, ProfileSource,
    ProfileSourcePage, ProfileSourceView, ProfileStatus, ProfileView, TrustedProfile,
};
mod runtime;
mod schema;
mod session_page;
mod session_reference;
mod session_storage;
mod sessions;
mod storage;
mod transaction;
mod types;
pub use attempts::{AttemptWindow, AuthenticationPolicy};
pub use credentials::CredentialKeys;
pub use department::{
    DepartmentAccessError, TrustedDepartmentSnapshot, VerifiedDepartmentSnapshot,
};
pub use federation::{
    FederatedOutcome, FederatedRedirect, Federation, FederationConfig, LinkRequest, LinkResult,
    LoginOption, LoginRequest, SessionSecurity,
};
pub use groups::{GroupAccessError, TrustedGroups, VerifiedGroups};
pub use management::{
    ManagementContext, ManagementDenied, ManagementOperation, ManagementPolicy,
    ReauthenticationRequirement,
};
pub use operations::AccountView;
use rss_identity_core::{
    InstanceId,
    account::{AccountChange, AccountKey, AccountState},
    session::SessionPolicy,
};
use rss_request_context::Deadline;
use rss_request_context::TenantId;
use rss_transactional_messaging::fence::ExecutionBinding;
use rss_transactional_messaging_postgres::PgRuntime;
pub use schema::{
    MIGRATION_SQL, SCHEMA_SIGNATURE, SCHEMA_VERSION, grant_personnel_fact_read,
    grant_platform_subject_admission, grant_profile, grant_profile_source_admission, install,
    schema_signature, verify_personnel_fact_read, verify_platform_subject_admission,
    verify_profile, verify_profile_source_admission,
};
pub use session_reference::{RevalidatedSession, SessionReference};
pub use sessions::{
    AuthenticatedSession, IssuedSession, SessionIdentity, SessionPage, SessionView,
};
use std::sync::Arc;
pub use types::*;

/// Instance and admission are explicit; URLs and upstream credentials belong to adapters.
#[derive(Clone)]
pub struct AuthorityConfig {
    instance: InstanceId,
    sessions: SessionPolicy,
    audit: rss_audit_postgres::Integrity,
    audit_budget: rss_audit_postgres::WriteBudget,
    platform: Option<Arc<dyn platform::PlatformVerifier>>,
    oidc: Option<Arc<dyn rss_identity_core::federation::UpstreamOidc>>,
    enterprise: Option<platform::EnterpriseConfig>,
    profile_limits: rss_identity_core::profile::ProfileLimits,
    authentication: AuthenticationPolicy,
    profile_receipt_capacity: std::num::NonZeroU32,
    future_skew_seconds: u32,
    operation_proof_seconds: std::num::NonZeroU32,
    max_auth_facts_bytes: std::num::NonZeroU32,
    provider_capacity: std::num::NonZeroU16,
}
impl AuthorityConfig {
    /// Install the host's OIDC adapter for login and subsequent session or proof revalidation.
    pub fn with_oidc(mut self, oidc: Arc<dyn rss_identity_core::federation::UpstreamOidc>) -> Self {
        self.oidc = Some(oidc);
        self
    }

    pub fn with_provider_capacity(
        mut self,
        capacity: std::num::NonZeroU16,
    ) -> Result<Self, AuthorityError> {
        if capacity.get() > rss_identity_core::federation::MAX_PROVIDERS {
            return Err(AuthorityError::Configuration);
        }
        self.provider_capacity = capacity;
        Ok(self)
    }

    pub fn with_future_skew(mut self, seconds: u32) -> Self {
        self.future_skew_seconds = seconds;
        self
    }
    pub fn with_operation_proof_lifetime(mut self, seconds: std::num::NonZeroU32) -> Self {
        self.operation_proof_seconds = seconds;
        self
    }
    pub fn with_auth_facts_budget(mut self, bytes: std::num::NonZeroU32) -> Self {
        self.max_auth_facts_bytes = bytes;
        self
    }

    pub fn with_authentication_policy(mut self, policy: AuthenticationPolicy) -> Self {
        self.authentication = policy;
        self
    }
    pub fn with_profile_receipt_capacity(mut self, capacity: std::num::NonZeroU32) -> Self {
        self.profile_receipt_capacity = capacity;
        self
    }
    pub fn with_enterprise(mut self, config: platform::EnterpriseConfig) -> Self {
        self.enterprise = Some(config);
        self
    }
    pub fn with_profile_limits(
        mut self,
        limits: rss_identity_core::profile::ProfileLimits,
    ) -> Self {
        self.profile_limits = limits;
        self
    }
    /// Install only a deployment-trusted verifier; replacing it is a host trust decision.
    pub fn with_platform(mut self, verifier: Arc<dyn platform::PlatformVerifier>) -> Self {
        self.platform = Some(verifier);
        self
    }
    pub fn new(
        instance: InstanceId,
        sessions: SessionPolicy,
        audit: rss_audit_postgres::Integrity,
        audit_budget: rss_audit_postgres::WriteBudget,
    ) -> Result<Self, AuthorityError> {
        let max_events = transaction::MAX_MUTATION_EVENTS;
        if !audit_budget.supports_batch(max_events, max_events * rss_audit_core::MAX_RECORD_BYTES) {
            return Err(AuthorityError::Configuration);
        }
        Ok(Self {
            instance,
            sessions,
            audit,
            audit_budget,
            platform: None,
            oidc: None,
            enterprise: None,
            profile_limits: Default::default(),
            authentication: AuthenticationPolicy::standard(std::time::Duration::from_secs(60))?,
            profile_receipt_capacity: const { std::num::NonZeroU32::new(4096).unwrap() },
            future_skew_seconds: 30,
            operation_proof_seconds: const { std::num::NonZeroU32::new(300).unwrap() },
            max_auth_facts_bytes: const { std::num::NonZeroU32::new(32768).unwrap() },
            provider_capacity: const {
                std::num::NonZeroU16::new(rss_identity_core::federation::MAX_PROVIDERS).unwrap()
            },
        })
    }
}
#[derive(Clone)]
pub struct Authority {
    enterprise: Option<platform::EnterpriseConfig>,
    session_checks: session_checks::SessionChecks,
    kdf: Arc<rss_identity_core::account::PasswordKdf>,
    runtime: Arc<runtime::RuntimeBundle>,
    profile: AuthorityProfile,
    instance: InstanceId,
    session_policy: SessionPolicy,
    policy: Arc<dyn ManagementPolicy>,
    profile_limits: rss_identity_core::profile::ProfileLimits,
    authentication: AuthenticationPolicy,
    profile_receipt_capacity: std::num::NonZeroU32,
    future_skew_seconds: u32,
    operation_proof_seconds: std::num::NonZeroU32,
    max_auth_facts_bytes: std::num::NonZeroU32,
    provider_capacity: std::num::NonZeroU16,
}
impl Authority {
    pub async fn connect_runtime(
        runtime: Arc<PgRuntime>,
        kdf: Arc<rss_identity_core::account::PasswordKdf>,
        config: AuthorityConfig,
        probe: ExecutionBinding,
        policy: Arc<dyn ManagementPolicy>,
        deadline: Deadline,
    ) -> Result<Self, AuthorityError> {
        Self::connect(
            runtime,
            kdf,
            config,
            probe,
            AuthorityProfile::Runtime,
            policy,
            deadline,
        )
        .await
    }
    pub async fn connect_maintenance(
        runtime: Arc<PgRuntime>,
        kdf: Arc<rss_identity_core::account::PasswordKdf>,
        config: AuthorityConfig,
        probe: ExecutionBinding,
        deadline: Deadline,
    ) -> Result<Self, AuthorityError> {
        Self::connect(
            runtime,
            kdf,
            config,
            probe,
            AuthorityProfile::Maintenance,
            Arc::new(management::DenyManagement),
            deadline,
        )
        .await
    }
    async fn connect(
        runtime: Arc<PgRuntime>,
        kdf: Arc<rss_identity_core::account::PasswordKdf>,
        config: AuthorityConfig,
        probe: ExecutionBinding,
        profile: AuthorityProfile,
        policy: Arc<dyn ManagementPolicy>,
        deadline: Deadline,
    ) -> Result<Self, AuthorityError> {
        let budget = Budget::new(deadline, runtime.execution_timer())?;
        let instance = config.instance;
        let authority = Self {
            enterprise: config.enterprise,
            session_checks: session_checks::SessionChecks {
                platform: config.platform,
                oidc: config.oidc,
                timer: runtime.execution_timer().clone(),
            },
            kdf,
            runtime: Arc::new(runtime::RuntimeBundle {
                runtime,
                audit: config.audit,
                audit_budget: config.audit_budget,
                instance,
            }),
            profile,
            instance,
            session_policy: config.sessions,
            policy,
            profile_limits: config.profile_limits,
            authentication: config.authentication,
            profile_receipt_capacity: config.profile_receipt_capacity,
            future_skew_seconds: config.future_skew_seconds,
            operation_proof_seconds: config.operation_proof_seconds,
            max_auth_facts_bytes: config.max_auth_facts_bytes,
            provider_capacity: config.provider_capacity,
        };
        let integrity = authority.runtime.audit.clone();
        let valid = Self::read_bundle(
            authority.runtime.clone(),
            probe,
            budget.cutoff,
            false,
            move |tx| {
                Box::pin(async move {
                    rss_audit_postgres::validate_in(tx, &integrity)
                        .await
                        .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                    transaction::connection(tx, move |c| {
                        Box::pin(schema::probe(c, profile, instance))
                    })
                    .await
                })
            },
        )
        .await;
        check_probe(valid)?;
        Ok(authority)
    }
    /// Observe the host timer used by the fenced PG runtime.
    pub fn execution_timer(&self) -> &rss_request_context::SharedExecutionTimer {
        self.runtime.runtime.execution_timer()
    }
    fn budget(&self, deadline: rss_request_context::Deadline) -> Result<Budget, AuthorityError> {
        Budget::new(deadline, self.execution_timer())
    }
    pub fn instance(&self) -> InstanceId {
        self.instance
    }
    fn require_maintenance(&self) -> Result<(), AuthorityError> {
        if self.profile != AuthorityProfile::Maintenance {
            return Err(AuthorityError::Rejected);
        }
        Ok(())
    }
    pub fn require_runtime(&self) -> Result<(), AuthorityError> {
        if self.profile != AuthorityProfile::Runtime {
            return Err(AuthorityError::Rejected);
        }
        Ok(())
    }
}
fn check_probe(result: Result<Option<String>, AuthorityError>) -> Result<(), AuthorityError> {
    let reason = match result?.as_deref() {
        Some("ok") => return Ok(()),
        Some("schema-version") => StorageMismatch::SchemaVersion,
        Some("role") => StorageMismatch::Role,
        Some("deployment-identity") => StorageMismatch::DeploymentIdentity,
        Some("privileges") => StorageMismatch::Privileges,
        _ => StorageMismatch::SchemaContract,
    };
    Err(AuthorityError::StorageIncompatible(reason))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[allow(clippy::unwrap_used, reason = "test fixture")]
    fn probe_preserves_settlement_and_retry_class() {
        for reason in [
            StorageFailure::Transient,
            StorageFailure::DeadlineElapsed,
            StorageFailure::Permanent,
            StorageFailure::Invariant,
        ] {
            for error in [
                AuthorityError::NotStarted(reason),
                AuthorityError::RolledBack(reason),
                AuthorityError::RollbackFailed(reason),
                AuthorityError::CommitUnknown(reason),
            ] {
                assert_eq!(check_probe(Err(error)), Err(error));
            }
        }
        assert_eq!(
            check_probe(Err(AuthorityError::Fenced)),
            Err(AuthorityError::Fenced)
        );
        for (code, reason) in [
            ("schema-version", StorageMismatch::SchemaVersion),
            ("role", StorageMismatch::Role),
            ("privileges", StorageMismatch::Privileges),
            ("schema-contract", StorageMismatch::SchemaContract),
            (
                "private unexpected provider value",
                StorageMismatch::SchemaContract,
            ),
        ] {
            let error = check_probe(Ok(Some(code.into()))).unwrap_err();
            assert_eq!(error, AuthorityError::StorageIncompatible(reason));
            assert!(!error.to_string().contains("private unexpected"));
        }
        assert_eq!(
            check_probe(Ok(None)),
            Err(AuthorityError::StorageIncompatible(
                StorageMismatch::SchemaContract
            ))
        );
        assert_eq!(check_probe(Ok(Some("ok".into()))), Ok(()));
    }
}

mod provisioning;
pub use provisioning::{AccountProvisioner, PreparedLocalAccount, ProvisioningError};

mod bearer;
pub use bearer::IssuedBearer;

mod profile_admission;
pub use profile_admission::{ProfileSourceAdmissionError, admit_profile_source_on};

mod step_up;
pub use step_up::{ConsumedStepUp, StepUpGrant};
mod webauthn;
pub use webauthn::{
    RegistrationAuthorization, RpGeneration, WebauthnAuthority, WebauthnChallenge,
    WebauthnCredentialView, activate_webauthn_rp_on, webauthn_management_context,
};

#[cfg(test)]
mod test_time;
