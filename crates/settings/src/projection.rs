//! Tenant-scoped, metadata-only persistence vocabulary for `settings.config-projection`.
//!
//! The types in this module deliberately cannot carry configuration values or encoded event
//! payloads. Production scopes are minted only from authenticated tenant authority and the sealed
//! projection source identity; PostgreSQL adapters may inspect them but cannot mint them.
//!
//! INVARIANT: SETTINGS-PROJECTION-SCOPE-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields; test-only read scope requires TenantRepoScope; production apply scope is minted only from ValidatedProjectionApply; compile-fail fixtures reject bare tenant, selector, and struct-literal construction" }
//! INVARIANT: SETTINGS-PROJECTION-METADATA-ONLY-01 { level = "Hard", exec = "native-compile", source = "code", native = "SettingsProjectionMutation and SettingsConfigProjectionRow expose an exact metadata-only field set with no payload or ConfigValue member" }
//! INVARIANT: SETTINGS-PROJECTION-VALIDATED-CONVERSION-01 { level = "Hard", exec = "native-compile", source = "code", native = "the sole production mint accepts eventexec::ValidatedProjectionApply and returns only SettingsProjectionApplyScope plus SettingsProjectionMutation; no Settings target wrapper can own ConfigRepo, ConfigUnitOfWork, active pointer, or cache" }

use std::time::SystemTime;

use consistency::Lsn;
use consistency::{ProjectionApplyErrorKind, ProjectionApplyErrorReason};
use eventexec::{ProjectionId, ProjectionVersion, ValidatedProjectionApply};
use generated::event::settings_v1::SettingsConfigChangeKind;

use crate::application::{
    ConfigVersionChangedEvent, ConfigVersionChangedEventError,
    config_version_changed_event_from_payload,
};
use crate::domain::SettingKey;
use crate::ports::TenantRepoScope;

const MAX_SOURCE_EVENT_ID_LEN: usize = 512;

/// Canonical Settings metadata projection id from the generated workflow contract.
pub const SETTINGS_CONFIG_PROJECTION_ID: &str = generated::projection::settings_v3::CONTRACT_ID;

/// Tenant capability plus one materialized projection generation for read-only serving.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsProjectionReadScope {
    tenant: TenantRepoScope,
    generation: ProjectionVersion,
    _seal: (),
}

impl SettingsProjectionReadScope {
    /// Authenticated tenant capability carried by this read scope.
    pub fn tenant_scope(&self) -> TenantRepoScope {
        self.tenant
    }

    /// Exact target generation selected for this read.
    pub fn generation(&self) -> &ProjectionVersion {
        &self.generation
    }

    /// Test-only scope funnel; production callers cannot turn a bare tenant into read authority.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(tenant: TenantRepoScope, generation: ProjectionVersion) -> Self {
        Self {
            tenant,
            generation,
            _seal: (),
        }
    }
}

/// Tenant, definition, input generation, and target generation bound apply authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsProjectionApplyScope {
    tenant: TenantRepoScope,
    projection: ProjectionId,
    target_generation: ProjectionVersion,
    definition_version: Box<str>,
    definition_schema_digest: vocab::CanonicalSha256Digest,
    input_generation: vocab::CanonicalSha256Digest,
    _seal: (),
}

impl SettingsProjectionApplyScope {
    fn validated(
        tenant: TenantRepoScope,
        projection: ProjectionId,
        target_generation: ProjectionVersion,
        definition_version: &str,
        definition_schema_digest: &str,
        input_generation: &str,
    ) -> Result<Self, SettingsProjectionScopeError> {
        if projection.as_str() != SETTINGS_CONFIG_PROJECTION_ID {
            return Err(SettingsProjectionScopeError::ProjectionMismatch);
        }
        if !is_canonical_ident(definition_version) {
            return Err(SettingsProjectionScopeError::DefinitionVersionInvalid);
        }
        let definition_schema_digest =
            vocab::CanonicalSha256Digest::parse(definition_schema_digest)
                .map_err(|_| SettingsProjectionScopeError::DefinitionDigestInvalid)?;
        let input_generation = vocab::CanonicalSha256Digest::parse(input_generation)
            .map_err(|_| SettingsProjectionScopeError::InputGenerationInvalid)?;
        Ok(Self {
            tenant,
            projection,
            target_generation,
            definition_version: definition_version.into(),
            definition_schema_digest,
            input_generation,
            _seal: (),
        })
    }

    /// Authenticated tenant capability carried by this apply scope.
    pub fn tenant_scope(&self) -> TenantRepoScope {
        self.tenant
    }

    /// Fixed projection id.
    pub fn projection(&self) -> &ProjectionId {
        &self.projection
    }

    /// Exact materialized target generation.
    pub fn target_generation(&self) -> &ProjectionVersion {
        &self.target_generation
    }

    /// Generated workflow definition version.
    pub fn definition_version(&self) -> &str {
        &self.definition_version
    }

    /// Generated workflow definition schema digest.
    pub const fn definition_schema_digest(&self) -> &vocab::CanonicalSha256Digest {
        &self.definition_schema_digest
    }

    /// Exact generated projection input binding generation.
    pub const fn input_generation(&self) -> &vocab::CanonicalSha256Digest {
        &self.input_generation
    }

    /// Test-only funnel for downstream PostgreSQL conformance tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(
        tenant: TenantRepoScope,
        projection: ProjectionId,
        target_generation: ProjectionVersion,
        definition_version: &str,
        definition_schema_digest: &str,
        input_generation: &str,
    ) -> Result<Self, SettingsProjectionScopeError> {
        Self::validated(
            tenant,
            projection,
            target_generation,
            definition_version,
            definition_schema_digest,
            input_generation,
        )
    }
}

/// Apply-scope construction failed closed before any repository I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SettingsProjectionScopeError {
    #[error("settings projection scope has the wrong projection id")]
    ProjectionMismatch,
    #[error("settings projection definition version is invalid")]
    DefinitionVersionInvalid,
    #[error("settings projection definition digest is invalid")]
    DefinitionDigestInvalid,
    #[error("settings projection input generation is invalid")]
    InputGenerationInvalid,
}

/// One typed, metadata-only Settings projection mutation.
pub struct SettingsProjectionMutation {
    tenant: vocab::TenantId,
    key: SettingKey,
    config_version: u64,
    change_kind: SettingsConfigChangeKind,
    source_event_id: String,
    source_lsn: Lsn,
    source_occurred_at_secs: u64,
    fact_digest: [u8; 32],
    _seal: (),
}

impl std::fmt::Debug for SettingsProjectionMutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SettingsProjectionMutation")
            .field("tenant", &self.tenant)
            .field("key", &"<redacted>")
            .field("config_version", &self.config_version)
            .field("change_kind", &self.change_kind)
            .field("source_event_id", &"<redacted>")
            .field("source_lsn", &self.source_lsn)
            .field("source_occurred_at_secs", &self.source_occurred_at_secs)
            .field("fact_digest", &"<redacted>")
            .finish()
    }
}

impl SettingsProjectionMutation {
    pub(crate) fn from_event(
        scope: &SettingsProjectionApplyScope,
        event: ConfigVersionChangedEvent,
        source_event_id: impl Into<String>,
        source_lsn: Lsn,
        fact_digest: [u8; 32],
    ) -> Result<Self, SettingsProjectionMutationError> {
        if event.tenant() != scope.tenant_scope().tenant() {
            return Err(SettingsProjectionMutationError::TenantMismatch);
        }
        let source_event_id = source_event_id.into();
        if source_event_id.is_empty() || source_event_id.len() > MAX_SOURCE_EVENT_ID_LEN {
            return Err(SettingsProjectionMutationError::SourceEventIdInvalid);
        }
        if event.version() == 0 {
            return Err(SettingsProjectionMutationError::ConfigVersionZero);
        }
        ensure_pg_i64(event.version(), "config_version")?;
        ensure_pg_i64(source_lsn.get(), "source_lsn")?;
        ensure_pg_i64(event.occurred_at_secs(), "source_occurred_at_secs")?;
        Ok(Self {
            tenant: event.tenant(),
            key: event.key().clone(),
            config_version: event.version(),
            change_kind: event.change_kind(),
            source_event_id,
            source_lsn,
            source_occurred_at_secs: event.occurred_at_secs(),
            fact_digest,
            _seal: (),
        })
    }

    /// Test-only mutation funnel; it executes the same tenant and numeric validation as production.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(
        scope: &SettingsProjectionApplyScope,
        event: ConfigVersionChangedEvent,
        source_event_id: impl Into<String>,
        source_lsn: Lsn,
        fact_digest: [u8; 32],
    ) -> Result<Self, SettingsProjectionMutationError> {
        Self::from_event(scope, event, source_event_id, source_lsn, fact_digest)
    }

    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    pub fn key(&self) -> &SettingKey {
        &self.key
    }

    pub fn config_version(&self) -> u64 {
        self.config_version
    }

    pub fn change_kind(&self) -> SettingsConfigChangeKind {
        self.change_kind
    }

    pub fn source_event_id(&self) -> &str {
        &self.source_event_id
    }

    pub fn source_lsn(&self) -> Lsn {
        self.source_lsn
    }

    pub fn source_occurred_at_secs(&self) -> u64 {
        self.source_occurred_at_secs
    }

    pub fn fact_digest(&self) -> &[u8; 32] {
        &self.fact_digest
    }
}

/// Convert the generic sealed projection input into the only Settings persistence vocabulary.
///
/// This is the sole production mint for [`SettingsProjectionApplyScope`] and
/// [`SettingsProjectionMutation`]. It rechecks every generated identity before decoding the raw
/// payload, and the encoded bytes are never retained in either returned type.
pub fn settings_projection_apply_from_validated(
    input: &ValidatedProjectionApply,
) -> Result<(SettingsProjectionApplyScope, SettingsProjectionMutation), SettingsProjectionApplyError>
{
    validate_target_identity(input)?;
    validate_source_binding(input)?;

    let selector_tenant = input.key().tenant();
    if input.metadata().tenant() != selector_tenant {
        return Err(SettingsProjectionApplyError::TenantMismatch);
    }
    let envelope_tenant = envelope_tenant(input)?;
    if envelope_tenant != selector_tenant {
        return Err(SettingsProjectionApplyError::TenantMismatch);
    }

    // The encoded payload is deliberately borrowed only for this decode call. Neither the event
    // nor the returned persistence types can carry the raw bytes.
    let event = config_version_changed_event_from_payload(input.payload())
        .map_err(SettingsProjectionApplyError::from_payload_error)?;
    if event.tenant() != selector_tenant {
        return Err(SettingsProjectionApplyError::TenantMismatch);
    }

    let contract = input.definition().contract();
    let scope = SettingsProjectionApplyScope::validated(
        TenantRepoScope::from_authenticated_tenant(selector_tenant),
        input.key().projection().clone(),
        input.key().generation().clone(),
        contract.version(),
        contract.schema_hash(),
        input.definition().input_generation().as_str(),
    )
    .map_err(|_| SettingsProjectionApplyError::TargetIdentityMismatch)?;
    let mutation = SettingsProjectionMutation::from_event(
        &scope,
        event,
        input.key().event_id(),
        input.lsn(),
        *input.fact_digest(),
    )
    .map_err(SettingsProjectionApplyError::from_mutation_error)?;
    Ok((scope, mutation))
}

fn validate_target_identity(
    input: &ValidatedProjectionApply,
) -> Result<(), SettingsProjectionApplyError> {
    if input.definition().contract() != generated::projection::settings_v3::CONTRACT {
        return Err(SettingsProjectionApplyError::TargetIdentityMismatch);
    }
    if input.definition().input_generation().as_str()
        != generated::event::PROJECTION_INPUT_GENERATION
    {
        return Err(SettingsProjectionApplyError::InputGenerationMismatch);
    }
    Ok(())
}

fn validate_source_binding(
    input: &ValidatedProjectionApply,
) -> Result<(), SettingsProjectionApplyError> {
    let expected = generated::event::settings_v1::FACT;
    let contract = expected.contract();
    let metadata = input.metadata();
    if metadata.domain() != contract.domain()
        || metadata.contract_id() != contract.contract_id()
        || metadata.contract_version() != contract.version()
        || metadata.schema_hash() != contract.schema_hash()
        || input.topic().as_str() != expected.topic()
    {
        return Err(SettingsProjectionApplyError::SourceBindingMismatch);
    }
    Ok(())
}

fn envelope_tenant(
    input: &ValidatedProjectionApply,
) -> Result<vocab::TenantId, SettingsProjectionApplyError> {
    let raw = input
        .metadata()
        .metadata_json()
        .as_object()
        .and_then(|metadata| metadata.get(diport::KEY_TENANT_ID))
        .and_then(serde_json::Value::as_str)
        .ok_or(SettingsProjectionApplyError::EnvelopeTenantInvalid)?;
    vocab::TenantId::parse(raw).map_err(|_| SettingsProjectionApplyError::EnvelopeTenantInvalid)
}

/// Closed failure classification for the Settings conversion funnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SettingsProjectionApplyError {
    #[error("settings projection target definition identity mismatch")]
    TargetIdentityMismatch,
    #[error("settings projection generated input generation mismatch")]
    InputGenerationMismatch,
    #[error("settings projection source binding mismatch")]
    SourceBindingMismatch,
    #[error("settings projection tenant identity mismatch")]
    TenantMismatch,
    #[error("settings projection envelope tenant metadata is invalid")]
    EnvelopeTenantInvalid,
    #[error("settings projection payload is malformed")]
    PayloadMalformed,
    #[error("settings projection payload tenant is invalid")]
    PayloadTenantInvalid,
    #[error("settings projection payload key is invalid")]
    PayloadKeyInvalid,
    #[error("settings projection payload numeric value is negative")]
    PayloadNumericNegative,
    #[error("settings projection config version must be positive")]
    ConfigVersionZero,
    #[error("settings projection source event id is invalid")]
    SourceEventIdInvalid,
    #[error("settings projection {field} is outside PostgreSQL bigint range")]
    NumericOutOfRange { field: &'static str },
}

impl SettingsProjectionApplyError {
    /// Stable runner classification. Identity and tenant drift are invariants; malformed facts
    /// under an otherwise legal binding are permanent poison.
    pub const fn kind(self) -> ProjectionApplyErrorKind {
        self.reason().kind()
    }

    /// Stable, low-cardinality operator action reason.
    pub const fn reason(self) -> ProjectionApplyErrorReason {
        match self {
            Self::TargetIdentityMismatch => ProjectionApplyErrorReason::TargetDefinitionDrift,
            Self::InputGenerationMismatch | Self::SourceBindingMismatch => {
                ProjectionApplyErrorReason::InputBindingDrift
            }
            Self::TenantMismatch | Self::EnvelopeTenantInvalid => {
                ProjectionApplyErrorReason::TenantDrift
            }
            Self::PayloadMalformed => ProjectionApplyErrorReason::PayloadMalformed,
            Self::PayloadTenantInvalid
            | Self::PayloadKeyInvalid
            | Self::PayloadNumericNegative
            | Self::ConfigVersionZero
            | Self::SourceEventIdInvalid
            | Self::NumericOutOfRange { .. } => ProjectionApplyErrorReason::PayloadValueInvalid,
        }
    }

    fn from_payload_error(error: ConfigVersionChangedEventError) -> Self {
        match error {
            ConfigVersionChangedEventError::Decode(_) => Self::PayloadMalformed,
            ConfigVersionChangedEventError::Tenant(_) => Self::PayloadTenantInvalid,
            ConfigVersionChangedEventError::Key(_) => Self::PayloadKeyInvalid,
            ConfigVersionChangedEventError::NegativeVersion
            | ConfigVersionChangedEventError::NegativeOccurredAt => Self::PayloadNumericNegative,
        }
    }

    fn from_mutation_error(error: SettingsProjectionMutationError) -> Self {
        match error {
            SettingsProjectionMutationError::TenantMismatch => Self::TenantMismatch,
            SettingsProjectionMutationError::SourceEventIdInvalid => Self::SourceEventIdInvalid,
            SettingsProjectionMutationError::ConfigVersionZero => Self::ConfigVersionZero,
            SettingsProjectionMutationError::NumericOutOfRange { field } => {
                Self::NumericOutOfRange { field }
            }
        }
    }
}

/// Metadata mutation construction failed before repository I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SettingsProjectionMutationError {
    #[error("settings projection event tenant does not match apply scope")]
    TenantMismatch,
    #[error("settings projection source event id is invalid")]
    SourceEventIdInvalid,
    #[error("settings projection config version must be positive")]
    ConfigVersionZero,
    #[error("settings projection {field} is outside PostgreSQL bigint range")]
    NumericOutOfRange { field: &'static str },
}

fn ensure_pg_i64(value: u64, field: &'static str) -> Result<(), SettingsProjectionMutationError> {
    i64::try_from(value)
        .map(|_| ())
        .map_err(|_| SettingsProjectionMutationError::NumericOutOfRange { field })
}

/// One restored current-state Settings projection row.
#[derive(Clone)]
pub struct SettingsConfigProjectionRow {
    tenant: vocab::TenantId,
    generation: ProjectionVersion,
    key: SettingKey,
    config_version: u64,
    change_kind: SettingsConfigChangeKind,
    source_event_id: String,
    source_lsn: Lsn,
    source_occurred_at_secs: u64,
    created_at: SystemTime,
    updated_at: SystemTime,
}

impl std::fmt::Debug for SettingsConfigProjectionRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SettingsConfigProjectionRow")
            .field("tenant", &self.tenant)
            .field("generation", &self.generation)
            .field("key", &"<redacted>")
            .field("config_version", &self.config_version)
            .field("change_kind", &self.change_kind)
            .field("source_event_id", &"<redacted>")
            .field("source_lsn", &self.source_lsn)
            .field("source_occurred_at_secs", &self.source_occurred_at_secs)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl SettingsConfigProjectionRow {
    /// Validated hydration funnel for provider adapters.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        tenant: vocab::TenantId,
        generation: ProjectionVersion,
        key: SettingKey,
        config_version: u64,
        change_kind: SettingsConfigChangeKind,
        source_event_id: String,
        source_lsn: Lsn,
        source_occurred_at_secs: u64,
        created_at: SystemTime,
        updated_at: SystemTime,
    ) -> Result<Self, SettingsProjectionRowError> {
        if config_version == 0 {
            return Err(SettingsProjectionRowError::ConfigVersionZero);
        }
        if source_event_id.is_empty() || source_event_id.len() > MAX_SOURCE_EVENT_ID_LEN {
            return Err(SettingsProjectionRowError::SourceEventIdInvalid);
        }
        if created_at > updated_at {
            return Err(SettingsProjectionRowError::TimestampOrderInvalid);
        }
        Ok(Self {
            tenant,
            generation,
            key,
            config_version,
            change_kind,
            source_event_id,
            source_lsn,
            source_occurred_at_secs,
            created_at,
            updated_at,
        })
    }

    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    pub fn generation(&self) -> &ProjectionVersion {
        &self.generation
    }

    pub fn key(&self) -> &SettingKey {
        &self.key
    }

    pub fn config_version(&self) -> u64 {
        self.config_version
    }

    pub fn change_kind(&self) -> SettingsConfigChangeKind {
        self.change_kind
    }

    pub fn source_event_id(&self) -> &str {
        &self.source_event_id
    }

    pub fn source_lsn(&self) -> Lsn {
        self.source_lsn
    }

    pub fn source_occurred_at_secs(&self) -> u64 {
        self.source_occurred_at_secs
    }

    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }

    pub fn updated_at(&self) -> SystemTime {
        self.updated_at
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SettingsProjectionRowError {
    #[error("stored settings projection config version is zero")]
    ConfigVersionZero,
    #[error("stored settings projection source event id is invalid")]
    SourceEventIdInvalid,
    #[error("stored settings projection timestamps are reversed")]
    TimestampOrderInvalid,
}

/// Read-side storage failure with a type-level redacted provider source.
#[derive(Debug, thiserror::Error)]
#[error("settings projection repository read failed")]
pub struct SettingsProjectionRepoError {
    #[source]
    source: diport::RedactedSource,
}

impl SettingsProjectionRepoError {
    pub fn storage<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: diport::RedactedSource::new(source),
        }
    }
}

fn is_canonical_ident(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "fixed projection fixtures fail loudly when generated identities drift"
)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use consistency::{
        EventTopic, ProjectionApplyOutcome, ProjectionEventMetadata, ProjectionEventRecord,
        Projector,
    };
    use eventexec::{
        ConformingProjectionTarget, ProjectionProjector, ProjectionSelector,
        ProjectionTargetDefinition, ProjectionTargetStore, ProjectionTargetStoreError,
        ProjectionTargetStoreOutcome,
    };
    use futures::future::BoxFuture;

    const DIGEST: &str = "sha256:3504a1f33b4e2765fff012fd263ed9a317d24cbe200382c364e4220d7bf05baa";
    const INPUT: &str = "sha256:6ceef61bfb723713a3d27682fb2597b6ed830e4497d97b78c044d9d999130286";

    fn tenant(raw: &str) -> vocab::TenantId {
        vocab::TenantId::parse(raw).expect("fixed tenant")
    }

    fn scope(tenant: vocab::TenantId) -> SettingsProjectionApplyScope {
        SettingsProjectionApplyScope::for_test(
            TenantRepoScope::for_test(tenant),
            ProjectionId::parse(SETTINGS_CONFIG_PROJECTION_ID).expect("fixed projection"),
            ProjectionVersion::parse("test-generation").expect("fixed generation"),
            "v3",
            DIGEST,
            INPUT,
        )
        .expect("fixed scope")
    }

    fn event(tenant: vocab::TenantId, version: u64, occurred_at: u64) -> ConfigVersionChangedEvent {
        ConfigVersionChangedEvent::for_test(
            tenant,
            SettingKey::parse("projection.boundary").expect("fixed key"),
            version,
            SettingsConfigChangeKind::Published,
            occurred_at,
        )
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct AppliedSnapshot {
        tenant: vocab::TenantId,
        generation: String,
        key: String,
        version: u64,
        change_kind: SettingsConfigChangeKind,
        lsn: u64,
        debug: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum ConversionObservation {
        Applied(AppliedSnapshot),
        Rejected(SettingsProjectionApplyError),
    }

    #[derive(Default)]
    struct ConvertingStore {
        observation: Mutex<Option<ConversionObservation>>,
    }

    impl ProjectionTargetStore for ConvertingStore {
        fn apply<'a>(
            &'a self,
            input: &'a ValidatedProjectionApply,
        ) -> BoxFuture<'a, Result<ProjectionTargetStoreOutcome, ProjectionTargetStoreError>>
        {
            let converted = settings_projection_apply_from_validated(input);
            let result = match converted {
                Ok((scope, mutation)) => {
                    let snapshot = AppliedSnapshot {
                        tenant: mutation.tenant(),
                        generation: scope.target_generation().as_str().to_string(),
                        key: mutation.key().as_str().to_string(),
                        version: mutation.config_version(),
                        change_kind: mutation.change_kind(),
                        lsn: mutation.source_lsn().get(),
                        debug: format!("{mutation:?}"),
                    };
                    *self.observation.lock().expect("observation lock") =
                        Some(ConversionObservation::Applied(snapshot));
                    Ok(ProjectionTargetStoreOutcome::Applied)
                }
                Err(error) => {
                    *self.observation.lock().expect("observation lock") =
                        Some(ConversionObservation::Rejected(error));
                    Err(ProjectionTargetStoreError::new(error.reason(), error))
                }
            };
            Box::pin(async move { result })
        }
    }

    struct ApplyFixture {
        definition: vocab::ContractBinding,
        input_generation: &'static str,
        binding: vocab::ProjectionInputBinding,
        selector_tenant: vocab::TenantId,
        metadata_tenant: vocab::TenantId,
        envelope_tenant: serde_json::Value,
        topic: &'static str,
        payload: Vec<u8>,
        lsn: u64,
    }

    impl ApplyFixture {
        fn canonical(payload: Vec<u8>) -> Self {
            let tenant = tenant("018f5d8a-7b6c-7d2e-8a1b-1234567890aa");
            Self {
                definition: generated::projection::settings_v3::CONTRACT,
                input_generation: generated::event::PROJECTION_INPUT_GENERATION,
                binding: generated::event::PROJECTION_INPUTS[1],
                selector_tenant: tenant,
                metadata_tenant: tenant,
                envelope_tenant: serde_json::json!(tenant.to_string()),
                topic: generated::event::settings_v1::TOPIC,
                payload,
                lsn: 17,
            }
        }

        async fn run(
            self,
        ) -> (
            Result<ProjectionApplyOutcome, consistency::ProjectionApplyError>,
            Option<ConversionObservation>,
        ) {
            let binding_contract = self.binding.contract();
            let metadata = ProjectionEventMetadata::new(
                self.metadata_tenant,
                "event-super-secret",
                binding_contract.domain(),
                binding_contract.contract_id(),
                binding_contract.version(),
                binding_contract.schema_hash(),
                serde_json::json!({diport::KEY_TENANT_ID: self.envelope_tenant}),
                None,
                None,
            );
            let event = ProjectionEventRecord::with_metadata(
                Lsn::new(self.lsn),
                EventTopic::parse(self.topic).expect("fixture topic"),
                self.payload,
                metadata,
            );
            let definition =
                ProjectionTargetDefinition::new(self.definition, self.input_generation)
                    .expect("fixture definition");
            let store = Arc::new(ConvertingStore::default());
            let target =
                ConformingProjectionTarget::new(definition, vec![self.binding], Arc::clone(&store))
                    .expect("fixture target");
            let selector = ProjectionSelector::new(
                self.selector_tenant,
                ProjectionId::parse(SETTINGS_CONFIG_PROJECTION_ID).expect("projection"),
                ProjectionVersion::parse("shadow-generation").expect("generation"),
            );
            let execution =
                eventexec::WorkflowRuntimePlan::generated_projection_operator_execution_fixture(
                    selector.projection(),
                    selector.tenant(),
                )
                .expect("generated Settings projection execution");
            let projector =
                ProjectionProjector::with_execution(execution, selector, Arc::new(target))
                    .expect("plan-issued execution matches Settings selector");
            let result = projector.apply(&event).await;
            let observation = store.observation.lock().expect("observation lock").clone();
            (result, observation)
        }
    }

    fn payload(
        tenant: vocab::TenantId,
        change_kind: &str,
        version: serde_json::Value,
        occurred_at: serde_json::Value,
    ) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "tenantId": tenant.to_string(),
            "key": "projection.internal-key",
            "version": version,
            "changeKind": change_kind,
            "occurredAt": occurred_at,
        }))
        .expect("payload")
    }

    #[tokio::test]
    async fn validated_conversion_accepts_all_change_kinds_and_redacts_debug() {
        let tenant = tenant("018f5d8a-7b6c-7d2e-8a1b-1234567890aa");
        for (wire, expected) in [
            ("published", SettingsConfigChangeKind::Published),
            ("rolledBack", SettingsConfigChangeKind::RolledBack),
            ("deleted", SettingsConfigChangeKind::Deleted),
        ] {
            let (result, observation) =
                ApplyFixture::canonical(payload(tenant, wire, 3.into(), 9.into()))
                    .run()
                    .await;
            assert_eq!(
                result.expect("valid conversion"),
                ProjectionApplyOutcome::Applied
            );
            let Some(ConversionObservation::Applied(snapshot)) = observation else {
                panic!("conversion must reach the typed store")
            };
            assert_eq!(snapshot.tenant, tenant);
            assert_eq!(snapshot.generation, "shadow-generation");
            assert_eq!(snapshot.version, 3);
            assert_eq!(snapshot.change_kind, expected);
            assert_eq!(snapshot.lsn, 17);
            assert!(!snapshot.debug.contains("projection.internal-key"));
            assert!(!snapshot.debug.contains("event-super-secret"));
            assert!(!snapshot.debug.contains(&"07".repeat(32)));
        }
    }

    #[tokio::test]
    async fn conversion_rejects_definition_input_and_source_binding_drift_as_invariant() {
        let tenant = tenant("018f5d8a-7b6c-7d2e-8a1b-1234567890aa");
        let body = || payload(tenant, "published", 1.into(), 1.into());
        let alternate_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut cases = Vec::new();

        let mut definition = ApplyFixture::canonical(body());
        definition.definition = vocab::ContractBinding::from_static(
            "settings",
            SETTINGS_CONFIG_PROJECTION_ID,
            "v4",
            generated::projection::settings_v3::CONTRACT.schema_hash(),
        );
        cases.push(definition);

        let mut generation = ApplyFixture::canonical(body());
        generation.input_generation = alternate_digest;
        cases.push(generation);

        for binding in [
            vocab::ProjectionInputBinding::from_static(
                SETTINGS_CONFIG_PROJECTION_ID,
                "other",
                generated::event::settings_v1::CONTRACT_ID,
                generated::event::settings_v1::CONTRACT.version(),
                generated::event::settings_v1::CONTRACT.schema_hash(),
                generated::event::settings_v1::TOPIC,
            ),
            vocab::ProjectionInputBinding::from_static(
                SETTINGS_CONFIG_PROJECTION_ID,
                "settings",
                "settings.other-event",
                "v1",
                generated::event::settings_v1::CONTRACT.schema_hash(),
                generated::event::settings_v1::TOPIC,
            ),
            vocab::ProjectionInputBinding::from_static(
                SETTINGS_CONFIG_PROJECTION_ID,
                "settings",
                generated::event::settings_v1::CONTRACT_ID,
                "v2",
                generated::event::settings_v1::CONTRACT.schema_hash(),
                generated::event::settings_v1::TOPIC,
            ),
            vocab::ProjectionInputBinding::from_static(
                SETTINGS_CONFIG_PROJECTION_ID,
                "settings",
                generated::event::settings_v1::CONTRACT_ID,
                generated::event::settings_v1::CONTRACT.version(),
                alternate_digest,
                generated::event::settings_v1::TOPIC,
            ),
            vocab::ProjectionInputBinding::from_static(
                SETTINGS_CONFIG_PROJECTION_ID,
                "settings",
                generated::event::settings_v1::CONTRACT_ID,
                generated::event::settings_v1::CONTRACT.version(),
                generated::event::settings_v1::CONTRACT.schema_hash(),
                "settings.other-event",
            ),
        ] {
            let mut source = ApplyFixture::canonical(body());
            source.topic = binding.topic();
            source.binding = binding;
            cases.push(source);
        }

        for case in cases {
            let (result, observation) = case.run().await;
            assert_eq!(
                result.expect_err("identity drift").kind(),
                ProjectionApplyErrorKind::Invariant
            );
            assert!(matches!(
                observation,
                Some(ConversionObservation::Rejected(
                    SettingsProjectionApplyError::TargetIdentityMismatch
                        | SettingsProjectionApplyError::InputGenerationMismatch
                        | SettingsProjectionApplyError::SourceBindingMismatch
                ))
            ));
        }
    }

    #[tokio::test]
    async fn conversion_rejects_selector_envelope_and_payload_tenant_drift() {
        let tenant_a = tenant("018f5d8a-7b6c-7d2e-8a1b-1234567890aa");
        let tenant_b = tenant("018f5d8a-7b6c-7d2e-8a1b-1234567890ab");

        let mut selector_drift =
            ApplyFixture::canonical(payload(tenant_a, "published", 1.into(), 1.into()));
        selector_drift.metadata_tenant = tenant_b;
        let (result, observation) = selector_drift.run().await;
        assert_eq!(
            result.expect_err("selector drift").kind(),
            ProjectionApplyErrorKind::Invariant
        );
        assert!(
            observation.is_none(),
            "generic funnel must reject before store I/O"
        );

        let mut envelope_drift =
            ApplyFixture::canonical(payload(tenant_a, "published", 1.into(), 1.into()));
        envelope_drift.envelope_tenant = serde_json::json!(tenant_b.to_string());
        let (result, observation) = envelope_drift.run().await;
        assert_eq!(
            result.expect_err("envelope drift").kind(),
            ProjectionApplyErrorKind::Invariant
        );
        assert_eq!(
            observation,
            Some(ConversionObservation::Rejected(
                SettingsProjectionApplyError::TenantMismatch
            ))
        );

        let payload_drift =
            ApplyFixture::canonical(payload(tenant_b, "published", 1.into(), 1.into()));
        let (result, observation) = payload_drift.run().await;
        assert_eq!(
            result.expect_err("payload drift").kind(),
            ProjectionApplyErrorKind::Invariant
        );
        assert_eq!(
            observation,
            Some(ConversionObservation::Rejected(
                SettingsProjectionApplyError::TenantMismatch
            ))
        );
    }

    #[tokio::test]
    async fn legal_binding_payload_failures_are_permanent() {
        let tenant = tenant("018f5d8a-7b6c-7d2e-8a1b-1234567890aa");
        let cases = [
            (b"not-json".to_vec(), SettingsProjectionApplyError::PayloadMalformed),
            (
                br#"{"tenantId":"018f5d8a-7b6c-7d2e-8a1b-1234567890aa","key":"projection.key","version":1,"changeKind":"published","occurredAt":1,"unknown":true}"#.to_vec(),
                SettingsProjectionApplyError::PayloadMalformed,
            ),
            (
                payload(tenant, "published", (-1).into(), 1.into()),
                SettingsProjectionApplyError::PayloadNumericNegative,
            ),
            (
                payload(tenant, "published", 0.into(), 1.into()),
                SettingsProjectionApplyError::ConfigVersionZero,
            ),
            (
                payload(tenant, "published", 1.into(), (-1).into()),
                SettingsProjectionApplyError::PayloadNumericNegative,
            ),
            (
                br#"{"tenantId":"018f5d8a-7b6c-7d2e-8a1b-1234567890aa","key":"projection.key","version":9223372036854775808,"changeKind":"published","occurredAt":1}"#.to_vec(),
                SettingsProjectionApplyError::PayloadMalformed,
            ),
            (
                serde_json::to_vec(&serde_json::json!({
                    "tenantId": tenant.to_string(),
                    "key": "",
                    "version": 1,
                    "changeKind": "published",
                    "occurredAt": 1,
                }))
                .expect("invalid-key payload"),
                SettingsProjectionApplyError::PayloadKeyInvalid,
            ),
        ];

        for (body, expected) in cases {
            let (result, observation) = ApplyFixture::canonical(body).run().await;
            assert_eq!(
                result.expect_err("permanent payload").kind(),
                ProjectionApplyErrorKind::Permanent
            );
            assert_eq!(observation, Some(ConversionObservation::Rejected(expected)));
        }

        let mut lsn_overflow =
            ApplyFixture::canonical(payload(tenant, "published", 1.into(), 1.into()));
        lsn_overflow.lsn = i64::MAX as u64 + 1;
        let (result, observation) = lsn_overflow.run().await;
        assert_eq!(
            result.expect_err("lsn overflow").kind(),
            ProjectionApplyErrorKind::Permanent
        );
        assert_eq!(
            observation,
            Some(ConversionObservation::Rejected(
                SettingsProjectionApplyError::NumericOutOfRange {
                    field: "source_lsn"
                }
            ))
        );
    }

    #[test]
    fn exact_settings_failures_map_to_distinct_operator_reasons() {
        let cases = [
            (
                SettingsProjectionApplyError::TargetIdentityMismatch,
                ProjectionApplyErrorReason::TargetDefinitionDrift,
            ),
            (
                SettingsProjectionApplyError::TenantMismatch,
                ProjectionApplyErrorReason::TenantDrift,
            ),
            (
                SettingsProjectionApplyError::PayloadMalformed,
                ProjectionApplyErrorReason::PayloadMalformed,
            ),
            (
                SettingsProjectionApplyError::PayloadKeyInvalid,
                ProjectionApplyErrorReason::PayloadValueInvalid,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.reason(), expected);
        }
    }

    #[test]
    fn apply_scope_validation_rejects_each_invalid_identity_class() {
        struct Case {
            name: &'static str,
            projection: &'static str,
            definition_version: &'static str,
            definition_digest: &'static str,
            input_generation: &'static str,
            expected: SettingsProjectionScopeError,
        }

        let uppercase_digest =
            "sha256:3504A1f33b4e2765fff012fd263ed9a317d24cbe200382c364e4220d7bf05baa";
        let non_hex_digest =
            "sha256:3504g1f33b4e2765fff012fd263ed9a317d24cbe200382c364e4220d7bf05baa";
        let cases = [
            Case {
                name: "projection mismatch",
                projection: "settings.other-projection",
                definition_version: "v3",
                definition_digest: DIGEST,
                input_generation: INPUT,
                expected: SettingsProjectionScopeError::ProjectionMismatch,
            },
            Case {
                name: "empty definition version",
                projection: SETTINGS_CONFIG_PROJECTION_ID,
                definition_version: "",
                definition_digest: DIGEST,
                input_generation: INPUT,
                expected: SettingsProjectionScopeError::DefinitionVersionInvalid,
            },
            Case {
                name: "non-canonical definition version",
                projection: SETTINGS_CONFIG_PROJECTION_ID,
                definition_version: "v/3",
                definition_digest: DIGEST,
                input_generation: INPUT,
                expected: SettingsProjectionScopeError::DefinitionVersionInvalid,
            },
            Case {
                name: "short definition digest",
                projection: SETTINGS_CONFIG_PROJECTION_ID,
                definition_version: "v3",
                definition_digest: "sha256:00",
                input_generation: INPUT,
                expected: SettingsProjectionScopeError::DefinitionDigestInvalid,
            },
            Case {
                name: "uppercase definition digest",
                projection: SETTINGS_CONFIG_PROJECTION_ID,
                definition_version: "v3",
                definition_digest: uppercase_digest,
                input_generation: INPUT,
                expected: SettingsProjectionScopeError::DefinitionDigestInvalid,
            },
            Case {
                name: "non-hex definition digest",
                projection: SETTINGS_CONFIG_PROJECTION_ID,
                definition_version: "v3",
                definition_digest: non_hex_digest,
                input_generation: INPUT,
                expected: SettingsProjectionScopeError::DefinitionDigestInvalid,
            },
            Case {
                name: "invalid input generation",
                projection: SETTINGS_CONFIG_PROJECTION_ID,
                definition_version: "v3",
                definition_digest: DIGEST,
                input_generation: "sha256:00",
                expected: SettingsProjectionScopeError::InputGenerationInvalid,
            },
        ];

        for case in cases {
            let result = SettingsProjectionApplyScope::validated(
                TenantRepoScope::for_test(tenant("018f5d8a-7b6c-7d2e-8a1b-1234567890aa")),
                ProjectionId::parse(case.projection).expect(case.name),
                ProjectionVersion::parse("test-generation").expect("fixed generation"),
                case.definition_version,
                case.definition_digest,
                case.input_generation,
            );
            assert_eq!(result.unwrap_err(), case.expected, "{}", case.name);
        }
    }

    #[test]
    fn apply_scope_validation_accepts_minimal_canonical_boundaries() {
        let zero_digest = format!("sha256:{}", "0".repeat(64));
        let scope = SettingsProjectionApplyScope::validated(
            TenantRepoScope::for_test(tenant("018f5d8a-7b6c-7d2e-8a1b-1234567890aa")),
            ProjectionId::parse(SETTINGS_CONFIG_PROJECTION_ID).expect("fixed projection"),
            ProjectionVersion::parse("g").expect("minimal generation"),
            "a",
            &zero_digest,
            &zero_digest,
        )
        .expect("minimal canonical identities must be accepted");

        assert_eq!(scope.definition_version(), "a");
        assert_eq!(scope.definition_schema_digest().as_str(), zero_digest);
        assert_eq!(scope.input_generation().as_str(), zero_digest);
    }

    #[test]
    fn mutation_funnel_rejects_tenant_event_id_and_bigint_boundary_violations() {
        let tenant_a = tenant("018f5d8a-7b6c-7d2e-8a1b-1234567890aa");
        let tenant_b = tenant("018f5d8a-7b6c-7d2e-8a1b-1234567890ab");
        let scope = scope(tenant_a);
        let valid = |event, event_id: &str, lsn| {
            SettingsProjectionMutation::from_event(&scope, event, event_id, Lsn::new(lsn), [7; 32])
        };

        assert_eq!(
            valid(event(tenant_b, 1, 1), "event", 1).unwrap_err(),
            SettingsProjectionMutationError::TenantMismatch
        );
        assert_eq!(
            valid(event(tenant_a, 1, 1), "", 1).unwrap_err(),
            SettingsProjectionMutationError::SourceEventIdInvalid
        );
        assert_eq!(
            valid(
                event(tenant_a, 1, 1),
                &"x".repeat(MAX_SOURCE_EVENT_ID_LEN + 1),
                1,
            )
            .unwrap_err(),
            SettingsProjectionMutationError::SourceEventIdInvalid
        );
        assert_eq!(
            valid(event(tenant_a, 0, 1), "event", 1).unwrap_err(),
            SettingsProjectionMutationError::ConfigVersionZero
        );
        for (result, field) in [
            (
                valid(event(tenant_a, i64::MAX as u64 + 1, 1), "event", 1),
                "config_version",
            ),
            (
                valid(event(tenant_a, 1, 1), "event", i64::MAX as u64 + 1),
                "source_lsn",
            ),
            (
                valid(event(tenant_a, 1, i64::MAX as u64 + 1), "event", 1),
                "source_occurred_at_secs",
            ),
        ] {
            assert_eq!(
                result.unwrap_err(),
                SettingsProjectionMutationError::NumericOutOfRange { field }
            );
        }
        assert!(
            valid(
                event(tenant_a, i64::MAX as u64, i64::MAX as u64),
                "event",
                i64::MAX as u64,
            )
            .is_ok()
        );
    }
}
