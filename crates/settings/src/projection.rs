//! Tenant-scoped, metadata-only persistence vocabulary for `settings.config-projection`.
//!
//! The types in this module deliberately cannot carry configuration values or encoded event
//! payloads. Production scopes are minted only from authenticated tenant authority and the sealed
//! projection source identity; PostgreSQL adapters may inspect them but cannot mint them.
//!
//! INVARIANT: SETTINGS-PROJECTION-SCOPE-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields; read scope minted from TenantRepoScope; apply scope minted from ProjectionSourceScope; compile-fail fixtures reject bare tenant, selector, and struct-literal construction" }
//! INVARIANT: SETTINGS-PROJECTION-METADATA-ONLY-01 { level = "Hard", exec = "native-compile", source = "code", native = "SettingsProjectionMutation and SettingsConfigProjectionRow expose an exact metadata-only field set with no payload or ConfigValue member" }

use std::time::SystemTime;

use consistency::Lsn;
use eventexec::{ProjectionId, ProjectionSourceScope, ProjectionVersion};
use generated::event::settings_v1::SettingsConfigChangeKind;

use crate::application::ConfigVersionChangedEvent;
use crate::domain::SettingKey;
use crate::ports::TenantRepoScope;

const MAX_SOURCE_EVENT_ID_LEN: usize = 512;

/// Canonical Settings metadata projection id from the generated workflow contract.
pub const SETTINGS_CONFIG_PROJECTION_ID: &str = generated::http::settings_v3::CONTRACT_ID;

/// Tenant capability plus one materialized projection generation for read-only serving.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsProjectionReadScope {
    tenant: TenantRepoScope,
    generation: ProjectionVersion,
    _seal: (),
}

impl SettingsProjectionReadScope {
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "domain-internal mint is delivered by #1918 before #1919 target activation"
        )
    )]
    pub(crate) fn from_tenant_generation(
        tenant: TenantRepoScope,
        generation: ProjectionVersion,
    ) -> Self {
        Self {
            tenant,
            generation,
            _seal: (),
        }
    }

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
        Self::from_tenant_generation(tenant, generation)
    }
}

/// Tenant, definition, input generation, and target generation bound apply authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsProjectionApplyScope {
    tenant: TenantRepoScope,
    projection: ProjectionId,
    target_generation: ProjectionVersion,
    definition_version: Box<str>,
    definition_schema_digest: Box<str>,
    input_generation: Box<str>,
    _seal: (),
}

impl SettingsProjectionApplyScope {
    pub fn from_source_scope(
        source: &ProjectionSourceScope,
        target_generation: ProjectionVersion,
    ) -> Result<Self, SettingsProjectionScopeError> {
        Self::validated(
            TenantRepoScope::from_authenticated_tenant(source.tenant()),
            source.projection().clone(),
            target_generation,
            source.definition_version(),
            source.definition_schema_digest(),
            source.input_generation(),
        )
    }

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
        if !is_sha256_identity(definition_schema_digest) {
            return Err(SettingsProjectionScopeError::DefinitionDigestInvalid);
        }
        if !is_sha256_identity(input_generation) {
            return Err(SettingsProjectionScopeError::InputGenerationInvalid);
        }
        Ok(Self {
            tenant,
            projection,
            target_generation,
            definition_version: definition_version.into(),
            definition_schema_digest: definition_schema_digest.into(),
            input_generation: input_generation.into(),
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
    pub fn definition_schema_digest(&self) -> &str {
        &self.definition_schema_digest
    }

    /// Exact generated projection input binding generation.
    pub fn input_generation(&self) -> &str {
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
    pub fn from_event(
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

fn is_sha256_identity(value: &str) -> bool {
    value.len() == 71
        && value.strip_prefix("sha256:").is_some_and(|hex| {
            hex.bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(scope.definition_schema_digest(), zero_digest);
        assert_eq!(scope.input_generation(), zero_digest);
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
