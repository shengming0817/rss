//! Consistency crash matrix fixture DSL.
//!
//! The DSL is a provider-agnostic description of crash recovery cases. It is
//! intentionally data-only: ready cases are parsed and validated here, while
//! opt-in journeys execute the real-backend fault scenarios.
//!
//! ref: risinglightdb/sqllogictest-rs sqllogictest/src/parser.rs@ebab8dae6d6655e86a4793c70246df6fbaa80ecb

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const MAX_ALIAS_LEN: usize = 128;
const LONG_MATERIAL_MIN: usize = 32;

/// Crash fixture parsing and validation errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CrashFixtureError {
    /// TOML parsing failed.
    #[error("parse crash fixture failed: {0}")]
    Parse(#[from] toml::de::Error),
    /// Filesystem discovery failed.
    #[error("read crash fixture failed: {0}")]
    Io(String),
    /// Fixture content violates the DSL contract.
    #[error("invalid crash fixture {subject}: {detail}")]
    Invalid { subject: String, detail: String },
}

fn invalid(subject: impl Into<String>, detail: impl Into<String>) -> CrashFixtureError {
    CrashFixtureError::Invalid {
        subject: subject.into(),
        detail: detail.into(),
    }
}

/// Consistency level targeted by a crash fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[non_exhaustive]
pub enum CrashLevel {
    #[serde(rename = "L0")]
    L0,
    #[serde(rename = "L1")]
    L1,
    #[serde(rename = "L2")]
    L2,
    #[serde(rename = "L3")]
    L3,
    #[serde(rename = "L4")]
    L4,
}

/// Consistency mechanism targeted by a crash fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CrashMechanism {
    Outbox,
    Inbox,
    Saga,
    Projection,
    Reconcile,
}

/// Fixture lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CrashStatus {
    /// Parsed and indexed but not executed by the fault matrix runner.
    Pending,
    /// Executed by the opt-in fault matrix runner.
    Ready,
}

/// Real backend runner required by a crash fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CrashRunner {
    Postgres,
    Rabbitmq,
    PostgresRabbitmq,
    PostgresRedis,
}

/// Closed semantic fault covered by the consistency crash matrix.
///
/// # INVARIANT: CONSISTENCY-FAULT-SPEC-01 { level = "Hard", exec = "native-compile", source = "code", native = "closed enum plus parser make executable fault ids compile-time named variants instead of free-form strings" }
///
/// Ready-case runners bind this enum, not free-form `crashPoint` / `expectedInvariant`
/// strings. Adding a new executable fault therefore requires extending this closed type and the
/// parser below; a typo cannot silently become a runtime-only mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CrashFaultSpec {
    OutboxAfterPublishBeforeSettle,
    OutboxTransientPublishFailure,
    OutboxAmbiguousPublishFailure,
    OutboxPermanentPublishFailure,
    InboxClaimCrashBeforeCommit,
    InboxCommitBeforeAckCrash,
    InboxLeaseLostBeforeCommit,
    SagaForwardCompletedBeforeCheckpoint,
    SagaCompensationInterrupted,
    ProjectionAfterApplyBeforeCheckpoint,
    ProjectionStaleCheckpointWriter,
    ReconcileDispatchBeforeResultRecord,
    ReconcileLeaseLostBeforeWrite,
}

impl CrashFaultSpec {
    /// Derive the closed fault spec from the provider-agnostic fixture fields.
    pub fn from_parts(
        mechanism: CrashMechanism,
        crash_point: &str,
        expected_invariant: &str,
    ) -> Option<Self> {
        match (mechanism, crash_point, expected_invariant) {
            (
                CrashMechanism::Outbox,
                "after-publish-before-settle",
                "outbox-publish-settled-once",
            ) => Some(Self::OutboxAfterPublishBeforeSettle),
            (
                CrashMechanism::Outbox,
                "during-transient-publish",
                "outbox-transient-remains-retryable",
            ) => Some(Self::OutboxTransientPublishFailure),
            (
                CrashMechanism::Outbox,
                "during-ambiguous-publish",
                "outbox-ambiguous-stable-id-budget-dlx",
            ) => Some(Self::OutboxAmbiguousPublishFailure),
            (CrashMechanism::Outbox, "during-permanent-publish", "outbox-dlx-summary-redacted") => {
                Some(Self::OutboxPermanentPublishFailure)
            }
            (
                CrashMechanism::Inbox,
                "after-claim-before-commit",
                "inbox-stale-claim-reclaimable",
            ) => Some(Self::InboxClaimCrashBeforeCommit),
            (CrashMechanism::Inbox, "after-commit-before-ack", "inbox-redelivery-dedupes-once") => {
                Some(Self::InboxCommitBeforeAckCrash)
            }
            (
                CrashMechanism::Inbox,
                "lease-lost-before-commit",
                "inbox-stale-lease-cannot-commit",
            ) => Some(Self::InboxLeaseLostBeforeCommit),
            (
                CrashMechanism::Saga,
                "after-forward-before-checkpoint",
                "saga-resume-skips-completed-step",
            ) => Some(Self::SagaForwardCompletedBeforeCheckpoint),
            (CrashMechanism::Saga, "during-compensation", "saga-compensation-resumes-once") => {
                Some(Self::SagaCompensationInterrupted)
            }
            (
                CrashMechanism::Projection,
                "after-apply-before-checkpoint",
                "projection-replay-idempotent",
            ) => Some(Self::ProjectionAfterApplyBeforeCheckpoint),
            (
                CrashMechanism::Projection,
                "stale-checkpoint-writer",
                "projection-stale-writer-rejected",
            ) => Some(Self::ProjectionStaleCheckpointWriter),
            (
                CrashMechanism::Reconcile,
                "after-dispatch-before-result-record",
                "reconcile-dispatch-key-stable",
            ) => Some(Self::ReconcileDispatchBeforeResultRecord),
            (
                CrashMechanism::Reconcile,
                "lease-lost-before-write",
                "reconcile-stale-writer-rejected",
            ) => Some(Self::ReconcileLeaseLostBeforeWrite),
            _ => None,
        }
    }

    /// Parse a Rust enum variant spelling from the journey runner table.
    pub fn from_rust_variant(value: &str) -> Option<Self> {
        match value {
            "OutboxAfterPublishBeforeSettle" => Some(Self::OutboxAfterPublishBeforeSettle),
            "OutboxTransientPublishFailure" => Some(Self::OutboxTransientPublishFailure),
            "OutboxAmbiguousPublishFailure" => Some(Self::OutboxAmbiguousPublishFailure),
            "OutboxPermanentPublishFailure" => Some(Self::OutboxPermanentPublishFailure),
            "InboxClaimCrashBeforeCommit" => Some(Self::InboxClaimCrashBeforeCommit),
            "InboxCommitBeforeAckCrash" => Some(Self::InboxCommitBeforeAckCrash),
            "InboxLeaseLostBeforeCommit" => Some(Self::InboxLeaseLostBeforeCommit),
            "SagaForwardCompletedBeforeCheckpoint" => {
                Some(Self::SagaForwardCompletedBeforeCheckpoint)
            }
            "SagaCompensationInterrupted" => Some(Self::SagaCompensationInterrupted),
            "ProjectionAfterApplyBeforeCheckpoint" => {
                Some(Self::ProjectionAfterApplyBeforeCheckpoint)
            }
            "ProjectionStaleCheckpointWriter" => Some(Self::ProjectionStaleCheckpointWriter),
            "ReconcileDispatchBeforeResultRecord" => {
                Some(Self::ReconcileDispatchBeforeResultRecord)
            }
            "ReconcileLeaseLostBeforeWrite" => Some(Self::ReconcileLeaseLostBeforeWrite),
            _ => None,
        }
    }

    /// Expected real-backend runner for this closed fault.
    pub fn expected_runner(self) -> CrashRunner {
        match self {
            Self::OutboxAfterPublishBeforeSettle | Self::InboxCommitBeforeAckCrash => {
                CrashRunner::PostgresRabbitmq
            }
            Self::SagaForwardCompletedBeforeCheckpoint | Self::SagaCompensationInterrupted => {
                CrashRunner::PostgresRedis
            }
            Self::OutboxTransientPublishFailure
            | Self::OutboxAmbiguousPublishFailure
            | Self::OutboxPermanentPublishFailure
            | Self::InboxClaimCrashBeforeCommit
            | Self::InboxLeaseLostBeforeCommit
            | Self::ProjectionAfterApplyBeforeCheckpoint
            | Self::ProjectionStaleCheckpointWriter
            | Self::ReconcileDispatchBeforeResultRecord
            | Self::ReconcileLeaseLostBeforeWrite => CrashRunner::Postgres,
        }
    }
}

/// State of broker tenant authority represented by a fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum TenantAuthorityState {
    Valid,
    Missing,
    Invalid,
    Expired,
    Mismatch,
}

/// One consistency crash fixture case.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashCase {
    #[serde(rename = "schemaVersion")]
    schema_version: u16,
    id: String,
    title: String,
    level: CrashLevel,
    mechanism: CrashMechanism,
    status: CrashStatus,
    #[serde(rename = "pendingReason")]
    pending_reason: Option<String>,
    domain: String,
    #[serde(rename = "contractId")]
    contract_id: String,
    #[serde(rename = "tenantAlias")]
    tenant_alias: String,
    #[serde(rename = "messageAlias")]
    message_alias: String,
    #[serde(rename = "partitionKeyAlias")]
    partition_key_alias: String,
    #[serde(rename = "tenantAuthority")]
    tenant_authority: TenantAuthorityState,
    #[serde(rename = "crashPoint")]
    crash_point: String,
    #[serde(rename = "expectedInvariant")]
    expected_invariant: String,
    runner: CrashRunner,
}

impl CrashCase {
    /// Parse and validate a single TOML fixture case.
    pub fn from_toml_str(src: &str) -> Result<Self, CrashFixtureError> {
        validate_raw_toml_safety(src)?;
        let case: Self = toml::from_str(src)?;
        case.validate()?;
        Ok(case)
    }

    /// Fixture schema version. Version 1 is the only accepted version.
    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Stable case id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Human-readable title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Consistency level.
    pub fn level(&self) -> CrashLevel {
        self.level
    }

    /// Consistency mechanism.
    pub fn mechanism(&self) -> CrashMechanism {
        self.mechanism
    }

    /// Fixture lifecycle status.
    pub fn status(&self) -> CrashStatus {
        self.status
    }

    /// Pending reason when status is pending.
    pub fn pending_reason(&self) -> Option<&str> {
        self.pending_reason.as_deref()
    }

    /// Owning domain for the referenced contract.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Contract id whose consistency capability is verified by the case.
    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    /// Redacted tenant alias.
    pub fn tenant_alias(&self) -> &str {
        &self.tenant_alias
    }

    /// Redacted message alias.
    pub fn message_alias(&self) -> &str {
        &self.message_alias
    }

    /// Redacted partition key alias.
    pub fn partition_key_alias(&self) -> &str {
        &self.partition_key_alias
    }

    /// Tenant authority state represented by this case.
    pub fn tenant_authority(&self) -> TenantAuthorityState {
        self.tenant_authority
    }

    /// Crash point slug.
    pub fn crash_point(&self) -> &str {
        &self.crash_point
    }

    /// Expected invariant slug asserted by the real-backend runner.
    pub fn expected_invariant(&self) -> &str {
        &self.expected_invariant
    }

    /// Real backend runner required by this case.
    pub fn runner(&self) -> CrashRunner {
        self.runner
    }

    /// Closed fault spec derived from the fixture's data-only DSL fields.
    pub fn fault_spec(&self) -> Result<CrashFaultSpec, CrashFixtureError> {
        CrashFaultSpec::from_parts(self.mechanism, &self.crash_point, &self.expected_invariant)
            .ok_or_else(|| {
                invalid(
                    &self.id,
                    "crashPoint/expectedInvariant must map to a closed CrashFaultSpec",
                )
            })
    }

    fn validate(&self) -> Result<(), CrashFixtureError> {
        if self.schema_version != 1 {
            return Err(invalid(
                &self.id,
                format!("schemaVersion must be 1, got {}", self.schema_version),
            ));
        }
        validate_slug("id", &self.id, &self.id)?;
        validate_nonempty("title", &self.title, &self.id)?;
        validate_domain_name("domain", &self.domain, &self.id)?;
        validate_dotted("contractId", &self.contract_id, &self.id)?;
        validate_alias("tenantAlias", &self.tenant_alias, &self.id)?;
        validate_alias("messageAlias", &self.message_alias, &self.id)?;
        validate_alias("partitionKeyAlias", &self.partition_key_alias, &self.id)?;
        validate_slug("crashPoint", &self.crash_point, &self.id)?;
        validate_slug("expectedInvariant", &self.expected_invariant, &self.id)?;
        validate_mechanism_level(self)?;
        if CrashFaultSpec::from_parts(self.mechanism, &self.crash_point, &self.expected_invariant)
            .is_none()
        {
            return Err(invalid(
                &self.id,
                "crashPoint/expectedInvariant must map to a closed CrashFaultSpec",
            ));
        }
        match self.status {
            CrashStatus::Pending => {
                let Some(reason) = self.pending_reason.as_deref() else {
                    return Err(invalid(
                        &self.id,
                        "pendingReason is required for pending cases",
                    ));
                };
                validate_nonempty("pendingReason", reason, &self.id)?;
            }
            CrashStatus::Ready => {
                if self.pending_reason.is_some() {
                    return Err(invalid(
                        &self.id,
                        "pendingReason is only allowed when status is pending",
                    ));
                }
            }
        }
        self.validate_no_sensitive_values()
    }

    fn validate_no_sensitive_values(&self) -> Result<(), CrashFixtureError> {
        for (field, value) in [
            ("id", self.id.as_str()),
            ("title", self.title.as_str()),
            (
                "pendingReason",
                self.pending_reason.as_deref().unwrap_or(""),
            ),
            ("domain", self.domain.as_str()),
            ("contractId", self.contract_id.as_str()),
            ("tenantAlias", self.tenant_alias.as_str()),
            ("messageAlias", self.message_alias.as_str()),
            ("partitionKeyAlias", self.partition_key_alias.as_str()),
            ("crashPoint", self.crash_point.as_str()),
            ("expectedInvariant", self.expected_invariant.as_str()),
        ] {
            if looks_sensitive(value) {
                return Err(invalid(
                    &self.id,
                    format!("{field} contains a secret-like or PII-like value"),
                ));
            }
        }
        Ok(())
    }
}

/// A validated collection of crash cases.
#[derive(Debug, Clone)]
pub struct CrashMatrix {
    cases: Vec<CrashCase>,
}

impl CrashMatrix {
    /// Validate uniqueness and construct a matrix.
    pub fn new(cases: Vec<CrashCase>) -> Result<Self, CrashFixtureError> {
        let mut ids = BTreeSet::new();
        for case in &cases {
            if !ids.insert(case.id.clone()) {
                return Err(invalid(
                    &case.id,
                    format!("duplicate crash fixture id `{}`", case.id),
                ));
            }
        }
        Ok(Self { cases })
    }

    /// Discover and parse `fixture-*.toml` files under a directory.
    pub fn from_fixture_dir(dir: impl AsRef<Path>) -> Result<Self, CrashFixtureError> {
        let dir = dir.as_ref();
        let mut files = Vec::new();
        collect_fixture_files(dir, &mut files)?;
        if files.is_empty() {
            return Err(invalid(
                dir.display().to_string(),
                "no fixture-*.toml files found",
            ));
        }
        files.sort();

        let mut cases = Vec::with_capacity(files.len());
        for path in files {
            let src = std::fs::read_to_string(&path)
                .map_err(|e| CrashFixtureError::Io(format!("{}: {e}", path.display())))?;
            let case = CrashCase::from_toml_str(&src)
                .map_err(|e| invalid(path.display().to_string(), e.to_string()))?;
            cases.push(case);
        }
        Self::new(cases)
    }

    /// Borrow all validated cases.
    pub fn cases(&self) -> &[CrashCase] {
        &self.cases
    }

    /// Count pending cases.
    pub fn pending_count(&self) -> usize {
        self.cases
            .iter()
            .filter(|case| case.status == CrashStatus::Pending)
            .count()
    }

    /// Count executable ready cases.
    pub fn ready_count(&self) -> usize {
        self.cases
            .iter()
            .filter(|case| case.status == CrashStatus::Ready)
            .count()
    }
}

fn collect_fixture_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), CrashFixtureError> {
    if !dir.is_dir() {
        return Err(CrashFixtureError::Io(format!(
            "fixture directory {} does not exist",
            dir.display()
        )));
    }
    let entries = std::fs::read_dir(dir)
        .map_err(|e| CrashFixtureError::Io(format!("{}: {e}", dir.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| CrashFixtureError::Io(e.to_string()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_fixture_files(&path, out)?;
        } else if is_fixture_toml(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_fixture_toml(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("toml")
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("fixture-"))
}

fn validate_mechanism_level(case: &CrashCase) -> Result<(), CrashFixtureError> {
    let ok = matches!(
        (case.mechanism, case.level),
        (
            CrashMechanism::Outbox | CrashMechanism::Inbox,
            CrashLevel::L2
        ) | (
            CrashMechanism::Saga | CrashMechanism::Projection,
            CrashLevel::L3
        ) | (CrashMechanism::Reconcile, CrashLevel::L4)
    );
    if ok {
        Ok(())
    } else {
        Err(invalid(
            &case.id,
            "mechanism and level are inconsistent with consistency-runtime rules",
        ))
    }
}

fn validate_nonempty(
    field: &'static str,
    value: &str,
    subject: &str,
) -> Result<(), CrashFixtureError> {
    if value.trim().is_empty() {
        Err(invalid(subject, format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

fn validate_slug(field: &'static str, value: &str, subject: &str) -> Result<(), CrashFixtureError> {
    validate_nonempty(field, value, subject)?;
    let ok = value.split('-').all(|seg| {
        !seg.is_empty()
            && seg
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    });
    if ok {
        Ok(())
    } else {
        Err(invalid(
            subject,
            format!("{field} must be a lowercase kebab-case slug"),
        ))
    }
}

fn validate_alias(
    field: &'static str,
    value: &str,
    subject: &str,
) -> Result<(), CrashFixtureError> {
    validate_slug(field, value, subject)?;
    if value.len() > MAX_ALIAS_LEN {
        return Err(invalid(
            subject,
            format!("{field} exceeds {MAX_ALIAS_LEN} bytes"),
        ));
    }
    Ok(())
}

fn validate_domain_name(
    field: &'static str,
    value: &str,
    subject: &str,
) -> Result<(), CrashFixtureError> {
    validate_nonempty(field, value, subject)?;
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(invalid(subject, format!("{field} must not be empty")));
    };
    let ok = first.is_ascii_lowercase()
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(invalid(
            subject,
            format!("{field} must be a lowercase domain name"),
        ))
    }
}

fn validate_dotted(
    field: &'static str,
    value: &str,
    subject: &str,
) -> Result<(), CrashFixtureError> {
    validate_nonempty(field, value, subject)?;
    let ok = value.split('.').all(|seg| {
        !seg.is_empty()
            && matches!(seg.bytes().next(), Some(b) if b.is_ascii_lowercase())
            && seg
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    if ok {
        Ok(())
    } else {
        Err(invalid(
            subject,
            format!("{field} must be a canonical dotted id"),
        ))
    }
}

fn validate_raw_toml_safety(src: &str) -> Result<(), CrashFixtureError> {
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if looks_sensitive(key) {
            return Err(invalid(
                "fixture key",
                raw_toml_safety_detail("fixture key"),
            ));
        }
        if looks_sensitive(value) {
            let subject = raw_toml_safety_value_subject(key);
            return Err(invalid(subject, raw_toml_safety_detail(subject)));
        }
    }

    Ok(())
}

fn raw_toml_safety_detail(subject: &str) -> String {
    format!("{subject} contains raw payload, secret-like, or PII-like material")
}

fn raw_toml_safety_value_subject(key: &str) -> &'static str {
    match key {
        "schemaVersion" => "schemaVersion",
        "id" => "id",
        "title" => "title",
        "level" => "level",
        "mechanism" => "mechanism",
        "status" => "status",
        "pendingReason" => "pendingReason",
        "domain" => "domain",
        "contractId" => "contractId",
        "tenantAlias" => "tenantAlias",
        "messageAlias" => "messageAlias",
        "partitionKeyAlias" => "partitionKeyAlias",
        "tenantAuthority" => "tenantAuthority",
        "crashPoint" => "crashPoint",
        "expectedInvariant" => "expectedInvariant",
        "runner" => "runner",
        _ => "fixture value",
    }
}

fn looks_sensitive(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("bearer ")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("token")
        || lower.contains("apikey")
        || lower.contains("api_key")
        || lower.contains("hmac")
        || lower.contains("vault")
        || lower.contains("payload")
        || lower.contains('@')
        || lower.contains("://")
        || lower.contains("error")
        || lower.contains("exception")
        || lower.contains("panic")
        || lower.contains("stacktrace")
        || lower.contains("traceback")
        || lower.contains("handler")
        || looks_like_uuid(&lower)
        || contains_long_hex_material(&lower)
        || contains_long_base64_material(value)
        || looks_name_like_pii(&lower)
}

fn looks_like_uuid(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_hexdigit() || ch == '-'))
        .any(is_uuid_token)
}

fn is_uuid_token(token: &str) -> bool {
    if token.len() != 36 {
        return false;
    }

    token.chars().enumerate().all(|(idx, ch)| {
        if matches!(idx, 8 | 13 | 18 | 23) {
            ch == '-'
        } else {
            ch.is_ascii_hexdigit()
        }
    })
}

fn contains_long_hex_material(value: &str) -> bool {
    let mut run = 0;
    for byte in value.bytes() {
        if byte.is_ascii_hexdigit() {
            run += 1;
            if run >= LONG_MATERIAL_MIN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn contains_long_base64_material(value: &str) -> bool {
    let mut run = 0;
    let mut has_base64_marker = false;
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=') {
            run += 1;
            has_base64_marker |= byte.is_ascii_uppercase() || matches!(byte, b'+' | b'/' | b'=');
            if run >= LONG_MATERIAL_MIN && has_base64_marker {
                return true;
            }
        } else {
            run = 0;
            has_base64_marker = false;
        }
    }
    false
}

fn looks_name_like_pii(lower: &str) -> bool {
    [
        "full name",
        "first name",
        "last name",
        "given name",
        "family name",
        "display name",
        "legal name",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    const READY_OUTBOX: &str = r#"
schemaVersion = 1
id = "outbox-after-publish-before-settle"
title = "publish succeeds before settle crash"
level = "L2"
mechanism = "outbox"
status = "ready"
domain = "identity"
contractId = "identity.session-created"
tenantAlias = "tenant-a"
messageAlias = "message-a"
partitionKeyAlias = "aggregate-a"
tenantAuthority = "valid"
crashPoint = "after-publish-before-settle"
expectedInvariant = "outbox-publish-settled-once"
runner = "postgres-rabbitmq"
"#;

    #[test]
    fn ready_case_derives_closed_fault_spec() -> Result<(), CrashFixtureError> {
        let case = CrashCase::from_toml_str(READY_OUTBOX)?;

        assert_eq!(
            case.fault_spec()?,
            CrashFaultSpec::OutboxAfterPublishBeforeSettle
        );
        Ok(())
    }

    #[test]
    fn unknown_fault_spec_is_rejected() -> Result<(), CrashFixtureError> {
        let result = CrashCase::from_toml_str(&READY_OUTBOX.replace(
            "expectedInvariant = \"outbox-publish-settled-once\"",
            "expectedInvariant = \"outbox-drifted-invariant\"",
        ));
        match result {
            Err(err) => {
                assert!(
                    err.to_string().contains("closed CrashFaultSpec"),
                    "unexpected error: {err}"
                );
                Ok(())
            }
            Ok(case) => Err(invalid(
                case.id(),
                "unknown fault spec unexpectedly passed validation",
            )),
        }
    }
}
