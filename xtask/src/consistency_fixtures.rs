//! Consistency crash fixture gate.
//!
//! Scans `fixtures/consistency/**/fixture-*.toml` and keeps the N-003 crash
//! matrix skeleton machine-visible. This is a no-compile governance gate: it
//! validates data shape and redaction boundaries, but does not execute runtime
//! crash recovery.
//!
//! INVARIANT: CONSISTENCY-CRASH-FIXTURE-01 { level = "Medium", exec = "verify", source = "code" } -- consistency crash fixture ids must be unique, fixtures must parse as the closed TOML DSL, and N-003 must keep at least five pending cases.

use crate::contract::manifest::{ContractManifest, ContractOwner};
use crate::diagnostic::{self, GovernanceCheck, finding};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub(crate) type Finding = diagnostic::Finding<Rule>;

const MIN_PENDING_CASES: usize = 5;
const MAX_ALIAS_LEN: usize = 128;
const LONG_MATERIAL_MIN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    MissingDirectory,
    MissingReadme,
    NoFixtures,
    Parse,
    InvalidFixture,
    DuplicateId,
    PendingCount,
}

pub(crate) struct ConsistencyFixtures;

impl GovernanceCheck for ConsistencyFixtures {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "consistency-fixtures"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        Ok(check_root(&root))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
enum CrashLevel {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CrashMechanism {
    Outbox,
    Inbox,
    Saga,
    Projection,
    Reconcile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CrashStatus {
    Pending,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TenantAuthorityState {
    Valid,
    Missing,
    Invalid,
    Expired,
    Mismatch,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
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
    #[serde(rename = "expectedRecovery")]
    expected_recovery: String,
}

#[derive(Debug, Clone)]
struct ContractEntry {
    owner_domain: String,
}

fn check_root(root: &Path) -> (String, Vec<Finding>) {
    let dir = root.join("fixtures").join("consistency");
    let mut findings = Vec::new();
    if !dir.is_dir() {
        findings.push(finding(
            Rule::MissingDirectory,
            rel(root, &dir),
            "fixtures/consistency directory is required",
        ));
        return (String::new(), findings);
    }
    if !dir.join("README.md").is_file() {
        findings.push(finding(
            Rule::MissingReadme,
            "fixtures/consistency/README.md",
            "README must describe how to add consistency crash cases",
        ));
    }

    let mut files = Vec::new();
    if let Err(e) = collect_fixture_files(&dir, &mut files) {
        findings.push(finding(Rule::MissingDirectory, rel(root, &dir), e));
        return (String::new(), findings);
    }
    files.sort();
    if files.is_empty() {
        findings.push(finding(
            Rule::NoFixtures,
            rel(root, &dir),
            "no fixture-*.toml files found",
        ));
        return (String::new(), findings);
    }

    let contracts = match contract_index(root) {
        Ok(contracts) => contracts,
        Err(detail) => {
            findings.push(finding(Rule::InvalidFixture, "contracts", detail));
            BTreeMap::new()
        }
    };

    let mut ids = BTreeSet::new();
    let mut pending = 0usize;
    for path in &files {
        let rel_path = rel(root, path);
        let src = match std::fs::read_to_string(path) {
            Ok(src) => src,
            Err(e) => {
                findings.push(finding(Rule::Parse, rel_path, e.to_string()));
                continue;
            }
        };
        if let Some(detail) = raw_toml_safety_finding(&src) {
            findings.push(finding(Rule::InvalidFixture, rel_path, detail));
            continue;
        }
        let fixture: Fixture = match toml::from_str(&src) {
            Ok(fixture) => fixture,
            Err(_) => {
                findings.push(finding(
                    Rule::Parse,
                    rel_path,
                    "TOML parse failed; check closed fixture fields and enum values",
                ));
                continue;
            }
        };
        if fixture.status == CrashStatus::Pending {
            pending += 1;
        }
        if !ids.insert(fixture.id.clone()) {
            findings.push(finding(
                Rule::DuplicateId,
                fixture.id.clone(),
                format!("duplicate id in {rel_path}"),
            ));
        }
        findings.extend(validate_fixture(&fixture, &rel_path, &contracts));
    }

    if pending < MIN_PENDING_CASES {
        findings.push(finding(
            Rule::PendingCount,
            rel(root, &dir),
            format!("expected at least {MIN_PENDING_CASES} pending fixtures, found {pending}"),
        ));
    }
    let summary = format!(
        "{} fixture files scanned, {} pending cases",
        files.len(),
        pending
    );
    (summary, findings)
}

fn collect_fixture_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
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

fn contract_index(root: &Path) -> Result<BTreeMap<String, ContractEntry>, String> {
    let dir = root.join("contracts");
    if !dir.is_dir() {
        return Err("contracts directory is required for contractId validation".to_string());
    }

    let mut files = Vec::new();
    collect_contract_files(&dir, &mut files)?;
    let mut contracts = BTreeMap::new();
    for path in files {
        let src = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let manifest = ContractManifest::from_toml_str(&src)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let owner_domain = match manifest.owner {
            ContractOwner::Domain(owner) => owner,
            ContractOwner::Framework => "_framework".to_string(),
        };
        if contracts
            .insert(manifest.id.clone(), ContractEntry { owner_domain })
            .is_some()
        {
            return Err(format!("duplicate contract id `{}`", manifest.id));
        }
    }

    Ok(contracts)
}

fn collect_contract_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            collect_contract_files(&path, out)?;
        } else if path.file_name().and_then(|name| name.to_str()) == Some("contract.toml") {
            out.push(path);
        }
    }
    Ok(())
}

fn validate_fixture(
    fixture: &Fixture,
    rel_path: &str,
    contracts: &BTreeMap<String, ContractEntry>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if fixture.schema_version != 1 {
        findings.push(invalid(
            rel_path,
            format!("schemaVersion must be 1, got {}", fixture.schema_version),
        ));
    }
    validate_slug(&mut findings, rel_path, "id", &fixture.id);
    validate_nonempty(&mut findings, rel_path, "title", &fixture.title);
    validate_domain_name(&mut findings, rel_path, "domain", &fixture.domain);
    validate_dotted(&mut findings, rel_path, "contractId", &fixture.contract_id);
    validate_alias(
        &mut findings,
        rel_path,
        "tenantAlias",
        &fixture.tenant_alias,
    );
    validate_alias(
        &mut findings,
        rel_path,
        "messageAlias",
        &fixture.message_alias,
    );
    validate_alias(
        &mut findings,
        rel_path,
        "partitionKeyAlias",
        &fixture.partition_key_alias,
    );
    validate_slug(&mut findings, rel_path, "crashPoint", &fixture.crash_point);
    validate_slug(
        &mut findings,
        rel_path,
        "expectedRecovery",
        &fixture.expected_recovery,
    );
    if fixture.status == CrashStatus::Pending {
        match fixture.pending_reason.as_deref() {
            Some(reason) => validate_nonempty(&mut findings, rel_path, "pendingReason", reason),
            None => findings.push(invalid(rel_path, "pendingReason is required for pending")),
        }
    } else if fixture.pending_reason.is_some() {
        findings.push(invalid(
            rel_path,
            "pendingReason is only allowed when status is pending",
        ));
    }
    if !mechanism_level_ok(fixture.mechanism, fixture.level) {
        findings.push(invalid(
            rel_path,
            "mechanism and level are inconsistent with consistency-runtime rules",
        ));
    }
    validate_contract_reference(&mut findings, rel_path, fixture, contracts);
    for (field, value) in fixture_strings(fixture) {
        if looks_sensitive(value) {
            findings.push(invalid(
                rel_path,
                format!("{field} contains a secret-like or PII-like value"),
            ));
        }
    }
    let _ = fixture.tenant_authority; // parsed closed enum; validation is structural.
    findings
}

fn fixture_strings(fixture: &Fixture) -> [(&'static str, &str); 10] {
    [
        ("id", fixture.id.as_str()),
        ("title", fixture.title.as_str()),
        (
            "pendingReason",
            fixture.pending_reason.as_deref().unwrap_or(""),
        ),
        ("domain", fixture.domain.as_str()),
        ("contractId", fixture.contract_id.as_str()),
        ("tenantAlias", fixture.tenant_alias.as_str()),
        ("messageAlias", fixture.message_alias.as_str()),
        ("partitionKeyAlias", fixture.partition_key_alias.as_str()),
        ("crashPoint", fixture.crash_point.as_str()),
        ("expectedRecovery", fixture.expected_recovery.as_str()),
    ]
}

fn invalid(subject: impl Into<String>, detail: impl Into<String>) -> Finding {
    finding(Rule::InvalidFixture, subject, detail)
}

fn validate_nonempty(findings: &mut Vec<Finding>, subject: &str, field: &str, value: &str) {
    if value.trim().is_empty() {
        findings.push(invalid(subject, format!("{field} must not be empty")));
    }
}

fn validate_slug(findings: &mut Vec<Finding>, subject: &str, field: &str, value: &str) {
    validate_nonempty(findings, subject, field, value);
    let ok = value.split('-').all(|seg| {
        !seg.is_empty()
            && seg
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    });
    if !ok {
        findings.push(invalid(
            subject,
            format!("{field} must be a lowercase kebab-case slug"),
        ));
    }
}

fn validate_alias(findings: &mut Vec<Finding>, subject: &str, field: &str, value: &str) {
    validate_slug(findings, subject, field, value);
    if value.len() > MAX_ALIAS_LEN {
        findings.push(invalid(
            subject,
            format!("{field} exceeds {MAX_ALIAS_LEN} bytes"),
        ));
    }
}

fn validate_domain_name(findings: &mut Vec<Finding>, subject: &str, field: &str, value: &str) {
    validate_nonempty(findings, subject, field, value);
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        findings.push(invalid(subject, format!("{field} must not be empty")));
        return;
    };
    let ok = first.is_ascii_lowercase()
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !ok {
        findings.push(invalid(
            subject,
            format!("{field} must be a lowercase domain name"),
        ));
    }
}

fn validate_dotted(findings: &mut Vec<Finding>, subject: &str, field: &str, value: &str) {
    validate_nonempty(findings, subject, field, value);
    let ok = value.split('.').all(|seg| {
        !seg.is_empty()
            && matches!(seg.bytes().next(), Some(b) if b.is_ascii_lowercase())
            && seg
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    if !ok {
        findings.push(invalid(
            subject,
            format!("{field} must be a canonical dotted id"),
        ));
    }
}

fn validate_contract_reference(
    findings: &mut Vec<Finding>,
    subject: &str,
    fixture: &Fixture,
    contracts: &BTreeMap<String, ContractEntry>,
) {
    match contracts.get(&fixture.contract_id) {
        Some(contract) if contract.owner_domain == fixture.domain => {}
        Some(contract) => findings.push(invalid(
            subject,
            format!(
                "contractId `{}` is owned by `{}`, not fixture domain `{}`",
                fixture.contract_id, contract.owner_domain, fixture.domain
            ),
        )),
        None => findings.push(invalid(
            subject,
            format!(
                "contractId `{}` is not declared in contracts/**/contract.toml",
                fixture.contract_id
            ),
        )),
    }
}

fn mechanism_level_ok(mechanism: CrashMechanism, level: CrashLevel) -> bool {
    matches!(
        (mechanism, level),
        (
            CrashMechanism::Outbox | CrashMechanism::Inbox,
            CrashLevel::L2
        ) | (
            CrashMechanism::Saga | CrashMechanism::Projection,
            CrashLevel::L3
        ) | (CrashMechanism::Reconcile, CrashLevel::L4)
    )
}

fn raw_toml_safety_finding(src: &str) -> Option<String> {
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
            return Some(raw_toml_safety_detail("fixture key"));
        }
        if looks_sensitive(value) {
            return Some(raw_toml_safety_detail(raw_toml_safety_value_subject(key)));
        }
    }

    None
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
        "expectedRecovery" => "expectedRecovery",
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

fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_TMP: AtomicUsize = AtomicUsize::new(0);

    const VALID: &str = r#"
schemaVersion = 1
id = "outbox-after-publish-before-settle"
title = "publish succeeds before settle crash"
level = "L2"
mechanism = "outbox"
status = "pending"
pendingReason = "N-003 only creates the DSL skeleton"
domain = "identity"
contractId = "identity.session-created"
tenantAlias = "tenant-a"
messageAlias = "message-a"
partitionKeyAlias = "aggregate-a"
tenantAuthority = "valid"
crashPoint = "after-publish-before-settle"
expectedRecovery = "redeliver-or-settle-idempotently"
"#;

    const VALID_CONTRACT: &str = r#"
id = "identity.session-created"
kind = "event"
domain = "identity"
version = "v1"
owner = "identity"
consistencyLevel = "OutboxFact"
lifecycle = "active"
topic = "identity.session-created"
delivery = "at-least-once"

[schemas]
payload = "payload.schema.json"

[[subscriptions]]
consumer = "identity"
group = "identity.session-created"

[subscriptions.topology]
partitionKey = "none"
readiness = "required"
"#;

    fn temp_root(name: &str) -> Result<PathBuf> {
        let n = NEXT_TMP.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "rss-consistency-fixtures-{name}-{}-{n}",
            std::process::id()
        ));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        fs::create_dir_all(root.join("fixtures/consistency/outbox"))?;
        fs::write(root.join("fixtures/consistency/README.md"), "fixture docs")?;
        fs::create_dir_all(root.join("contracts/event/identity/v1/session-created"))?;
        fs::write(
            root.join("contracts/event/identity/v1/session-created/contract.toml"),
            VALID_CONTRACT,
        )?;
        Ok(root)
    }

    fn write_fixture(root: &Path, name: &str, src: &str) -> Result<()> {
        fs::write(
            root.join("fixtures/consistency/outbox")
                .join(format!("fixture-{name}.toml")),
            src,
        )?;
        Ok(())
    }

    #[test]
    fn green_real_tree_has_required_pending_fixtures() -> Result<()> {
        let root = crate::workspace_root()?;
        let (_, findings) = check_root(&root);
        assert!(
            findings.is_empty(),
            "real fixtures should pass: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_missing_directory_fails_closed() -> Result<()> {
        let root = temp_root("missing")?;
        fs::remove_dir_all(root.join("fixtures/consistency"))?;
        let (_, findings) = check_root(&root);
        assert_eq!(findings[0].rule, Rule::MissingDirectory);
        Ok(())
    }

    #[test]
    fn red_unknown_field_is_parse_error() -> Result<()> {
        let root = temp_root("unknown")?;
        write_fixture(&root, "bad", &format!("{VALID}\nextraField = \"x\"\n"))?;
        let (_, findings) = check_root(&root);
        assert!(findings.iter().any(|f| f.rule == Rule::Parse));
        Ok(())
    }

    #[test]
    fn red_duplicate_id_is_reported() -> Result<()> {
        let root = temp_root("duplicate")?;
        write_fixture(&root, "a", VALID)?;
        write_fixture(&root, "b", VALID)?;
        let (_, findings) = check_root(&root);
        assert!(findings.iter().any(|f| f.rule == Rule::DuplicateId));
        Ok(())
    }

    #[test]
    fn red_pending_count_floor_is_enforced() -> Result<()> {
        let root = temp_root("floor")?;
        write_fixture(&root, "one", VALID)?;
        let (_, findings) = check_root(&root);
        assert!(findings.iter().any(|f| f.rule == Rule::PendingCount));
        Ok(())
    }

    #[test]
    fn red_secret_like_alias_is_rejected() -> Result<()> {
        let root = temp_root("secret")?;
        write_fixture(&root, "secret", &VALID.replace("message-a", "bearer-token"))?;
        let (_, findings) = check_root(&root);
        assert!(
            findings
                .iter()
                .any(|f| { f.rule == Rule::InvalidFixture && f.detail.contains("secret-like") })
        );
        Ok(())
    }

    #[test]
    fn red_unknown_contract_id_is_reported() -> Result<()> {
        let root = temp_root("missing-contract")?;
        write_fixture(
            &root,
            "missing-contract",
            &VALID.replace("identity.session-created", "identity.missing"),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings
                .iter()
                .any(|f| { f.rule == Rule::InvalidFixture && f.detail.contains("not declared") }),
            "missing contractId should be reported: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_contract_owner_domain_mismatch_is_reported() -> Result<()> {
        let root = temp_root("contract-owner")?;
        write_fixture(
            &root,
            "owner",
            &VALID.replace("domain = \"identity\"", "domain = \"settings\""),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings
                .iter()
                .any(|f| { f.rule == Rule::InvalidFixture && f.detail.contains("owned by") }),
            "owner/domain mismatch should be reported: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_long_alias_is_rejected() -> Result<()> {
        let root = temp_root("long-alias")?;
        let long_alias = "g".repeat(MAX_ALIAS_LEN + 1);
        write_fixture(&root, "long", &VALID.replace("message-a", &long_alias))?;
        let (_, findings) = check_root(&root);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::InvalidFixture && f.detail.contains("messageAlias exceeds")
            }),
            "long alias should be reported: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_parse_time_secret_value_is_rejected_without_raw_leak() -> Result<()> {
        let root = temp_root("enum-secret")?;
        write_fixture(
            &root,
            "enum-secret",
            &VALID.replace(
                "tenantAuthority = \"valid\"",
                "tenantAuthority = \"Bearer super-secret-token\"",
            ),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::InvalidFixture
                    && f.detail.contains("tenantAuthority")
                    && !f.detail.contains("super-secret-token")
            }),
            "secret-like enum value should be rejected without echoing raw value: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_parse_time_secret_key_is_rejected_without_raw_leak() -> Result<()> {
        let root = temp_root("key-secret")?;
        write_fixture(
            &root,
            "key-secret",
            &format!("{VALID}\n\"super-secret-token\" = \"x\"\n"),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::InvalidFixture
                    && f.detail.contains("fixture key")
                    && !f.subject.contains("super-secret-token")
                    && !f.detail.contains("super-secret-token")
            }),
            "secret-like key should be rejected without echoing raw key: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_uuid_like_alias_is_rejected() -> Result<()> {
        let root = temp_root("uuid")?;
        write_fixture(
            &root,
            "uuid",
            &VALID.replace("message-a", "550e8400-e29b-41d4-a716-446655440000"),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings
                .iter()
                .any(|f| { f.rule == Rule::InvalidFixture && f.detail.contains("messageAlias") }),
            "UUID-looking alias should be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_handler_error_text_is_rejected() -> Result<()> {
        let root = temp_root("handler-error")?;
        write_fixture(
            &root,
            "handler-error",
            &VALID.replace(
                "publish succeeds before settle crash",
                "handler error stacktrace",
            ),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings
                .iter()
                .any(|f| { f.rule == Rule::InvalidFixture && f.detail.contains("title") }),
            "handler error text should be rejected: {findings:?}"
        );
        Ok(())
    }
}
