use std::path::Path;

use testkit::crash_matrix::{
    CrashCase, CrashLevel, CrashMatrix, CrashMechanism, CrashRunner, CrashStatus,
    TenantAuthorityState,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const VALID_READY: &str = r#"
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
fn ready_fixture_parses_into_closed_enums() -> TestResult {
    let case = CrashCase::from_toml_str(VALID_READY)?;

    assert_case_identity(&case);
    assert_case_scope(&case);
    assert_case_fault_contract(&case);
    Ok(())
}

fn assert_case_identity(case: &CrashCase) {
    assert_eq!(case.schema_version(), 1);
    assert_eq!(case.id(), "outbox-after-publish-before-settle");
    assert_eq!(case.level(), CrashLevel::L2);
    assert_eq!(case.mechanism(), CrashMechanism::Outbox);
    assert_eq!(case.status(), CrashStatus::Ready);
    assert_eq!(case.pending_reason(), None);
}

fn assert_case_scope(case: &CrashCase) {
    assert_eq!(case.domain(), "identity");
    assert_eq!(case.contract_id(), "identity.session-created");
    assert_eq!(case.tenant_alias(), "tenant-a");
    assert_eq!(case.message_alias(), "message-a");
    assert_eq!(case.partition_key_alias(), "aggregate-a");
    assert_eq!(case.tenant_authority(), TenantAuthorityState::Valid);
}

fn assert_case_fault_contract(case: &CrashCase) {
    assert_eq!(case.crash_point(), "after-publish-before-settle");
    assert_eq!(case.expected_invariant(), "outbox-publish-settled-once");
    assert_eq!(case.runner(), CrashRunner::PostgresRabbitmq);
}

#[test]
fn unknown_fields_are_rejected() -> TestResult {
    let src = format!("{VALID_READY}\nextraField = \"silent drift\"\n");
    let err = match CrashCase::from_toml_str(&src) {
        Ok(_) => return Err("unknown fields must fail closed".into()),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("extraField") || err.to_string().contains("unknown"),
        "error should name or describe the unknown field: {err}"
    );
    Ok(())
}

#[test]
fn old_expected_recovery_field_is_rejected() -> TestResult {
    let src = VALID_READY.replace(
        "expectedInvariant = \"outbox-publish-settled-once\"",
        "expectedRecovery = \"redeliver-or-settle-idempotently\"",
    );
    let err = match CrashCase::from_toml_str(&src) {
        Ok(_) => return Err("old expectedRecovery field must fail closed".into()),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("expectedRecovery") || err.to_string().contains("unknown"),
        "error should identify the old field: {err}"
    );
    Ok(())
}

#[test]
fn expected_invariant_is_required() -> TestResult {
    let src = VALID_READY.replace("expectedInvariant = \"outbox-publish-settled-once\"\n", "");
    let err = match CrashCase::from_toml_str(&src) {
        Ok(_) => return Err("expectedInvariant must be required".into()),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("expectedInvariant"),
        "error should identify expectedInvariant: {err}"
    );
    Ok(())
}

#[test]
fn runner_is_required() -> TestResult {
    let src = VALID_READY.replace("runner = \"postgres-rabbitmq\"\n", "");
    let err = match CrashCase::from_toml_str(&src) {
        Ok(_) => return Err("runner must be required".into()),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("runner"),
        "error should identify runner: {err}"
    );
    Ok(())
}

#[test]
fn duplicate_case_ids_fail_matrix_validation() -> TestResult {
    let first = CrashCase::from_toml_str(VALID_READY)?;
    let second = CrashCase::from_toml_str(VALID_READY)?;
    let err = match CrashMatrix::new(vec![first, second]) {
        Ok(_) => return Err("duplicate ids must fail".into()),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("outbox-after-publish-before-settle"),
        "duplicate id should be visible: {err}"
    );
    Ok(())
}

#[test]
fn secret_like_fixture_values_are_rejected() -> TestResult {
    let src = VALID_READY.replace("message-a", "Bearer super-secret-token");
    let err = match CrashCase::from_toml_str(&src) {
        Ok(_) => return Err("secret-looking values must fail".into()),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("secret") || err.to_string().contains("messageAlias"),
        "error should describe the redaction boundary: {err}"
    );
    Ok(())
}

#[test]
fn parse_time_secret_values_are_rejected_without_raw_leak() -> TestResult {
    let src = VALID_READY.replace(
        "tenantAuthority = \"valid\"",
        "tenantAuthority = \"Bearer abc\"",
    );
    let err = match CrashCase::from_toml_str(&src) {
        Ok(_) => {
            return Err("secret-looking enum values must fail before parse diagnostics".into());
        }
        Err(err) => err,
    };
    let message = err.to_string();
    assert!(
        message.contains("tenantAuthority") && !message.contains("Bearer abc"),
        "error should name the field without echoing the secret-like value: {err}"
    );
    Ok(())
}

#[test]
fn parse_time_secret_keys_are_rejected_without_raw_leak() -> TestResult {
    let raw_key = "\"super-secret-token\"";
    let src = format!("{VALID_READY}\n{raw_key} = \"x\"\n");
    let err = match CrashCase::from_toml_str(&src) {
        Ok(_) => {
            return Err("secret-looking TOML keys must fail before parse diagnostics".into());
        }
        Err(err) => err,
    };
    let message = err.to_string();
    assert!(
        message.contains("fixture key")
            && !message.contains(raw_key)
            && !message.contains("super-secret-token"),
        "error should identify the redacted key boundary without echoing the raw key: {err}"
    );
    Ok(())
}

#[test]
fn domain_must_be_domain_name_not_dotted_id() -> TestResult {
    let src = VALID_READY.replace("domain = \"identity\"", "domain = \"identity.foo\"");
    let err = match CrashCase::from_toml_str(&src) {
        Ok(_) => return Err("domain must be a domain name".into()),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("domain"),
        "error should identify domain: {err}"
    );
    Ok(())
}

#[test]
fn uuid_like_aliases_are_rejected() -> TestResult {
    let src = VALID_READY.replace("message-a", "550e8400-e29b-41d4-a716-446655440000");
    let err = match CrashCase::from_toml_str(&src) {
        Ok(_) => return Err("UUID-looking aliases must fail".into()),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("messageAlias") || err.to_string().contains("secret-like"),
        "error should describe the redaction boundary: {err}"
    );
    Ok(())
}

#[test]
fn long_material_values_are_rejected() -> TestResult {
    let src = VALID_READY.replace("message-a", "0123456789abcdef0123456789abcdef");
    let err = match CrashCase::from_toml_str(&src) {
        Ok(_) => return Err("long key material must fail".into()),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("messageAlias") || err.to_string().contains("secret-like"),
        "error should describe the redaction boundary: {err}"
    );
    Ok(())
}

#[test]
fn handler_error_text_is_rejected() -> TestResult {
    let src = VALID_READY.replace(
        "publish succeeds before settle crash",
        "handler error stacktrace after publish",
    );
    let err = match CrashCase::from_toml_str(&src) {
        Ok(_) => return Err("handler error text must fail".into()),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("title") || err.to_string().contains("secret-like"),
        "error should describe the redaction boundary: {err}"
    );
    Ok(())
}

#[test]
fn name_like_pii_is_rejected() -> TestResult {
    let src = VALID_READY.replace(
        "publish succeeds before settle crash",
        "full name alice smith",
    );
    let err = match CrashCase::from_toml_str(&src) {
        Ok(_) => return Err("name-like PII must fail".into()),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("title") || err.to_string().contains("PII-like"),
        "error should describe the redaction boundary: {err}"
    );
    Ok(())
}

#[test]
fn plaintext_payload_fields_are_rejected_without_raw_key_leak() -> TestResult {
    let src = format!("{VALID_READY}\npayloadBytes = \"SECRET_PAYLOAD_MARKER\"\n");
    let err = match CrashCase::from_toml_str(&src) {
        Ok(_) => return Err("payload fields must fail".into()),
        Err(err) => err,
    };
    let message = err.to_string();
    assert!(
        message.contains("fixture key") && !message.contains("payloadBytes"),
        "error should reject payload fields without echoing the raw key: {err}"
    );
    Ok(())
}

#[test]
fn real_fixture_directory_has_at_least_twelve_ready_cases() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("testkit manifest should be under crates/testkit")?;
    let matrix = CrashMatrix::from_fixture_dir(root.join("fixtures").join("consistency"))?;

    assert!(
        matrix.ready_count() >= 12,
        "N-028 requires at least twelve ready consistency crash fixtures"
    );
    assert!(
        matrix
            .cases()
            .iter()
            .any(|case| case.mechanism() == CrashMechanism::Outbox),
        "outbox fixture should be present"
    );
    Ok(())
}
