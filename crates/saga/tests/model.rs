use rss_request_context::TenantId;
use rss_saga::{Definition, Identity, Phase, Scope, Snapshot, Status, StepSpec};
fn definition() -> Result<Definition, rss_saga::Error> {
    let identity = Identity::new(
        rss_contract::ContractId::from_static("orders.checkout"),
        rss_contract::ContractVersion::from_static_major(1),
        rss_contract::SchemaDigest::from_static(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        rss_saga::ActionGeneration::parse(&format!("sha256:{}", "b".repeat(64)))?,
    );
    Definition::new(
        "orders",
        identity,
        vec![StepSpec::new(
            "reserve",
            "receipt.v1",
            "reserve",
            "release",
            2,
        )?],
    )
}
#[test]
fn stable_key_excludes_attempt_and_definition_fingerprint() -> anyhow::Result<()> {
    let d = definition()?;
    let scope = Scope::new(
        TenantId::parse("11111111-2222-4333-8444-555555555555")?,
        uuid::Uuid::nil(),
    );
    let key = d.effect_key(scope, 0, Phase::Forward)?;
    assert_eq!(
        key.to_hex(),
        "decaa6cc81a3c1bc1d607c91376988f984ed5e6747d5e54866943f6bcf46a080"
    );
    let changed = Definition::new(
        "orders",
        d.identity().clone(),
        vec![StepSpec::new(
            "reserve",
            "receipt.v1",
            "reserve",
            "release",
            3,
        )?],
    )?;
    assert_ne!(d.fingerprint(), changed.fingerprint());
    assert_eq!(key, changed.effect_key(scope, 0, Phase::Forward)?);
    Ok(())
}
#[test]
fn compensation_failure_is_not_terminal() {
    assert!(!Status::CompensationFailed.is_terminal());
    assert!(Status::Succeeded.is_terminal());
    assert!(Status::Compensated.is_terminal());
}
#[test]
fn empty_definition_and_duplicate_step_fail() -> anyhow::Result<()> {
    let d = definition()?;
    assert!(Definition::new("orders", d.identity().clone(), vec![]).is_err());
    assert!(
        Definition::new(
            "orders",
            d.identity().clone(),
            vec![d.steps()[0].clone(), d.steps()[0].clone()]
        )
        .is_err()
    );
    assert_eq!(Snapshot::empty(d).status(), Status::Ready);
    Ok(())
}
#[test]
fn lease_debug_redacts_credentials_and_diagnostics_hide_sources() -> anyhow::Result<()> {
    use rss_saga::{DiagnosticPhase, Error, ErrorKind, Lease};
    let token = uuid::Uuid::new_v4();
    let scope = Scope::new(
        TenantId::parse("11111111-2222-4333-8444-555555555555")?,
        uuid::Uuid::nil(),
    );
    let lease = Lease::from_provider(scope, token, 3)?;
    assert!(!format!("{lease:?}").contains(&token.to_string()));
    let error = Error::provider(
        ErrorKind::Store,
        DiagnosticPhase::Acquire,
        Some("42501"),
        std::io::Error::other("secret-material"),
    );
    assert_eq!(error.diagnostic().and_then(|d| d.sqlstate()), Some("42501"));
    assert!(!format!("{error:?}").contains("secret-material"));
    assert!(!error.to_string().contains("secret-material"));
    Ok(())
}

#[test]
fn identity_preserves_canonical_value_owners() -> anyhow::Result<()> {
    let d = definition()?;
    let _: &rss_contract::ContractId = d.identity().contract();
    let _: rss_contract::ContractVersion = d.identity().version();
    let _: &rss_contract::SchemaDigest = d.identity().schema();
    let _: &rss_saga::ActionGeneration = d.identity().generation();
    let mut wire = serde_json::to_value(&d)?;
    wire["identity"]["version"] = serde_json::json!("v01");
    assert!(serde_json::from_value::<Definition>(wire).is_err());
    Ok(())
}
