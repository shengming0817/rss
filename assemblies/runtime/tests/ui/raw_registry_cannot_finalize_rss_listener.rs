fn bypass_security_root(
    mut registry: bootstrap::WriteAdmittedRegistry,
    provider: std::sync::Arc<oidc::OidcProvider<diport::RssAccessProfile>>,
    grants: std::sync::Arc<identity::AuthGrantValidationService>,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: std::sync::Arc<dyn diport::Clock>,
) {
    let _ = runtime::test_support::finalize_rss_listener(
        &mut registry,
        provider,
        grants,
        audit_sink,
        audit_clock,
        assembly_schema::AssemblyListenerKind::Primary,
    );
}

fn main() {}
