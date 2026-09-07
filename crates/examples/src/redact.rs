pub fn run() -> anyhow::Result<()> {
    use rss_redact::{
        Redact, RedactScope, RedactedBytes, RedactedSource, RedactionHashKey, SecretText,
    };
    let secret = SecretText::from_string("do-not-log".into());
    let key = RedactionHashKey::from_bytes(vec![42; 32])?;
    for scope in [RedactScope::ServerLog, RedactScope::Wire] {
        assert_eq!(secret.redact_scoped(scope), "SecretText(<redacted>)");
        assert_eq!(key.redact_scoped(scope), "RedactionHashKey(<redacted>)");
    }
    assert_eq!(format!("{secret:?}"), "SecretText(<redacted>)");
    assert_eq!(format!("{key:?}"), "RedactionHashKey(<redacted>)");
    assert_eq!(format!("{:?}", RedactedBytes::new(vec![42])), "<redacted>");
    let source = RedactedSource::new(std::io::Error::other("do-not-log"));
    assert_eq!(format!("{source:?}"), "RedactedSource(<redacted>)");
    assert!(std::error::Error::source(&source).is_none());
    Ok(())
}
