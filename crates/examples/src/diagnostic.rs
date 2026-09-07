pub fn run() -> anyhow::Result<()> {
    use rss_diag_context::{CorrelationId, DiagnosticCtx};
    let context = DiagnosticCtx::new(CorrelationId::parse("request-42")?);
    assert_eq!(context.correlation().as_str(), "request-42");
    assert!(CorrelationId::parse("invalid\nheader").is_err());
    Ok(())
}
