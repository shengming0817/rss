fn main() -> Result<(), Box<dyn std::error::Error>> {
    use rss_ledger::*;
    let auth = Authenticator::new(KeyId::parse("example-key")?, vec![7; 32])?;
    let ledger = LedgerId::new(
        rss_request_context::TenantId::parse("00000000-0000-0000-0000-000000000001")?,
        ChainId::parse("example")?,
    );
    let request = AppendRequest::new(ledger.clone(), RecordId::parse("one")?, vec![1])?;
    let entry = auth.append(&request, None)?;
    assert_eq!(auth.verify_chain(&ledger, &[entry])?.count(), 1);
    Ok(())
}
