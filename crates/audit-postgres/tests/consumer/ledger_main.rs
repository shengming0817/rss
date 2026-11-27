fn main() -> Result<(), Box<dyn std::error::Error>> {
    let chain = rss_ledger::ChainId::parse("standalone-ledger")?;
    assert_eq!(chain.as_str(), "standalone-ledger");
    let _bound = rss_ledger_postgres::ReadLimit::new(1, 1024)?;
    #[cfg(feature = "messaging")]
    {
        let error = rss_transactional_messaging_postgres::PgError::from(
            rss_ledger_postgres::Error::Conflict,
        );
        assert_eq!(
            error.kind(),
            rss_transactional_messaging::error::MessagingErrorKind::Conflict
        );
    }
    println!("ledger consumer passed");
    Ok(())
}
