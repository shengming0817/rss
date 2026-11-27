//! Compiled in four independent consumer workspaces by verify.py.
use rss_audit_core::EventId;
use rss_audit_postgres::{Integrity, ReadLimit, WriteBudget};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(EventId::parse("sample-1")?.as_str(), "sample-1");
    let limit = ReadLimit::new(3, 1024)?;
    assert_eq!((limit.rows(), limit.bytes()), (3, 1024));
    let budget = WriteBudget::new(1, 1024, 1024)?;
    let _empty = budget.try_admit(&[])?;
    let _plain = Integrity::Plain;
    #[cfg(feature = "ledger")]
    {
        let chain = rss_ledger::ChainId::parse(rss_audit_core::AUDIT_CHAIN_ID)?;
        assert_eq!(chain.as_str(), "rss.audit.v1");
        let key = rss_ledger::KeyId::parse("consumer-test")?;
        let _ledger = Integrity::Ledger(std::sync::Arc::new(rss_ledger::Authenticator::new(
            key,
            vec![1; 32],
        )?));
    }
    #[cfg(feature = "messaging")]
    {
        let classified = rss_transactional_messaging_postgres::PgError::from(
            rss_audit_postgres::Error::Conflict,
        );
        assert_eq!(
            classified.kind(),
            rss_transactional_messaging::error::MessagingErrorKind::Conflict
        );
    }
    Ok(())
}
