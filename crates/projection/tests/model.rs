use rss_projection::{BatchLimit, Event, Position, SourceScope};
use rss_request_context::TenantId;

#[test]
fn position_and_source_identity_are_validated() -> anyhow::Result<()> {
    let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
    let source = SourceScope::new(tenant, "journal")?;
    assert!(SourceScope::new(tenant, "").is_err());
    assert!(BatchLimit::new(0).is_err());
    assert!(BatchLimit::new(1001).is_err());
    assert!(Position::new(u64::MAX).is_err());
    let event = Event::new(source, Position::new(0)?, "event-1", b"secret".to_vec())?;
    assert_eq!(event.position().get(), 0);
    assert!(!format!("{event:?}").contains("secret"));
    Ok(())
}

#[test]
fn baseline_requires_valid_complete_receipt_input() -> anyhow::Result<()> {
    use rss_projection::{BaselineReceipt, Error, GenerationStart};
    let source = SourceScope::new(
        TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
        "journal",
    )?;
    let fact = Event::new(source.clone(), Position::new(1)?, "one", vec![1])?;
    assert_eq!(
        GenerationStart::after(Position::new(1)?, vec![]),
        Err(Error::new(rss_projection::ErrorKind::InvalidInput))
    );
    assert_eq!(
        GenerationStart::after(Position::new(0)?, vec![BaselineReceipt::from_event(&fact)]),
        Err(Error::new(rss_projection::ErrorKind::InvalidInput))
    );
    let changed = Event::new(source, Position::new(1)?, "one", vec![2])?;
    assert_eq!(
        GenerationStart::after(
            Position::new(1)?,
            vec![
                BaselineReceipt::from_event(&fact),
                BaselineReceipt::from_event(&changed)
            ]
        ),
        Err(Error::new(rss_projection::ErrorKind::Conflict))
    );
    assert_eq!(
        GenerationStart::after(
            Position::new(1)?,
            vec![
                BaselineReceipt::from_event(&fact),
                BaselineReceipt::from_event(&fact)
            ]
        )?
        .receipts()
        .len(),
        1
    );
    Ok(())
}

#[test]
fn diagnostics_keep_classification_and_stop_before_raw_source() -> anyhow::Result<()> {
    use rss_projection::{Error, ErrorKind, Phase};
    let error = Error::provider(
        ErrorKind::Unavailable,
        Phase::Acquire,
        Some("08006"),
        std::io::Error::other("postgres://secret"),
    );
    assert_eq!(error.kind(), ErrorKind::Unavailable);
    assert_eq!(
        error.diagnostic().map(|d| (d.phase(), d.sqlstate())),
        Some((Phase::Acquire, Some("08006")))
    );
    assert!(!format!("{error:?} {error}").contains("secret"));
    let source = std::error::Error::source(&error)
        .ok_or_else(|| anyhow::anyhow!("missing redacted evidence"))?;
    assert!(source.source().is_none());
    assert!(!format!("{source:?} {source}").contains("secret"));
    let invalid = Error::provider(
        ErrorKind::Deadline,
        Phase::Operation,
        Some("password=secret"),
        std::io::Error::other("secret"),
    );
    assert_eq!(invalid.diagnostic().and_then(|d| d.sqlstate()), None);
    assert_eq!(invalid.uncertain().kind(), ErrorKind::CommitUnknown);
    Ok(())
}
