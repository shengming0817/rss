use rss_transactional_messaging_recovery::archive::{Error, Retention};

#[test]
fn retention_preserves_database_safety_floor_and_strict_boundary() -> Result<(), Error> {
    let policy = Retention::new(20, 30)?;
    assert_eq!(policy.minimum_lock_until(100, 40)?, 140);
    assert!(policy.validate_hot_floor(10, 10).is_ok());
    assert_eq!(policy.validate_hot_floor(11, 10), Err(Error::Retention));
    assert_eq!(
        policy.minimum_lock_until(i64::MAX, 40),
        Err(Error::Retention)
    );
    assert!(Retention::new(0, 30).is_err());
    Ok(())
}
