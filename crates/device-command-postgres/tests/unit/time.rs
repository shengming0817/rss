use crate::IntegrationClock;
use std::sync::Arc;

#[test]
fn controlled_time_is_nonnegative_monotonic_and_shared() -> Result<(), rss_device_command::Error> {
    assert!(IntegrationClock::new(-1).is_err());
    let clock = Arc::new(IntegrationClock::new(0)?);
    let shared = clock.clone();
    clock.advance_to(99)?;
    assert_eq!(shared.now(), 99);
    shared.advance_to(100)?;
    assert_eq!(clock.now(), 100);
    assert!(clock.advance_to(99).is_err());
    assert!(clock.advance_to(-1).is_err());
    clock.advance_to(100)?;
    let independent = IntegrationClock::new(0)?;
    assert_eq!(independent.now(), 0);
    clock.advance_to(i64::MAX)?;
    assert!(clock.advance_to(i64::MAX - 1).is_err());
    Ok(())
}

#[test]
fn competing_advances_never_roll_back_time() -> Result<(), rss_device_command::Error> {
    let clock = Arc::new(IntegrationClock::new(0)?);
    std::thread::scope(|scope| {
        for at in [30, 90, 20, 80, 100, 40] {
            let clock = clock.clone();
            scope.spawn(move || {
                let _ = clock.advance_to(at);
            });
        }
    });
    assert_eq!(clock.now(), 100);
    Ok(())
}
