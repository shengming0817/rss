use rss_device_command::*;
use rss_request_context::TenantId;

fn spec(id: &str) -> Result<CommandSpec, Box<dyn std::error::Error>> {
    Ok(CommandSpec::new(
        Scope::new(
            TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
            DeviceId::parse("550e8400-e29b-41d4-a716-446655440000")?,
        ),
        CommandId::parse(id)?,
        Coordinate::new(1, 1)?,
        StateDigest::from_bytes([7; 32]),
        100,
    ))
}
#[test]
fn receipt_is_not_application_and_received_can_reject() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::queue(spec("one")?, 1)?;
    let authority = command.spec().coordinate();
    assert_eq!(
        command.transition(Event::Received, authority, 2)?,
        Outcome::OutOfOrder
    );
    assert_eq!(
        command.transition(Event::Published, authority, 3)?,
        Outcome::Advanced
    );
    assert_eq!(
        command.transition(Event::Received, authority, 4)?,
        Outcome::Advanced
    );
    assert_eq!(command.status(), Status::Received);
    assert_eq!(
        command.transition(Event::Rejected, authority, 5)?,
        Outcome::Advanced
    );
    assert_eq!(command.status(), Status::Rejected);
    Ok(())
}
#[test]
fn deadline_and_fence_reject_false_success() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::queue(spec("one")?, 1)?;
    assert_eq!(
        command.transition(Event::Published, Coordinate::new(1, 2)?, 2),
        Err(Error::Fenced)
    );
    assert_eq!(command.version(), 1);
    assert_eq!(
        command.transition(Event::Published, Coordinate::new(1, 1)?, 100)?,
        Outcome::Advanced
    );
    assert_eq!(command.status(), Status::TimedOut);
    Ok(())
}
fn advance(c: &mut Command, event: Event, coordinate: Coordinate, time: i64) -> Result<(), Error> {
    assert_eq!(c.transition(event, coordinate, time)?, Outcome::Advanced);
    Ok(())
}
fn at(status: Status) -> Result<Command, Box<dyn std::error::Error>> {
    let mut c = Command::queue(spec("matrix")?, 1)?;
    let a = c.spec().coordinate();
    if matches!(
        status,
        Status::Published | Status::Received | Status::Applied | Status::Rejected
    ) {
        advance(&mut c, Event::Published, a, 2)?;
    }
    if matches!(status, Status::Received | Status::Applied) {
        advance(&mut c, Event::Received, a, 3)?;
    }
    match status {
        Status::Applied => {
            advance(
                &mut c,
                Event::Reported(StateDigest::from_bytes([7; 32])),
                a,
                4,
            )?;
        }
        Status::Rejected => {
            advance(&mut c, Event::Rejected, a, 4)?;
        }
        Status::TimedOut => {
            advance(&mut c, Event::Expire, a, 100)?;
        }
        Status::Cancelled => {
            advance(&mut c, Event::Cancel, a, 4)?;
        }
        Status::Superseded => {
            advance(&mut c, Event::Supersede, Coordinate::new(1, 2)?, 4)?;
        }
        _ => {}
    }
    Ok(c)
}
#[test]
fn complete_state_event_matrix() -> Result<(), Box<dyn std::error::Error>> {
    use Status as S;
    let events = [
        Event::Published,
        Event::Received,
        Event::Reported(StateDigest::from_bytes([7; 32])),
        Event::Rejected,
        Event::Expire,
        Event::Cancel,
        Event::Supersede,
    ];
    let expected = [
        [
            S::Published,
            S::Queued,
            S::Queued,
            S::Queued,
            S::Queued,
            S::Cancelled,
            S::Superseded,
        ],
        [
            S::Published,
            S::Received,
            S::Published,
            S::Rejected,
            S::Published,
            S::Cancelled,
            S::Superseded,
        ],
        [
            S::Received,
            S::Received,
            S::Applied,
            S::Rejected,
            S::Received,
            S::Cancelled,
            S::Superseded,
        ],
    ];
    use Outcome::{Advanced as A, Duplicate as D, Late as L, OutOfOrder as O};
    let outcomes = [
        [A, O, O, O, D, A, A],
        [D, A, O, A, D, A, A],
        [D, D, A, A, D, A, A],
        [L, L, D, L, L, L, L],
        [L, L, L, D, L, L, L],
        [L, L, L, L, D, L, L],
        [L, L, L, L, L, L, D],
        [L, L, L, L, L, D, L],
    ];
    for (index, status) in Status::ALL.into_iter().enumerate() {
        for (column, event) in events.into_iter().enumerate() {
            let mut command = at(status)?;
            let before = command.clone();
            let authority = if event == Event::Supersede {
                Coordinate::new(1, 2)?
            } else {
                Coordinate::new(1, 1)?
            };
            let outcome = command.transition(event, authority, 10)?;
            assert_eq!(outcome, outcomes[index][column], "{status:?} + {event:?}");
            let next = if index < 3 {
                expected[index][column]
            } else {
                status
            };
            assert_eq!(command.status(), next, "{status:?} + {event:?}");
            if next == status {
                assert_eq!(command, before);
                assert_ne!(outcome, Outcome::Advanced);
            } else {
                assert_eq!(command.version(), before.version() + 1);
            }
            assert_eq!(Command::restore(command.record().clone())?, command);
            assert_eq!(Status::restore(status.as_str())?, status);
        }
    }
    Ok(())
}
#[test]
fn exact_report_identity_and_snapshot_validation() -> Result<(), Box<dyn std::error::Error>> {
    let mut c = at(Status::Received)?;
    let original = c.clone();
    let mut input = DeviceReport {
        scope: c.spec().scope(),
        command_id: c.spec().id().clone(),
        coordinate: c.spec().coordinate(),
        event: DeviceEvent::Reported(StateDigest::from_bytes([7; 32])),
    };
    input.command_id = CommandId::parse("other")?;
    assert_eq!(c.report(&input, input.coordinate, 5), Err(Error::Fenced));
    input.command_id = c.spec().id().clone();
    input.coordinate = Coordinate::new(1, 2)?;
    assert_eq!(c.report(&input, input.coordinate, 5), Err(Error::Fenced));
    input.coordinate = c.spec().coordinate();
    input.scope = Scope::new(
        TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d478")?,
        input.scope.device(),
    );
    assert_eq!(c.report(&input, input.coordinate, 5), Err(Error::Fenced));
    assert_eq!(c, original);
    assert_eq!(
        c.transition(
            Event::Reported(StateDigest::from_bytes([9; 32])),
            input.coordinate,
            5
        ),
        Err(Error::Conflict)
    );
    assert_eq!(
        c.transition(Event::Rejected, input.coordinate, 2),
        Err(Error::InvalidSnapshot)
    );
    assert_eq!(c, original);
    Ok(())
}
#[test]
fn invalid_snapshots() -> Result<(), Box<dyn std::error::Error>> {
    let c = at(Status::Received)?;
    for version in [0, -1, i64::MAX] {
        let mut raw = c.record().clone();
        raw.version = version;
        assert!(Command::restore(raw).is_err());
    }
    let mut raw = c.record().clone();
    raw.published_at = None;
    assert!(Command::restore(raw).is_err());
    let mut raw = c.record().clone();
    raw.received_at = Some(101);
    assert!(Command::restore(raw).is_err());
    let mut raw = c.record().clone();
    raw.terminal_at = Some(4);
    assert!(Command::restore(raw).is_err());
    Ok(())
}
#[test]
fn values_and_independent_coordinates() -> Result<(), Box<dyn std::error::Error>> {
    assert!(Status::restore("future").is_err());
    assert!(Coordinate::new(0, 1).is_err());
    assert!(Coordinate::new(1, 0).is_err());
    assert!(Coordinate::new(2, 3)?.supersedes(Coordinate::new(1, 2)?));
    assert!(Coordinate::new(1, 3)?.supersedes(Coordinate::new(1, 2)?));
    assert!(!Coordinate::new(2, 2)?.supersedes(Coordinate::new(1, 2)?));
    assert!(!Coordinate::new(1, 4)?.supersedes(Coordinate::new(2, 3)?));
    Ok(())
}
#[test]
fn bounded_identity_values() -> Result<(), Box<dyn std::error::Error>> {
    let c = at(Status::Received)?;
    for bad in ["", "space here", "invalid/route"] {
        assert!(CommandId::parse(bad).is_err());
    }
    assert!(CommandId::parse(&"a".repeat(256)).is_err());
    assert!(DeviceId::parse("bad").is_err());
    assert!(DeviceId::parse("00000000-0000-0000-0000-000000000000").is_err());
    assert!(BatchLimit::new(0).is_err());
    assert!(BatchLimit::new(65).is_err());
    assert_eq!(BatchLimit::new(64)?.get(), 64);
    assert!(!format!("{:?}", c.spec()).contains("matrix"));
    Ok(())
}
#[test]
fn late_controls_keep_their_actual_reason() -> Result<(), Box<dyn std::error::Error>> {
    for state in [Status::Queued, Status::Published, Status::Received] {
        for time in [99, 100, 101] {
            for (event, want) in [
                (Event::Cancel, Status::Cancelled),
                (Event::Supersede, Status::Superseded),
            ] {
                let mut c = at(state)?;
                let coord = if event == Event::Supersede {
                    Coordinate::new(1, 2)?
                } else {
                    Coordinate::new(1, 1)?
                };
                assert_eq!(c.transition(event, coord, time)?, Outcome::Advanced);
                assert_eq!(c.status(), want);
                assert_eq!(Command::restore(c.record().clone())?, c);
            }
        }
    }
    Ok(())
}
#[test]
fn late_rejection_is_not_success() -> Result<(), Box<dyn std::error::Error>> {
    for state in [Status::Published, Status::Received] {
        let mut c = at(state)?;
        assert_eq!(
            c.transition(Event::Rejected, Coordinate::new(1, 1)?, 101)?,
            Outcome::Advanced
        );
        assert_eq!(c.status(), Status::Rejected);
    }
    let mut c = at(Status::Received)?;
    assert_eq!(
        c.transition(
            Event::Reported(StateDigest::from_bytes([7; 32])),
            Coordinate::new(1, 1)?,
            100
        )?,
        Outcome::Advanced
    );
    assert_eq!(c.status(), Status::TimedOut);
    Ok(())
}
