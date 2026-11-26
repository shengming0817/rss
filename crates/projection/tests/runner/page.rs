use super::*;

async fn invoke(
    source: &impl Source<Item = Event>,
    exec: &Memory,
    c: &Control<'_, Clock>,
    bytes: u32,
    batched: bool,
) -> anyhow::Result<Report> {
    let limit = RunLimit::new(PageBudget::new(8, bytes)?, 20)?;
    let (report, observation) = if batched {
        let work = run_batched(source, exec, c, limit);
        let observation = work.observation();
        (work.await, observation)
    } else {
        let work = run(source, exec, c, limit);
        let observation = work.observation();
        (work.await, observation)
    };
    assert_eq!(
        observation.read(),
        ObservationStatus::Stopped(report.clone())
    );
    assert_eq!(exec.checkpoint(c).await?.position, report.position);
    Ok(report)
}

#[tokio::test]
async fn both_runners_resume_the_exact_prefix() -> anyhow::Result<()> {
    let scope = scope()?;
    let bytes = 3;
    let sizes = [bytes, 0, bytes - 1, bytes + 1, 1];
    let source = Journal(
        sizes
            .into_iter()
            .enumerate()
            .map(|(i, n)| {
                Event::new(
                    scope.source().clone(),
                    Position::new(i as u64)?,
                    format!("e{i}"),
                    vec![0; n],
                )
            })
            .collect::<Result<_, _>>()?,
    );
    let clock = Clock(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    let c = Control::new(&clock, Duration::from_secs(10), &cancel);
    let required_bytes = sizes[3] as u32;
    let blocked = Stop::PayloadBudget {
        position: Position::new(3)?,
        required_bytes,
    };
    for batched in [false, true] {
        let exec = Memory::new(scope.clone(), ReplayBound::Live);
        let first = invoke(&source, &exec, &c, bytes as u32, batched)
            .await?
            .into_result()?;
        assert_eq!(
            (&first.stop, first.position, first.applied + first.filtered),
            (&blocked, Some(Position::new(2)?), 3)
        );
        let again = invoke(&source, &exec, &c, bytes as u32, batched).await?;
        assert_eq!(
            (&again.stop, again.position, again.applied + again.filtered),
            (&blocked, first.position, 0)
        );
        let resumed = invoke(&source, &exec, &c, required_bytes, batched).await?;
        assert_eq!(
            (
                resumed.stop,
                resumed.position,
                resumed.applied + resumed.filtered
            ),
            (Stop::CaughtUp, Some(Position::new(4)?), 2)
        );
        let empty = invoke(&source, &exec, &c, 1, batched).await?;
        assert_eq!(
            (empty.stop, empty.applied + empty.filtered),
            (Stop::CaughtUp, 0)
        );
        let replay = Memory::new(scope.clone(), ReplayBound::Through(first.position));
        let report = invoke(&source, &replay, &c, bytes as u32, batched).await?;
        assert_eq!(
            (report.stop, report.position),
            (Stop::CaughtUp, first.position)
        );
    }
    Ok(())
}

#[tokio::test]
async fn live_journal_with_no_events_is_caught_up_from_the_beginning() -> anyhow::Result<()> {
    let source = Journal(Vec::new());
    let clock = Clock(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    let c = Control::new(&clock, Duration::from_secs(10), &cancel);
    for batched in [false, true] {
        let exec = Memory::new(scope()?, ReplayBound::Live);
        let report = invoke(&source, &exec, &c, 1, batched).await?;
        assert_eq!(
            report,
            Report {
                position: None,
                applied: 0,
                filtered: 0,
                duplicates: 0,
                stop: Stop::CaughtUp
            }
        );
        assert_eq!(exec.applied.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

struct Nonconforming(ReadPage<Event>);
impl Source for Nonconforming {
    type Item = Event;
    async fn high_water<T: Timer>(
        &self,
        _: &SourceScope,
        _: &Control<'_, T>,
    ) -> Result<Option<Position>, Error> {
        Err(Error::new(ErrorKind::SourceContract))
    }
    async fn read<T: Timer>(
        &self,
        _: &SourceScope,
        _: Option<Position>,
        _: PageBudget,
        c: &Control<'_, T>,
    ) -> Result<ReadPage<Event>, Error> {
        c.check()?;
        Ok(match &self.0 {
            ReadPage::Events(events) => ReadPage::Events(events.clone()),
            ReadPage::Blocked {
                position,
                required_bytes,
            } => ReadPage::Blocked {
                position: *position,
                required_bytes: *required_bytes,
            },
        })
    }
}

#[tokio::test]
async fn invalid_page_evidence_is_rejected_before_settlement() -> anyhow::Result<()> {
    let scope = scope()?;
    let clock = Clock(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    let c = Control::new(&clock, Duration::from_secs(10), &cancel);
    let end = Position::new(2)?;
    for page in [
        ReadPage::Events(vec![event(&scope, 0)?, event(&scope, 1)?]),
        ReadPage::Blocked {
            position: end,
            required_bytes: 1,
        },
        ReadPage::Blocked {
            position: end,
            required_bytes: Event::MAX_PAYLOAD_BYTES + 1,
        },
        ReadPage::Blocked {
            position: Position::new(3)?,
            required_bytes: 2,
        },
    ] {
        let source = Nonconforming(page);
        for batched in [true, false] {
            let exec = Memory::new(scope.clone(), ReplayBound::Through(Some(end)));
            let report = invoke(&source, &exec, &c, 1, batched).await?;
            assert_eq!(
                report.stop,
                Stop::Failed(Error::new(ErrorKind::SourceContract))
            );
            assert_eq!(
                (report.position, exec.applied.load(Ordering::SeqCst)),
                (None, 0)
            );
        }
    }
    Ok(())
}
