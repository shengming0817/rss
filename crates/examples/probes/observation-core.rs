fn main() -> Result<(), Box<dyn std::error::Error>> {
    use rss_observation::*;
    let coverage = Coverage::new(
        Id::new("all")?,
        Id::new("1")?,
        Id::new("catalog")?,
        Id::new("bytes")?,
    );
    let policy = Policy::new(10, 1, 10)?;
    let time = rss_contract::Timepoint::try_from(10)?;
    let batch = Batch::new(
        Id::new("snapshot")?,
        0,
        time,
        coverage.clone(),
        Body::Snapshot(vec![]),
    )?;
    let decision = State::initial().advance(&batch, 10, &policy)?;
    assert_eq!(decision.state().cursor(), Some(0));
    assert_eq!(decision.state().revision(), 1);
    let delta = Batch::new(
        Id::new("delta")?,
        1,
        time,
        coverage,
        Body::Delta {
            baseline: Id::new("snapshot")?,
            previous: 0,
            changes: vec![],
        },
    )?;
    let next = decision.state().advance(&delta, 10, &policy)?;
    assert_eq!(next.state().cursor(), Some(1));
    assert!(next.state().needs_snapshot().is_none());
    Ok(())
}
