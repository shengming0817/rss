use rss_contract::Timepoint;
use rss_observation::*;
use rss_request_context::TenantId;
struct SubmitOnly;
impl Authority for SubmitOnly {
    fn authorize(&self, request: Access<'_>) -> Result<(), Error> {
        match request {
            Access::Submit { .. } => Ok(()),
            _ => Err(ErrorKind::Unauthorized.into()),
        }
    }
}
#[test]
fn submission_does_not_grant_journal_access() -> anyhow::Result<()> {
    let tenant = TenantId::parse("00000000-0000-0000-0000-000000000001")?;
    assert_eq!(
        JournalReadGrant::verify(&SubmitOnly, tenant)
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::Unauthorized)
    );
    Ok(())
}
#[test]
fn only_historically_applicable_records_cross_the_seam() -> anyhow::Result<()> {
    let tenant = TenantId::parse("00000000-0000-0000-0000-000000000001")?;
    let scope = Scope::new(
        tenant,
        Id::new("object")?,
        Registration::new("r")?,
        Id::new("source")?,
        Id::new("dataset")?,
        Epoch::new("e")?,
    );
    let coverage = Coverage::new(
        Id::new("all")?,
        Id::new("v1")?,
        Id::new("catalog")?,
        Id::new("bytes")?,
    );
    for (body, applicable) in [
        (Body::Snapshot(vec![]), true),
        (Body::Partial(vec![]), false),
        (
            Body::Failed {
                code: Id::new("failed")?,
            },
            false,
        ),
        (
            Body::Delta {
                baseline: Id::new("missing")?,
                previous: 0,
                changes: vec![],
            },
            false,
        ),
    ] {
        let batch = Batch::new(
            Id::new("batch")?,
            1,
            Timepoint::try_from(100)?,
            coverage.clone(),
            body,
        )?;
        let policy = Policy::new(10, 1, 10)?;
        let decision = State::initial().advance(&batch, 100, &policy)?;
        let record = Record::from_durable(scope.clone(), batch, 100, policy, decision)?;
        assert_eq!(record.into_applicable().is_ok(), applicable);
    }
    Ok(())
}
