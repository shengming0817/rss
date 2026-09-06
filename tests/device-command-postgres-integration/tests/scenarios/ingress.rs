use super::*;
use rss_transactional_messaging::{
    inbox::{IdempotencyDisposition, InboxStore},
    observability::TransactionalMessagingTransactionStatus as TxStatus,
    transaction::{ConsumerTx, RejectKind, TerminalDisposition},
};
use rss_transactional_messaging_postgres::{PgConsumerTx, PgInboxStore};
async fn deliver(
    f: &Fixture,
    m: &PendingMessage<Vec<u8>>,
    report: DeviceReport,
    expected: MessageFingerprint,
) -> anyhow::Result<TerminalDispositionOrRetry> {
    let binding = binding(m.envelope())?;
    let inbox = PgInboxStore::new(
        f.runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(60))?,
    )?;
    let IdempotencyDisposition::Acquired(claim) =
        inbox.claim(binding.identity(), budget()?).await?
    else {
        anyhow::bail!("expected fresh ingress claim")
    };
    let consumer = PgConsumerTx::new(
        f.runtime.clone(),
        compose::ReportEffect {
            store: f.store.clone(),
            decoder: Decoder {
                fingerprint: expected,
                report,
            },
        },
    );
    let status = consumer
        .execute(&claim, m.envelope(), binding.receipt_intent(), budget()?)
        .await
        .status();
    let receipt = inbox.read_terminal(binding.identity(), budget()?).await?;
    if status != TxStatus::Committed {
        assert!(receipt.is_none());
        inbox.release(claim, budget()?).await?;
        return Ok(TerminalDispositionOrRetry::Retry);
    }
    let receipt = receipt.ok_or_else(|| anyhow::anyhow!("terminal receipt missing"))?;
    let disposition = receipt.disposition();
    assert!(binding.validate_terminal(receipt).is_ok());
    Ok(TerminalDispositionOrRetry::Terminal(disposition))
}
#[derive(Debug, PartialEq, Eq)]
enum TerminalDispositionOrRetry {
    Retry,
    Terminal(TerminalDisposition),
}
fn report(id: &str, coordinate: Coordinate, event: DeviceEvent) -> anyhow::Result<DeviceReport> {
    Ok(DeviceReport {
        scope: scope(TENANT)?,
        command_id: CommandId::parse(id)?,
        coordinate,
        event,
    })
}
pub(crate) async fn actual_state_redelivery(f: &Fixture) -> anyhow::Result<()> {
    use TerminalDispositionOrRetry as R;
    let s = scope(TENANT)?;
    let c = Coordinate::new(2, 3)?;
    f.queue("early-state", s, c).await?;
    let m = message("early-state-report", s.tenant())?;
    let report = report(
        "early-state",
        c,
        DeviceEvent::Reported(StateDigest::from_bytes([7; 32])),
    )?;
    assert_eq!(
        deliver(f, &m, report.clone(), m.fingerprint()).await?,
        R::Retry
    );
    f.publish().await?;
    let _page = f.recover(s).await?;
    assert_eq!(
        deliver(f, &m, report.clone(), m.fingerprint()).await?,
        R::Retry
    );
    assert_eq!(
        f.report("early-state", s, c, DeviceEvent::Received)
            .await?
            .outcome,
        Outcome::Advanced
    );
    assert_eq!(
        deliver(f, &m, report, m.fingerprint()).await?,
        R::Terminal(TerminalDisposition::Succeeded)
    );
    assert_eq!(
        f.load("early-state", s).await?.map(|c| c.status()),
        Some(Status::Applied)
    );
    Ok(())
}
pub(crate) async fn permanent_inputs(f: &Fixture) -> anyhow::Result<()> {
    use TerminalDispositionOrRetry as R;
    let s = scope(TENANT)?;
    let c = Coordinate::new(2, 3)?;
    f.queue("poison-target", s, c).await?;
    let original = f.load("poison-target", s).await?;
    for (id, input) in [
        (
            "stale-ingress",
            report(
                "poison-target",
                Coordinate::new(1, 1)?,
                DeviceEvent::Received,
            )?,
        ),
        (
            "conflicting-ingress",
            report(
                "poison-target",
                c,
                DeviceEvent::Reported(StateDigest::from_bytes([8; 32])),
            )?,
        ),
    ] {
        let m = message(id, s.tenant())?;
        assert_eq!(
            deliver(f, &m, input, m.fingerprint()).await?,
            R::Terminal(TerminalDisposition::Rejected(RejectKind::Permanent))
        );
        let inbox = PgInboxStore::new(
            f.runtime.clone(),
            LeaseRenewalPolicy::from_ttl(Duration::from_secs(60))?,
        )?;
        assert!(matches!(
            inbox
                .claim(binding(m.envelope())?.identity(), budget()?)
                .await?,
            IdempotencyDisposition::Terminal(_)
        ));
    }
    assert_eq!(f.load("poison-target", s).await?, original);
    let expected = message("expected-ingress", s.tenant())?;
    let other = message("unrelated-ingress", s.tenant())?;
    assert_eq!(
        deliver(
            f,
            &other,
            report("poison-target", c, DeviceEvent::Received)?,
            expected.fingerprint()
        )
        .await?,
        R::Terminal(TerminalDisposition::Rejected(RejectKind::Permanent))
    );
    assert_eq!(f.load("poison-target", s).await?, original);
    Ok(())
}
