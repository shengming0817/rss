use super::*;
use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

struct Remote {
    facts: Mutex<HashMap<(ProjectionScope, String), [u8; 32]>>,
    writes: AtomicU64,
    store: PgStore,
    lose_checkpoint_ack: AtomicBool,
}
impl ExternalTarget for &Remote {
    async fn apply<T: Timer>(
        &self,
        scope: &ProjectionScope,
        event: &Event,
        control: &Control<'_, T>,
    ) -> Result<ApplyOutcome, Error> {
        control.check()?;
        let mut facts = self
            .facts
            .lock()
            .map_err(|_| Error::new(rss_projection::ErrorKind::Unavailable))?;
        let key = (scope.clone(), event.id().to_owned());
        let digest = event.fingerprint();
        if let Some(previous) = facts.get(&key) {
            return if *previous == digest {
                Ok(ApplyOutcome::Duplicate)
            } else {
                Err(Error::new(rss_projection::ErrorKind::Conflict))
            };
        }
        facts.insert(key, digest);
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.lose_checkpoint_ack.swap(false, Ordering::SeqCst) {
            self.store.inject_next_fault(PgFault::CommitUnknownAfterAck);
        }
        Ok(ApplyOutcome::Applied)
    }
}
pub(crate) async fn external_recovery(
    store: &PgStore,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("external", TENANT)?;
    store
        .initialize(&s, GenerationStart::beginning(), ReplayBound::Live, control)
        .await?;
    let remote = Remote {
        facts: Mutex::new(HashMap::new()),
        writes: AtomicU64::new(0),
        store: store.clone(),
        lose_checkpoint_ack: AtomicBool::new(true),
    };
    let old = store.external_checkpoint(store.takeover(&s, control).await?)?;
    let checkpoint = store.external_checkpoint(store.takeover(&s, control).await?)?;
    let execution = AtLeastOnce::new(checkpoint, &remote);
    let first = event(&s, 0, "one", b"one")?;
    assert_eq!(
        execution.execute(None, &first, control).await,
        Err(Error::new(rss_projection::ErrorKind::CommitUnknown))
    );
    assert_eq!(
        execution.checkpoint().await?.position,
        Some(first.position())
    );
    assert_eq!(
        old.load().await,
        Err(Error::new(rss_projection::ErrorKind::Fenced))
    );
    duplicate_and_conflict(&execution, &remote, &s, first.position(), control).await
}
async fn duplicate_and_conflict(
    execution: &AtLeastOnce<PgCheckpoint, &Remote>,
    remote: &Remote,
    s: &ProjectionScope,
    first: Position,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let duplicate = event(s, 1, "one", b"one")?;
    assert_eq!(
        execution.execute(Some(first), &duplicate, control).await?,
        ApplyOutcome::Duplicate
    );
    assert_eq!(remote.writes.load(Ordering::SeqCst), 1);
    let conflict = event(s, 2, "one", b"changed")?;
    assert_eq!(
        execution
            .execute(Some(duplicate.position()), &conflict, control)
            .await,
        Err(Error::new(rss_projection::ErrorKind::Conflict))
    );
    assert_eq!(
        execution.checkpoint().await?.position,
        Some(duplicate.position())
    );
    Ok(())
}

pub(crate) async fn direct_advance_obeys_control(
    store: &PgStore,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("direct-advance", TENANT)?;
    store
        .initialize(&s, GenerationStart::beginning(), ReplayBound::Live, control)
        .await?;
    let checkpoint = store.external_checkpoint(store.takeover(&s, control).await?)?;
    let fact = event(&s, 0, "one", b"one")?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let cancelled = Control::new(&clock, Duration::from_secs(10), &cancel);
    assert_eq!(
        checkpoint.advance(None, &fact, &cancelled).await,
        Err(Error::new(rss_projection::ErrorKind::Cancelled))
    );
    assert_eq!(checkpoint.load().await?.position, None);
    let signal = CancellationToken::new();
    let expired = Control::new(&clock, Duration::ZERO, &signal);
    assert_eq!(
        checkpoint.advance(None, &fact, &expired).await,
        Err(Error::new(rss_projection::ErrorKind::Deadline))
    );
    store.inject_next_fault(PgFault::CommitUnknownAfterAck);
    assert_eq!(
        checkpoint.advance(None, &fact, control).await,
        Err(Error::new(rss_projection::ErrorKind::CommitUnknown))
    );
    assert_eq!(checkpoint.load().await?.position, Some(fact.position()));
    Ok(())
}
