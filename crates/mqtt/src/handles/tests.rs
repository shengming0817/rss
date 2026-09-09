use super::*;
use crate::ConnectionState;
use std::{cell::RefCell, sync::atomic::AtomicUsize};

thread_local! {
    static PREFLIGHT: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}
pub(crate) fn preflight() {
    let hook = PREFLIGHT.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

pub(crate) struct TestClock {
    epoch: std::time::Instant,
    pub(crate) elapsed: AtomicU64,
    observations: AtomicUsize,
    expire_on: usize,
}
impl TestClock {
    pub(crate) fn new() -> Arc<Self> {
        Self::expiring_on(usize::MAX)
    }
    #[allow(clippy::disallowed_methods)] // reason: injected test clock owns its monotonic origin.
    fn expiring_on(expire_on: usize) -> Arc<Self> {
        Arc::new(Self {
            epoch: tokio::time::Instant::now().into_std(),
            elapsed: AtomicU64::new(0),
            observations: AtomicUsize::new(0),
            expire_on,
        })
    }
}
impl Clock for TestClock {
    fn now(&self) -> std::time::Instant {
        if self.observations.fetch_add(1, Ordering::SeqCst) >= self.expire_on {
            self.elapsed.store(10, Ordering::SeqCst);
        }
        self.epoch + Duration::from_secs(self.elapsed.load(Ordering::SeqCst))
    }
}

pub(crate) fn publisher(clock: Arc<TestClock>) -> (MqttPublisher, mpsc::Receiver<Command>) {
    let (commands, rx) = mpsc::channel(1);
    let (state, _) = watch::channel(ConnectionState::Ready {
        generation: 1,
        session_present: false,
    });
    (
        MqttPublisher {
            packet_bytes: 65536,
            shared: Arc::new(Shared {
                #[cfg(feature = "consumer")]
                subscriptions: Vec::new(),
                commands,
                clock: ClockRef(clock),
                state,
                closing: AtomicBool::new(false),
                generation: AtomicU64::new(1),
                retire: AtomicU64::new(0),
                wake: Notify::new(),
                cancelled: CancellationToken::new(),
                deliveries: Mutex::new(VecDeque::new()),
                delivered: Notify::new(),
            }),
        },
        rx,
    )
}

fn spend_preflight(clock: Arc<TestClock>, seconds: u64) {
    PREFLIGHT.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            clock.elapsed.store(seconds, Ordering::SeqCst);
        }))
    });
}
fn budget() -> OperationDeadline {
    OperationDeadline::from_remaining(Duration::from_secs(10))
}
fn assert_expired(outcome: PublishOutcome<()>) {
    assert!(matches!(outcome, PublishOutcome::DefinitelyNotPublished(f)
        if f.reason() == Reason::DeadlineElapsed && f.stage() == Stage::Admission));
}

#[tokio::test]
async fn size_preflight_expiration_never_enqueues() -> anyhow::Result<()> {
    let clock = TestClock::new();
    let (publisher, mut commands) = publisher(clock.clone());
    spend_preflight(clock, 11);
    assert_expired(
        publisher
            .publish(PublishRequest::new("events", vec![])?, budget())
            .await,
    );
    assert!(commands.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn permit_acquisition_expiration_never_enqueues() -> anyhow::Result<()> {
    // Entry, post-preflight and pre-reserve observations are live; the next observation expires.
    let (publisher, mut commands) = publisher(TestClock::expiring_on(3));
    assert_expired(
        publisher
            .publish(PublishRequest::new("events", vec![])?, budget())
            .await,
    );
    assert!(commands.try_recv().is_err());
    assert_eq!(publisher.shared.commands.capacity(), 1);
    Ok(())
}

async fn reject_with_remaining(
    commands: &mut mpsc::Receiver<Command>,
    clock: &TestClock,
) -> anyhow::Result<()> {
    let Some(Command::Publish {
        deadline, response, ..
    }) = commands.recv().await
    else {
        anyhow::bail!("publication missing");
    };
    assert_eq!(
        deadline.remaining(clock.now()),
        Some(Duration::from_secs(3))
    );
    let _ = response.send(Err(outcome::definite(
        Kind::Transient,
        Stage::Admission,
        Reason::TransportUnavailable,
    )));
    Ok(())
}

#[tokio::test]
async fn size_preflight_is_deducted_from_command_budget() -> anyhow::Result<()> {
    let clock = TestClock::new();
    let (publisher, mut commands) = publisher(clock.clone());
    let request = PublishRequest::new("events", vec![])?;
    spend_preflight(clock.clone(), 7);
    let (result, observed) = tokio::join!(
        publisher.publish(request, budget()),
        reject_with_remaining(&mut commands, &clock)
    );
    observed?;
    assert!(matches!(result, PublishOutcome::DefinitelyNotPublished(_)));
    Ok(())
}

#[tokio::test]
async fn submitted_expiration_stays_ambiguous() -> anyhow::Result<()> {
    let clock = TestClock::new();
    let (publisher, mut commands) = publisher(clock.clone());
    let request = PublishRequest::new("events", vec![])?;
    let (result, ()) = tokio::join!(publisher.publish(request, budget()), async {
        let command = commands.recv().await;
        clock.elapsed.store(11, Ordering::SeqCst);
        drop(command);
    });
    assert!(
        matches!(result, PublishOutcome::Ambiguous(f) if f.reason() == Reason::DeadlineElapsed)
    );
    Ok(())
}

#[cfg(feature = "consumer")]
#[tokio::test]
async fn outbox_encoding_consumes_the_original_budget() -> anyhow::Result<()> {
    use rss_transactional_messaging::{message::*, transport::Publisher};
    for elapsed in [7, 11] {
        let clock = TestClock::new();
        let (raw, mut commands) = publisher(clock.clone());
        let route = MessageRoute::parse("created")?;
        let domain = MessagingDomain::parse("test")?;
        let plan = crate::MqttOutboxPlan::new(
            domain.clone(),
            [(route.clone(), crate::MqttOutboxTopic::new("events")?)],
        )?;
        let publisher = crate::MqttOutboxPublisher::new(raw, plan);
        let message = MessageEnvelope::new(
            MessageId::parse("message-1")?,
            MessageMetadata::new(
                AuthoredMessageMetadata::new(
                    rss_request_context::TenantId::parse("00000000-0000-0000-0000-000000000001")?,
                    rss_contract::Timepoint::try_from(0)?,
                    domain,
                    route,
                    ContractIdentity::new(
                        rss_contract::ContractId::parse("test.created")?,
                        rss_contract::ContractVersion::from_major(1)?,
                        rss_contract::SchemaDigest::parse(
                            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                        )?,
                    ),
                ),
                MessageMetadataExtensions::default(),
            ),
            vec![],
        );
        spend_preflight(clock.clone(), elapsed);
        if elapsed == 7 {
            let (_, observed) = tokio::join!(
                publisher.publish(&message, budget()),
                reject_with_remaining(&mut commands, &clock)
            );
            observed?;
        } else {
            assert_expired(publisher.publish(&message, budget()).await);
            assert!(commands.try_recv().is_err());
        }
    }
    Ok(())
}
