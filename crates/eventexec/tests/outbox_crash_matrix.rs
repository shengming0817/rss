use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use consistency::{
    BacklogSample, Disposition, InboxState, LeaseOutcome, LeaseToken, OutboxContractId,
    OutboxMetricSubject, OutboxRelay, SeenState,
};
use eventexec::{
    OutboxMetricScope, OutboxMetrics, RelayConfig, RelayPhase, WorkerHealth, relay_loop,
};
use testkit::crash_matrix::{CrashCase, CrashFaultSpec, CrashStatus};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const FIXTURE: &str = include_str!(
    "../../../fixtures/consistency/outbox/fixture-outbox-after-publish-before-settle.toml"
);
const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const TENANT_B: &str = "8d9d3a33-8144-4e49-b1ad-67f6ee88c13a";
const MESSAGE_ID: &str = "session-created-01";
const TOPIC: &str = "identity.session-created";
const CONTRACT_ID: &str = "identity.session-created";
const PARTITION_KEY: &str = "session-01";
const PAYLOAD: &[u8] = br#"{"sessionId":"session-01"}"#;
const START_EPOCH_MICROS: i64 = 1_000_000;
const LEASE_TTL_MICROS: i64 = 60_000_000;

fn relay_admission() -> primitives::RelayAdmission {
    let (control, relay, _, _) = primitives::prepare_dr_admission_controls().into_parts();
    assert!(control.start_running().is_ok());
    relay
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DurableStatus {
    Pending,
    Publishing,
    Published,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Delivery {
    tenant_id: String,
    message_id: String,
    partition_key: String,
    topic: String,
    contract_id: String,
    payload: Vec<u8>,
}

struct DurableRow {
    delivery: Delivery,
    status: DurableStatus,
    lease_token: Option<String>,
    lease_deadline_epoch_micros: Option<i64>,
}

/// CrashStore 私有铸造、按值消费的 durable claim capability。
struct CrashClaim {
    subject: OutboxMetricSubject,
    message_id: String,
    lease_token: String,
    lease_deadline_epoch_micros: i64,
}

impl CrashClaim {
    #[allow(clippy::expect_used)]
    // reason: fixed crash fixture tenant/contract values are valid by construction.
    fn new(row: &DurableRow, lease_token: String, lease_deadline_epoch_micros: i64) -> Self {
        Self {
            subject: OutboxMetricSubject::new(
                vocab::TenantId::parse(&row.delivery.tenant_id).expect("valid tenant"),
                OutboxContractId::parse(&row.delivery.contract_id).expect("valid contract"),
            ),
            message_id: row.delivery.message_id.clone(),
            lease_token,
            lease_deadline_epoch_micros,
        }
    }
}

struct CrashStore {
    domain: vocab::DomainName,
    rows: Mutex<Vec<DurableRow>>,
    deliveries: Mutex<Vec<Delivery>>,
    published_before_settle: Notify,
    settled: Notify,
    block_first_settle: Mutex<bool>,
    now_epoch_micros: Mutex<i64>,
    next_token: Mutex<u64>,
    first_claim: Mutex<Option<(String, i64)>>,
}

impl CrashStore {
    #[allow(clippy::expect_used)]
    // reason: fixed crash fixture provider domain is valid by construction.
    fn new() -> Arc<Self> {
        Arc::new(Self {
            domain: vocab::DomainName::parse("identity").expect("valid fixture domain"),
            rows: Mutex::new(vec![
                DurableRow {
                    delivery: delivery(TENANT_A, MESSAGE_ID),
                    status: DurableStatus::Pending,
                    lease_token: None,
                    lease_deadline_epoch_micros: None,
                },
                DurableRow {
                    delivery: delivery(TENANT_B, "other-tenant-message"),
                    status: DurableStatus::Publishing,
                    lease_token: Some("00000000-0000-4000-8000-000000000002".to_string()),
                    lease_deadline_epoch_micros: Some(i64::MAX),
                },
            ]),
            deliveries: Mutex::new(Vec::new()),
            published_before_settle: Notify::new(),
            settled: Notify::new(),
            block_first_settle: Mutex::new(true),
            now_epoch_micros: Mutex::new(START_EPOCH_MICROS),
            next_token: Mutex::new(10),
            first_claim: Mutex::new(None),
        })
    }

    #[allow(clippy::expect_used)]
    // reason: hermetic fake uses fixed rows; missing/poisoned state is a test invariant failure.
    fn status(&self, tenant_id: &str) -> DurableStatus {
        self.rows
            .lock()
            .expect("row lock")
            .iter()
            .find(|row| row.delivery.tenant_id == tenant_id)
            .expect("tenant row")
            .status
    }

    #[allow(clippy::expect_used)]
    // reason: hermetic fake uses fixed rows; missing/poisoned state is a test invariant failure.
    fn expire_lease(&self, tenant_id: &str) {
        let deadline = {
            let rows = self.rows.lock().expect("row lock");
            let row = rows
                .iter()
                .find(|row| row.delivery.tenant_id == tenant_id)
                .expect("tenant row");
            assert_eq!(row.status, DurableStatus::Publishing);
            row.lease_deadline_epoch_micros
                .expect("publishing row deadline")
        };
        *self.now_epoch_micros.lock().expect("clock lock") = deadline;
    }

    #[allow(clippy::expect_used)]
    // reason: hermetic fake uses fixed rows; missing/poisoned state is a test invariant failure.
    fn lease_expired(&self, tenant_id: &str) -> bool {
        let now = *self.now_epoch_micros.lock().expect("clock lock");
        self.rows
            .lock()
            .expect("row lock")
            .iter()
            .find(|row| row.delivery.tenant_id == tenant_id)
            .expect("tenant row")
            .lease_deadline_epoch_micros
            .is_some_and(|deadline| deadline <= now)
    }

    #[allow(clippy::expect_used)]
    // reason: hermetic fake uses fixed rows; missing/poisoned state is a test invariant failure.
    fn partition_key(&self, tenant_id: &str) -> String {
        self.rows
            .lock()
            .expect("row lock")
            .iter()
            .find(|row| row.delivery.tenant_id == tenant_id)
            .expect("tenant row")
            .delivery
            .partition_key
            .clone()
    }

    #[allow(clippy::expect_used)]
    // reason: hermetic fake uses fixed rows; poisoned state is a test invariant failure.
    fn deliveries(&self) -> Vec<Delivery> {
        self.deliveries.lock().expect("delivery lock").clone()
    }

    #[allow(clippy::expect_used)]
    // reason: first relay always records one claim before notifying the crash point.
    fn first_claim_is_lost(&self) -> bool {
        let (token, deadline) = self
            .first_claim
            .lock()
            .expect("claim lock")
            .clone()
            .expect("first claim");
        let now = *self.now_epoch_micros.lock().expect("clock lock");
        let rows = self.rows.lock().expect("row lock");
        let row = rows
            .iter()
            .find(|row| row.delivery.message_id == MESSAGE_ID)
            .expect("claimed row");
        deadline <= now
            || row.lease_token.as_deref() != Some(token.as_str())
            || row.lease_deadline_epoch_micros != Some(deadline)
    }

    #[allow(clippy::expect_used)]
    // reason: hermetic fake lock poisoning is a test invariant failure.
    fn mint_lease_token(&self) -> String {
        let mut next = self.next_token.lock().expect("token lock");
        let token = format!("00000000-0000-4000-8000-{:012x}", *next);
        *next += 1;
        token
    }
}

impl OutboxRelay for CrashStore {
    type Claim = CrashClaim;

    fn claim_subject(claim: &Self::Claim) -> &OutboxMetricSubject {
        &claim.subject
    }

    fn claim_domain(&self) -> &vocab::DomainName {
        &self.domain
    }

    #[allow(clippy::expect_used)]
    // reason: hermetic fake uses fixed rows; poisoned state is a test invariant failure.
    async fn claim_batch(
        &self,
        limit: usize,
    ) -> Result<Vec<Self::Claim>, consistency::EngineError> {
        let now = *self.now_epoch_micros.lock().expect("clock lock");
        let deadline = now + LEASE_TTL_MICROS;
        let mut rows = self.rows.lock().expect("row lock");
        let mut claimed = Vec::new();
        for row in rows.iter_mut().filter(|row| {
            row.status == DurableStatus::Pending
                || (row.status == DurableStatus::Publishing
                    && row
                        .lease_deadline_epoch_micros
                        .is_some_and(|lease_until| lease_until <= now))
        }) {
            if claimed.len() == limit {
                break;
            }
            let lease_token = self.mint_lease_token();
            row.status = DurableStatus::Publishing;
            row.lease_token = Some(lease_token.clone());
            row.lease_deadline_epoch_micros = Some(deadline);
            claimed.push(CrashClaim::new(row, lease_token, deadline));
        }
        Ok(claimed)
    }
    #[allow(clippy::expect_used)]
    // reason: hermetic fake uses fixed rows; missing/poisoned state is a test invariant failure.
    async fn relay(&self, entry: Self::Claim) -> Result<Disposition, consistency::EngineError> {
        let delivery = {
            let rows = self.rows.lock().expect("row lock");
            let row = rows
                .iter()
                .find(|row| row.delivery.message_id == entry.message_id)
                .expect("claimed row");
            row.delivery.clone()
        };
        self.deliveries
            .lock()
            .expect("delivery lock")
            .push(delivery);

        let block = {
            let mut first = self.block_first_settle.lock().expect("crash lock");
            std::mem::take(&mut *first)
        };
        if block {
            *self.first_claim.lock().expect("claim lock") =
                Some((entry.lease_token.clone(), entry.lease_deadline_epoch_micros));
            self.published_before_settle.notify_one();
            std::future::pending::<()>().await;
        }

        let now = *self.now_epoch_micros.lock().expect("clock lock");
        let mut rows = self.rows.lock().expect("row lock");
        let row = rows
            .iter_mut()
            .find(|row| row.delivery.message_id == entry.message_id)
            .expect("relayed row");
        assert_eq!(row.lease_token.as_deref(), Some(entry.lease_token.as_str()));
        assert_eq!(
            row.lease_deadline_epoch_micros,
            Some(entry.lease_deadline_epoch_micros)
        );
        assert!(entry.lease_deadline_epoch_micros > now);
        row.status = DurableStatus::Published;
        row.lease_token = None;
        row.lease_deadline_epoch_micros = None;
        self.settled.notify_one();
        Ok(Disposition::Ack)
    }
}

fn delivery(tenant_id: &str, message_id: &str) -> Delivery {
    Delivery {
        tenant_id: tenant_id.to_string(),
        message_id: message_id.to_string(),
        partition_key: PARTITION_KEY.to_string(),
        topic: TOPIC.to_string(),
        contract_id: CONTRACT_ID.to_string(),
        payload: PAYLOAD.to_vec(),
    }
}

struct FixedClock;

impl diport::Clock for FixedClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH
    }
}

struct NoopMetrics;

impl OutboxMetrics for NoopMetrics {
    fn record_publish(&self, _scope: &OutboxMetricScope<'_>, _disposition: Disposition) {}
    fn record_backlog(&self, _scope: &OutboxMetricScope<'_>, _sample: BacklogSample) {}
    fn record_partition_blocked(&self, _scope: &OutboxMetricScope<'_>, _blocked_depth: u64) {}
    fn record_tick_duration(&self, _phase: RelayPhase, _seconds: f64) {}
}

#[allow(clippy::expect_used)]
// reason: fixed relay limits are valid by construction; rejection must fail the test.
fn relay_config() -> RelayConfig {
    RelayConfig::new(Duration::from_millis(100), 10).expect("valid relay config")
}

fn consume_deliveries_once(deliveries: &[Delivery]) -> usize {
    let mut state = InboxState::Absent;
    let mut side_effects = 0;

    for delivery in deliveries {
        assert_eq!(delivery.message_id, MESSAGE_ID);
        let lease = LeaseToken::mint();
        let (seen, claimed) = state.try_claim(lease.clone());
        if seen == SeenState::Fresh {
            side_effects += 1;
            let (outcome, committed) = claimed.commit(&lease);
            assert_eq!(outcome, LeaseOutcome::Held);
            state = committed;
        } else {
            assert_eq!(seen, SeenState::Duplicate);
            state = claimed;
        }
    }

    assert_eq!(state, InboxState::Done);
    side_effects
}

#[tokio::test]
#[allow(clippy::expect_used)]
// reason: fixture parsing and spawned task completion are assertions in this integration test.
async fn publish_then_crash_recovers_with_stable_identity_and_consumer_dedup() {
    let fixture = CrashCase::from_toml_str(FIXTURE).expect("valid crash fixture");
    let spec = fixture.fault_spec().expect("closed crash spec");
    assert_eq!(spec, CrashFaultSpec::OutboxAfterPublishBeforeSettle);
    assert_eq!(fixture.status(), CrashStatus::Ready);
    assert_eq!(fixture.domain(), "identity");
    assert_eq!(fixture.contract_id(), CONTRACT_ID);
    assert_eq!(fixture.runner(), spec.expected_runner());
    assert_eq!(TOPIC, fixture.contract_id());

    let store = CrashStore::new();
    let worker = tokio::spawn(relay_loop(
        store.clone(),
        relay_config(),
        Arc::new(FixedClock),
        CancellationToken::new(),
        Arc::new(WorkerHealth::healthy()),
        Arc::new(NoopMetrics),
        relay_admission(),
    ));
    tokio::time::timeout(
        Duration::from_secs(5),
        store.published_before_settle.notified(),
    )
    .await
    .expect("first relay reaches publish-before-settle");
    worker.abort();
    let aborted = worker.await;
    assert!(aborted.is_err_and(|error| error.is_cancelled()));

    assert_eq!(store.status(TENANT_A), DurableStatus::Publishing);
    assert_eq!(store.status(TENANT_B), DurableStatus::Publishing);
    assert_eq!(store.partition_key(TENANT_A), store.partition_key(TENANT_B));

    store.expire_lease(TENANT_A);
    assert!(store.lease_expired(TENANT_A));
    assert!(!store.lease_expired(TENANT_B));
    assert!(
        store.first_claim_is_lost(),
        "expired claim must lose settle authority before another worker reclaims it"
    );

    let token = CancellationToken::new();
    let restarted = tokio::spawn(relay_loop(
        store.clone(),
        relay_config(),
        Arc::new(FixedClock),
        token.clone(),
        Arc::new(WorkerHealth::healthy()),
        Arc::new(NoopMetrics),
        relay_admission(),
    ));
    tokio::time::timeout(Duration::from_secs(5), store.settled.notified())
        .await
        .expect("restarted relay settles recovered row");
    token.cancel();
    tokio::time::timeout(Duration::from_secs(5), restarted)
        .await
        .expect("restarted relay exits before timeout")
        .expect("restarted relay exits cleanly");

    assert_eq!(store.status(TENANT_A), DurableStatus::Published);
    assert_eq!(store.status(TENANT_B), DurableStatus::Publishing);
    assert!(!store.lease_expired(TENANT_B));

    let deliveries = store.deliveries();
    assert_eq!(deliveries.len(), 2, "broker publish is at-least-once");
    assert_eq!(
        deliveries[0], deliveries[1],
        "retry identity must be stable"
    );
    assert_eq!(deliveries[0].tenant_id, TENANT_A);
    assert_eq!(deliveries[0].topic, TOPIC);
    assert_eq!(deliveries[0].contract_id, CONTRACT_ID);
    assert_eq!(deliveries[0].partition_key, PARTITION_KEY);
    assert_eq!(deliveries[0].payload, PAYLOAD);
    assert_eq!(consume_deliveries_once(&deliveries), 1);
}
