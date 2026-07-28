//! Database policy for bounded same-ID outbox delivery and relay I/O.
//!
//! The type and every field stay crate-private. Runtime assemblies can only receive capabilities
//! bound to a policy loaded during [`crate::PgRuntimeDeps::connect_serving`]; before transport activation they
//! exact-match the configured typed relay budget through [`crate::PgRuntimeHandle`].

use crate::{PgError, PgStore};
use eventexec::RelayBudget;

const POLICY_REVISION: &str = "same-id-delivery-v1";
const AUTOMATIC_RETRY_WINDOW_SECONDS: u64 = 24 * 60 * 60;
const SAME_ID_REDRIVE_HORIZON_SECONDS: u64 = 24 * 60 * 60;
const SAFETY_MARGIN_SECONDS: u64 = 24 * 60 * 60;
const INBOX_RECEIPT_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;
const RELAY_BUDGET_REVISION: &str = "relay-budget-v1";
#[cfg(any(test, feature = "test-support"))]
const RELAY_LEASE_TTL_MS: i64 = 60_000;
#[cfg(any(test, feature = "test-support"))]
const RELAY_PUBLISH_TIMEOUT_MS: i64 = 40_000;
#[cfg(any(test, feature = "test-support"))]
const RELAY_SETTLE_TIMEOUT_MS: i64 = 5_000;
#[cfg(any(test, feature = "test-support"))]
const RELAY_SAFETY_MARGIN_MS: i64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EventDeliveryPolicy {
    automatic_retry_window_seconds: u64,
    same_id_redrive_horizon_seconds: u64,
    safety_margin_seconds: u64,
    inbox_receipt_retention_seconds: u64,
    relay_budget: RelayBudget,
}

#[derive(sqlx::FromRow)]
struct EventDeliveryPolicyRow {
    policy_revision: String,
    automatic_retry_window_seconds: i64,
    same_id_redrive_horizon_seconds: i64,
    safety_margin_seconds: i64,
    inbox_receipt_retention_seconds: i64,
    relay_budget_revision: String,
    relay_lease_ttl_ms: i64,
    relay_publish_timeout_ms: i64,
    relay_settle_timeout_ms: i64,
    relay_safety_margin_ms: i64,
}

impl EventDeliveryPolicy {
    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::expect_used)]
    pub(crate) fn release() -> Self {
        Self {
            automatic_retry_window_seconds: AUTOMATIC_RETRY_WINDOW_SECONDS,
            same_id_redrive_horizon_seconds: SAME_ID_REDRIVE_HORIZON_SECONDS,
            safety_margin_seconds: SAFETY_MARGIN_SECONDS,
            inbox_receipt_retention_seconds: INBOX_RECEIPT_RETENTION_SECONDS,
            relay_budget: RelayBudget::new(
                std::time::Duration::from_millis(RELAY_LEASE_TTL_MS as u64),
                std::time::Duration::from_millis(RELAY_PUBLISH_TIMEOUT_MS as u64),
                std::time::Duration::from_millis(RELAY_SETTLE_TIMEOUT_MS as u64),
                std::time::Duration::from_millis(RELAY_SAFETY_MARGIN_MS as u64),
            )
            .expect("frozen release relay budget must be valid"),
        }
    }

    fn hydrate(row: EventDeliveryPolicyRow) -> Result<Self, PgError> {
        let relay_budget = relay_budget_from_row(&row)?;
        let candidate = Self {
            automatic_retry_window_seconds: positive_u64(row.automatic_retry_window_seconds)?,
            same_id_redrive_horizon_seconds: positive_u64(row.same_id_redrive_horizon_seconds)?,
            safety_margin_seconds: positive_u64(row.safety_margin_seconds)?,
            inbox_receipt_retention_seconds: positive_u64(row.inbox_receipt_retention_seconds)?,
            relay_budget,
        };
        let covered_window = candidate
            .automatic_retry_window_seconds
            .checked_add(candidate.same_id_redrive_horizon_seconds)
            .and_then(|sum| sum.checked_add(candidate.safety_margin_seconds))
            .ok_or(PgError::EventDeliveryPolicyMismatch)?;
        if row.policy_revision != POLICY_REVISION
            || row.relay_budget_revision != RELAY_BUDGET_REVISION
            || candidate.inbox_receipt_retention_seconds <= covered_window
            || candidate.automatic_retry_window_seconds != AUTOMATIC_RETRY_WINDOW_SECONDS
            || candidate.same_id_redrive_horizon_seconds != SAME_ID_REDRIVE_HORIZON_SECONDS
            || candidate.safety_margin_seconds != SAFETY_MARGIN_SECONDS
            || candidate.inbox_receipt_retention_seconds != INBOX_RECEIPT_RETENTION_SECONDS
        {
            return Err(PgError::EventDeliveryPolicyMismatch);
        }
        Ok(candidate)
    }

    pub(crate) const fn inbox_receipt_retention_seconds(self) -> u64 {
        self.inbox_receipt_retention_seconds
    }

    pub(crate) fn validate_relay_budget(self, budget: RelayBudget) -> Result<(), PgError> {
        if budget == self.relay_budget {
            Ok(())
        } else {
            Err(PgError::EventDeliveryPolicyMismatch)
        }
    }
}

fn relay_budget_from_row(row: &EventDeliveryPolicyRow) -> Result<RelayBudget, PgError> {
    let duration = |value: i64| {
        u64::try_from(value)
            .map(std::time::Duration::from_millis)
            .map_err(|_| PgError::EventDeliveryPolicyMismatch)
    };
    RelayBudget::new(
        duration(row.relay_lease_ttl_ms)?,
        duration(row.relay_publish_timeout_ms)?,
        duration(row.relay_settle_timeout_ms)?,
        duration(row.relay_safety_margin_ms)?,
    )
    .map_err(|_| PgError::EventDeliveryPolicyMismatch)
}

fn positive_u64(value: i64) -> Result<u64, PgError> {
    let value = u64::try_from(value).map_err(|_| PgError::EventDeliveryPolicyMismatch)?;
    if value == 0 {
        return Err(PgError::EventDeliveryPolicyMismatch);
    }
    Ok(value)
}

impl PgStore {
    pub(crate) async fn load_event_delivery_policy(&self) -> Result<EventDeliveryPolicy, PgError> {
        let rows: Vec<EventDeliveryPolicyRow> = sqlx::query_as(
            r#"
            SELECT policy_revision,
                   automatic_retry_window_seconds,
                   same_id_redrive_horizon_seconds,
                   safety_margin_seconds,
                   inbox_receipt_retention_seconds,
                   relay_budget_revision,
                   relay_lease_ttl_ms,
                   relay_publish_timeout_ms,
                   relay_settle_timeout_ms,
                   relay_safety_margin_ms
            FROM rss_load_event_delivery_policy()
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(PgError::EventDeliveryPolicyProbe)?;
        let [row] = rows
            .try_into()
            .map_err(|_| PgError::EventDeliveryPolicyMismatch)?;
        EventDeliveryPolicy::hydrate(row)
    }
}

#[cfg(test)]
mod tests {
    use super::{EventDeliveryPolicy, EventDeliveryPolicyRow, POLICY_REVISION};
    use crate::PgError;

    fn row() -> EventDeliveryPolicyRow {
        let policy = EventDeliveryPolicy::release();
        EventDeliveryPolicyRow {
            policy_revision: POLICY_REVISION.to_string(),
            automatic_retry_window_seconds: i64::try_from(policy.automatic_retry_window_seconds)
                .unwrap_or_default(),
            same_id_redrive_horizon_seconds: i64::try_from(policy.same_id_redrive_horizon_seconds)
                .unwrap_or_default(),
            safety_margin_seconds: i64::try_from(policy.safety_margin_seconds).unwrap_or_default(),
            inbox_receipt_retention_seconds: i64::try_from(policy.inbox_receipt_retention_seconds)
                .unwrap_or_default(),
            relay_budget_revision: "relay-budget-v1".to_string(),
            relay_lease_ttl_ms: 60_000,
            relay_publish_timeout_ms: 40_000,
            relay_settle_timeout_ms: 5_000,
            relay_safety_margin_ms: 5_000,
        }
    }

    #[test]
    fn release_policy_hydrates_only_exact_frozen_values() {
        assert!(matches!(
            EventDeliveryPolicy::hydrate(row()),
            Ok(policy) if policy == EventDeliveryPolicy::release()
        ));

        let mut revision = row();
        revision.policy_revision = "same-id-delivery-v2".to_string();
        assert!(matches!(
            EventDeliveryPolicy::hydrate(revision),
            Err(PgError::EventDeliveryPolicyMismatch)
        ));

        let mut drift = row();
        drift.same_id_redrive_horizon_seconds += 1;
        assert!(matches!(
            EventDeliveryPolicy::hydrate(drift),
            Err(PgError::EventDeliveryPolicyMismatch)
        ));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: fixed typed-budget fixtures are deliberately valid and a construction failure must fail the test.
    fn release_policy_accepts_only_the_exact_release_relay_budget() {
        let policy = EventDeliveryPolicy::hydrate(row()).unwrap();
        let release = eventexec::RelayBudget::new(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(40),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        assert!(policy.validate_relay_budget(release).is_ok());

        let drift = eventexec::RelayBudget::new(
            std::time::Duration::from_secs(61),
            std::time::Duration::from_secs(40),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        assert!(matches!(
            policy.validate_relay_budget(drift),
            Err(PgError::EventDeliveryPolicyMismatch)
        ));

        for (publish, settle, safety) in [(39, 5, 5), (40, 4, 5), (40, 5, 4)] {
            let drift = eventexec::RelayBudget::new(
                std::time::Duration::from_secs(60),
                std::time::Duration::from_secs(publish),
                std::time::Duration::from_secs(settle),
                std::time::Duration::from_secs(safety),
            )
            .unwrap();
            assert!(matches!(
                policy.validate_relay_budget(drift),
                Err(PgError::EventDeliveryPolicyMismatch)
            ));
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: alternate typed-budget fixture is valid by construction and construction failure must fail the test.
    fn alternate_valid_database_budget_hydrates_and_requires_an_exact_runtime_match() {
        let mut alternate = row();
        alternate.relay_lease_ttl_ms = 61_000;
        alternate.relay_publish_timeout_ms = 41_000;
        let policy = EventDeliveryPolicy::hydrate(alternate).unwrap();
        let matching = eventexec::RelayBudget::new(
            std::time::Duration::from_secs(61),
            std::time::Duration::from_secs(41),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        assert!(policy.validate_relay_budget(matching).is_ok());
        assert!(matches!(
            policy.validate_relay_budget(EventDeliveryPolicy::release().relay_budget),
            Err(PgError::EventDeliveryPolicyMismatch)
        ));
    }

    #[test]
    fn policy_hydration_rejects_zero_negative_equal_and_overflow() {
        for invalid in [0, -1] {
            let mut value = row();
            value.automatic_retry_window_seconds = invalid;
            assert!(matches!(
                EventDeliveryPolicy::hydrate(value),
                Err(PgError::EventDeliveryPolicyMismatch)
            ));
        }

        let mut equal = row();
        equal.inbox_receipt_retention_seconds = equal.automatic_retry_window_seconds
            + equal.same_id_redrive_horizon_seconds
            + equal.safety_margin_seconds;
        assert!(matches!(
            EventDeliveryPolicy::hydrate(equal),
            Err(PgError::EventDeliveryPolicyMismatch)
        ));

        let mut overflow = row();
        overflow.automatic_retry_window_seconds = i64::MAX;
        overflow.same_id_redrive_horizon_seconds = i64::MAX;
        overflow.safety_margin_seconds = i64::MAX;
        assert!(matches!(
            EventDeliveryPolicy::hydrate(overflow),
            Err(PgError::EventDeliveryPolicyMismatch)
        ));
    }
}
