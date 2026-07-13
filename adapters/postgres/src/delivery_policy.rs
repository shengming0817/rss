//! Frozen database policy for bounded same-ID outbox delivery.
//!
//! The type and every field stay crate-private. Runtime assemblies can only receive capabilities
//! already bound to a policy loaded and validated during [`crate::PgRuntimeDeps::setup`].

use crate::{PgError, PgStore};

const POLICY_REVISION: &str = "same-id-delivery-v1";
const AUTOMATIC_RETRY_WINDOW_SECONDS: u64 = 24 * 60 * 60;
const SAME_ID_REDRIVE_HORIZON_SECONDS: u64 = 24 * 60 * 60;
const SAFETY_MARGIN_SECONDS: u64 = 24 * 60 * 60;
const INBOX_RECEIPT_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EventDeliveryPolicy {
    automatic_retry_window_seconds: u64,
    same_id_redrive_horizon_seconds: u64,
    safety_margin_seconds: u64,
    inbox_receipt_retention_seconds: u64,
}

#[derive(sqlx::FromRow)]
struct EventDeliveryPolicyRow {
    policy_revision: String,
    automatic_retry_window_seconds: i64,
    same_id_redrive_horizon_seconds: i64,
    safety_margin_seconds: i64,
    inbox_receipt_retention_seconds: i64,
}

impl EventDeliveryPolicy {
    pub(crate) const fn release() -> Self {
        Self {
            automatic_retry_window_seconds: AUTOMATIC_RETRY_WINDOW_SECONDS,
            same_id_redrive_horizon_seconds: SAME_ID_REDRIVE_HORIZON_SECONDS,
            safety_margin_seconds: SAFETY_MARGIN_SECONDS,
            inbox_receipt_retention_seconds: INBOX_RECEIPT_RETENTION_SECONDS,
        }
    }

    fn hydrate(row: EventDeliveryPolicyRow) -> Result<Self, PgError> {
        let candidate = Self {
            automatic_retry_window_seconds: positive_u64(row.automatic_retry_window_seconds)?,
            same_id_redrive_horizon_seconds: positive_u64(row.same_id_redrive_horizon_seconds)?,
            safety_margin_seconds: positive_u64(row.safety_margin_seconds)?,
            inbox_receipt_retention_seconds: positive_u64(row.inbox_receipt_retention_seconds)?,
        };
        let covered_window = candidate
            .automatic_retry_window_seconds
            .checked_add(candidate.same_id_redrive_horizon_seconds)
            .and_then(|sum| sum.checked_add(candidate.safety_margin_seconds))
            .ok_or(PgError::EventDeliveryPolicyMismatch)?;
        if row.policy_revision != POLICY_REVISION
            || candidate.inbox_receipt_retention_seconds <= covered_window
            || candidate != Self::release()
        {
            return Err(PgError::EventDeliveryPolicyMismatch);
        }
        Ok(candidate)
    }

    pub(crate) const fn inbox_receipt_retention_seconds(self) -> u64 {
        self.inbox_receipt_retention_seconds
    }
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
                   inbox_receipt_retention_seconds
            FROM event_delivery_policy
            WHERE singleton
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
