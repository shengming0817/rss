//! The database owns partition membership; this state prevents reuse after cancelled I/O.
use crate::{PgError, PgTransaction};
use rss_transactional_messaging::message::PartitionIdentity;

pub(crate) enum Admission {
    Open,
    Failed,
    Unavailable,
}

impl Admission {
    pub(crate) fn begin(&mut self) -> Result<(), PgError> {
        if !matches!(self, Self::Open) {
            return Err(PgError::invariant());
        }
        *self = Self::Failed;
        Ok(())
    }

    pub(crate) fn complete(&mut self) {
        *self = Self::Open;
    }

    pub(crate) fn check_commit(&self) -> Result<(), PgError> {
        if matches!(self, Self::Failed) {
            return Err(PgError::invariant());
        }
        Ok(())
    }
}

impl PgTransaction<'_> {
    /// Declare the complete set of ordered Outbox partitions for this transaction.
    ///
    /// PostgreSQL sorts and locks the exact identities before allocating any partition ordinal.
    /// A nonempty set can be declared once; duplicates within it are harmless. An empty set
    /// acquires nothing. Ordered append outside the set fails even for same-ID readback.
    /// Declare before companion business locks when the identities are already known; this
    /// protocol does not impose a global lock order on arbitrary companion SQL.
    ///
    /// SQL clients use the same database function. The database, not this Rust view, owns
    /// membership. Failure/cancellation prevents commit even if the caller ignores the error.
    pub async fn prepare_outbox_partitions(
        &mut self,
        partitions: &[PartitionIdentity],
    ) -> Result<(), PgError> {
        self.outbox_admission.begin()?;
        if partitions
            .iter()
            .any(|partition| partition.tenant_id() != self.tenant_id())
        {
            return Err(PgError::invariant());
        }
        let pairs: Vec<_> = partitions
            .iter()
            .map(|partition| (partition.domain().as_str(), partition.key().as_str()))
            .collect();
        let encoded = serde_json::to_string(&pairs).map_err(|_| PgError::invariant())?;
        self.with_connection(move |connection| {
            Box::pin(async move {
                sqlx::query(
                    "SELECT rss_transactional_messaging.prepare_outbox_partitions($1::jsonb)",
                )
                .bind(encoded)
                .execute(connection)
                .await
                .map(|_| ())
            })
        })
        .await?;
        self.outbox_admission.complete();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Admission;

    #[test]
    fn cancelled_or_failed_admission_cannot_be_reused_or_committed() {
        let mut admission = Admission::Open;
        assert!(admission.begin().is_ok());
        assert!(admission.begin().is_err());
        assert!(admission.check_commit().is_err());
    }

    #[test]
    fn acknowledged_operation_and_rejected_effect_have_distinct_reuse_rights() {
        let mut admission = Admission::Open;
        assert!(admission.begin().is_ok());
        admission.complete();
        assert!(admission.check_commit().is_ok());
        assert!(admission.begin().is_ok());
        admission = Admission::Unavailable;
        assert!(admission.begin().is_err());
        assert!(admission.check_commit().is_ok());
    }
}
