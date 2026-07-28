//! Read-only schema identity gate for serving processes.
//!
//! The shared inventory crate contains only typed `(version, SHA-384 checksum)` identities. No SQL
//! text or migration executor is compiled into this crate.

use crate::{PgError, PgStore};

impl PgStore {
    pub(crate) async fn verify_migration_ledger(&self) -> Result<(), PgError> {
        let applied: Vec<(i64, bool, Vec<u8>)> = sqlx::query_as(
            "SELECT version, success, checksum FROM public._sqlx_migrations ORDER BY version",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(PgError::SchemaLedgerProbe)?;
        let expected = postgres_migration_inventory::migrations();
        let first_invalid = first_invalid_ledger_entry(&applied, expected);
        if ledger_is_exact(&applied, expected) {
            return Ok(());
        }
        let expected_head = expected.last().map(|migration| migration.version);
        let actual_head = applied.last().map(|(version, _, _)| *version);
        tracing::error!(
            target: "postgres",
            expected_head,
            actual_head,
            expected_entries = expected.len(),
            actual_entries = applied.len(),
            first_invalid,
            "postgres schema ledger does not match this serving binary"
        );
        Err(PgError::SchemaLedgerMismatch {
            expected_head,
            actual_head,
            expected_entries: expected.len(),
            actual_entries: applied.len(),
            first_invalid,
        })
    }
}

fn ledger_is_exact(
    applied: &[(i64, bool, Vec<u8>)],
    expected: &[postgres_migration_inventory::MigrationIdentity],
) -> bool {
    applied.len() == expected.len() && first_invalid_ledger_entry(applied, expected).is_none()
}

fn first_invalid_ledger_entry(
    applied: &[(i64, bool, Vec<u8>)],
    expected: &[postgres_migration_inventory::MigrationIdentity],
) -> Option<i64> {
    applied.iter().zip(expected).find_map(
        |((actual_version, success, actual_checksum), migration)| {
            (*actual_version != migration.version
                || !*success
                || actual_checksum.as_slice() != migration.checksum)
                .then_some(*actual_version)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{first_invalid_ledger_entry, ledger_is_exact};
    use postgres_migration_inventory::MigrationIdentity;

    fn expected() -> Vec<MigrationIdentity> {
        vec![
            MigrationIdentity {
                version: 1,
                checksum: [1; 48],
            },
            MigrationIdentity {
                version: 2,
                checksum: [2; 48],
            },
        ]
    }

    #[test]
    fn exact_ledger_has_no_invalid_entry() {
        let ledger = [(1, true, vec![1; 48]), (2, true, vec![2; 48])];
        assert!(ledger_is_exact(&ledger, &expected()));
        assert_eq!(first_invalid_ledger_entry(&ledger, &expected()), None);
    }

    #[test]
    fn failed_version_and_checksum_drift_are_rejected() {
        for (ledger, invalid) in [
            (vec![(1, false, vec![1; 48]), (2, true, vec![2; 48])], 1),
            (vec![(1, true, vec![1; 48]), (2, true, vec![9; 48])], 2),
            (vec![(1, true, vec![1; 48]), (3, true, vec![2; 48])], 3),
        ] {
            assert_eq!(
                first_invalid_ledger_entry(&ledger, &expected()),
                Some(invalid)
            );
        }
    }

    #[test]
    fn stale_and_ahead_ledgers_are_rejected_even_when_the_shared_prefix_is_exact() {
        assert!(!ledger_is_exact(&[(1, true, vec![1; 48])], &expected()));
        assert!(!ledger_is_exact(
            &[
                (1, true, vec![1; 48]),
                (2, true, vec![2; 48]),
                (3, true, vec![3; 48])
            ],
            &expected()
        ));
    }
}
