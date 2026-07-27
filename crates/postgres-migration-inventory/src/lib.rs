//! SQL-text-free typed identity for every committed forward PostgreSQL migration.
//!
//! INVARIANT: POSTGRES-MIGRATION-INVENTORY-01 { level = "Hard", exec = "native-compile", source = "code", native = "one build-time scanner emits the version/checksum inventory consumed by operator, serving ledger, and deployment generation" }.

use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationIdentity {
    pub version: i64,
    pub checksum: [u8; 48],
}

static MIGRATIONS: &[MigrationIdentity] = include!(concat!(env!("OUT_DIR"), "/inventory.rs"));

#[must_use]
pub fn migrations() -> &'static [MigrationIdentity] {
    MIGRATIONS
}

#[must_use]
pub fn migration_head_fingerprint() -> String {
    const TAG: &[u8] = b"rss-postgres-migration-head-v1";
    let mut head = Sha256::new();
    head.update(TAG);
    head.update([0]);
    for migration in MIGRATIONS {
        head.update(migration.version.to_be_bytes());
        head.update(migration.checksum);
    }
    format!("sha256:{:x}", head.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_inventory_is_non_empty_contiguous_and_sha384_sized() {
        assert!(!migrations().is_empty());
        for (index, migration) in migrations().iter().enumerate() {
            assert_eq!(migration.version, index as i64 + 1);
            assert_ne!(migration.checksum, [0; 48]);
        }
        assert!(migration_head_fingerprint().starts_with("sha256:"));
    }
}
