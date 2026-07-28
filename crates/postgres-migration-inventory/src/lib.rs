//! SQL-text-free typed identity for every committed forward PostgreSQL migration.
//!
//! INVARIANT: POSTGRES-MIGRATION-INVENTORY-01 { level = "Hard", exec = "native-compile", source = "code", native = "one build-time scanner emits the version/checksum inventory consumed by operator, serving ledger, and deployment generation" }.

use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationIdentity {
    pub version: i64,
    pub checksum: [u8; 48],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionInputIdentity {
    projection_id: &'static str,
    domain: &'static str,
    contract_id: &'static str,
    version: &'static str,
    schema_hash: &'static str,
    topic: &'static str,
}

impl ProjectionInputIdentity {
    const fn from_static(
        projection_id: &'static str,
        domain: &'static str,
        contract_id: &'static str,
        version: &'static str,
        schema_hash: &'static str,
        topic: &'static str,
    ) -> Self {
        Self {
            projection_id,
            domain,
            contract_id,
            version,
            schema_hash,
            topic,
        }
    }

    #[must_use]
    pub const fn projection_id(self) -> &'static str {
        self.projection_id
    }
    #[must_use]
    pub const fn domain(self) -> &'static str {
        self.domain
    }
    #[must_use]
    pub const fn contract_id(self) -> &'static str {
        self.contract_id
    }
    #[must_use]
    pub const fn version(self) -> &'static str {
        self.version
    }
    #[must_use]
    pub const fn schema_hash(self) -> &'static str {
        self.schema_hash
    }
    #[must_use]
    pub const fn topic(self) -> &'static str {
        self.topic
    }
}

mod projection_inputs;

static MIGRATIONS: &[MigrationIdentity] = include!(concat!(env!("OUT_DIR"), "/inventory.rs"));

#[must_use]
pub fn migrations() -> &'static [MigrationIdentity] {
    MIGRATIONS
}

#[must_use]
pub const fn projection_input_generation() -> &'static str {
    projection_inputs::PROJECTION_INPUT_GENERATION
}

#[must_use]
pub const fn projection_inputs() -> &'static [ProjectionInputIdentity] {
    projection_inputs::PROJECTION_INPUTS
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
