//! SQL-text-free typed identity for every committed forward PostgreSQL migration.
//!
//! Facts are a build-time projection of `sqlx_core::migrate::resolve_blocking` (same
//! resolver as `sqlx::migrate!`): only `(version, checksum)` are embedded, so serving
//! stays SQL-text-free.
//!
//! INVARIANT: POSTGRES-MIGRATION-INVENTORY-01 { level = "Hard", exec = "native-compile", source = "code", native = "sqlx resolve_blocking derives version/checksum inventory consumed by operator, serving ledger, and deployment generation" }.

use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationIdentity {
    pub version: i64,
    pub checksum: [u8; 48],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionInputIdentity {
    projection_id: &'static str,
    projection_definition_version: &'static str,
    projection_definition_schema_digest: &'static str,
    domain: &'static str,
    contract_id: &'static str,
    version: &'static str,
    schema_hash: &'static str,
    topic: &'static str,
}

impl ProjectionInputIdentity {
    #[allow(clippy::too_many_arguments)]
    // reason: generated registry identity is one closed eight-field security tuple; grouping or
    // defaults would make definition/source coordinates easier to omit or transpose.
    const fn from_static(
        projection_id: &'static str,
        projection_definition_version: &'static str,
        projection_definition_schema_digest: &'static str,
        domain: &'static str,
        contract_id: &'static str,
        version: &'static str,
        schema_hash: &'static str,
        topic: &'static str,
    ) -> Self {
        Self {
            projection_id,
            projection_definition_version,
            projection_definition_schema_digest,
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
    pub const fn projection_definition_version(self) -> &'static str {
        self.projection_definition_version
    }
    #[must_use]
    pub const fn projection_definition_schema_digest(self) -> &'static str {
        self.projection_definition_schema_digest
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

// Anti-vacuity for build-time Hard gates (also path-included by build.rs).
#[cfg(test)]
mod validate_inventory;

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
    fn generated_inventory_is_non_empty_unique_and_sha384_sized() {
        let migrations = migrations();
        assert!(!migrations.is_empty());
        for window in migrations.windows(2) {
            assert!(
                window[0].version < window[1].version,
                "versions must be strictly increasing: {} then {}",
                window[0].version,
                window[1].version
            );
        }
        for migration in migrations {
            assert_ne!(migration.checksum, [0; 48]);
        }
        assert!(migration_head_fingerprint().starts_with("sha256:"));
    }
}
