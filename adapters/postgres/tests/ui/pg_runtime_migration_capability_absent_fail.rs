//! INVARIANT: MIGRATION-CAPABILITY-SEPARATION-01 { level = "Hard", exec = "verify", source = "trybuild" }

use postgres::{PgConfig, PgRuntimeDeps};

fn serving_adapter_cannot_migrate(config: &PgConfig) {
    let _migration = PgRuntimeDeps::migrate_reader_lane_only(config);
}

fn main() {}
