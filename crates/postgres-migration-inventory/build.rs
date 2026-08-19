//! Build-time migration identity projection.
//!
//! Uses `sqlx_core::migrate::resolve_blocking` — the same resolver behind
//! `sqlx::migrate!` — then emits only `(version, checksum)` so serving stays
//! SQL-text-free.
//!
//! INVARIANT: POSTGRES-MIGRATION-INVENTORY-01 { level = "Hard", exec = "native-compile", source = "code", native = "sqlx resolve_blocking derives version/checksum inventory" }.

#[path = "src/validate_inventory.rs"]
mod validate_inventory;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};
use sqlx_core::migrate::MigrationType;
use validate_inventory::{ensure_forward_migration, validate_inventory_identities};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let migrations = Path::new("../../adapters/postgres/migrations");
    println!("cargo:rerun-if-changed={}", migrations.display());

    let resolved = sqlx_core::migrate::resolve_blocking(migrations).map_err(|err| {
        format!(
            "sqlx resolve_blocking failed for {}: {err}",
            migrations.display()
        )
    })?;

    let mut on_disk_sql = BTreeSet::new();
    for entry in fs::read_dir(migrations)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "sql") {
            on_disk_sql.insert(path.canonicalize()?);
        }
    }

    let mut identities: Vec<(i64, [u8; 48], String)> = Vec::new();
    for (migration, path) in &resolved {
        let canon = path.canonicalize()?;
        let path_display = path.display().to_string();
        if !on_disk_sql.remove(&canon) {
            return Err(format!(
                "resolved migration path not present as on-disk .sql: {path_display}"
            )
            .into());
        }
        ensure_forward_migration(
            &path_display,
            matches!(migration.migration_type, MigrationType::Simple),
        )?;
        let checksum: [u8; 48] = migration.checksum.as_ref().try_into().map_err(|_| {
            format!(
                "migration version {} checksum length {} != 48",
                migration.version,
                migration.checksum.len()
            )
        })?;
        identities.push((migration.version, checksum, path_display));
    }

    let leftovers: Vec<String> = on_disk_sql
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    validate_inventory_identities(&mut identities, &leftovers)?;

    let mut head = Sha256::new();
    head.update(b"rss-postgres-migration-head-v1");
    head.update([0]);

    let mut generated = String::from("&[\n");
    for (version, checksum, _) in identities {
        head.update(version.to_be_bytes());
        head.update(checksum);
        write!(
            generated,
            "    MigrationIdentity {{ version: {version}, checksum: ["
        )?;
        for byte in checksum {
            write!(generated, "{byte},")?;
        }
        generated.push_str("] },\n");
    }
    generated.push_str("]\n");
    fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("inventory.rs"),
        generated,
    )?;
    println!(
        "cargo:rustc-env=RSS_POSTGRES_MIGRATION_HEAD_FINGERPRINT=sha256:{:x}",
        head.finalize()
    );
    Ok(())
}
