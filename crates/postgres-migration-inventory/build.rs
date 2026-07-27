use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha384};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let migrations = Path::new("../../adapters/postgres/migrations");
    println!("cargo:rerun-if-changed={}", migrations.display());
    let mut files: Vec<(i64, PathBuf)> = Vec::new();
    for entry in fs::read_dir(migrations)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.ends_with(".sql") {
            continue;
        }
        let (serial, description) = name
            .strip_suffix(".sql")
            .and_then(|stem| stem.split_once('_'))
            .ok_or_else(|| {
                format!("migration filename is not <serial>_<description>.sql: {name}")
            })?;
        if serial.len() != 4 || description.is_empty() {
            return Err(format!("migration filename is not canonical: {name}").into());
        }
        files.push((serial.parse::<i64>()?, path));
    }
    files.sort_by_key(|(version, _)| *version);
    assert!(!files.is_empty(), "migration inventory must not be empty");

    let mut generated = String::from("&[\n");
    for (index, (version, path)) in files.into_iter().enumerate() {
        assert_eq!(
            version,
            index as i64 + 1,
            "migration versions must be contiguous"
        );
        let checksum = Sha384::digest(fs::read(path)?);
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
    Ok(())
}
