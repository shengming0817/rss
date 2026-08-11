use assembly_schema::{ParsedAssemblyLock, RepositoryAssemblyManifestV2, RepositoryAssemblySnapshotV2};
use std::path::PathBuf;

#[allow(dead_code)]
fn verify_bundled_lock() -> Result<(), Box<dyn std::error::Error>> {
    verify_bundled_lock_inner(false)
}

#[allow(dead_code)]
fn emit_bundled_repository_snapshot() -> Result<(), Box<dyn std::error::Error>> {
    verify_bundled_lock_inner(true)
}

fn verify_bundled_lock_inner(emit_snapshot: bool) -> Result<(), Box<dyn std::error::Error>> {
    let assembly_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").ok_or(
        "CARGO_MANIFEST_DIR is required for AssemblyLock repository verification",
    )?);
    let repository_root = assembly_dir
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("assembly crate must be nested under the repository assemblies directory")?;
    let lock_path = assembly_dir.join("assembly.lock.json");

    println!("cargo:rerun-if-changed={}", assembly_dir.join("assembly.toml").display());
    println!("cargo:rerun-if-changed={}", lock_path.display());
    println!(
        "cargo:rerun-if-changed={}",
        assembly_dir.join("src/generated").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repository_root.join("contracts").display()
    );

    let manifest = RepositoryAssemblyManifestV2::discover_v2(repository_root, &assembly_dir)?;
    let lock_bytes = std::fs::read(lock_path)?;
    if emit_snapshot {
        let snapshot = RepositoryAssemblySnapshotV2::capture_v2(&manifest, &lock_bytes)?;
        let out_dir = PathBuf::from(
            std::env::var_os("OUT_DIR").ok_or("OUT_DIR is required for repository snapshot")?,
        );
        std::fs::write(
            out_dir.join("repository-assembly-v2.json"),
            snapshot.to_pretty_json_vec()?,
        )?;
    } else {
        ParsedAssemblyLock::from_json_slice(&lock_bytes)?.verify_repository_v2(&manifest)?;
    }
    Ok(())
}
