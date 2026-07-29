use assembly_schema::ParsedAssemblyLock;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    verify_bundled_lock()
}

fn verify_bundled_lock() -> Result<(), Box<dyn std::error::Error>> {
    let assembly_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").ok_or(
        "CARGO_MANIFEST_DIR is required for AssemblyLock build attestation",
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

    ParsedAssemblyLock::from_json_slice(&std::fs::read(lock_path)?)?
        .verify_repository_v2(repository_root, &assembly_dir)?;
    Ok(())
}
