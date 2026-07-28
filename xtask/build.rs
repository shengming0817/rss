use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;

const EXPECTED_TOOLS: [&str; 9] = [
    "cargo-nextest",
    "cargo-llvm-cov",
    "cargo-deny",
    "cargo-audit",
    "cargo-dylint",
    "dylint-link",
    "cargo-public-api",
    "sccache",
    "promtool",
];

fn invalid_catalog(row: usize, message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid CI tool catalog row {row}: {message}"),
    )
}

fn main() -> Result<(), Box<dyn Error>> {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "CARGO_MANIFEST_DIR is unavailable")
    })?);
    let catalog = manifest.join("../.github/scripts/ci-tool-catalog.txt");
    println!("cargo:rerun-if-changed={}", catalog.display());

    let source = fs::read_to_string(&catalog)?;
    let mut versions = BTreeMap::new();
    for (index, line) in source.lines().enumerate() {
        let row = index + 1;
        let mut fields = line.split('|');
        let name = fields
            .next()
            .ok_or_else(|| invalid_catalog(row, "missing name"))?;
        let version = fields
            .next()
            .ok_or_else(|| invalid_catalog(row, "missing version"))?;
        let backend = fields
            .next()
            .ok_or_else(|| invalid_catalog(row, "missing backend"))?;
        let relative = fields
            .next()
            .ok_or_else(|| invalid_catalog(row, "missing relative path"))?;
        let probe = fields
            .next()
            .ok_or_else(|| invalid_catalog(row, "missing probe"))?;
        if fields.next().is_some() {
            return Err(invalid_catalog(row, "too many fields").into());
        }
        if version.is_empty()
            || !version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-+".contains(&byte))
        {
            return Err(invalid_catalog(row, "invalid version").into());
        }
        if !matches!(backend, "install-action" | "binstall" | "docker") {
            return Err(invalid_catalog(row, "invalid backend").into());
        }
        if relative.is_empty()
            || relative.starts_with('/')
            || (backend == "docker"
                && !(name == "promtool"
                    && relative.starts_with("prom/prometheus@sha256:")
                    && relative["prom/prometheus@sha256:".len()..].len() == 64
                    && relative["prom/prometheus@sha256:".len()..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())))
        {
            return Err(invalid_catalog(row, "invalid relative path").into());
        }
        if !matches!(
            probe,
            "nextest" | "llvm-cov" | "dylint" | "direct" | "receipt" | "sccache" | "promtool"
        ) {
            return Err(invalid_catalog(row, "invalid probe").into());
        }
        if (backend == "docker") != (name == "promtool" && probe == "promtool") {
            return Err(invalid_catalog(row, "invalid docker policy").into());
        }
        if versions.insert(name, version).is_some() {
            return Err(invalid_catalog(row, "duplicate tool").into());
        }
    }

    let actual = versions.keys().copied().collect::<BTreeSet<_>>();
    let expected = EXPECTED_TOOLS.into_iter().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CI tool catalog set changed; update xtask consumers explicitly",
        )
        .into());
    }
    for (name, version) in versions {
        let key = name.replace('-', "_").to_ascii_uppercase();
        println!("cargo:rustc-env=RSS_TOOL_VERSION_{key}={version}");
    }
    Ok(())
}
