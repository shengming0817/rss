//! #2045 executable Platform Application waist contract.
//!
//! INVARIANT: PLATFORM-WAIST-CONTRACT-01 { level = "Medium", exec = "test", source = "external-cargo" }.
//! Fixed selector: `cargo test -p xtask --test platform_application_waist_trybuild`.
//! This one-target T1 carrier owns an exact API-shape hazard that existing authn and assembly-schema
//! construction proofs cannot name. #2049 must move the accepted signatures into the real façade
//! and delete this harness, its UI inventory, and the fixture atomically; #2048 then owns release
//! leakage. It is not package, SemVer, or independent-consumer evidence.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

// The repository's nextest inventory discovers trybuild carriers from source AST and serializes the
// dedicated target. The load-bearing proof uses isolated external Cargo consumers and exact rustc
// JSON diagnostics because a regular trybuild case would inherit xtask's internal dependency graph.
#[cfg(any())]
fn nextest_trybuild_scheduler_carrier() {
    let _ = trybuild::TestCases::new();
}

struct CompileCase {
    name: String,
    source: PathBuf,
    should_pass: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DiagnosticKey {
    code: String,
    line: u64,
}

impl DiagnosticKey {
    fn new(code: &str, line: u64) -> Self {
        Self {
            code: code.to_owned(),
            line,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DependencyKey {
    name: String,
    rename: Option<String>,
    kind: Option<String>,
    target: Option<String>,
}

struct TempConsumer {
    root: PathBuf,
}

impl TempConsumer {
    fn create() -> io::Result<Self> {
        loop {
            let nonce = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("rss-platform-waist-{}-{nonce}", std::process::id()));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(Self { root }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

impl Drop for TempConsumer {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn platform_application_waist_contract() -> Result<(), Box<dyn std::error::Error>> {
    let xtask = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = xtask.join("tests/fixtures/platform_application_waist");
    let ui = xtask.join("tests/ui/platform_application_waist");

    let consumer = TempConsumer::create()?;
    assert_fixture_is_isolated(&consumer.root, &fixture)?;
    check_fixture_tests(&consumer.root, &fixture)?;
    let cases = discover_cases(&ui)?;
    let mut failures = Vec::new();
    for case in &cases {
        if let Err(error) = check_case(&consumer.root, &fixture, case) {
            failures.push(format!("{}: {error}", case.name));
        }
    }
    assert!(
        failures.is_empty(),
        "compile contract failures:\n{}",
        failures.join("\n\n"),
    );
    Ok(())
}

fn check_fixture_tests(root: &Path, fixture: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = fixture.join("Cargo.toml");
    let manifest_arg = manifest.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "fixture manifest path must be UTF-8",
        )
    })?;
    let output = Command::new(env!("CARGO"))
        .args([
            "test",
            "--quiet",
            "--offline",
            "--manifest-path",
            manifest_arg,
        ])
        .env("CARGO_TARGET_DIR", root.join("fixture-target"))
        .env("CARGO_TERM_COLOR", "never")
        .output()?;
    assert!(
        output.status.success(),
        "fixture unit tests must pass:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(())
}

fn assert_fixture_is_isolated(
    root: &Path,
    fixture: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest: toml::Value = fs::read_to_string(fixture.join("Cargo.toml"))?.parse()?;
    assert_eq!(
        manifest["package"]["publish"].as_bool(),
        Some(false),
        "the executable contract must never be publishable",
    );
    assert!(
        manifest["workspace"].as_table().is_some(),
        "the executable contract must own an isolated workspace",
    );
    let metadata = cargo_metadata(&fixture.join("Cargo.toml"), &root.join("metadata-target"))?;
    let package = sole_package(&metadata)?;
    assert_dependency_exact_set(package, &[])?;
    assert_eq!(
        metadata["workspace_root"].as_str().map(Path::new),
        Some(fixture),
        "the executable contract must be its own Cargo workspace root",
    );
    Ok(())
}

fn check_case(
    root: &Path,
    fixture: &Path,
    case: &CompileCase,
) -> Result<(), Box<dyn std::error::Error>> {
    let name = &case.name;
    let case_dir = root.join(name);
    fs::create_dir_all(&case_dir)?;
    let source = &case.source;
    let extra_dependencies = case_extra_dependencies(name);
    let mut dependency_toml = format!(
        "platform-application-waist-contract = {{ path = \"{}\" }}\n",
        toml_path(fixture),
    );
    for dependency in &extra_dependencies {
        dependency_toml.push_str(&format!("{} = \"{}\"\n", dependency.name, dependency.req));
    }
    let manifest = format!(
        "[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n[workspace]\n\n[dependencies]\n{dependency_toml}\n[[bin]]\nname = \"{name}\"\npath = \"{}\"\n",
        toml_path(source),
    );
    let manifest_path = case_dir.join("Cargo.toml");
    fs::write(&manifest_path, manifest)?;
    let metadata = cargo_metadata(&manifest_path, &root.join("metadata-target"))?;
    let package = sole_package(&metadata)?;
    let mut expected_dependencies =
        vec![DependencyKey::normal("platform-application-waist-contract")];
    expected_dependencies.extend(
        extra_dependencies
            .iter()
            .map(|dependency| DependencyKey::normal(dependency.name)),
    );
    assert_dependency_exact_set(package, &expected_dependencies)?;
    let manifest_arg = manifest_path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "temporary manifest path must be UTF-8",
        )
    })?;

    let output = Command::new(env!("CARGO"))
        .args([
            "check",
            "--quiet",
            "--offline",
            "--message-format=json",
            "--manifest-path",
            manifest_arg,
        ])
        .env("CARGO_TARGET_DIR", root.join("target"))
        .env("CARGO_TERM_COLOR", "never")
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);

    if case.should_pass {
        assert!(output.status.success(), "{name} must compile:\n{stderr}");
        return Ok(());
    }

    assert!(!output.status.success(), "{name} must fail to compile");
    let actual = parse_compiler_diagnostics(&output.stdout, name)?;
    let expected =
        read_expected_diagnostics(&source.with_extension("stderr"), source).map_err(|error| {
            io::Error::other(format!(
                "{error}; actual diagnostics:\n{}",
                render_diagnostics(&actual),
            ))
        })?;
    assert_exact_diagnostics(&actual, &expected)
        .map_err(|error| io::Error::other(format!("{error}\nrustc stderr:\n{stderr}")))?;
    Ok(())
}

struct ExtraDependency {
    name: &'static str,
    req: &'static str,
}

fn case_extra_dependencies(name: &str) -> Vec<ExtraDependency> {
    match name {
        "authority_traits_fail" => vec![ExtraDependency {
            name: "serde",
            req: "1",
        }],
        _ => Vec::new(),
    }
}

impl DependencyKey {
    fn normal(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            rename: None,
            kind: None,
            target: None,
        }
    }
}

fn discover_cases(ui: &Path) -> io::Result<Vec<CompileCase>> {
    let mut rust_sources = BTreeSet::new();
    let mut golden_files = BTreeSet::new();
    for entry in fs::read_dir(ui)? {
        let path = entry?.path();
        if !path.is_file() {
            return Err(io::Error::other(format!(
                "UI inventory contains a non-file entry: {}",
                path.display(),
            )));
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| io::Error::other("UI file names must be UTF-8"))?
            .to_owned();
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("rs") => {
                rust_sources.insert(file_name);
            }
            Some("stderr") => {
                golden_files.insert(file_name);
            }
            _ => {
                return Err(io::Error::other(format!(
                    "unknown UI fixture suffix: {}",
                    path.display(),
                )));
            }
        }
    }

    if !rust_sources.contains("positive.rs") {
        return Err(io::Error::other(
            "UI inventory must contain exactly one positive.rs",
        ));
    }
    if golden_files.contains("positive.stderr") {
        return Err(io::Error::other(
            "positive.rs must not have a stderr golden",
        ));
    }

    let mut cases = Vec::with_capacity(rust_sources.len());
    for source in &rust_sources {
        let should_pass = source == "positive.rs";
        if !should_pass && !source.ends_with("_fail.rs") {
            return Err(io::Error::other(format!(
                "negative UI source must end in _fail.rs: {source}",
            )));
        }
        let name = source
            .strip_suffix(".rs")
            .ok_or_else(|| io::Error::other("Rust source suffix disappeared"))?;
        if !should_pass && !golden_files.contains(&format!("{name}.stderr")) {
            return Err(io::Error::other(format!(
                "negative UI source has no matching stderr golden: {source}",
            )));
        }
        cases.push(CompileCase {
            name: name.to_owned(),
            source: ui.join(source),
            should_pass,
        });
    }
    for golden in &golden_files {
        let source = format!(
            "{}.rs",
            golden
                .strip_suffix(".stderr")
                .ok_or_else(|| io::Error::other("stderr suffix disappeared"))?,
        );
        if !rust_sources.contains(&source) {
            return Err(io::Error::other(format!(
                "orphan stderr golden has no matching Rust source: {golden}",
            )));
        }
    }
    cases.sort_by_key(|case| (!case.should_pass, case.name.clone()));
    Ok(cases)
}

fn cargo_metadata(manifest: &Path, target_dir: &Path) -> io::Result<serde_json::Value> {
    let manifest_arg = manifest
        .to_str()
        .ok_or_else(|| io::Error::other("manifest path must be UTF-8"))?;
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--quiet",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            manifest_arg,
        ])
        .env("CARGO_TARGET_DIR", target_dir)
        .env("CARGO_TERM_COLOR", "never")
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "cargo metadata failed for {}:\n{}",
            manifest.display(),
            String::from_utf8_lossy(&output.stderr),
        )));
    }
    serde_json::from_slice(&output.stdout).map_err(io::Error::other)
}

fn sole_package(metadata: &serde_json::Value) -> io::Result<&serde_json::Value> {
    let packages = metadata["packages"]
        .as_array()
        .ok_or_else(|| io::Error::other("cargo metadata packages must be an array"))?;
    match packages.as_slice() {
        [package] => Ok(package),
        _ => Err(io::Error::other(format!(
            "isolated manifest must expose exactly one package, found {}",
            packages.len(),
        ))),
    }
}

fn assert_dependency_exact_set(
    package: &serde_json::Value,
    expected: &[DependencyKey],
) -> io::Result<()> {
    let dependencies = package["dependencies"]
        .as_array()
        .ok_or_else(|| io::Error::other("package dependencies must be an array"))?;
    let mut actual = dependencies
        .iter()
        .map(|dependency| {
            Ok(DependencyKey {
                name: dependency["name"]
                    .as_str()
                    .ok_or_else(|| io::Error::other("dependency name must be a string"))?
                    .to_owned(),
                rename: dependency["rename"].as_str().map(str::to_owned),
                kind: dependency["kind"].as_str().map(str::to_owned),
                target: dependency["target"].as_str().map(str::to_owned),
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    actual.sort();
    let mut expected = expected.to_vec();
    expected.sort();
    if actual != expected {
        return Err(io::Error::other(format!(
            "Cargo dependency exact-set mismatch\nexpected: {expected:#?}\nactual: {actual:#?}",
        )));
    }
    Ok(())
}

fn parse_compiler_diagnostics(stdout: &[u8], target_name: &str) -> io::Result<Vec<DiagnosticKey>> {
    let mut diagnostics = Vec::new();
    for line in stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let message: serde_json::Value = serde_json::from_slice(line).map_err(io::Error::other)?;
        if message["reason"].as_str() != Some("compiler-message")
            || message["target"]["name"].as_str() != Some(target_name)
            || message["message"]["level"].as_str() != Some("error")
        {
            continue;
        }
        let code = message["message"]["code"]["code"]
            .as_str()
            .unwrap_or("NO_CODE");
        let primary_lines = message["message"]["spans"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|span| span["is_primary"].as_bool() == Some(true))
            .filter_map(|span| span["line_start"].as_u64())
            .collect::<Vec<_>>();
        if primary_lines.is_empty() {
            diagnostics.push(DiagnosticKey::new(code, 0));
        } else {
            diagnostics.extend(
                primary_lines
                    .into_iter()
                    .map(|line| DiagnosticKey::new(code, line)),
            );
        }
    }
    diagnostics.sort();
    Ok(diagnostics)
}

fn read_expected_diagnostics(golden: &Path, source: &Path) -> io::Result<Vec<DiagnosticKey>> {
    let source_text = fs::read_to_string(source)?;
    let source_lines = source_text.lines().collect::<Vec<_>>();
    let mut expected = Vec::new();
    for (index, line) in fs::read_to_string(golden)?.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let (location, source_fragment) = line.split_once('|').ok_or_else(|| {
            io::Error::other(format!(
                "{}:{} must use CODE@LINE|SOURCE_FRAGMENT",
                golden.display(),
                index + 1,
            ))
        })?;
        let (code, line_number) = location.split_once('@').ok_or_else(|| {
            io::Error::other(format!(
                "{}:{} must bind an error code to a primary line",
                golden.display(),
                index + 1,
            ))
        })?;
        let line_number = line_number.parse::<u64>().map_err(io::Error::other)?;
        let source_line = line_number
            .checked_sub(1)
            .and_then(|line| source_lines.get(line as usize))
            .ok_or_else(|| {
                io::Error::other(format!("golden line {line_number} is out of range"))
            })?;
        if !source_line.contains(source_fragment) {
            return Err(io::Error::other(format!(
                "{}:{} source line does not contain `{source_fragment}`: {source_line}",
                golden.display(),
                index + 1,
            )));
        }
        expected.push(DiagnosticKey::new(code, line_number));
    }
    expected.sort();
    Ok(expected)
}

fn assert_exact_diagnostics(
    actual: &[DiagnosticKey],
    expected: &[DiagnosticKey],
) -> io::Result<()> {
    if actual != expected {
        return Err(io::Error::other(format!(
            "structured diagnostic exact-set mismatch\nexpected:\n{}\nactual:\n{}",
            render_diagnostics(expected),
            render_diagnostics(actual),
        )));
    }
    Ok(())
}

fn render_diagnostics(diagnostics: &[DiagnosticKey]) -> String {
    diagnostics
        .iter()
        .map(|diagnostic| format!("{}@{}", diagnostic.code, diagnostic.line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn toml_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

#[test]
fn structured_oracle_rejects_a_partially_opened_boundary() {
    let expected = [
        DiagnosticKey::new("E0277", 8),
        DiagnosticKey::new("E0277", 12),
    ];
    let actual = [DiagnosticKey::new("E0277", 12)];
    assert!(assert_exact_diagnostics(&actual, &expected).is_err());
}

#[test]
fn inventory_rejects_orphaned_golden_files() -> Result<(), Box<dyn std::error::Error>> {
    let root = TempConsumer::create()?;
    fs::write(root.root.join("positive.rs"), "fn main() {}")?;
    fs::write(root.root.join("orphan_fail.stderr"), "E0277@1\n")?;
    assert!(discover_cases(&root.root).is_err());
    Ok(())
}

#[test]
fn dependency_oracle_rejects_hidden_dependency_kinds() {
    let package = serde_json::json!({
        "dependencies": [
            {"name": "hidden-dev", "kind": "dev", "target": null},
            {"name": "hidden-build", "kind": "build", "target": "cfg(unix)"}
        ]
    });
    assert!(assert_dependency_exact_set(&package, &[]).is_err());
}
