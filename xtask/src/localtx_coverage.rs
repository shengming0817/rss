//! LocalTx static coverage closure gate.
//!
//! INVARIANT: LOCALTX-COVERAGE-CLOSURE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "missing_route_and_duplicate_marker_are_rejected", anti_vacuity = "green_fixture_closes_every_active_localtx_contract" }.

use crate::contract::manifest::{ConsistencyLevel, ContractKind, ContractOwner, Lifecycle};
use crate::diagnostic::{self, GovernanceCheck, finding};
use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use syn::spanned::Spanned as _;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprCall, ExprMethodCall, File, GenericArgument, Item, ItemConst, ItemFn,
    Meta, PathArguments, Stmt, Type, UseTree,
};

pub(crate) type Finding = diagnostic::Finding<Rule>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rule {
    InvalidDomainOwner,
    MissingOwnerCrate,
    MissingGeneratedSpec,
    UnexpectedGeneratedSpec,
    MissingGeneratedEvidence,
    MissingRouteBinding,
    MissingTestMarker,
    DuplicateTestMarker,
    UnexpectedTestMarker,
    OpaqueSourceScope,
}

pub(crate) struct LocalTxCoverage;

impl GovernanceCheck for LocalTxCoverage {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "localtx-coverage"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        check_root(&crate::workspace_root()?)
    }
}

#[derive(Debug)]
struct Contract {
    id: String,
    owner: String,
    key: String,
    subject: String,
    valid_owner: bool,
}

#[derive(Debug, Clone)]
struct WorkspaceCrate {
    name: String,
    relative: PathBuf,
    root: PathBuf,
    targets: Vec<CargoTarget>,
    normal_dependencies: BTreeMap<String, DependencyRef>,
    dev_dependencies: BTreeMap<String, DependencyRef>,
    normal_test_dependencies: BTreeMap<String, DependencyRef>,
    dev_test_dependencies: BTreeMap<String, DependencyRef>,
}

#[derive(Debug, Clone)]
struct CargoTarget {
    path: PathBuf,
    integration_test: bool,
}

#[derive(Debug, Clone)]
struct DependencyRef {
    package: String,
    path: Option<PathBuf>,
    source: Option<String>,
    unconditional: bool,
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<MetadataPackage>,
    workspace_members: Vec<String>,
}

#[derive(Deserialize)]
struct MetadataPackage {
    id: String,
    name: String,
    manifest_path: PathBuf,
    targets: Vec<MetadataTarget>,
    dependencies: Vec<MetadataDependency>,
}

#[derive(Deserialize)]
struct MetadataTarget {
    src_path: PathBuf,
    kind: Vec<String>,
}

#[derive(Deserialize)]
struct MetadataDependency {
    name: String,
    rename: Option<String>,
    path: Option<PathBuf>,
    kind: Option<String>,
    target: Option<String>,
    source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MarkerOccurrence {
    key: String,
    owner: String,
    path: String,
    ordinal: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OpaqueTrigger {
    subject: String,
    attribute: String,
}

fn check_root(root: &Path) -> Result<(String, Vec<Finding>)> {
    check_root_inner(root).map_err(|error| sanitized(root, error))
}

fn check_root_inner(root: &Path) -> Result<(String, Vec<Finding>)> {
    reject_symlinks(root, &root.join("contracts"))?;
    let contracts = discover(root)?;
    if contracts.is_empty() {
        bail!("localtx-coverage: no active LocalTx HTTP contracts discovered");
    }
    let expected: BTreeMap<_, _> = contracts.iter().map(|c| (c.key.clone(), c)).collect();
    if expected.len() != contracts.len() {
        bail!("localtx-coverage: duplicate generated identity among active LocalTx contracts");
    }

    let generated_root = root.join("generated/src/http");
    reject_symlinks(root, &generated_root)?;
    let registry = parse_registry(root, &generated_root.join("mod.rs"))?;
    let generated = parse_generated_specs(root, &generated_root)?;
    let workspace_crates = load_workspace_crates(root)?;
    let expected_packages: BTreeMap<_, _> = workspace_crates
        .iter()
        .map(|member| (member.name.clone(), member.root.clone()))
        .collect();
    let mut owner_evidence = BTreeMap::new();
    let mut all_markers = Vec::new();
    for member in &workspace_crates {
        let evidence = scan_owner(root, member, &expected_packages)?;
        all_markers.extend(evidence.markers.iter().cloned());
        if member.relative == Path::new("crates").join(&member.name) {
            owner_evidence.insert(member.name.clone(), evidence);
        }
    }
    all_markers.sort_by(|a, b| {
        (&a.key, &a.owner, &a.path, a.ordinal).cmp(&(&b.key, &b.owner, &b.path, b.ordinal))
    });
    all_markers.dedup();
    let mut findings = Vec::new();

    for contract in &contracts {
        if !contract.valid_owner {
            findings.push(contract_finding(
                Rule::InvalidDomainOwner,
                contract,
                "owner must be a safe Domain owner equal to domain",
            ));
            continue;
        }
        if !registry.contains(&contract.key) {
            findings.push(contract_finding(
                Rule::MissingGeneratedSpec,
                contract,
                "missing from generated LOCAL_TX_SPECS",
            ));
        }
        match generated.get(&contract.key) {
            None => findings.push(contract_finding(
                Rule::MissingGeneratedSpec,
                contract,
                "generated SPEC is missing",
            )),
            Some(false) => findings.push(contract_finding(
                Rule::MissingGeneratedEvidence,
                contract,
                "generated SPEC.local_tx is not Some(...)",
            )),
            Some(true) => {}
        }

        let Some(evidence) = owner_evidence.get(&contract.owner) else {
            findings.push(contract_finding(
                Rule::MissingOwnerCrate,
                contract,
                "owner is not a real crates/* workspace member with Cargo.toml and src",
            ));
            continue;
        };
        let route_missing = !evidence.routes.contains(&contract.key);
        if route_missing {
            findings.push(contract_finding(Rule::MissingRouteBinding, contract, "production GeneratedEndpoint binding with matching ContractMarker<RouteMarker> is missing"));
        }
        let occurrences: Vec<_> = all_markers
            .iter()
            .filter(|occurrence| occurrence.key == contract.key)
            .collect();
        let marker_invalid =
            !matches!(occurrences.as_slice(), [only] if only.owner == contract.owner);
        append_relevant_opaque_findings(&mut findings, evidence, route_missing, marker_invalid);
        match occurrences.as_slice() {
            [] => findings.push(contract_finding(
                Rule::MissingTestMarker,
                contract,
                "typed marker is missing from a real test function",
            )),
            [only] if only.owner == contract.owner => {}
            [only] => findings.push(finding(
                Rule::UnexpectedTestMarker,
                only.path.clone(),
                format!(
                    "typed marker `{}` is in owner `{}`; expected `{}`",
                    contract.key, only.owner, contract.owner
                ),
            )),
            many => findings.push(finding(
                Rule::DuplicateTestMarker,
                many.iter()
                    .find(|occurrence| occurrence.owner != contract.owner)
                    .unwrap_or(&many[0])
                    .path
                    .clone(),
                format!(
                    "typed marker `{}` occurs {} times at {}; expected exactly one in owner `{}`",
                    contract.key,
                    many.len(),
                    many.iter()
                        .map(|occurrence| occurrence.path.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    contract.owner
                ),
            )),
        }
    }
    for occurrence in all_markers
        .iter()
        .filter(|occurrence| !expected.contains_key(&occurrence.key))
    {
        findings.push(finding(
            Rule::UnexpectedTestMarker,
            occurrence.path.clone(),
            format!(
                "typed marker `{}` in owner `{}` has no active LocalTx manifest",
                occurrence.key, occurrence.owner
            ),
        ));
    }
    let generated_localtx: BTreeSet<_> = generated
        .iter()
        .filter_map(|(key, evidence)| evidence.then_some(key.clone()))
        .collect();
    for key in registry
        .union(&generated_localtx)
        .filter(|key| !expected.contains_key(*key))
    {
        findings.push(finding(
            Rule::UnexpectedGeneratedSpec,
            "generated/src/http",
            format!("generated LocalTx evidence `{key}` has no active LocalTx manifest"),
        ));
    }
    findings.sort_by(|a, b| {
        (format!("{:?}", a.rule), &a.subject, &a.detail).cmp(&(
            format!("{:?}", b.rule),
            &b.subject,
            &b.detail,
        ))
    });
    findings.dedup();
    Ok((
        format!(
            "{} active LocalTx HTTP contract(s) covered",
            contracts.len()
        ),
        findings,
    ))
}

fn append_relevant_opaque_findings(
    findings: &mut Vec<Finding>,
    evidence: &OwnerEvidence,
    route_missing: bool,
    marker_invalid: bool,
) {
    if route_missing || marker_invalid {
        append_opaque_findings(findings, evidence);
    }
}

fn append_opaque_findings(findings: &mut Vec<Finding>, evidence: &OwnerEvidence) {
    findings.extend(evidence.opaque_triggers.iter().map(|trigger| {
        finding(
            Rule::OpaqueSourceScope,
            trigger.subject.clone(),
            format!(
                "unsupported attribute `{}` makes LocalTx evidence in this lexical scope opaque",
                trigger.attribute
            ),
        )
    }));
}

fn load_workspace_crates(root: &Path) -> Result<Vec<WorkspaceCrate>> {
    let manifest_path = root.join("Cargo.toml");
    let manifest = manifest_path
        .to_str()
        .ok_or_else(|| anyhow!("workspace Cargo.toml path is not UTF-8"))?;
    let args = [
        "metadata",
        "--format-version=1",
        "--locked",
        "--no-deps",
        "--manifest-path",
        manifest,
    ];
    let output = crate::cmd::cargo_cmd(
        crate::cmd::CargoSubcommand::Metadata,
        &args[1..],
        &[],
        Some(root),
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .output()
    .context("execute cargo metadata for LocalTx coverage")?;
    if !output.status.success() {
        let stderr = bounded_stderr(&output.stderr);
        bail!(
            "cargo metadata --locked --no-deps failed (status={}): {stderr}",
            output.status
        );
    }
    let metadata: CargoMetadata =
        serde_json::from_slice(&output.stdout).context("parse cargo metadata JSON")?;
    let workspace_members: BTreeSet<_> = metadata.workspace_members.into_iter().collect();
    let mut out = Vec::new();
    let mut names = BTreeSet::new();
    for package in metadata.packages {
        if !workspace_members.contains(&package.id) {
            continue;
        }
        let member_root = package
            .manifest_path
            .parent()
            .ok_or_else(|| anyhow!("workspace package manifest has no parent"))?
            .to_path_buf();
        ensure_contained(root, root, &member_root)?;
        reject_symlinks(root, &member_root)?;
        let relative = member_root
            .strip_prefix(root)
            .map_err(|_| anyhow!("workspace package escapes workspace"))?
            .to_path_buf();
        let mut targets = Vec::new();
        for target in package.targets {
            if target.kind.iter().any(|kind| kind == "test") {
                targets.push(CargoTarget {
                    path: target.src_path,
                    integration_test: true,
                });
            } else if target.kind.iter().any(|kind| {
                matches!(
                    kind.as_str(),
                    "lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro" | "bin"
                )
            }) {
                targets.push(normal_target(target.src_path));
            }
        }
        targets.sort_by(|a, b| (&a.path, a.integration_test).cmp(&(&b.path, b.integration_test)));
        targets.dedup_by(|a, b| a.path == b.path && a.integration_test == b.integration_test);
        let mut normal_dependencies = BTreeMap::new();
        let mut dev_dependencies = BTreeMap::new();
        let mut normal_test_dependencies = BTreeMap::new();
        let mut dev_test_dependencies = BTreeMap::new();
        for dependency in package.dependencies {
            let key = dependency
                .rename
                .clone()
                .unwrap_or_else(|| dependency.name.clone());
            if !protected_root(&key)
                && !matches!(key.as_str(), "tokio" | "rstest" | "thiserror" | "tracing")
            {
                continue;
            }
            let reference = DependencyRef {
                package: dependency.name,
                path: dependency.path,
                source: dependency.source,
                unconditional: dependency.target.is_none(),
            };
            let destination = match (protected_root(&key), dependency.kind.as_deref()) {
                (true, Some("dev")) => &mut dev_dependencies,
                (true, None) => &mut normal_dependencies,
                (false, Some("dev")) => &mut dev_test_dependencies,
                (false, None) => &mut normal_test_dependencies,
                _ => continue,
            };
            destination.insert(key, reference);
        }
        let name = package.name;
        let workspace_crate = WorkspaceCrate {
            name: name.clone(),
            relative,
            root: member_root,
            targets,
            normal_dependencies,
            dev_dependencies,
            normal_test_dependencies,
            dev_test_dependencies,
        };
        if !names.insert(name.clone()) {
            bail!("duplicate crates/* workspace package name `{name}`");
        }
        out.push(workspace_crate);
    }
    out.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(out)
}

fn normal_target(path: PathBuf) -> CargoTarget {
    CargoTarget {
        path,
        integration_test: false,
    }
}

fn contract_finding(rule: Rule, contract: &Contract, detail: impl Into<String>) -> Finding {
    finding(
        rule,
        contract.subject.clone(),
        format!("contract `{}`: {}", contract.id, detail.into()),
    )
}

fn discover(root: &Path) -> Result<Vec<Contract>> {
    let discovered =
        crate::contract::discover(&root.join("contracts")).map_err(|e| sanitized(root, e))?;
    let mut out = Vec::new();
    for item in discovered {
        let m = &item.manifest;
        if m.lifecycle != Lifecycle::Active
            || m.kind != ContractKind::Http
            || m.consistency_level != ConsistencyLevel::LocalTx
        {
            continue;
        }
        let owner = match &m.owner {
            ContractOwner::Domain(owner) if owner == &m.domain && safe_segment(owner) => {
                owner.clone()
            }
            _ => {
                let subject = relative(root, &item.dir.join("contract.toml"))?;
                // Preserve invalid owners as a finding without ever joining an unsafe segment.
                out.push(Contract {
                    id: m.id.clone(),
                    owner: String::new(),
                    key: generated_key(&m.domain, &m.version, item.slug.as_deref()),
                    subject,
                    valid_owner: false,
                });
                continue;
            }
        };
        out.push(Contract {
            id: m.id.clone(),
            owner,
            key: generated_key(&m.domain, &m.version, item.slug.as_deref()),
            subject: relative(root, &item.dir.join("contract.toml"))?,
            valid_owner: true,
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

fn safe_segment(value: &str) -> bool {
    !value.is_empty()
        && Path::new(value)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        && !value.contains(['/', '\\'])
}

fn generated_key(domain: &str, version: &str, slug: Option<&str>) -> String {
    let module = format!("{}_{}", domain.replace('-', "_"), version.replace('-', "_"));
    slug.map_or(module.clone(), |slug| {
        format!("{module}::{}", slug.replace('-', "_"))
    })
}

fn parse_registry(root: &Path, file: &Path) -> Result<BTreeSet<String>> {
    let syntax = parse_file(root, file)?;
    let item = syntax
        .items
        .iter()
        .find_map(|item| match item {
            Item::Const(item) if item.ident == "LOCAL_TX_SPECS" => Some(item),
            _ => None,
        })
        .ok_or_else(|| anyhow!("generated/src/http/mod.rs: LOCAL_TX_SPECS is missing"))?;
    let expr = peel_expr(&item.expr);
    let Expr::Array(array) = expr else {
        bail!("generated/src/http/mod.rs: LOCAL_TX_SPECS must be an array reference")
    };
    let entries: Vec<String> = array
        .elems
        .iter()
        .map(|expr| {
            let Expr::Path(path) = peel_expr(expr) else {
                bail!("generated/src/http/mod.rs: LOCAL_TX_SPECS entries must be SPEC paths")
            };
            let segments: Vec<_> = path
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if segments.last().is_none_or(|s| s != "SPEC") || segments.len() < 2 {
                bail!("generated/src/http/mod.rs: invalid LOCAL_TX_SPECS entry")
            }
            Ok(segments[..segments.len() - 1].join("::"))
        })
        .collect::<Result<_>>()?;
    let registry: BTreeSet<_> = entries.iter().cloned().collect();
    if registry.len() != entries.len() {
        let mut counts = BTreeMap::new();
        for entry in entries {
            *counts.entry(entry).or_insert(0_usize) += 1;
        }
        let duplicate = counts
            .into_iter()
            .find(|(_, count)| *count > 1)
            .map(|(key, _)| key)
            .ok_or_else(|| anyhow!("LOCAL_TX_SPECS duplicate accounting failed"))?;
        bail!("generated/src/http/mod.rs: duplicate LOCAL_TX_SPECS entry `{duplicate}`");
    }
    Ok(registry)
}

fn peel_expr(expr: &Expr) -> &Expr {
    match expr {
        Expr::Reference(reference) => peel_expr(&reference.expr),
        Expr::Paren(paren) => peel_expr(&paren.expr),
        Expr::Group(group) => peel_expr(&group.expr),
        other => other,
    }
}

fn parse_generated_specs(root: &Path, dir: &Path) -> Result<BTreeMap<String, bool>> {
    let mut out = BTreeMap::new();
    for file in rs_files_contained(root, dir)? {
        if file.file_name().and_then(|x| x.to_str()) == Some("mod.rs") {
            continue;
        }
        let module = file
            .file_stem()
            .and_then(|x| x.to_str())
            .ok_or_else(|| anyhow!("generated HTTP module filename is not UTF-8"))?
            .to_string();
        collect_specs(
            &parse_file(root, &file)?.items,
            &module,
            &mut Vec::new(),
            &mut out,
        )?;
    }
    Ok(out)
}

fn collect_specs(
    items: &[Item],
    module: &str,
    nested: &mut Vec<String>,
    out: &mut BTreeMap<String, bool>,
) -> Result<()> {
    for item in items {
        match item {
            Item::Const(item) if item.ident == "SPEC" => {
                let key = std::iter::once(module.to_string())
                    .chain(nested.iter().cloned())
                    .collect::<Vec<_>>()
                    .join("::");
                let evidence = spec_has_local_tx(&item.expr);
                if out.insert(key.clone(), evidence).is_some() {
                    bail!("generated/src/http: duplicate SPEC `{key}`")
                }
            }
            Item::Mod(item) => {
                if let Some((_, items)) = &item.content {
                    nested.push(item.ident.to_string());
                    collect_specs(items, module, nested, out)?;
                    nested.pop();
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn spec_has_local_tx(expr: &Expr) -> bool {
    let Expr::Struct(value) = peel_expr(expr) else {
        return false;
    };
    value.fields.iter().any(|field| {
        matches!(&field.member, syn::Member::Named(ident) if ident == "local_tx")
            && matches!(peel_expr(&field.expr), Expr::Call(call) if call_path_ends(call, "Some"))
    })
}

#[derive(Default)]
struct OwnerEvidence {
    routes: BTreeSet<String>,
    canonical_mounts: BTreeMap<String, BTreeSet<CanonicalRouteMount>>,
    reachable_production_sources: BTreeSet<String>,
    markers: Vec<MarkerOccurrence>,
    test_macros: BTreeSet<String>,
    production_macros: BTreeSet<String>,
    opaque_triggers: BTreeSet<OpaqueTrigger>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CanonicalMountedState {
    Stateless,
    Ordinary,
    Classified(String),
    Opaque,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CanonicalRouteMount {
    pub(crate) source: String,
    pub(crate) state: CanonicalMountedState,
}

pub(crate) struct CanonicalOwnerEvidence {
    pub(crate) mounts: BTreeMap<String, BTreeSet<CanonicalRouteMount>>,
    pub(crate) reachable_production_sources: BTreeSet<String>,
}

/// Canonical production routes mounted by one `crates/*` owner.
///
/// This is deliberately the same evidence used by the LocalTx closure gate: Cargo targets,
/// reachable modules, cfg state, aliases, handler markers, `Domain::init`, `route_group`, and
/// `mount` are resolved once instead of being reimplemented by sibling consistency checks.
pub(crate) fn canonical_owner_evidence(root: &Path, owner: &str) -> Result<CanonicalOwnerEvidence> {
    let workspace_crates = load_workspace_crates(root)?;
    let expected_packages: BTreeMap<_, _> = workspace_crates
        .iter()
        .map(|member| (member.name.clone(), member.root.clone()))
        .collect();
    let member = workspace_crates
        .iter()
        .find(|member| member.name == owner && member.relative == Path::new("crates").join(owner))
        .ok_or_else(|| anyhow!("owner `{owner}` is not a canonical crates/* workspace member"))?;
    let evidence = scan_owner(root, member, &expected_packages)?;
    Ok(CanonicalOwnerEvidence {
        mounts: evidence.canonical_mounts,
        reachable_production_sources: evidence.reachable_production_sources,
    })
}

struct FileUnit {
    relative: String,
    module: Vec<String>,
    syntax: File,
    resolvers: BTreeMap<String, Resolver>,
    reachability: Reachability,
}

#[derive(Debug, Clone, Copy)]
struct Reachability {
    prod: bool,
    test: bool,
    unknown: bool,
}

impl Reachability {
    const BOTH: Self = Self {
        prod: true,
        test: true,
        unknown: false,
    };
    const TEST_ONLY: Self = Self {
        prod: false,
        test: true,
        unknown: false,
    };

    fn with_attrs(self, attrs: &[Attribute]) -> Self {
        let mut reach = self;
        for attr in attrs {
            if attr.path().is_ident("cfg_attr") {
                return Self {
                    prod: false,
                    test: false,
                    unknown: true,
                };
            }
            if !attr.path().is_ident("cfg") {
                continue;
            }
            let Some(meta) = cfg_expression(attr) else {
                return Self {
                    prod: false,
                    test: false,
                    unknown: true,
                };
            };
            let prod = cfg_truth(&meta, false);
            let test = cfg_truth(&meta, true);
            reach.unknown |= prod == Truth::Unknown || test == Truth::Unknown;
            reach.prod &= prod == Truth::True;
            reach.test &= test == Truth::True;
        }
        reach
    }
}

/// Whether an attributed item/field can exist in a production build.
///
/// Unknown cfg predicates are production-possible and therefore retained for fail-closed static
/// analysis. Only an expression proven false when `test = false` is excluded.
pub(crate) fn attrs_may_be_production(attrs: &[Attribute]) -> bool {
    attrs.iter().all(|attr| {
        if attr.path().is_ident("cfg_attr") {
            return true;
        }
        if !attr.path().is_ident("cfg") {
            return true;
        }
        cfg_expression(attr).is_none_or(|meta| cfg_truth(&meta, false) != Truth::False)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Truth {
    True,
    False,
    Unknown,
}

#[derive(Clone, Default)]
struct Resolver {
    aliases: BTreeMap<String, Vec<String>>,
    local_aliases: BTreeMap<String, Vec<String>>,
    shadowed_roots: BTreeSet<String>,
    opaque_empty_item_macro: bool,
    shadowed_test_macros: BTreeSet<String>,
    shadowed_builtin_macros: BTreeSet<String>,
    trusted_macros: BTreeSet<String>,
}

impl Resolver {
    fn inherited_risks(&self) -> Self {
        Self {
            shadowed_roots: self.shadowed_roots.clone(),
            opaque_empty_item_macro: self.opaque_empty_item_macro,
            shadowed_test_macros: self.shadowed_test_macros.clone(),
            shadowed_builtin_macros: self.shadowed_builtin_macros.clone(),
            trusted_macros: self.trusted_macros.clone(),
            ..Self::default()
        }
    }
}

const MAX_MODULE_DEPTH: usize = 64;
const MAX_CANONICAL_FILES: usize = 512;
const MAX_LOGICAL_UNITS: usize = 1024;
const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

#[derive(Default)]
struct ModuleBudget {
    canonical_files: BTreeSet<PathBuf>,
    logical_units: usize,
    source_bytes: u64,
}

impl ModuleBudget {
    fn enter(&mut self, canonical: &Path, bytes: u64, depth: usize) -> Result<()> {
        if depth > MAX_MODULE_DEPTH {
            bail!("Rust module depth budget exceeded");
        }
        self.logical_units += 1;
        if self.logical_units > MAX_LOGICAL_UNITS {
            bail!("Rust logical module unit budget exceeded");
        }
        if self.canonical_files.insert(canonical.to_path_buf()) {
            if self.canonical_files.len() > MAX_CANONICAL_FILES {
                bail!("Rust canonical module file budget exceeded");
            }
            self.source_bytes = self.source_bytes.saturating_add(bytes);
            if self.source_bytes > MAX_SOURCE_BYTES {
                bail!("Rust module source byte budget exceeded");
            }
        }
        Ok(())
    }

    fn enter_inline(&mut self, depth: usize) -> Result<()> {
        if depth > MAX_MODULE_DEPTH {
            bail!("Rust module depth budget exceeded");
        }
        self.logical_units += 1;
        if self.logical_units > MAX_LOGICAL_UNITS {
            bail!("Rust logical module unit budget exceeded");
        }
        Ok(())
    }
}

fn scan_owner(
    root: &Path,
    member: &WorkspaceCrate,
    expected_packages: &BTreeMap<String, PathBuf>,
) -> Result<OwnerEvidence> {
    let mut evidence = OwnerEvidence::default();
    for target in &member.targets {
        let initial = if target.integration_test {
            Reachability::TEST_ONLY
        } else {
            Reachability::BOTH
        };
        let target_label = relative(root, &target.path)?;
        let units = load_target_units(root, member, &target.path, initial)
            .with_context(|| format!("load Cargo target `{target_label}`"))?;
        let mut target_evidence = OwnerEvidence::default();
        scan_units(&member.name, &units, &mut target_evidence)?;
        validate_evidence_dependencies(member, &target_evidence, expected_packages)?;
        evidence.routes.extend(target_evidence.routes);
        for (key, mounts) in target_evidence.canonical_mounts {
            evidence
                .canonical_mounts
                .entry(key)
                .or_default()
                .extend(mounts);
        }
        evidence
            .reachable_production_sources
            .extend(target_evidence.reachable_production_sources);
        evidence.markers.extend(target_evidence.markers);
        evidence.test_macros.extend(target_evidence.test_macros);
        evidence
            .production_macros
            .extend(target_evidence.production_macros);
        evidence
            .opaque_triggers
            .extend(target_evidence.opaque_triggers);
    }
    Ok(evidence)
}

fn validate_evidence_dependencies(
    member: &WorkspaceCrate,
    evidence: &OwnerEvidence,
    expected_packages: &BTreeMap<String, PathBuf>,
) -> Result<()> {
    if !evidence.routes.is_empty() {
        for key in ["bootstrap", "generated", "httpserve"] {
            validate_dependency(member, key, false, expected_packages)?;
        }
    }
    if !evidence.markers.is_empty() {
        for key in ["generated", "vocab"] {
            validate_dependency(member, key, true, expected_packages)?;
        }
    }
    for macro_name in &evidence.test_macros {
        validate_macro_dependency(member, macro_name, false)?;
    }
    for macro_name in &evidence.production_macros {
        validate_macro_dependency(member, macro_name, true)?;
    }
    Ok(())
}

fn validate_macro_dependency(
    member: &WorkspaceCrate,
    key: &str,
    require_normal: bool,
) -> Result<()> {
    let normal = member.normal_test_dependencies.get(key);
    let dev = member.dev_test_dependencies.get(key);
    let candidates: Vec<_> = if key == "rstest" || require_normal {
        if require_normal {
            normal.into_iter().collect()
        } else {
            dev.into_iter().collect()
        }
    } else {
        normal.into_iter().chain(dev).collect()
    };
    if candidates.is_empty() {
        bail!("typed marker test macro lacks its effective dependency");
    }
    for dependency in candidates {
        if dependency.package != key
            || dependency.path.is_some()
            || dependency.source.as_deref() != Some(CRATES_IO_SOURCE)
            || !dependency.unconditional
        {
            bail!("typed marker test macro dependency has the wrong package identity");
        }
    }
    Ok(())
}

fn validate_dependency(
    member: &WorkspaceCrate,
    key: &str,
    allow_dev: bool,
    expected_packages: &BTreeMap<String, PathBuf>,
) -> Result<()> {
    let expected = expected_packages
        .get(key)
        .ok_or_else(|| anyhow!("protected dependency package is not a workspace member"))?;
    let normal = member.normal_dependencies.get(key);
    let dev = member.dev_dependencies.get(key);
    let candidates = normal.into_iter().chain(dev);
    let found = normal.is_some() || (allow_dev && dev.is_some());
    for candidate in candidates {
        let actual = std::fs::canonicalize(
            candidate
                .path
                .as_ref()
                .ok_or_else(|| anyhow!("protected dependency is not a workspace path package"))?,
        )
        .context("canonicalize protected dependency package")?;
        let expected = std::fs::canonicalize(expected)
            .context("canonicalize expected protected dependency package")?;
        if candidate.package != key || actual != expected || !candidate.unconditional {
            bail!("protected dependency key does not identify the expected workspace package");
        }
    }
    if !found {
        bail!("evidence-bearing target lacks a required protected dependency");
    }
    Ok(())
}

fn load_target_units(
    root: &Path,
    member: &WorkspaceCrate,
    target: &Path,
    reachability: Reachability,
) -> Result<Vec<FileUnit>> {
    let mut units = Vec::new();
    let mut visited = BTreeSet::new();
    let mut active = BTreeSet::new();
    let mut budget = ModuleBudget::default();
    load_module_file(
        root,
        member,
        target,
        Vec::new(),
        reachability,
        Resolver::default(),
        &mut visited,
        &mut active,
        &mut budget,
        &mut units,
    )?;
    Ok(units)
}

#[allow(clippy::too_many_arguments)]
fn load_module_file(
    root: &Path,
    member: &WorkspaceCrate,
    file: &Path,
    module: Vec<String>,
    reachability: Reachability,
    inherited_resolver: Resolver,
    visited: &mut BTreeSet<(PathBuf, Vec<String>)>,
    active: &mut BTreeSet<PathBuf>,
    budget: &mut ModuleBudget,
    units: &mut Vec<FileUnit>,
) -> Result<()> {
    ensure_contained(root, &member.root, file)?;
    let canonical = std::fs::canonicalize(file).context("canonicalize reachable Rust module")?;
    if !active.insert(canonical.clone()) {
        bail!("active Rust module inclusion cycle");
    }
    if !visited.insert((canonical.clone(), module.clone())) {
        active.remove(&canonical);
        return Ok(());
    }
    let bytes = std::fs::metadata(&canonical)
        .context("read reachable Rust module metadata")?
        .len();
    budget.enter(&canonical, bytes, module.len() + 1)?;
    let syntax = parse_file_in(root, &member.root, file)?;
    reject_sensitive_item_macros(&syntax)?;
    let mut resolvers = BTreeMap::new();
    collect_resolvers(&syntax.items, &module, &mut resolvers, inherited_resolver);
    let source_dir = file
        .parent()
        .ok_or_else(|| anyhow!("Rust module has no source directory"))?;
    let module_dir = module_child_dir(file, module.is_empty())?;
    load_external_modules(
        root,
        member,
        &syntax.items,
        source_dir,
        &module_dir,
        &module,
        reachability,
        &resolvers,
        visited,
        active,
        budget,
        units,
    )?;
    units.push(FileUnit {
        relative: relative(root, file)?,
        module,
        syntax,
        resolvers,
        reachability,
    });
    active.remove(&canonical);
    Ok(())
}

fn module_child_dir(file: &Path, target_root: bool) -> Result<PathBuf> {
    let parent = file
        .parent()
        .ok_or_else(|| anyhow!("Rust target has no parent directory"))?;
    let stem = file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| anyhow!("Rust target filename is not UTF-8"))?;
    if target_root || matches!(stem, "lib" | "main" | "mod") {
        Ok(parent.to_path_buf())
    } else {
        Ok(parent.join(stem))
    }
}

#[allow(clippy::too_many_arguments)]
fn load_external_modules(
    root: &Path,
    member: &WorkspaceCrate,
    items: &[Item],
    source_dir: &Path,
    module_dir: &Path,
    module: &[String],
    inherited_reachability: Reachability,
    resolvers: &BTreeMap<String, Resolver>,
    visited: &mut BTreeSet<(PathBuf, Vec<String>)>,
    active: &mut BTreeSet<PathBuf>,
    budget: &mut ModuleBudget,
    units: &mut Vec<FileUnit>,
) -> Result<()> {
    for item in items {
        let Item::Mod(item) = item else {
            continue;
        };
        let mut child_module = module.to_vec();
        child_module.push(item.ident.to_string());
        let child_reachability = inherited_reachability.with_attrs(&item.attrs);
        if !child_reachability.prod && !child_reachability.test && !child_reachability.unknown {
            continue;
        }
        if let Some((_, nested)) = &item.content {
            budget.enter_inline(child_module.len() + 1)?;
            load_external_modules(
                root,
                member,
                nested,
                source_dir,
                &module_dir.join(item.ident.to_string()),
                &child_module,
                child_reachability,
                resolvers,
                visited,
                active,
                budget,
                units,
            )?;
            continue;
        }
        let child_file = if let Some(path) = module_path_attribute(&item.attrs)? {
            source_dir.join(path)
        } else {
            let flat = module_dir.join(format!("{}.rs", item.ident));
            let nested = module_dir.join(item.ident.to_string()).join("mod.rs");
            match (flat.is_file(), nested.is_file()) {
                (true, false) => flat,
                (false, true) => nested,
                (true, true) => bail!("external module has two source candidates"),
                (false, false) => bail!(
                    "external module source is missing for `{}`",
                    child_module.join("::")
                ),
            }
        };
        load_module_file(
            root,
            member,
            &child_file,
            child_module,
            child_reachability,
            resolver_for(resolvers, module)
                .map(Resolver::inherited_risks)
                .unwrap_or_default(),
            visited,
            active,
            budget,
            units,
        )?;
    }
    Ok(())
}

fn module_path_attribute(attrs: &[Attribute]) -> Result<Option<PathBuf>> {
    let mut found = None;
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("path")) {
        let Meta::NameValue(value) = &attr.meta else {
            bail!("module #[path] must be a string name-value attribute");
        };
        let Expr::Lit(literal) = &value.value else {
            bail!("module #[path] must be a string literal");
        };
        let syn::Lit::Str(path) = &literal.lit else {
            bail!("module #[path] must be a string literal");
        };
        let path = PathBuf::from(path.value());
        if path.is_absolute() {
            bail!("module #[path] must be workspace-relative");
        }
        if found.replace(path).is_some() {
            bail!("module has duplicate #[path] attributes");
        }
    }
    Ok(found)
}

fn scan_units(owner: &str, units: &[FileUnit], evidence: &mut OwnerEvidence) -> Result<()> {
    let mut handlers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for unit in units {
        if unit.reachability.prod && !unit.reachability.unknown {
            evidence
                .reachable_production_sources
                .insert(unit.relative.clone());
        }
        let mut collector = HandlerCollector {
            module: unit.module.clone(),
            resolvers: &unit.resolvers,
            handlers: &mut handlers,
            reachability: unit.reachability,
            attribute_safe: true,
            item_scope: Vec::new(),
        };
        collector.visit_file(&unit.syntax);
    }
    for unit in units {
        let resolver = resolver_for(&unit.resolvers, &unit.module)
            .cloned()
            .ok_or_else(|| anyhow!("module resolver is missing"))?;
        let mut scanner = SourceScanner {
            owner,
            source: &unit.relative,
            module: unit.module.clone(),
            resolvers: &unit.resolvers,
            resolver_stack: vec![resolver],
            handlers: &handlers,
            evidence,
            reachability: unit.reachability,
            in_test_function: false,
            marker_ordinal: 0,
            attribute_safe: true,
            test_macro: None,
            canonical_domain_impl: false,
            domain_init_router: None,
            domain_init_body_pending: false,
        };
        scanner.visit_file(&unit.syntax);
    }
    Ok(())
}

fn reject_sensitive_item_macros(file: &File) -> Result<()> {
    struct DefinitionVisitor {
        error: Option<String>,
    }
    impl<'ast> Visit<'ast> for DefinitionVisitor {
        fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
            if item.ident.is_some()
                && let Some(protected) = protected_token(&item.mac.tokens)
            {
                self.error = Some(format!(
                    "local macro definition touches protected LocalTx symbol `{protected}`"
                ));
            }
            visit::visit_item_macro(self, item);
        }
    }
    let mut definitions = DefinitionVisitor { error: None };
    definitions.visit_file(file);
    if let Some(error) = definitions.error {
        bail!(error);
    }

    struct InvocationVisitor {
        error: Option<String>,
    }
    impl<'ast> Visit<'ast> for InvocationVisitor {
        fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
            if item.ident.is_none() && self.error.is_none() {
                let name = item
                    .mac
                    .path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string())
                    .unwrap_or_default();
                if name == "include" {
                    self.error = Some("reachable include! is unsupported".to_string());
                } else if protected_root(&name) {
                    self.error = Some("item macro binds a protected LocalTx root".to_string());
                } else if let Some(protected) = protected_token(&item.mac.tokens) {
                    self.error = Some(format!(
                        "item-position macro invocation touches protected LocalTx symbol `{protected}`"
                    ));
                }
            }
            visit::visit_item_macro(self, item);
        }
    }
    let mut invocations = InvocationVisitor { error: None };
    invocations.visit_file(file);
    if let Some(error) = invocations.error {
        bail!(error);
    }
    Ok(())
}

fn protected_token(tokens: &proc_macro2::TokenStream) -> Option<String> {
    for token in tokens.clone() {
        match token {
            proc_macro2::TokenTree::Ident(ident) if protected_root(&ident.to_string()) => {
                return Some(ident.to_string());
            }
            proc_macro2::TokenTree::Group(group) => {
                if let Some(ident) = protected_token(&group.stream()) {
                    return Some(ident);
                }
            }
            _ => {}
        }
    }
    None
}

fn module_key(module: &[String]) -> String {
    module.join("::")
}

fn collect_resolvers(
    items: &[Item],
    module: &[String],
    out: &mut BTreeMap<String, Resolver>,
    inherited: Resolver,
) {
    collect_resolvers_with_risks(items, module, out, inherited);
}

fn collect_resolvers_with_risks(
    items: &[Item],
    module: &[String],
    out: &mut BTreeMap<String, Resolver>,
    inherited: Resolver,
) {
    let resolver = resolver_with_items(inherited, items, module);
    out.insert(module_key(module), resolver);
    for item in items {
        if let Item::Mod(item) = item
            && let Some((_, nested)) = &item.content
        {
            let mut child = module.to_vec();
            child.push(item.ident.to_string());
            let parent = out
                .get(&module_key(module))
                .map(Resolver::inherited_risks)
                .unwrap_or_default();
            collect_resolvers_with_risks(nested, &child, out, parent);
        }
    }
}

fn resolver_with_items(mut resolver: Resolver, items: &[Item], module: &[String]) -> Resolver {
    collect_macro_namespace_pollution(items, &mut resolver);
    for item in items {
        let Some(trusted) =
            trusted_scope_attributes_with_resolver(item_attributes(item), &resolver)
        else {
            resolver.opaque_empty_item_macro = true;
            continue;
        };
        resolver.trusted_macros.extend(trusted);
        if let Item::Mod(item) = item
            && protected_root(&item.ident.to_string())
        {
            resolver.shadowed_roots.insert(item.ident.to_string());
        }
        if let Item::Mod(item) = item
            && matches!(
                item.ident.to_string().as_str(),
                "tokio" | "rstest" | "thiserror" | "tracing"
            )
        {
            resolver.shadowed_test_macros.insert(item.ident.to_string());
        }
        if let Item::ExternCrate(item) = item {
            let binding = item
                .rename
                .as_ref()
                .map_or_else(|| item.ident.to_string(), |(_, rename)| rename.to_string());
            if protected_root(&binding) {
                resolver.shadowed_roots.insert(binding.clone());
            }
            if matches!(
                binding.as_str(),
                "tokio" | "rstest" | "thiserror" | "tracing"
            ) {
                resolver.shadowed_test_macros.insert(binding);
            }
        }
        if let Item::Macro(item) = item
            && item.ident.is_none()
        {
            resolver.opaque_empty_item_macro = true;
        }
    }
    for item in items {
        if let Item::Use(item) = item {
            collect_use(
                &item.tree,
                Vec::new(),
                item.leading_colon.is_some(),
                module,
                &mut resolver,
            );
        }
    }
    if resolver
        .trusted_macros
        .iter()
        .any(|root| resolver.shadowed_test_macros.contains(root))
    {
        resolver.opaque_empty_item_macro = true;
    }
    resolver
}

fn collect_macro_namespace_pollution(items: &[Item], resolver: &mut Resolver) {
    for item in items {
        match item {
            Item::Macro(item) => {
                if let Some(name) = item.ident.as_ref() {
                    mark_builtin_macro_shadow(&name.to_string(), resolver);
                }
            }
            Item::ExternCrate(item) => {
                let binding = item
                    .rename
                    .as_ref()
                    .map_or_else(|| item.ident.to_string(), |(_, rename)| rename.to_string());
                mark_builtin_macro_shadow(&binding, resolver);
            }
            Item::Mod(item) => mark_builtin_macro_shadow(&item.ident.to_string(), resolver),
            Item::Use(item) => collect_use_macro_pollution(&item.tree, Vec::new(), resolver),
            _ => {}
        }
    }
}

fn collect_use_macro_pollution(tree: &UseTree, mut prefix: Vec<String>, resolver: &mut Resolver) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_macro_pollution(&path.tree, prefix, resolver);
        }
        UseTree::Name(name) => mark_builtin_macro_shadow(&name.ident.to_string(), resolver),
        UseTree::Rename(rename) => {
            mark_builtin_macro_shadow(&rename.rename.to_string(), resolver);
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_macro_pollution(item, prefix.clone(), resolver);
            }
        }
        UseTree::Glob(_) => {
            if prefix.as_slice() != ["super"] {
                resolver.shadowed_builtin_macros.insert("test".to_string());
                for name in BUILTIN_DERIVES {
                    resolver.shadowed_builtin_macros.insert((*name).to_string());
                }
            }
        }
    }
}

const BUILTIN_DERIVES: &[&str] = &[
    "Clone",
    "Copy",
    "Debug",
    "Default",
    "Eq",
    "Hash",
    "Ord",
    "PartialEq",
    "PartialOrd",
];

fn mark_builtin_macro_shadow(binding: &str, resolver: &mut Resolver) {
    if binding == "test" || builtin_derive(binding) {
        resolver.shadowed_builtin_macros.insert(binding.to_string());
    }
}

fn item_attributes(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        Item::Verbatim(_) => &[],
        _ => &[],
    }
}

fn trusted_scope_attributes(attrs: &[Attribute]) -> Option<BTreeSet<String>> {
    trusted_scope_attributes_with_resolver(attrs, &Resolver::default())
}

fn trusted_scope_attributes_with_resolver(
    attrs: &[Attribute],
    resolver: &Resolver,
) -> Option<BTreeSet<String>> {
    let mut trusted = BTreeSet::new();
    for attr in attrs {
        extend_trusted_attribute(attr, resolver, &mut trusted)?;
    }
    Some(trusted)
}

fn extend_trusted_attribute(
    attr: &Attribute,
    resolver: &Resolver,
    trusted: &mut BTreeSet<String>,
) -> Option<()> {
    let path = raw_segments(attr.path());
    if matches!(
        path.as_slice(),
        [single]
            if matches!(
                single.as_str(),
                "cfg" | "test" | "allow" | "warn" | "deny" | "forbid" | "doc" | "inline"
                    | "cold" | "must_use" | "ignore" | "should_panic" | "non_exhaustive" | "path"
            )
    ) {
        return Some(());
    }
    if path.as_slice() == ["derive"] {
        return extend_trusted_derives(attr, resolver, trusted);
    }
    match path.as_slice() {
        [root, leaf] if root == "tracing" && leaf == "instrument" => {
            trusted.insert("tracing".to_string());
            Some(())
        }
        [root, leaf]
            if (root == "tokio" && leaf == "test") || (root == "rstest" && leaf == "rstest") =>
        {
            Some(())
        }
        _ => None,
    }
}

fn extend_trusted_derives(
    attr: &Attribute,
    resolver: &Resolver,
    trusted: &mut BTreeSet<String>,
) -> Option<()> {
    let derives = attr
        .parse_args_with(syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated)
        .ok()?;
    for derive in derives {
        let derive = raw_segments(&derive);
        match derive.as_slice() {
            [single]
                if builtin_derive(single) && !resolver.shadowed_builtin_macros.contains(single) => {
            }
            [root, leaf] if root == "thiserror" && leaf == "Error" => {
                trusted.insert("thiserror".to_string());
            }
            _ => return None,
        }
    }
    Some(())
}

fn builtin_derive(name: &str) -> bool {
    BUILTIN_DERIVES.contains(&name)
}

fn collect_use(
    tree: &UseTree,
    mut prefix: Vec<String>,
    absolute: bool,
    module: &[String],
    resolver: &mut Resolver,
) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use(&path.tree, prefix, absolute, module, resolver);
        }
        UseTree::Name(name) => {
            prefix.push(name.ident.to_string());
            let binding = name.ident.to_string();
            if import_is_canonical(&prefix, absolute, resolver) {
                resolver.aliases.insert(binding.clone(), prefix.clone());
            } else {
                if let Some(local) = local_import_identity(&prefix, module) {
                    resolver.local_aliases.insert(binding.clone(), local);
                }
                if protected_root(&binding) {
                    resolver.shadowed_roots.insert(binding.clone());
                }
            }
            if matches!(
                binding.as_str(),
                "tokio" | "rstest" | "thiserror" | "tracing"
            ) {
                resolver.shadowed_test_macros.insert(binding);
            }
        }
        UseTree::Rename(rename) => {
            prefix.push(rename.ident.to_string());
            let binding = rename.rename.to_string();
            if import_is_canonical(&prefix, absolute, resolver) {
                resolver.aliases.insert(binding.clone(), prefix.clone());
            } else {
                if let Some(local) = local_import_identity(&prefix, module) {
                    resolver.local_aliases.insert(binding.clone(), local);
                }
                if protected_root(&binding) {
                    resolver.shadowed_roots.insert(binding.clone());
                }
            }
            if matches!(
                binding.as_str(),
                "tokio" | "rstest" | "thiserror" | "tracing"
            ) {
                resolver.shadowed_test_macros.insert(binding);
            }
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use(item, prefix.clone(), absolute, module, resolver);
            }
        }
        _ => {}
    }
}

fn protected_root(binding: &str) -> bool {
    matches!(binding, "bootstrap" | "generated" | "httpserve" | "vocab")
}

fn local_import_identity(segments: &[String], module: &[String]) -> Option<Vec<String>> {
    match segments.first().map(String::as_str) {
        Some("crate") => Some(segments[1..].to_vec()),
        Some("self") => Some(
            module
                .iter()
                .cloned()
                .chain(segments[1..].iter().cloned())
                .collect(),
        ),
        Some("super") => {
            let mut parent = module.to_vec();
            parent.pop()?;
            parent.extend_from_slice(&segments[1..]);
            Some(parent)
        }
        _ => None,
    }
}

fn import_is_canonical(segments: &[String], absolute: bool, _resolver: &Resolver) -> bool {
    let Some(root) = segments.first() else {
        return false;
    };
    protected_root(root) && absolute
}

fn resolver_for<'a>(
    resolvers: &'a BTreeMap<String, Resolver>,
    module: &[String],
) -> Option<&'a Resolver> {
    resolvers.get(&module_key(module))
}

fn canonical_segments(path: &syn::Path, resolver: &Resolver) -> Option<Vec<String>> {
    if resolver.opaque_empty_item_macro {
        return None;
    }
    let raw: Vec<String> = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let first = raw.first()?;
    if resolver.shadowed_roots.contains(first) {
        return None;
    }
    if path.leading_colon.is_some() && protected_root(first) {
        return Some(raw);
    }
    if resolver.local_aliases.contains_key(first) {
        return None;
    }
    if let Some(imported) = resolver.aliases.get(first) {
        return Some(
            imported
                .iter()
                .cloned()
                .chain(raw.into_iter().skip(1))
                .collect(),
        );
    }
    if protected_root(first) && path.leading_colon.is_some() {
        Some(raw)
    } else {
        None
    }
}

struct HandlerCollector<'a> {
    module: Vec<String>,
    resolvers: &'a BTreeMap<String, Resolver>,
    handlers: &'a mut BTreeMap<String, BTreeSet<String>>,
    reachability: Reachability,
    attribute_safe: bool,
    item_scope: Vec<String>,
}

impl<'ast> Visit<'ast> for HandlerCollector<'_> {
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        self.reachability = self.reachability.with_attrs(&node.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&node.attrs);
        if let Some(segment) = type_last_segment(&node.self_ty) {
            self.item_scope.push(segment);
        }
        visit::visit_item_impl(self, node);
        if type_last_segment(&node.self_ty).is_some() {
            self.item_scope.pop();
        }
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        self.reachability = self.reachability.with_attrs(&node.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&node.attrs);
        self.item_scope.push(node.ident.to_string());
        visit::visit_item_trait(self, node);
        self.item_scope.pop();
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.collect_method_signature(&node.attrs, &node.sig);
    }
    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.collect_method_signature(&node.attrs, &node.sig);
    }
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let Some((_, items)) = &node.content else {
            return;
        };
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        self.reachability = self.reachability.with_attrs(&node.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&node.attrs);
        self.module.push(node.ident.to_string());
        for item in items {
            self.visit_item(item);
        }
        self.module.pop();
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let function_reachability = self.reachability.with_attrs(&node.attrs);
        if let Some(resolver) = resolver_for(self.resolvers, &self.module)
            && self.attribute_safe
            && attrs_safe_for_evidence(&node.attrs)
            && function_reachability.prod
            && !is_test_with_resolver(&node.attrs, resolver)
        {
            let keys = marker_keys_in_signature(&node.sig, resolver);
            if !keys.is_empty() {
                let identity = function_identity(&self.module, &node.sig.ident.to_string());
                self.handlers.entry(identity).or_default().extend(keys);
            }
        }
    }
}

impl HandlerCollector<'_> {
    fn collect_method_signature(&mut self, attrs: &[Attribute], sig: &syn::Signature) {
        let reachability = self.reachability.with_attrs(attrs);
        let Some(resolver) = resolver_for(self.resolvers, &self.module) else {
            return;
        };
        if !self.attribute_safe
            || !attrs_safe_for_evidence(attrs)
            || !reachability.prod
            || reachability.unknown
            || is_test_with_resolver(attrs, resolver)
        {
            return;
        }
        let keys = marker_keys_in_signature(sig, resolver);
        if !keys.is_empty() {
            let mut identity = self.module.clone();
            identity.extend(self.item_scope.iter().cloned());
            identity.push(sig.ident.to_string());
            self.handlers
                .entry(module_key(&identity))
                .or_default()
                .extend(keys);
        }
    }
}

fn type_last_segment(ty: &Type) -> Option<String> {
    let Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

struct SourceScanner<'a> {
    owner: &'a str,
    source: &'a str,
    module: Vec<String>,
    resolvers: &'a BTreeMap<String, Resolver>,
    resolver_stack: Vec<Resolver>,
    handlers: &'a BTreeMap<String, BTreeSet<String>>,
    evidence: &'a mut OwnerEvidence,
    reachability: Reachability,
    in_test_function: bool,
    marker_ordinal: usize,
    attribute_safe: bool,
    test_macro: Option<&'static str>,
    canonical_domain_impl: bool,
    domain_init_router: Option<String>,
    domain_init_body_pending: bool,
}

impl<'ast> Visit<'ast> for SourceScanner<'_> {
    fn visit_item(&mut self, node: &'ast Item) {
        if let Some(resolver) = self.resolver_stack.last() {
            for attr in item_attributes(node) {
                let mut trusted = BTreeSet::new();
                if extend_trusted_attribute(attr, resolver, &mut trusted).is_none() {
                    self.evidence.opaque_triggers.insert(OpaqueTrigger {
                        subject: format!("{}:{}", self.source, attr.span().start().line),
                        attribute: unsupported_attribute_identity(attr, resolver),
                    });
                }
            }
        }
        visit::visit_item(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        let old_domain_impl = self.canonical_domain_impl;
        let old_domain_router = self.domain_init_router.take();
        let old_domain_body_pending = self.domain_init_body_pending;
        self.reachability = self.reachability.with_attrs(&node.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&node.attrs);
        self.canonical_domain_impl = self
            .resolver_stack
            .last()
            .is_some_and(|resolver| is_canonical_domain_impl(node, resolver));
        visit::visit_item_impl(self, node);
        self.canonical_domain_impl = old_domain_impl;
        self.domain_init_router = old_domain_router;
        self.domain_init_body_pending = old_domain_body_pending;
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        let old = self.enter_attrs(&node.attrs);
        visit::visit_item_trait(self, node);
        self.restore_attrs(old);
    }
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let old = self.enter_attrs(&node.attrs);
        let old_domain_router = self.domain_init_router.take();
        let old_domain_body_pending = self.domain_init_body_pending;
        self.domain_init_router = self.canonical_domain_impl.then_some(()).and_then(|()| {
            self.resolver_stack
                .last()
                .and_then(|resolver| canonical_domain_init_router(&node.sig, resolver))
        });
        self.domain_init_body_pending = self.domain_init_router.is_some();
        visit::visit_impl_item_fn(self, node);
        self.domain_init_router = old_domain_router;
        self.domain_init_body_pending = old_domain_body_pending;
        self.restore_attrs(old);
    }
    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        let old = self.enter_attrs(&node.attrs);
        visit::visit_trait_item_fn(self, node);
        self.restore_attrs(old);
    }
    fn visit_impl_item_const(&mut self, node: &'ast syn::ImplItemConst) {
        let old = self.enter_attrs(&node.attrs);
        visit::visit_impl_item_const(self, node);
        self.restore_attrs(old);
    }
    fn visit_trait_item_const(&mut self, node: &'ast syn::TraitItemConst) {
        let old = self.enter_attrs(&node.attrs);
        visit::visit_trait_item_const(self, node);
        self.restore_attrs(old);
    }
    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        let old = self.enter_attrs(&node.attrs);
        visit::visit_item_static(self, node);
        self.restore_attrs(old);
    }
    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        let old = self.enter_attrs(&node.attrs);
        visit::visit_arm(self, node);
        self.restore_attrs(old);
    }
    // AST audit: FieldValue is the remaining non-Expr runtime-expression carrier with attrs;
    // Variant discriminants are const-only, while all other executable carriers are scoped above.
    fn visit_field_value(&mut self, node: &'ast syn::FieldValue) {
        let old = self.enter_attrs(&node.attrs);
        visit::visit_field_value(self, node);
        self.restore_attrs(old);
    }
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let Some((_, items)) = &node.content else {
            return;
        };
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        self.reachability = self.reachability.with_attrs(&node.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&node.attrs);
        self.module.push(node.ident.to_string());
        let Some(resolver) = resolver_for(self.resolvers, &self.module).cloned() else {
            self.module.pop();
            self.reachability = old_reachability;
            self.attribute_safe = old_attribute_safe;
            return;
        };
        self.resolver_stack.push(resolver);
        for item in items {
            self.visit_item(item);
        }
        self.resolver_stack.pop();
        self.module.pop();
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let old_reachability = self.reachability;
        let old_test_function = self.in_test_function;
        let old_attribute_safe = self.attribute_safe;
        let old_test_macro = self.test_macro;
        let old_domain_router = self.domain_init_router.take();
        let old_domain_body_pending = self.domain_init_body_pending;
        self.domain_init_body_pending = false;
        self.reachability = self.reachability.with_attrs(&node.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&node.attrs);
        let resolver = self.resolver_stack.last();
        self.in_test_function = old_test_function
            || (resolver.is_some_and(|resolver| is_test_with_resolver(&node.attrs, resolver))
                && self.reachability.test
                && !self.reachability.unknown);
        self.test_macro = resolver
            .and_then(|resolver| safe_test_macro_name(&node.attrs, resolver))
            .or(old_test_macro);
        visit::visit_item_fn(self, node);
        self.in_test_function = old_test_function;
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
        self.test_macro = old_test_macro;
        self.domain_init_router = old_domain_router;
        self.domain_init_body_pending = old_domain_body_pending;
    }
    fn visit_block(&mut self, node: &'ast syn::Block) {
        let Some(parent) = self.resolver_stack.last().cloned() else {
            return;
        };
        let items: Vec<Item> = node
            .stmts
            .iter()
            .filter_map(|statement| match statement {
                syn::Stmt::Item(item) => Some(item.clone()),
                _ => None,
            })
            .collect();
        let mut resolver = resolver_with_items(parent, &items, &self.module);
        if node
            .stmts
            .iter()
            .any(|statement| matches!(statement, syn::Stmt::Macro(_)))
        {
            resolver.opaque_empty_item_macro = true;
        }
        if self.domain_init_body_pending
            && let Some(registry) = self.domain_init_router.as_deref()
        {
            self.domain_init_body_pending = false;
            let mounts = direct_domain_init_route_mounts(
                node,
                registry,
                &resolver,
                &self.module,
                self.handlers,
                self.reachability,
                self.attribute_safe,
            );
            if !mounts.is_empty() {
                self.evidence.routes.extend(mounts.keys().cloned());
                for (key, states) in mounts {
                    let destination = self.evidence.canonical_mounts.entry(key).or_default();
                    destination.extend(states.into_iter().map(|state| CanonicalRouteMount {
                        source: self.source.to_string(),
                        state,
                    }));
                }
                self.evidence
                    .production_macros
                    .extend(resolver.trusted_macros.iter().cloned());
            }
        }
        self.resolver_stack.push(resolver);
        visit::visit_block(self, node);
        self.resolver_stack.pop();
    }
    fn visit_item_const(&mut self, item: &'ast ItemConst) {
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        self.reachability = self.reachability.with_attrs(&item.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&item.attrs);
        if self.attribute_safe
            && self.in_test_function
            && self.reachability.test
            && !self.reachability.unknown
            && let Some(resolver) = self.resolver_stack.last()
            && let Some(type_key) = strict_test_marker_key(item, resolver)
        {
            self.evidence.markers.push(MarkerOccurrence {
                key: type_key,
                owner: self.owner.to_string(),
                path: self.source.to_string(),
                ordinal: self.marker_ordinal,
            });
            if let Some(test_macro) = self.test_macro {
                self.evidence.test_macros.insert(test_macro.to_string());
            }
            self.evidence
                .test_macros
                .extend(resolver.trusted_macros.iter().cloned());
            self.marker_ordinal += 1;
        }
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
    fn visit_local(&mut self, node: &'ast syn::Local) {
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        self.reachability = self.reachability.with_attrs(&node.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&node.attrs);
        visit::visit_local(self, node);
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
    fn visit_expr(&mut self, node: &'ast Expr) {
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        let attrs = expression_attributes(node);
        self.reachability = self.reachability.with_attrs(attrs);
        self.attribute_safe &= attrs_safe_for_evidence(attrs);
        visit::visit_expr(self, node);
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
}

fn is_canonical_domain_impl(node: &syn::ItemImpl, resolver: &Resolver) -> bool {
    node.trait_.as_ref().is_some_and(|(_, path, _)| {
        path.leading_colon.is_some()
            && matches!(canonical_segments(path, resolver).as_deref(), Some([root, item]) if root == "bootstrap" && item == "Domain")
    })
}

fn canonical_domain_init_router(signature: &syn::Signature, resolver: &Resolver) -> Option<String> {
    if signature.ident != "init" || signature.inputs.len() != 2 {
        return None;
    }
    let mut inputs = signature.inputs.iter();
    let syn::FnArg::Receiver(receiver) = inputs.next()? else {
        return None;
    };
    if receiver.reference.is_none() || receiver.mutability.is_some() {
        return None;
    }
    let syn::FnArg::Typed(registry) = inputs.next()? else {
        return None;
    };
    let syn::Pat::Ident(binding) = registry.pat.as_ref() else {
        return None;
    };
    let Type::Reference(reference) = registry.ty.as_ref() else {
        return None;
    };
    let Type::Path(path) = reference.elem.as_ref() else {
        return None;
    };
    (binding.subpat.is_none()
        && reference.mutability.is_some()
        && path.qself.is_none()
        && path.path.leading_colon.is_some()
        && matches!(canonical_segments(&path.path, resolver).as_deref(), Some([root, item]) if root == "bootstrap" && item == "Registry"))
    .then(|| binding.ident.to_string())
}

fn direct_domain_init_route_mounts(
    block: &syn::Block,
    registry: &str,
    resolver: &Resolver,
    module: &[String],
    handlers: &BTreeMap<String, BTreeSet<String>>,
    reachability: Reachability,
    attribute_safe: bool,
) -> BTreeMap<String, BTreeSet<CanonicalMountedState>> {
    let mut routes = BTreeMap::<String, BTreeSet<CanonicalMountedState>>::new();
    for statement in &block.stmts {
        let Stmt::Expr(expr, _) = statement else {
            continue;
        };
        let Some((call, call_reachability, call_attribute_safe)) =
            direct_method_call(expr, reachability, attribute_safe)
        else {
            continue;
        };
        if call.method != "route_group" || simple_ident(&call.receiver).as_deref() != Some(registry)
        {
            continue;
        }
        let Some(Expr::Closure(register)) = call.args.last().map(peel_expr) else {
            continue;
        };
        let Some(router) = (register.inputs.len() == 1)
            .then(|| register.inputs.first().and_then(simple_pattern_ident))
            .flatten()
        else {
            continue;
        };
        let Expr::Block(body) = peel_expr(&register.body) else {
            continue;
        };
        let items: Vec<Item> = body
            .block
            .stmts
            .iter()
            .filter_map(|statement| match statement {
                Stmt::Item(item) => Some(item.clone()),
                _ => None,
            })
            .collect();
        let mut closure_resolver = resolver_with_items(resolver.clone(), &items, module);
        if body
            .block
            .stmts
            .iter()
            .any(|statement| matches!(statement, Stmt::Macro(_)))
        {
            closure_resolver.opaque_empty_item_macro = true;
        }
        for (key, states) in mounted_route_states(
            &body.block,
            &router,
            &closure_resolver,
            module,
            handlers,
            call_reachability.with_attrs(&register.attrs),
            call_attribute_safe && attrs_safe_for_evidence(&register.attrs),
        ) {
            routes.entry(key).or_default().extend(states);
        }
    }
    routes
}

fn direct_method_call(
    expr: &Expr,
    reachability: Reachability,
    attribute_safe: bool,
) -> Option<(&ExprMethodCall, Reachability, bool)> {
    let attrs = expression_attributes(expr);
    let reachability = reachability.with_attrs(attrs);
    let attribute_safe = attribute_safe && attrs_safe_for_evidence(attrs);
    if !attribute_safe || !reachability.prod || reachability.unknown {
        return None;
    }
    match expr {
        Expr::Try(expr) => direct_method_call(&expr.expr, reachability, attribute_safe),
        Expr::Paren(expr) => direct_method_call(&expr.expr, reachability, attribute_safe),
        Expr::Group(expr) => direct_method_call(&expr.expr, reachability, attribute_safe),
        Expr::MethodCall(call) => Some((call, reachability, attribute_safe)),
        _ => None,
    }
}

fn mounted_route_states(
    block: &syn::Block,
    router: &str,
    resolver: &Resolver,
    module: &[String],
    handlers: &BTreeMap<String, BTreeSet<String>>,
    reachability: Reachability,
    attribute_safe: bool,
) -> BTreeMap<String, BTreeSet<CanonicalMountedState>> {
    let mut binding_counts = BTreeMap::<String, usize>::new();
    let mut endpoint_bindings = BTreeMap::<String, (String, CanonicalMountedState)>::new();
    for statement in &block.stmts {
        let Stmt::Local(local) = statement else {
            continue;
        };
        let syn::Pat::Ident(pattern) = &local.pat else {
            continue;
        };
        let name = pattern.ident.to_string();
        *binding_counts.entry(name.clone()).or_default() += 1;
        if pattern.subpat.is_none()
            && attribute_safe
            && attrs_safe_for_evidence(&local.attrs)
            && reachability.with_attrs(&local.attrs).prod
            && !reachability.with_attrs(&local.attrs).unknown
            && let Some(init) = &local.init
            && let Some(route) = endpoint_route(&init.expr, resolver, module, handlers)
        {
            endpoint_bindings.insert(name, (route, mounted_state(&init.expr)));
        }
    }

    let mut collector = SameScopeMountCollector {
        router,
        resolver,
        module,
        handlers,
        inline_routes: BTreeMap::new(),
        mounted_bindings: BTreeMap::new(),
        binding_uses: BTreeMap::new(),
        reachability,
        attribute_safe,
    };
    for statement in &block.stmts {
        match statement {
            Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    let old = (collector.reachability, collector.attribute_safe);
                    collector.reachability = collector.reachability.with_attrs(&local.attrs);
                    collector.attribute_safe &= attrs_safe_for_evidence(&local.attrs);
                    collector.visit_expr(&init.expr);
                    if let Some((_, diverge)) = &init.diverge {
                        collector.visit_expr(diverge);
                    }
                    (collector.reachability, collector.attribute_safe) = old;
                }
            }
            Stmt::Expr(expr, _) => collector.visit_expr(expr),
            Stmt::Item(_) | Stmt::Macro(_) => {}
        }
    }

    let mut routes = collector.inline_routes;
    for (binding, (route, state)) in endpoint_bindings {
        if binding_counts.get(&binding) == Some(&1)
            && collector.binding_uses.get(&binding) == Some(&1)
            && collector.mounted_bindings.get(&binding) == Some(&1)
        {
            routes.entry(route).or_default().insert(state);
        }
    }
    routes
}

struct SameScopeMountCollector<'a> {
    router: &'a str,
    resolver: &'a Resolver,
    module: &'a [String],
    handlers: &'a BTreeMap<String, BTreeSet<String>>,
    inline_routes: BTreeMap<String, BTreeSet<CanonicalMountedState>>,
    mounted_bindings: BTreeMap<String, usize>,
    binding_uses: BTreeMap<String, usize>,
    reachability: Reachability,
    attribute_safe: bool,
}

impl<'ast> Visit<'ast> for SameScopeMountCollector<'_> {
    fn visit_expr(&mut self, node: &'ast Expr) {
        let old = (self.reachability, self.attribute_safe);
        let attrs = expression_attributes(node);
        self.reachability = self.reachability.with_attrs(attrs);
        self.attribute_safe &= attrs_safe_for_evidence(attrs);
        visit::visit_expr(self, node);
        (self.reachability, self.attribute_safe) = old;
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if node.qself.is_none()
            && node.path.leading_colon.is_none()
            && node.path.segments.len() == 1
        {
            *self
                .binding_uses
                .entry(node.path.segments[0].ident.to_string())
                .or_default() += 1;
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if self.attribute_safe
            && self.reachability.prod
            && !self.reachability.unknown
            && node.method == "mount"
            && simple_ident(&node.receiver).as_deref() == Some(self.router)
            && node.args.len() == 1
            && let Some(argument) = node.args.first()
        {
            if let Some(route) = endpoint_route(argument, self.resolver, self.module, self.handlers)
            {
                self.inline_routes
                    .entry(route)
                    .or_default()
                    .insert(mounted_state(argument));
            } else if let Some(binding) = simple_ident(argument) {
                *self.mounted_bindings.entry(binding).or_default() += 1;
            }
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_block(&mut self, _node: &'ast syn::Block) {}

    fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}
}

fn mounted_state(expr: &Expr) -> CanonicalMountedState {
    use quote::ToTokens as _;
    match peel_expr(expr) {
        Expr::Try(value) => mounted_state(&value.expr),
        Expr::MethodCall(call) if call.method == "with_state" && call.args.len() == 1 => {
            CanonicalMountedState::Ordinary
        }
        Expr::MethodCall(call)
            if call.method == "with_classified_state" && call.args.len() == 1 =>
        {
            call.args
                .first()
                .map_or(CanonicalMountedState::Opaque, |state| {
                    CanonicalMountedState::Classified(state.to_token_stream().to_string())
                })
        }
        Expr::Call(_) => CanonicalMountedState::Stateless,
        _ => CanonicalMountedState::Opaque,
    }
}

fn simple_pattern_ident(pattern: &syn::Pat) -> Option<String> {
    let syn::Pat::Ident(pattern) = pattern else {
        return None;
    };
    pattern.subpat.is_none().then(|| pattern.ident.to_string())
}

fn simple_ident(expr: &Expr) -> Option<String> {
    let Expr::Path(path) = peel_endpoint_expr(expr) else {
        return None;
    };
    (path.qself.is_none() && path.path.leading_colon.is_none() && path.path.segments.len() == 1)
        .then(|| path.path.segments[0].ident.to_string())
}

fn endpoint_route(
    expr: &Expr,
    resolver: &Resolver,
    module: &[String],
    handlers: &BTreeMap<String, BTreeSet<String>>,
) -> Option<String> {
    let Expr::Call(call) = peel_endpoint_expr(expr) else {
        return None;
    };
    if !constructor_is_canonical(call, resolver) {
        return None;
    }
    let route = call
        .args
        .first()
        .and_then(|expr| route_key(expr, resolver))?;
    let handler = call.args.iter().nth(1)?;
    if let Some(identity) = handler_identity(handler, module, resolver) {
        handlers
            .get(&identity)
            .is_some_and(|keys| keys.contains(&route))
            .then_some(route)
    } else {
        expr_contains_marker(handler, &route, resolver).then_some(route)
    }
}

fn peel_endpoint_expr(expr: &Expr) -> &Expr {
    match peel_expr(expr) {
        Expr::Try(expr) => peel_endpoint_expr(&expr.expr),
        Expr::MethodCall(call)
            if matches!(
                call.method.to_string().as_str(),
                "with_state" | "with_classified_state"
            ) && call.args.len() == 1 =>
        {
            peel_endpoint_expr(&call.receiver)
        }
        other => other,
    }
}

fn unsupported_attribute_identity(attr: &Attribute, resolver: &Resolver) -> String {
    if attr.path().is_ident("derive")
        && let Ok(derives) = attr.parse_args_with(
            syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
        )
    {
        for derive in derives {
            let segments = raw_segments(&derive);
            let supported = matches!(segments.as_slice(), [single] if builtin_derive(single) && !resolver.shadowed_builtin_macros.contains(single))
                || matches!(segments.as_slice(), [root, leaf] if root == "thiserror" && leaf == "Error");
            if !supported {
                return segments.join("::");
            }
        }
    }
    raw_segments(attr.path()).join("::")
}

impl SourceScanner<'_> {
    fn enter_attrs(&mut self, attrs: &[Attribute]) -> (Reachability, bool) {
        let old = (self.reachability, self.attribute_safe);
        self.reachability = self.reachability.with_attrs(attrs);
        self.attribute_safe &= attrs_safe_for_evidence(attrs);
        old
    }

    fn restore_attrs(&mut self, old: (Reachability, bool)) {
        (self.reachability, self.attribute_safe) = old;
    }
}

fn expression_attributes(expr: &Expr) -> &[Attribute] {
    match expr {
        Expr::Array(expr) => &expr.attrs,
        Expr::Assign(expr) => &expr.attrs,
        Expr::Async(expr) => &expr.attrs,
        Expr::Await(expr) => &expr.attrs,
        Expr::Binary(expr) => &expr.attrs,
        Expr::Block(expr) => &expr.attrs,
        Expr::Break(expr) => &expr.attrs,
        Expr::Call(expr) => &expr.attrs,
        Expr::Cast(expr) => &expr.attrs,
        Expr::Closure(expr) => &expr.attrs,
        Expr::Const(expr) => &expr.attrs,
        Expr::Continue(expr) => &expr.attrs,
        Expr::Field(expr) => &expr.attrs,
        Expr::ForLoop(expr) => &expr.attrs,
        Expr::Group(expr) => &expr.attrs,
        Expr::If(expr) => &expr.attrs,
        Expr::Index(expr) => &expr.attrs,
        Expr::Infer(expr) => &expr.attrs,
        Expr::Let(expr) => &expr.attrs,
        Expr::Lit(expr) => &expr.attrs,
        Expr::Loop(expr) => &expr.attrs,
        Expr::Macro(expr) => &expr.attrs,
        Expr::Match(expr) => &expr.attrs,
        Expr::MethodCall(expr) => &expr.attrs,
        Expr::Paren(expr) => &expr.attrs,
        Expr::Path(expr) => &expr.attrs,
        Expr::Range(expr) => &expr.attrs,
        Expr::RawAddr(expr) => &expr.attrs,
        Expr::Reference(expr) => &expr.attrs,
        Expr::Repeat(expr) => &expr.attrs,
        Expr::Return(expr) => &expr.attrs,
        Expr::Struct(expr) => &expr.attrs,
        Expr::Try(expr) => &expr.attrs,
        Expr::TryBlock(expr) => &expr.attrs,
        Expr::Tuple(expr) => &expr.attrs,
        Expr::Unary(expr) => &expr.attrs,
        Expr::Unsafe(expr) => &expr.attrs,
        Expr::While(expr) => &expr.attrs,
        Expr::Yield(expr) => &expr.attrs,
        Expr::Verbatim(_) => &[],
        _ => &[],
    }
}

fn safe_test_macro_name(attrs: &[Attribute], resolver: &Resolver) -> Option<&'static str> {
    attrs
        .iter()
        .find_map(|attr| match raw_segments(attr.path()).as_slice() {
            [root, leaf]
                if root == "tokio"
                    && leaf == "test"
                    && !resolver.shadowed_test_macros.contains(root) =>
            {
                Some("tokio")
            }
            [root, leaf]
                if root == "rstest"
                    && leaf == "rstest"
                    && !resolver.shadowed_test_macros.contains(root) =>
            {
                Some("rstest")
            }
            _ => None,
        })
}

fn is_test_with_resolver(attrs: &[Attribute], resolver: &Resolver) -> bool {
    (attrs.iter().any(|attr| attr.path().is_ident("test"))
        && !resolver.shadowed_builtin_macros.contains("test"))
        || safe_test_macro_name(attrs, resolver).is_some()
}

fn attrs_safe_for_evidence(attrs: &[Attribute]) -> bool {
    trusted_scope_attributes(attrs).is_some()
}

fn strict_test_marker_key(item: &ItemConst, resolver: &Resolver) -> Option<String> {
    if item.ident != "_" {
        return None;
    }
    let Type::Path(binding) = item.ty.as_ref() else {
        return None;
    };
    if binding.qself.is_some()
        || binding.path.leading_colon.is_none()
        || raw_segments(&binding.path).as_slice() != ["vocab", "HttpRouteBinding"]
        || canonical_segments(&binding.path, resolver).as_deref()
            != Some(["vocab".to_string(), "HttpRouteBinding".to_string()].as_slice())
    {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &binding.path.segments.last()?.arguments else {
        return None;
    };
    if arguments.args.len() != 2 {
        return None;
    }
    let GenericArgument::Type(Type::Path(marker)) = arguments.args.first()? else {
        return None;
    };
    if marker.qself.is_some() || marker.path.leading_colon.is_none() {
        return None;
    }
    let marker_segments = raw_segments(&marker.path);
    if canonical_segments(&marker.path, resolver).as_deref() != Some(marker_segments.as_slice()) {
        return None;
    }
    let GenericArgument::Type(Type::Path(consistency)) = arguments.args.iter().nth(1)? else {
        return None;
    };
    if consistency.qself.is_some()
        || consistency.path.leading_colon.is_none()
        || canonical_segments(&consistency.path, resolver).as_deref()
            != Some(
                [
                    "vocab".to_string(),
                    "http".to_string(),
                    "LocalTx".to_string(),
                ]
                .as_slice(),
            )
    {
        return None;
    }
    let key = key_from_segments(&marker_segments, "RouteMarker")?;
    let Expr::Path(route) = item.expr.as_ref() else {
        return None;
    };
    if route.qself.is_some() || route.path.leading_colon.is_none() {
        return None;
    }
    let route_segments = raw_segments(&route.path);
    if canonical_segments(&route.path, resolver).as_deref() != Some(route_segments.as_slice()) {
        return None;
    }
    (key_from_segments(&route_segments, "ROUTE").as_deref() == Some(&key)).then_some(key)
}

fn raw_segments(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect()
}

fn marker_keys_in_signature(sig: &syn::Signature, resolver: &Resolver) -> BTreeSet<String> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(arg) => marker_key_from_type(&arg.ty, resolver),
            _ => None,
        })
        .collect()
}

fn marker_key_from_type(ty: &Type, resolver: &Resolver) -> Option<String> {
    let Type::Path(ty) = ty else {
        return None;
    };
    let canonical = canonical_segments(&ty.path, resolver)?;
    if canonical.as_slice() == ["httpserve", "ContractMarker"] {
        let contract = ty.path.segments.last()?;
        let PathArguments::AngleBracketed(args) = &contract.arguments else {
            return None;
        };
        return args.args.iter().find_map(|arg| match arg {
            GenericArgument::Type(Type::Path(path)) => {
                generated_key_from_path(&path.path, "RouteMarker", resolver)
            }
            _ => None,
        });
    }
    generated_key_from_path(&ty.path, "RouteMarker", resolver)
}

fn route_key(expr: &Expr, resolver: &Resolver) -> Option<String> {
    let Expr::Path(path) = peel_expr(expr) else {
        return None;
    };
    generated_key_from_path(&path.path, "ROUTE", resolver)
}

fn handler_identity(expr: &Expr, module: &[String], resolver: &Resolver) -> Option<String> {
    let Expr::Path(path) = peel_expr(expr) else {
        return None;
    };
    let segments: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    if let Some(first) = segments.first()
        && let Some(imported) = resolver.local_aliases.get(first)
    {
        return Some(module_key(
            &imported
                .iter()
                .cloned()
                .chain(segments.into_iter().skip(1))
                .collect::<Vec<_>>(),
        ));
    }
    let (mut base, rest) = match segments.first().map(String::as_str) {
        Some("crate") => (Vec::new(), &segments[1..]),
        Some("self") => (module.to_vec(), &segments[1..]),
        Some("super") => {
            let mut parent = module.to_vec();
            parent.pop()?;
            (parent, &segments[1..])
        }
        Some(_) => (module.to_vec(), segments.as_slice()),
        None => return None,
    };
    base.extend_from_slice(rest);
    Some(module_key(&base))
}

fn expr_contains_marker(expr: &Expr, key: &str, resolver: &Resolver) -> bool {
    struct MarkerVisitor<'a> {
        key: &'a str,
        resolver: &'a Resolver,
        found: bool,
    }
    impl<'ast> Visit<'ast> for MarkerVisitor<'_> {
        fn visit_type(&mut self, ty: &'ast Type) {
            self.found |= marker_key_from_type(ty, self.resolver).as_deref() == Some(self.key);
            visit::visit_type(self, ty);
        }
    }
    let mut visitor = MarkerVisitor {
        key,
        resolver,
        found: false,
    };
    visitor.visit_expr(expr);
    visitor.found
}

fn generated_key_from_path(
    path: &syn::Path,
    terminal: &str,
    resolver: &Resolver,
) -> Option<String> {
    let segments = canonical_segments(path, resolver)?;
    if segments.first().map(String::as_str) != Some("generated") {
        return None;
    }
    key_from_segments(&segments, terminal)
}

fn key_from_segments(segs: &[String], terminal: &str) -> Option<String> {
    if segs.last()? != terminal {
        return None;
    }
    if segs.first().map(String::as_str) != Some("generated")
        || segs.get(1).map(String::as_str) != Some("http")
    {
        return None;
    }
    let http = 1;
    let key = &segs[http + 1..segs.len() - 1];
    if key.is_empty() {
        None
    } else {
        Some(key.join("::"))
    }
}

fn constructor_is_canonical(call: &ExprCall, resolver: &Resolver) -> bool {
    let Expr::Path(path) = peel_expr(&call.func) else {
        return false;
    };
    let Some(segments) = canonical_segments(&path.path, resolver) else {
        return false;
    };
    matches!(
        segments.as_slice(),
        [httpserve, endpoint, new]
            if httpserve == "httpserve"
                && matches!(endpoint.as_str(), "GeneratedEndpoint" | "GeneratedPrimaryEndpoint")
                && new == "new"
    )
}

fn function_identity(module: &[String], name: &str) -> String {
    let mut identity = module.to_vec();
    identity.push(name.to_string());
    module_key(&identity)
}

fn call_path_ends(call: &ExprCall, ident: &str) -> bool {
    matches!(peel_expr(&call.func), Expr::Path(path) if path.path.segments.last().is_some_and(|s| s.ident == ident))
}
fn cfg_expression(attr: &Attribute) -> Option<Meta> {
    use syn::parse::Parser as _;
    let Meta::List(list) = &attr.meta else {
        return None;
    };
    syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated
        .parse2(list.tokens.clone())
        .ok()
        .and_then(|nested| (nested.len() == 1).then(|| nested[0].clone()))
}

fn cfg_truth(meta: &Meta, test: bool) -> Truth {
    use syn::parse::Parser as _;
    match meta {
        Meta::Path(path) if path.is_ident("test") => {
            if test {
                Truth::True
            } else {
                Truth::False
            }
        }
        Meta::Path(_) | Meta::NameValue(_) => Truth::Unknown,
        syn::Meta::List(list) => {
            let Some(nested) =
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                    .parse2(list.tokens.clone())
                    .ok()
            else {
                return Truth::Unknown;
            };
            if list.path.is_ident("not") && nested.len() == 1 {
                truth_not(cfg_truth(&nested[0], test))
            } else if list.path.is_ident("all") {
                nested.iter().fold(Truth::True, |value, item| {
                    truth_and(value, cfg_truth(item, test))
                })
            } else if list.path.is_ident("any") {
                nested.iter().fold(Truth::False, |value, item| {
                    truth_or(value, cfg_truth(item, test))
                })
            } else {
                Truth::Unknown
            }
        }
    }
}

fn truth_not(value: Truth) -> Truth {
    match value {
        Truth::True => Truth::False,
        Truth::False => Truth::True,
        Truth::Unknown => Truth::Unknown,
    }
}

fn truth_and(left: Truth, right: Truth) -> Truth {
    match (left, right) {
        (Truth::False, _) | (_, Truth::False) => Truth::False,
        (Truth::True, Truth::True) => Truth::True,
        _ => Truth::Unknown,
    }
}

fn truth_or(left: Truth, right: Truth) -> Truth {
    match (left, right) {
        (Truth::True, _) | (_, Truth::True) => Truth::True,
        (Truth::False, Truth::False) => Truth::False,
        _ => Truth::Unknown,
    }
}

fn parse_file(root: &Path, path: &Path) -> Result<File> {
    parse_file_in(root, root, path)
}

fn parse_file_in(root: &Path, base: &Path, path: &Path) -> Result<File> {
    let relative = relative(root, path)?;
    let text = read_text_contained(root, base, path)?;
    syn::parse_file(&text).with_context(|| format!("parse Rust `{relative}`"))
}

fn read_text_contained(root: &Path, base: &Path, path: &Path) -> Result<String> {
    ensure_contained(root, base, path)?;
    let label = relative(root, path)?;
    std::fs::read_to_string(path).with_context(|| format!("read `{label}`"))
}

fn ensure_contained(root: &Path, base: &Path, path: &Path) -> Result<()> {
    let root = std::fs::canonicalize(root).context("canonicalize workspace root")?;
    let base = std::fs::canonicalize(base).with_context(|| {
        format!(
            "canonicalize `{}`",
            relative(&root, base).unwrap_or_default()
        )
    })?;
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("canonicalize `{}`", path.display()))?;
    if !base.starts_with(&root) || !canonical.starts_with(&base) {
        bail!("path escapes its canonical workspace scope");
    }
    Ok(())
}

fn reject_symlinks(root: &Path, path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let label = relative(root, path)?;
    let metadata = std::fs::symlink_metadata(path).with_context(|| format!("inspect `{label}`"))?;
    if metadata.file_type().is_symlink() {
        bail!("symlink evidence is not allowed at `{label}`");
    }
    ensure_contained(root, root, path)?;
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path).with_context(|| format!("read directory `{label}`"))? {
            reject_symlinks(root, &entry?.path())?;
        }
    }
    Ok(())
}

fn rs_files_contained(root: &Path, dir: &Path) -> Result<Vec<PathBuf>> {
    reject_symlinks(root, dir)?;
    let mut files = Vec::new();
    collect_rs_files(dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_rs_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read `{}`", dir.display()))? {
        let entry = entry?;
        let metadata = entry.file_type()?;
        let path = entry.path();
        if metadata.is_dir() {
            collect_rs_files(&path, files)?;
        } else if metadata.is_file() && path.extension().is_some_and(|extension| extension == "rs")
        {
            files.push(path);
        }
    }
    Ok(())
}

fn relative(root: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| anyhow!("path is outside workspace root"))?;
    Ok(rel
        .to_str()
        .ok_or_else(|| anyhow!("workspace-relative path is not UTF-8"))?
        .replace('\\', "/"))
}

fn sanitized(root: &Path, error: anyhow::Error) -> anyhow::Error {
    let mut message = format!("{error:#}").replace(root.to_string_lossy().as_ref(), ".");
    if let Ok(canonical) = std::fs::canonicalize(root) {
        message = message.replace(canonical.to_string_lossy().as_ref(), ".");
    }
    anyhow!(message)
}

const MAX_CARGO_STDERR_CHARS: usize = 4096;

fn bounded_stderr(stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    let mut chars = stderr.chars();
    let mut bounded: String = chars.by_ref().take(MAX_CARGO_STDERR_CHARS).collect();
    if chars.next().is_some() {
        bounded.push_str("…[truncated]");
    }
    bounded.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/localtx_coverage")
            .join(name)
    }

    #[test]
    fn green_fixture_closes_every_active_localtx_contract() -> anyhow::Result<()> {
        let (summary, findings) = check_root(&fixture("green"))?;
        assert_eq!(summary, "1 active LocalTx HTTP contract(s) covered");
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn green_fixture_is_a_compiling_workspace() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-green-compile")?;
        let output = temp.cargo_check()?;
        assert!(
            output.status.success(),
            "green fixture must compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    #[test]
    fn endpoint_construction_without_mount_is_rejected() -> anyhow::Result<()> {
        for source in [
            r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init() {
    let _ = ::httpserve::GeneratedPrimaryEndpoint::new(
        ::generated::http::demo_v1::write::ROUTE,
        handler,
    );
}
"#,
            r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn dead_helper() {
    let _ = ::httpserve::GeneratedPrimaryEndpoint::new(
        ::generated::http::demo_v1::write::ROUTE,
        handler,
    );
}
fn init(reg: &mut ::httpserve::Registry) {
    reg.route_group(|rb| Ok(rb));
}
"#,
            r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init(reg: &mut ::httpserve::Registry) {
    reg.route_group(|rb| {
        let _ = ::httpserve::GeneratedPrimaryEndpoint::new(
            ::generated::http::demo_v1::write::ROUTE,
            handler,
        );
        Ok(rb)
    });
}
"#,
            r#"struct FakeMount;
fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init(fake: FakeMount) {
    fake.mount(::httpserve::GeneratedPrimaryEndpoint::new(
        ::generated::http::demo_v1::write::ROUTE,
        handler,
    ));
}
"#,
        ] {
            let temp = FixtureCopy::new("localtx-unmounted-endpoint")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            fs::write(
                &owner,
                format!(
                    "{source}\n#[test] fn covered() {{ const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }}\n"
                ),
            )?;
            let (_, findings) = check_root(&temp.path)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::MissingRouteBinding),
                "unmounted endpoint construction must not close coverage: {findings:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn route_mount_outside_canonical_domain_init_is_rejected() -> anyhow::Result<()> {
        for source in [
            r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn disconnected(reg: &mut ::httpserve::Registry) {
    reg.route_group(|rb| {
        Ok(rb.mount(::httpserve::GeneratedPrimaryEndpoint::new(
            ::generated::http::demo_v1::write::ROUTE,
            handler,
        )))
    });
}
"#,
            r#"struct Demo;
impl ::bootstrap::Domain for Demo {
    fn init(&self, reg: &mut ::httpserve::Registry) {
        reg.route_group(|rb| {
            Ok(rb.mount(::httpserve::GeneratedPrimaryEndpoint::new(
                ::generated::http::demo_v1::write::ROUTE,
                |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| (),
            )))
        });
    }
}
"#,
            r#"struct Demo;
impl ::bootstrap::Domain for Demo {
    fn init(&self, reg: &mut ::bootstrap::Registry) {
        let disconnected = || {
            reg.route_group(|rb| {
                Ok(rb.mount(::httpserve::GeneratedPrimaryEndpoint::new(
                    ::generated::http::demo_v1::write::ROUTE,
                    |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| (),
                )))
            });
        };
    }
}
"#,
            r#"struct Demo;
impl ::bootstrap::Domain for Demo {
    fn init(&self, reg: &mut ::bootstrap::Registry) {
        let disconnected = || reg.route_group(|rb| {
            Ok(rb.mount(::httpserve::GeneratedPrimaryEndpoint::new(
                ::generated::http::demo_v1::write::ROUTE,
                |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| (),
            )))
        });
    }
}
"#,
            r#"struct Demo;
impl ::bootstrap::Domain for Demo {
    fn init(&self, reg: &mut ::bootstrap::Registry) {
        match true {
            true => reg.route_group(|rb| {
                Ok(rb.mount(::httpserve::GeneratedPrimaryEndpoint::new(
                    ::generated::http::demo_v1::write::ROUTE,
                    |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| (),
                )))
            }),
            false => (),
        };
    }
}
"#,
        ] {
            let temp = FixtureCopy::new("localtx-non-domain-route")?;
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    "{source}\n#[test] fn covered() {{ const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }}\n"
                ),
            )?;
            let (_, findings) = check_root(&temp.path)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::MissingRouteBinding),
                "non-Domain or unreachable mount must not close coverage: {findings:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn missing_route_and_duplicate_marker_are_rejected() -> anyhow::Result<()> {
        let missing = FixtureCopy::new("localtx-missing-route")?;
        fs::write(
            missing.path.join("crates/demo/src/lib.rs"),
            "#[test] fn covered() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
        )?;
        let (_, route_findings) = check_root(&missing.path)?;
        assert!(
            route_findings
                .iter()
                .any(|f| f.rule == Rule::MissingRouteBinding)
        );
        let duplicate = FixtureCopy::new("localtx-duplicate-marker")?;
        let owner = duplicate.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "{}\n#[test] fn second() {{ const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }}\n",
                fs::read_to_string(&owner)?
            ),
        )?;
        let (_, marker_findings) = check_root(&duplicate.path)?;
        assert!(
            marker_findings
                .iter()
                .any(|f| f.rule == Rule::DuplicateTestMarker)
        );
        Ok(())
    }

    #[test]
    fn comments_strings_and_non_test_functions_are_not_markers() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-fake-marker")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            fs::read_to_string(&owner)?
                .replace("#[cfg(test)] mod tests {", "mod tests {")
                .replace("#[test] fn covered()", "fn covered()"),
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn generated_evidence_owner_and_parse_fail_closed() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-closure")?;
        let generated = temp.path.join("generated/src/http/demo_v1.rs");
        fs::write(
            &generated,
            fs::read_to_string(&generated)?.replace("Some(super::super::LocalTxSpec {})", "None"),
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::MissingGeneratedEvidence)
        );

        let manifest = temp.path.join("contracts/http/demo/v1/write/contract.toml");
        fs::write(
            &manifest,
            fs::read_to_string(&manifest)?.replace("owner = \"demo\"", "owner = \"../demo\""),
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::InvalidDomainOwner));

        fs::write(&generated, "this is not Rust")?;
        let error = match check_root(&temp.path) {
            Ok(_) => bail!("malformed Rust must fail closed"),
            Err(error) => error,
        };
        assert!(!format!("{error:#}").contains(temp.path.to_string_lossy().as_ref()));
        Ok(())
    }

    #[test]
    fn missing_and_unexpected_generated_entries_are_reported() -> anyhow::Result<()> {
        let missing = FixtureCopy::new("localtx-missing-generated")?;
        let registry = missing.path.join("generated/src/http/mod.rs");
        fs::write(&registry, "pub const LOCAL_TX_SPECS: &[HttpSpec] = &[];\n")?;
        let (_, findings) = check_root(&missing.path)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::MissingGeneratedSpec)
        );

        let unexpected = FixtureCopy::new("localtx-unexpected-generated")?;
        let registry = unexpected.path.join("generated/src/http/mod.rs");
        fs::write(
            &registry,
            "pub const LOCAL_TX_SPECS: &[HttpSpec] = &[demo_v1::write::SPEC, demo_v1::orphan::SPEC];\n",
        )?;
        let module = unexpected.path.join("generated/src/http/demo_v1.rs");
        let source = fs::read_to_string(&module)?;
        fs::write(
            &module,
            format!(
                "{source}\npub mod orphan {{\n    pub const SPEC: super::HttpSpec = super::HttpSpec {{ local_tx: Some(super::LocalTxSpec {{}}) }};\n}}\n"
            ),
        )?;
        let (_, findings) = check_root(&unexpected.path)?;
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::UnexpectedGeneratedSpec
                && finding.detail.contains("demo_v1::orphan")
        }));
        Ok(())
    }

    #[test]
    fn owner_closure_and_non_target_contracts_are_enforced() -> anyhow::Result<()> {
        let missing_owner = FixtureCopy::new("localtx-missing-owner")?;
        let workspace = missing_owner.path.join("Cargo.toml");
        fs::write(
            &workspace,
            fs::read_to_string(&workspace)?.replace("\"crates/demo\", ", ""),
        )?;
        let (_, findings) = check_root(&missing_owner.path)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::MissingOwnerCrate)
        );

        let framework_owner = FixtureCopy::new("localtx-framework-owner")?;
        let manifest = framework_owner
            .path
            .join("contracts/http/demo/v1/write/contract.toml");
        fs::write(
            &manifest,
            fs::read_to_string(&manifest)?.replace("owner = \"demo\"", "owner = \"_framework\""),
        )?;
        let (_, findings) = check_root(&framework_owner.path)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::InvalidDomainOwner)
        );

        let ignored = FixtureCopy::new("localtx-ignore-non-target")?;
        let active = ignored
            .path
            .join("contracts/http/demo/v1/write/contract.toml");
        let draft_dir = ignored.path.join("contracts/http/demo/v1/draft");
        fs::create_dir_all(&draft_dir)?;
        fs::write(
            draft_dir.join("contract.toml"),
            fs::read_to_string(active)?
                .replace("id = \"demo.write\"", "id = \"demo.draft\"")
                .replace("lifecycle = \"active\"", "lifecycle = \"draft\""),
        )?;
        let (summary, findings) = check_root(&ignored.path)?;
        assert_eq!(summary, "1 active LocalTx HTTP contract(s) covered");
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn orphan_marker_and_non_utf8_source_fail_closed() -> anyhow::Result<()> {
        let orphan = FixtureCopy::new("localtx-orphan-marker")?;
        let owner = orphan.path.join("crates/demo/src/lib.rs");
        let source = fs::read_to_string(&owner)?;
        fs::write(
            &owner,
            format!(
                "{source}\n#[cfg(test)] mod orphan_marker {{\n    #[test] fn covered() {{\n        const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::orphan::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::orphan::ROUTE;\n    }}\n}}\n"
            ),
        )?;
        let (_, findings) = check_root(&orphan.path)?;
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::UnexpectedTestMarker && finding.detail.contains("demo_v1::orphan")
        }));

        let non_utf8 = FixtureCopy::new("localtx-non-utf8")?;
        let generated = non_utf8.path.join("generated/src/http/demo_v1.rs");
        fs::write(&generated, [0xff, 0xfe])?;
        let error = match check_root(&non_utf8.path) {
            Ok(_) => bail!("non-UTF-8 Rust must fail closed"),
            Err(error) => error,
        };
        assert!(!format!("{error:#}").contains(non_utf8.path.to_string_lossy().as_ref()));
        Ok(())
    }

    #[test]
    fn actual_workspace_has_non_empty_complete_localtx_closure() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let (summary, findings) = check_root(&root)?;
        assert!(!summary.starts_with("0 active"), "anti-vacuity: {summary}");
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn findings_are_stably_sorted_and_workspace_relative() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-sorted-findings")?;
        fs::write(temp.path.join("crates/demo/src/lib.rs"), "")?;
        let (_, findings) = check_root(&temp.path)?;
        let lines: Vec<_> = findings.iter().map(diagnostic::format_finding).collect();
        let mut sorted = lines.clone();
        sorted.sort();
        assert_eq!(lines, sorted);
        assert!(
            lines
                .iter()
                .all(|line| !line.contains(env!("CARGO_MANIFEST_DIR")))
        );
        Ok(())
    }

    #[test]
    fn owner_must_be_a_real_workspace_member_crate() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-owner-member")?;
        let workspace = temp.path.join("Cargo.toml");
        fs::write(
            &workspace,
            fs::read_to_string(&workspace)?.replace("\"crates/demo\", ", ""),
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::MissingOwnerCrate),
            "directory-shaped decoys must not count as owner crates: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn markers_are_global_and_must_belong_to_the_owner() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-wrong-owner-marker")?;
        let workspace = temp.path.join("Cargo.toml");
        fs::write(
            &workspace,
            fs::read_to_string(&workspace)?
                .replace(", \"generated\"]", ", \"generated\", \"crates/other\"]"),
        )?;
        fs::create_dir_all(temp.path.join("crates/other/src"))?;
        fs::write(
            temp.path.join("crates/other/Cargo.toml"),
            "[package]\nname = \"other\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dev-dependencies]\ngenerated = { path = \"../../generated\" }\nvocab = { path = \"../vocab\" }\n",
        )?;
        fs::write(
            temp.path.join("crates/other/src/lib.rs"),
            "#[test] fn wrong_owner() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(
            findings.iter().any(|finding| {
                matches!(
                    finding.rule,
                    Rule::DuplicateTestMarker | Rule::UnexpectedTestMarker
                ) && finding.subject.contains("crates/other/src/lib.rs")
            }),
            "wrong-owner duplicate must name its source file: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn local_same_named_types_and_generated_module_are_not_canonical_evidence() -> anyhow::Result<()>
    {
        let temp = FixtureCopy::new("localtx-canonical-symbols")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
mod vocab { pub struct HttpRouteBinding<T>(core::marker::PhantomData<T>); }
mod httpserve {
    pub struct ContractMarker<T>(core::marker::PhantomData<T>);
    pub struct GeneratedEndpoint;
    impl GeneratedEndpoint { pub fn new<A, B>(_: A, _: B) {} }
}
mod generated { pub mod http { pub mod demo_v1 { pub mod write {
    pub struct RouteMarker;
    pub const ROUTE: () = ();
} } } }
use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init() { httpserve::GeneratedEndpoint::new(WRITE_ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn registry_duplicate_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-registry-duplicate")?;
        fs::write(
            temp.path.join("generated/src/http/mod.rs"),
            "pub const LOCAL_TX_SPECS: &[HttpSpec] = &[demo_v1::write::SPEC, demo_v1::write::SPEC];\n",
        )?;
        assert!(check_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn external_cfg_test_module_route_is_not_production_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-external-test-module")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            "#[cfg(test)] mod tests;\n",
        )?;
        fs::write(
            temp.path.join("crates/demo/src/tests.rs"),
            r#"
use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn bait() { let _ = httpserve::GeneratedEndpoint::new(WRITE_ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(!findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn cfg_test_only_boolean_semantics_are_fail_closed() {
        let not_test: Attribute = syn::parse_quote!(#[cfg(not(test))]);
        let mixed_any: Attribute = syn::parse_quote!(#[cfg(any(test, feature = "prod"))]);
        let test_all: Attribute = syn::parse_quote!(#[cfg(all(test, feature = "fixture"))]);
        let not_test = Reachability::BOTH.with_attrs(&[not_test]);
        assert!(not_test.prod);
        assert!(!not_test.test);
        let mixed_any = Reachability::BOTH.with_attrs(&[mixed_any]);
        assert!(!mixed_any.prod);
        assert!(mixed_any.test);
        let test_all = Reachability::BOTH.with_attrs(&[test_all]);
        assert!(!test_all.prod);
        assert!(!test_all.test);
    }

    #[test]
    fn same_named_handler_in_another_module_cannot_lend_its_marker() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-handler-identity")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
mod wrong { pub fn handler() {} }
mod right {
    pub fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
}
fn init() { let _ = httpserve::GeneratedEndpoint::new(WRITE_ROUTE, wrong::handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_source_file_is_rejected_fail_closed() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let temp = FixtureCopy::new("localtx-symlink")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        let outside = crate::testutil::unique_tmp("localtx-outside").with_extension("rs");
        fs::write(&outside, fs::read_to_string(&owner)?)?;
        fs::remove_file(&owner)?;
        symlink(&outside, &owner)?;
        let result = check_root(&temp.path);
        let _ = fs::remove_file(outside);
        assert!(result.is_err(), "symlinked evidence must fail closed");
        Ok(())
    }

    #[test]
    fn duplicate_marker_diagnostic_names_marker_file() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-duplicate-diagnostic")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "{}\n#[test] fn second() {{ const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }}\n",
                fs::read_to_string(&owner)?
            ),
        )?;
        let (_, findings) = check_root(&temp.path)?;
        let duplicate = findings
            .iter()
            .find(|finding| finding.rule == Rule::DuplicateTestMarker)
            .ok_or_else(|| anyhow!("duplicate marker finding is missing"))?;
        assert_eq!(duplicate.subject, "crates/demo/src/lib.rs");
        Ok(())
    }

    #[test]
    fn orphan_rust_file_is_not_reachable_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-orphan-rust")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        fs::write(
            temp.path.join("crates/demo/src/orphan.rs"),
            r#"
use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn bait() { let _ = httpserve::GeneratedEndpoint::new(WRITE_ROUTE, handler); }
"#,
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(!findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn path_attribute_propagates_external_test_scope() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-path-test-module")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            "#[cfg(test)]\n#[path = \"bait.rs\"]\nmod tests;\n",
        )?;
        fs::write(
            temp.path.join("crates/demo/src/bait.rs"),
            r#"
use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn bait() { let _ = httpserve::GeneratedEndpoint::new(WRITE_ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(!findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn block_local_canonical_aliases_are_supported() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-block-alias")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
struct Demo;
impl ::bootstrap::Domain for Demo {
    fn init(&self, reg: &mut ::bootstrap::Registry) {
        reg.route_group(|rb| {
            use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
            use ::httpserve::GeneratedPrimaryEndpoint as Endpoint;
            let endpoint = Endpoint::new(WRITE_ROUTE, handler);
            let _ = rb.mount(endpoint);
            Ok(rb)
        });
    }
}
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn renamed_fake_canonical_roots_are_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-renamed-roots")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
mod fake_vocab { pub struct HttpRouteBinding<T>(core::marker::PhantomData<T>); }
mod fake_httpserve {
    pub struct ContractMarker<T>(core::marker::PhantomData<T>);
    pub struct GeneratedEndpoint;
    impl GeneratedEndpoint { pub fn new<A, B>(_: A, _: B) {} }
}
mod fake_generated { pub mod http { pub mod demo_v1 { pub mod write {
    pub struct RouteMarker;
    pub const ROUTE: () = ();
} } } }
use crate::fake_generated as generated;
use crate::fake_httpserve as httpserve;
use crate::fake_vocab as vocab;
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init() { httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn macro_defined_canonical_shadow_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-macro-shadow")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
macro_rules! fake_roots { () => {
    mod vocab { pub struct HttpRouteBinding<T>(core::marker::PhantomData<T>); }
    mod httpserve {
        pub struct ContractMarker<T>(core::marker::PhantomData<T>);
        pub struct GeneratedEndpoint;
        impl GeneratedEndpoint { pub fn new<A, B>(_: A, _: B) {} }
    }
    mod generated { pub mod http { pub mod demo_v1 { pub mod write {
        pub struct RouteMarker;
        pub const ROUTE: () = ();
    } } } }
}; }
fake_roots!();
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init() { httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        assert!(check_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn extern_crate_self_canonical_shadows_are_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-extern-shadow")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
extern crate self as generated;
extern crate self as httpserve;
extern crate self as vocab;
pub struct HttpRouteBinding<T>(core::marker::PhantomData<T>);
pub struct ContractMarker<T>(core::marker::PhantomData<T>);
pub struct GeneratedEndpoint;
impl GeneratedEndpoint { pub fn new<A, B>(_: A, _: B) {} }
pub mod http { pub mod demo_v1 { pub mod write {
    pub struct RouteMarker;
    pub const ROUTE: () = ();
} } }
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init() { httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn block_local_fake_root_shadows_are_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-block-shadow")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
mod fake_vocab { pub struct HttpRouteBinding<T>(core::marker::PhantomData<T>); }
mod fake_httpserve {
    pub struct ContractMarker<T>(core::marker::PhantomData<T>);
    pub struct GeneratedEndpoint;
    impl GeneratedEndpoint { pub fn new<A, B>(_: A, _: B) {} }
}
mod fake_generated { pub mod http { pub mod demo_v1 { pub mod write {
    pub struct RouteMarker;
    pub const ROUTE: () = ();
} } } }
fn handler(_: fake_httpserve::ContractMarker<fake_generated::http::demo_v1::write::RouteMarker>) {}
fn init() {
    use crate::fake_generated as generated;
    use crate::fake_httpserve as httpserve;
    httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler);
}
#[test] fn covered() {
    use crate::fake_generated as generated;
    use crate::fake_vocab as vocab;
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        Ok(())
    }

    #[test]
    fn markers_in_non_domain_workspace_members_are_global() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-adapter-marker")?;
        let workspace = temp.path.join("Cargo.toml");
        fs::write(
            &workspace,
            fs::read_to_string(&workspace)?
                .replace(", \"generated\"]", ", \"generated\", \"adapters/other\"]"),
        )?;
        fs::create_dir_all(temp.path.join("adapters/other/src"))?;
        fs::write(
            temp.path.join("adapters/other/Cargo.toml"),
            "[package]\nname = \"other-adapter\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dev-dependencies]\ngenerated = { path = \"../../generated\" }\nvocab = { path = \"../../crates/vocab\" }\n",
        )?;
        fs::write(
            temp.path.join("adapters/other/src/lib.rs"),
            "#[test] fn wrong_owner() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::DuplicateTestMarker
                    && finding.subject == "adapters/other/src/lib.rs"
            }),
            "adapter marker must enter global exactly-one accounting: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn owner_path_basename_must_equal_domain_and_package() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-owner-path")?;
        fs::rename(
            temp.path.join("crates/demo"),
            temp.path.join("crates/decoy"),
        )?;
        let workspace = temp.path.join("Cargo.toml");
        fs::write(
            &workspace,
            fs::read_to_string(&workspace)?.replace("crates/demo", "crates/decoy"),
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingOwnerCrate));
        Ok(())
    }

    #[test]
    fn nested_handler_cannot_lend_module_level_identity() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-nested-handler")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
fn handler() {}
fn hidden() {
    fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
    let _ = handler;
}
fn init() { let _ = httpserve::GeneratedEndpoint::new(WRITE_ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        Ok(())
    }

    #[test]
    fn owner_parse_errors_never_leak_absolute_temp_paths() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-owner-parse-redaction")?;
        fs::write(temp.path.join("crates/demo/src/lib.rs"), "not valid Rust")?;
        let error = match check_root(&temp.path) {
            Ok(_) => bail!("malformed owner Rust must fail closed"),
            Err(error) => error,
        };
        assert!(!format!("{error:#}").contains(temp.path.to_string_lossy().as_ref()));
        Ok(())
    }

    #[test]
    fn bare_noncanonical_renames_shadow_all_protected_roots() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-bare-renames")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
mod fake_vocab { pub struct HttpRouteBinding<T>(core::marker::PhantomData<T>); }
mod fake_httpserve {
    pub struct ContractMarker<T>(core::marker::PhantomData<T>);
    pub struct GeneratedEndpoint;
    impl GeneratedEndpoint { pub fn new<A, B>(_: A, _: B) {} }
}
mod fake_generated { pub mod http { pub mod demo_v1 { pub mod write {
    pub struct RouteMarker;
    pub const ROUTE: () = ();
} } } }
use fake_generated as generated;
use fake_httpserve as httpserve;
use fake_vocab as vocab;
fn handler(_: httpserve::ContractMarker<generated::http::demo_v1::write::RouteMarker>) {}
fn init() { httpserve::GeneratedEndpoint::new(generated::http::demo_v1::write::ROUTE, handler); }
#[test] fn covered() {
    const _: vocab::HttpRouteBinding<generated::http::demo_v1::write::RouteMarker, vocab::http::LocalTx> =
        generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn reachable_include_macro_is_rejected_fail_closed() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-include")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!("{}\ninclude!(\"extra.rs\");\n", fs::read_to_string(&owner)?),
        )?;
        fs::write(
            temp.path.join("crates/demo/src/extra.rs"),
            "#[test] fn duplicate() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
        )?;
        assert!(check_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn unknown_empty_item_macro_is_rejected_fail_closed() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-unknown-macro")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "unknown_external_macro!();\n{}",
                fs::read_to_string(&owner)?
            ),
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn disabled_cfg_cannot_supply_route_or_marker_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-disabled-cfg")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
#[cfg(any())]
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
#[cfg(any())]
fn init() { let _ = httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }
#[cfg(any())]
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn disabled_same_named_handler_cannot_lend_identity() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-disabled-handler")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
#[cfg(any())]
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn handler() {}
fn init() { let _ = httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        Ok(())
    }

    #[test]
    fn aliased_test_marker_is_not_the_canonical_syntax() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-marker-alias")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            fs::read_to_string(&owner)?.replace(
                "const _: ::vocab::HttpRouteBinding<\n            ::generated::http::demo_v1::write::RouteMarker,\n            ::vocab::http::LocalTx,\n        > =\n            ::generated::http::demo_v1::write::ROUTE;",
                "use ::generated::http::demo_v1::write::{ROUTE as R, RouteMarker as M};\n        use ::vocab::HttpRouteBinding as B;\n        const _: B<M, ::vocab::http::LocalTx> = R;",
            ),
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn path_attribute_is_relative_to_current_source_directory() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-path-source-dir")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!("{}\nmod outer;\n", fs::read_to_string(&owner)?),
        )?;
        fs::write(
            temp.path.join("crates/demo/src/outer.rs"),
            "#[cfg(test)]\n#[path = \"bait.rs\"]\nmod tests;\n",
        )?;
        fs::write(temp.path.join("crates/demo/src/bait.rs"), "")?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn absolute_workspace_member_error_is_redacted() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-absolute-member")?;
        let workspace = temp.path.join("Cargo.toml");
        fs::write(
            &workspace,
            format!(
                "[workspace]\nresolver = \"2\"\nmembers = [\"crates/demo\", \"{}\"]\n",
                temp.path.join("outside").display()
            ),
        )?;
        let error = match check_root(&temp.path) {
            Ok(_) => bail!("absolute workspace member must fail closed"),
            Err(error) => error,
        };
        assert!(!format!("{error:#}").contains(temp.path.to_string_lossy().as_ref()));
        Ok(())
    }

    #[test]
    fn absolute_module_path_error_is_redacted() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-absolute-module")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            format!(
                "#[path = \"{}\"] mod outside;\n",
                temp.path.join("outside.rs").display()
            ),
        )?;
        let error = match check_root(&temp.path) {
            Ok(_) => bail!("absolute module path must fail closed"),
            Err(error) => error,
        };
        assert!(!format!("{error:#}").contains(temp.path.to_string_lossy().as_ref()));
        Ok(())
    }

    #[test]
    fn nonempty_unknown_item_macro_scope_cannot_supply_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-nonempty-macro")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "unknown_external_macro!(harmless);\n{}",
                fs::read_to_string(&owner)?
            ),
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn fake_dependency_rebinding_cannot_supply_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-fake-dependency")?;
        fs::create_dir_all(temp.path.join("fake/generated/src"))?;
        fs::write(
            temp.path.join("fake/generated/Cargo.toml"),
            "[package]\nname = \"fake-generated\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        fs::write(temp.path.join("fake/generated/src/lib.rs"), "")?;
        let workspace = temp.path.join("Cargo.toml");
        fs::write(
            &workspace,
            fs::read_to_string(&workspace)?
                .replace("\"generated\"]", "\"generated\", \"fake/generated\"]"),
        )?;
        let cargo = temp.path.join("crates/demo/Cargo.toml");
        fs::write(
            &cargo,
            fs::read_to_string(&cargo)?.replace(
                "generated = { path = \"../../generated\" }",
                "generated = { package = \"fake-generated\", path = \"../../fake/generated\" }",
            ),
        )?;
        assert!(check_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn fake_bootstrap_dependency_cannot_supply_domain_route_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-fake-bootstrap-dependency")?;
        let bootstrap = temp.path.join("crates/bootstrap/Cargo.toml");
        fs::write(
            &bootstrap,
            fs::read_to_string(&bootstrap)?
                .replace("name = \"bootstrap\"", "name = \"fake-bootstrap\""),
        )?;
        let cargo = temp.path.join("crates/demo/Cargo.toml");
        fs::write(
            &cargo,
            fs::read_to_string(&cargo)?.replace(
                "bootstrap = { path = \"../bootstrap\" }",
                "bootstrap = { package = \"fake-bootstrap\", path = \"../bootstrap\" }",
            ),
        )?;
        assert!(
            check_root(&temp.path).is_err(),
            "renamed bootstrap package must not authorize Domain/Registry evidence"
        );
        Ok(())
    }

    #[test]
    fn extern_crate_self_bootstrap_cannot_supply_domain_route_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-self-bootstrap")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "extern crate self as bootstrap;\n{}",
                fs::read_to_string(&owner)?
            ),
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::MissingRouteBinding),
            "self-alias bootstrap must not authorize Domain/Registry evidence: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn integration_test_marker_enters_global_exactly_one_accounting() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-integration-marker")?;
        fs::create_dir_all(temp.path.join("crates/demo/tests"))?;
        fs::write(
            temp.path.join("crates/demo/tests/duplicate.rs"),
            "#[test] fn duplicate() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
        )?;
        let cargo = temp.path.join("crates/demo/Cargo.toml");
        fs::write(
            &cargo,
            format!(
                "{}\n[dev-dependencies]\ngenerated = {{ path = \"../../generated\" }}\nvocab = {{ path = \"../vocab\" }}\n",
                fs::read_to_string(&cargo)?
            ),
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::DuplicateTestMarker));
        Ok(())
    }

    #[test]
    fn proc_attribute_scope_cannot_supply_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-proc-attr")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            fs::read_to_string(&owner)?.replace("fn init(", "#[unknown::rewrite]\nfn init("),
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        Ok(())
    }

    #[test]
    fn strict_marker_rejects_near_miss_grammar() -> anyhow::Result<()> {
        let resolver = Resolver::default();
        for source in [
            "const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::other::ROUTE;",
            "const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::WrongMarker> = ::generated::http::demo_v1::write::ROUTE;",
            "const _: vocab::HttpRouteBinding<generated::http::demo_v1::write::RouteMarker, vocab::http::LocalTx> = generated::http::demo_v1::write::ROUTE;",
            "const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ()> = ::generated::http::demo_v1::write::ROUTE;",
            "const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = (::generated::http::demo_v1::write::ROUTE);",
        ] {
            let item: ItemConst = syn::parse_str(source)?;
            assert!(
                strict_test_marker_key(&item, &resolver).is_none(),
                "accepted near miss: {source}"
            );
        }
        let canonical: ItemConst = syn::parse_str(
            "const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE;",
        )?;
        assert_eq!(
            strict_test_marker_key(&canonical, &resolver).as_deref(),
            Some("demo_v1::write")
        );
        Ok(())
    }

    #[test]
    fn statically_false_external_module_is_not_parsed() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-false-module")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "#[cfg(any())]\nmod absent;\n{}",
                fs::read_to_string(&owner)?
            ),
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.is_empty(), "{findings:#?}");

        fs::write(
            &owner,
            format!(
                "#[cfg(feature = \"unknown\")]\nmod absent;\n{}",
                fs::read_to_string(&owner)?.replace("#[cfg(any())]\nmod absent;\n", "")
            ),
        )?;
        assert!(check_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn active_module_inclusion_cycles_fail_with_fixed_relative_errors() -> anyhow::Result<()> {
        let self_cycle = FixtureCopy::new("localtx-self-cycle")?;
        fs::write(
            self_cycle.path.join("crates/demo/src/lib.rs"),
            "#[path = \"lib.rs\"] mod again;\n",
        )?;
        let error = match check_root(&self_cycle.path) {
            Ok(_) => bail!("self inclusion must fail"),
            Err(error) => error,
        };
        let rendered = format!("{error:#}");
        assert!(rendered.contains("active Rust module inclusion cycle"));
        assert!(!rendered.contains(self_cycle.path.to_string_lossy().as_ref()));

        let two_file = FixtureCopy::new("localtx-two-file-cycle")?;
        fs::write(two_file.path.join("crates/demo/src/lib.rs"), "mod a;\n")?;
        fs::write(
            two_file.path.join("crates/demo/src/a.rs"),
            "#[path = \"lib.rs\"] mod root;\n",
        )?;
        let error = match check_root(&two_file.path) {
            Ok(_) => bail!("two-file inclusion must fail"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("active Rust module inclusion cycle"));
        Ok(())
    }

    #[test]
    fn integration_route_is_test_only_and_cannot_supply_production_evidence() -> anyhow::Result<()>
    {
        let temp = FixtureCopy::new("localtx-integration-route")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            r#"#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        fs::create_dir_all(temp.path.join("crates/demo/tests"))?;
        fs::write(
            temp.path.join("crates/demo/tests/route.rs"),
            r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init() { let _ = ::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }
"#,
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        Ok(())
    }

    #[test]
    fn cargo_autotests_and_explicit_test_targets_are_authoritative() -> anyhow::Result<()> {
        let disabled = FixtureCopy::new("localtx-autotests-disabled")?;
        fs::create_dir_all(disabled.path.join("crates/demo/tests"))?;
        fs::write(
            disabled.path.join("crates/demo/tests/orphan.rs"),
            "#[test] fn duplicate() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
        )?;
        let cargo = disabled.path.join("crates/demo/Cargo.toml");
        fs::write(
            &cargo,
            fs::read_to_string(&cargo)?
                .replace("name = \"demo\"", "name = \"demo\"\nautotests = false"),
        )?;
        let (_, findings) = check_root(&disabled.path)?;
        assert!(findings.is_empty(), "{findings:#?}");

        let explicit = FixtureCopy::new("localtx-explicit-test")?;
        fs::create_dir_all(explicit.path.join("crates/demo/checks"))?;
        fs::write(
            explicit.path.join("crates/demo/checks/contract.rs"),
            "#[test] fn duplicate() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
        )?;
        let cargo = explicit.path.join("crates/demo/Cargo.toml");
        fs::write(
            &cargo,
            format!(
                "{}\n[[test]]\nname = \"contract\"\npath = \"checks/contract.rs\"\n",
                fs::read_to_string(&cargo)?
            ),
        )?;
        let (_, findings) = check_root(&explicit.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::DuplicateTestMarker));
        Ok(())
    }

    #[test]
    fn fake_tokio_and_rstest_dependencies_cannot_authorize_markers() -> anyhow::Result<()> {
        for (macro_path, dependency, package) in [
            ("tokio::test", "tokio", "fake-tokio"),
            ("rstest::rstest", "rstest", "fake-rstest"),
        ] {
            let temp = FixtureCopy::new("localtx-fake-test-macro")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            fs::write(
                &owner,
                fs::read_to_string(&owner)?.replace(
                    "#[test] fn covered()",
                    &format!("#[{macro_path}] fn covered()"),
                ),
            )?;
            let fake = temp.path.join(format!("fake/{dependency}"));
            fs::create_dir_all(fake.join("src"))?;
            fs::write(
                fake.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{package}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n"
                ),
            )?;
            fs::write(fake.join("src/lib.rs"), "")?;
            let workspace = temp.path.join("Cargo.toml");
            fs::write(
                &workspace,
                fs::read_to_string(&workspace)?.replace(
                    "\"generated\"]",
                    &format!("\"generated\", \"fake/{dependency}\"]"),
                ),
            )?;
            let cargo = temp.path.join("crates/demo/Cargo.toml");
            fs::write(
                &cargo,
                format!(
                    "{}\n[dev-dependencies]\n{dependency} = {{ package = \"{package}\", path = \"../../fake/{dependency}\" }}\n",
                    fs::read_to_string(&cargo)?
                ),
            )?;
            assert!(check_root(&temp.path).is_err());
        }
        Ok(())
    }

    #[test]
    fn local_test_macro_alias_cannot_borrow_a_real_cargo_dependency() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-test-macro-alias")?;
        let cargo = temp.path.join("crates/demo/Cargo.toml");
        fs::write(
            &cargo,
            format!(
                "{}\n[dev-dependencies]\ntokio = \"1\"\n",
                fs::read_to_string(&cargo)?
            ),
        )?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            fs::read_to_string(&owner)?.replace(
                "#[test] fn covered()",
                "use evil_macros as tokio;\n    #[tokio::test] fn covered()",
            ),
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));

        let trusted = FixtureCopy::new("localtx-trusted-macro-alias")?;
        let cargo = trusted.path.join("crates/demo/Cargo.toml");
        fs::write(
            &cargo,
            format!("{}\ntracing = \"0.1\"\n", fs::read_to_string(&cargo)?),
        )?;
        let owner = trusted.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "use evil_macros as tracing;\n#[tracing::instrument] fn bait() {{}}\n{}",
                fs::read_to_string(&owner)?
            ),
        )?;
        let (_, findings) = check_root(&trusted.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn local_item_macro_invocations_make_test_identity_opaque() -> anyhow::Result<()> {
        for (binding, test_attr, dependency, bait) in [
            ("tokio", "tokio::test", Some(("tokio", "1")), ""),
            ("rstest", "rstest::rstest", Some(("rstest", "0.24")), ""),
            ("test", "test", None, ""),
            ("Debug", "test", None, "#[derive(Debug)] struct Bait;"),
        ] {
            let temp = FixtureCopy::new("localtx-local-item-macro")?;
            if let Some((name, version)) = dependency {
                let cargo = temp.path.join("crates/demo/Cargo.toml");
                fs::write(
                    &cargo,
                    format!(
                        "{}\n[dev-dependencies]\n{name} = \"{version}\"\n",
                        fs::read_to_string(&cargo)?
                    ),
                )?;
            }
            let owner = temp.path.join("crates/demo/src/lib.rs");
            let source = fs::read_to_string(&owner)?.replace(
                "#[test] fn covered()",
                &format!("#[{test_attr}] fn covered()"),
            );
            fs::write(
                &owner,
                format!(
                    "macro_rules! poison {{ () => {{ use evil_macros as {binding}; }}; }}\npoison!();\n{bait}\n{source}"
                ),
            )?;
            let (_, findings) = check_root(&temp.path)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::MissingRouteBinding),
                "{binding}: {findings:#?}"
            );
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::MissingTestMarker),
                "{binding}: {findings:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn block_statement_macro_invocations_make_nested_evidence_opaque() -> anyhow::Result<()> {
        for (binding, test_attr, dependency, bait) in [
            ("tokio", "tokio::test", Some(("tokio", "1")), ""),
            ("rstest", "rstest::rstest", Some(("rstest", "0.24")), ""),
            ("test", "test", None, ""),
            ("Debug", "test", None, "#[derive(Debug)] struct Bait;"),
        ] {
            let temp = FixtureCopy::new("localtx-block-statement-macro")?;
            if let Some((name, version)) = dependency {
                let cargo = temp.path.join("crates/demo/Cargo.toml");
                fs::write(
                    &cargo,
                    format!(
                        "{}\n[dev-dependencies]\n{name} = \"{version}\"\n",
                        fs::read_to_string(&cargo)?
                    ),
                )?;
            }
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {{}}
fn init() {{
    macro_rules! poison {{ () => {{ use evil_macros as {binding}; }}; }}
    poison!();
    {bait}
    {{ let _ = ::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }}
}}
#[{test_attr}] fn covered() {{
    macro_rules! poison {{ () => {{ use evil_macros as {binding}; }}; }}
    poison!();
    {bait}
    {{
        const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
            ::generated::http::demo_v1::write::ROUTE;
    }}
}}
"#,
                ),
            )?;
            let (_, findings) = check_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
            assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }

        let control = FixtureCopy::new("localtx-block-expression-macros")?;
        let owner = control.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            fs::read_to_string(&owner)?
                .replace(
                    "fn init() {",
                    "fn init() { { assert!(true); let _formatted = format!(\"route\"); }",
                )
                .replace(
                    "#[test] fn covered() {",
                    "#[test] fn covered() { { assert!(true); let _formatted = format!(\"marker\"); }",
                ),
        )?;
        let (_, findings) = check_root(&control.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn unknown_sibling_attribute_or_derive_taints_the_module_scope() -> anyhow::Result<()> {
        for bait in [
            "#[unknown::rewrite] struct Bait;",
            "#[derive(unknown::Rewrite)] struct Bait;",
        ] {
            let temp = FixtureCopy::new("localtx-unknown-sibling-attr")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            fs::write(&owner, format!("{bait}\n{}", fs::read_to_string(&owner)?))?;
            let (_, findings) = check_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
            assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
            assert!(
                findings.iter().any(|finding| {
                    finding.rule == Rule::OpaqueSourceScope
                        && finding.subject == "crates/demo/src/lib.rs:1"
                        && (finding.detail.contains("unknown::rewrite")
                            || finding.detail.contains("unknown::Rewrite"))
                }),
                "opaque trigger must name its source line and attribute: {findings:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn cargo_metadata_failure_reports_bounded_sanitized_stderr() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-metadata-diagnostic")?;
        fs::write(temp.path.join("Cargo.toml"), "[workspace]\nmembers = [\n")?;
        let error = match check_root(&temp.path) {
            Ok(_) => bail!("malformed workspace must fail metadata"),
            Err(error) => error,
        };
        let message = format!("{error:#}");
        assert!(message.contains("cargo metadata --locked --no-deps failed"));
        assert!(
            message.contains("status="),
            "exit status must be retained: {message}"
        );
        assert!(
            message.contains("invalid array")
                || message.contains("invalid inline table")
                || message.contains("invalid type")
                || message.contains("unclosed array"),
            "cargo's actionable stderr must be retained: {message}"
        );
        assert!(!message.contains(temp.path.to_string_lossy().as_ref()));
        assert!(message.len() <= 5000, "stderr diagnostic must be bounded");
        Ok(())
    }

    #[test]
    fn recognized_test_functions_cannot_supply_production_routes() -> anyhow::Result<()> {
        for (attr, dependency) in [
            ("test", None),
            ("tokio::test", Some(("tokio", "1"))),
            ("rstest::rstest", Some(("rstest", "0.24"))),
        ] {
            let temp = FixtureCopy::new("localtx-test-route-bait")?;
            let cargo = temp.path.join("crates/demo/Cargo.toml");
            if let Some((dependency, version)) = dependency {
                fs::write(
                    &cargo,
                    format!(
                        "{}\n[dev-dependencies]\n{dependency} = \"{version}\"\n",
                        fs::read_to_string(&cargo)?
                    ),
                )?;
            }
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {{}}
#[{attr}] fn bait() {{ let _ = ::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }}
#[test] fn covered() {{
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}}
"#,
                ),
            )?;
            let (_, findings) = check_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
            assert!(!findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }
        Ok(())
    }

    #[test]
    fn parent_resolver_risks_propagate_into_external_modules() -> anyhow::Result<()> {
        for (root_source, missing_route, missing_marker) in [
            ("#[unknown::rewrite] mod evidence;\n", true, true),
            (
                "extern crate self as generated;\nmod evidence;\n",
                true,
                true,
            ),
            ("use evil::test;\nmod evidence;\n", false, true),
        ] {
            let temp = FixtureCopy::new("localtx-external-parent-risk")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            fs::write(
                temp.path.join("crates/demo/src/evidence.rs"),
                fs::read_to_string(&owner)?,
            )?;
            fs::write(&owner, root_source)?;
            let (_, findings) = check_root(&temp.path)?;
            assert_eq!(
                findings.iter().any(|f| f.rule == Rule::MissingRouteBinding),
                missing_route
            );
            assert_eq!(
                findings.iter().any(|f| f.rule == Rule::MissingTestMarker),
                missing_marker
            );
        }
        Ok(())
    }

    #[test]
    fn parent_canonical_aliases_do_not_leak_into_child_modules() -> anyhow::Result<()> {
        let evidence = r#"
struct Endpoint;
impl Endpoint { fn new<A, B>(_: A, _: B) {} }
const ROUTE: () = ();
fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init() { Endpoint::new(ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#;
        for external in [false, true] {
            let temp = FixtureCopy::new("localtx-parent-alias")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            let imports = "use ::generated::http::demo_v1::write::ROUTE;\nuse ::httpserve::GeneratedEndpoint as Endpoint;\n";
            if external {
                fs::write(
                    &owner,
                    format!("{imports}#[path = \"evidence.rs\"] mod evidence;\n"),
                )?;
                fs::write(temp.path.join("crates/demo/src/evidence.rs"), evidence)?;
            } else {
                fs::write(&owner, format!("{imports}mod evidence {{ {evidence} }}\n"))?;
            }
            let (_, findings) = check_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
            assert!(!findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }
        Ok(())
    }

    #[test]
    fn builtin_derive_names_cannot_be_rebound_or_globbed() -> anyhow::Result<()> {
        for bait in [
            "use evil::Rewrite as Debug;\n#[derive(Debug)] struct Bait;",
            "use evil::*;\n#[derive(Clone)] struct Bait;",
            "macro_rules! Copy { () => {} }\n#[derive(Copy)] struct Bait;",
        ] {
            let temp = FixtureCopy::new("localtx-derive-shadow")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            fs::write(&owner, format!("{bait}\n{}", fs::read_to_string(&owner)?))?;
            let (_, findings) = check_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
            assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }
        Ok(())
    }

    #[test]
    fn evidence_respects_const_statement_block_and_call_cfg_attributes() -> anyhow::Result<()> {
        let marker = FixtureCopy::new("localtx-cfg-const")?;
        let owner = marker.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            fs::read_to_string(&owner)?.replace(
                "const _: ::vocab::HttpRouteBinding",
                "#[cfg(any())] const _: ::vocab::HttpRouteBinding",
            ),
        )?;
        let (_, findings) = check_root(&marker.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));

        for body in [
            "#[cfg(test)] let _ = rb.mount(::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler));",
            "#[cfg(test)] rb.mount(::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler));",
            "#[cfg(test)] { let _ = rb.mount(::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler)); }",
            "#[cfg(test)] if true { let _ = rb.mount(::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler)); }",
        ] {
            let temp = FixtureCopy::new("localtx-cfg-route-evidence")?;
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {{}}
fn init(reg: &mut ::httpserve::Registry) {{ reg.route_group(|rb| {{ {body} Ok(rb) }}); }}
#[test] fn covered() {{
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}}
"#,
                ),
            )?;
            let (_, findings) = check_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        }

        let control = FixtureCopy::new("localtx-production-method-control")?;
        fs::write(
            control.path.join("crates/demo/src/lib.rs"),
            r#"struct Domain;
impl ::bootstrap::Domain for Domain {
    fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
    fn init(&self, reg: &mut ::bootstrap::Registry) { reg.route_group(|rb| { Ok(rb.mount(::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, Domain::handler))) }); }
}
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_root(&control.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn builtin_test_attribute_rejects_macro_namespace_pollution() -> anyhow::Result<()> {
        for bait in [
            "use evil::test;",
            "use evil::Rewrite as test;",
            "use evil::*;",
            "macro_rules! test { () => {} }",
            "extern crate self as test;",
        ] {
            let temp = FixtureCopy::new("localtx-test-shadow")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            fs::write(&owner, format!("{bait}\n{}", fs::read_to_string(&owner)?))?;
            let (_, findings) = check_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }
        Ok(())
    }

    #[test]
    fn local_globs_pollute_but_super_glob_inherits_known_parent_risks() -> anyhow::Result<()> {
        for bait in ["use crate::*;", "use self::*;"] {
            let temp = FixtureCopy::new("localtx-local-glob")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            fs::write(&owner, format!("{bait}\n{}", fs::read_to_string(&owner)?))?;
            let (_, findings) = check_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }

        let temp = FixtureCopy::new("localtx-super-glob")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            fs::read_to_string(&owner)?.replace(
                "#[test] fn covered()",
                "use super::*;\n    #[test] fn covered()",
            ),
        )?;
        let (_, findings) = check_root(&temp.path)?;
        assert!(findings.is_empty(), "{findings:#?}");

        let polluted = FixtureCopy::new("localtx-polluted-super-glob")?;
        let owner = polluted.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "use evil::test;\n{}",
                fs::read_to_string(&owner)?.replace(
                    "#[test] fn covered()",
                    "use super::*;\n    #[test] fn covered()",
                )
            ),
        )?;
        let (_, findings) = check_root(&polluted.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn cfg_limited_impls_cannot_supply_route_or_inline_handler_evidence() -> anyhow::Result<()> {
        for cfg in ["test", "any()"] {
            let temp = FixtureCopy::new("localtx-cfg-impl")?;
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"struct Domain;
#[cfg({cfg})]
impl Domain {{
    fn init() {{
        let _ = ::httpserve::GeneratedEndpoint::new(
            ::generated::http::demo_v1::write::ROUTE,
            |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| (),
        );
    }}
}}
#[test] fn covered() {{
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}}
"#,
                ),
            )?;
            let (_, findings) = check_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        }
        Ok(())
    }

    #[test]
    fn attributed_methods_traits_arms_and_statics_cannot_supply_routes() -> anyhow::Result<()> {
        for bait in [
            "#[cfg(test)] trait Bait { fn init() { CALL } }",
            "trait Bait { #[cfg(any())] fn init() { CALL } }",
            "struct Bait; impl Bait { #[unknown::rewrite] fn init() { CALL } }",
            "fn init() { match true { #[cfg(test)] true => { CALL }, _ => {} } }",
            "#[cfg(test)] static BAIT: () = { CALL };",
            "struct Bait; impl Bait { #[cfg(test)] const VALUE: () = { CALL }; }",
        ] {
            let temp = FixtureCopy::new("localtx-attributed-ancestor")?;
            let bait = bait.replace(
                "CALL",
                "let _ = ::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| ());",
            );
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"{bait}
#[test] fn covered() {{
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}}
"#,
                ),
            )?;
            let (_, findings) = check_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        }
        Ok(())
    }

    #[test]
    fn attributed_struct_field_initializers_respect_route_reachability() -> anyhow::Result<()> {
        for attr in ["cfg(test)", "cfg(any())", "unknown::rewrite"] {
            let temp = FixtureCopy::new("localtx-attributed-field-value")?;
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"struct Holder {{ #[{attr}] endpoint: () }}
fn init() {{
    let _ = Holder {{
        #[{attr}]
        endpoint: {{
            let _ = ::httpserve::GeneratedEndpoint::new(
                ::generated::http::demo_v1::write::ROUTE,
                |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| (),
            );
        }}
    }};
}}
#[test] fn covered() {{
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}}
"#,
                ),
            )?;
            let (_, findings) = check_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        }

        let control = FixtureCopy::new("localtx-field-value-control")?;
        fs::write(
            control.path.join("crates/demo/src/lib.rs"),
            r#"struct Demo;
impl ::bootstrap::Domain for Demo {
    fn init(&self, reg: &mut ::bootstrap::Registry) {
        reg.route_group(|rb| {
            Ok(rb.mount(::httpserve::GeneratedEndpoint::new(
                ::generated::http::demo_v1::write::ROUTE,
                |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| (),
            )))
        });
    }
}
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_root(&control.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn nested_helpers_in_recognized_tests_remain_test_only() -> anyhow::Result<()> {
        for (attr, dependency) in [
            ("test", None),
            ("tokio::test", Some(("tokio", "1"))),
            ("rstest::rstest", Some(("rstest", "0.24"))),
        ] {
            let temp = FixtureCopy::new("localtx-nested-test-route")?;
            if let Some((dependency, version)) = dependency {
                let cargo = temp.path.join("crates/demo/Cargo.toml");
                fs::write(
                    &cargo,
                    format!(
                        "{}\n[dev-dependencies]\n{dependency} = \"{version}\"\n",
                        fs::read_to_string(&cargo)?
                    ),
                )?;
            }
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {{}}
#[{attr}] fn covered() {{
    fn helper() {{
        let _ = ::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler);
    }}
    helper();
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}}
"#,
                ),
            )?;
            let (_, findings) = check_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
            assert!(!findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }
        Ok(())
    }

    #[test]
    fn fake_outer_test_macros_cannot_lend_identity_to_nested_markers() -> anyhow::Result<()> {
        for (root, version) in [("tokio", "1"), ("rstest", "0.24")] {
            let temp = FixtureCopy::new("localtx-fake-outer-test")?;
            let cargo = temp.path.join("crates/demo/Cargo.toml");
            fs::write(
                &cargo,
                format!(
                    "{}\n[dev-dependencies]\n{root} = \"{version}\"\n",
                    fs::read_to_string(&cargo)?
                ),
            )?;
            let attr = if root == "tokio" {
                "tokio::test"
            } else {
                "rstest::rstest"
            };
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"use evil_macros as {root};
#[{attr}] fn outer() {{
    fn nested() {{
        const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
            ::generated::http::demo_v1::write::ROUTE;
    }}
    nested();
}}
fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {{}}
fn init() {{ let _ = ::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }}
"#,
                ),
            )?;
            let (_, findings) = check_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn module_budget_accepts_boundary_and_rejects_deep_and_fanout() -> anyhow::Result<()> {
        let mut budget = ModuleBudget::default();
        for index in 0..MAX_CANONICAL_FILES {
            budget.enter(Path::new(&format!("file-{index}.rs")), 1, MAX_MODULE_DEPTH)?;
        }
        assert!(budget.enter(Path::new("too-many.rs"), 1, 1).is_err());
        let mut depth = ModuleBudget::default();
        assert!(
            depth
                .enter(Path::new("deep.rs"), 1, MAX_MODULE_DEPTH + 1)
                .is_err()
        );
        let mut bytes = ModuleBudget::default();
        bytes.enter(Path::new("boundary.rs"), MAX_SOURCE_BYTES, 1)?;
        assert!(bytes.enter(Path::new("too-large.rs"), 1, 1).is_err());

        let deep = FixtureCopy::new("localtx-module-depth")?;
        let owner = deep.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "{}\n#[path = \"depth-1.rs\"] mod depth;\n",
                fs::read_to_string(&owner)?
            ),
        )?;
        for index in 1..MAX_MODULE_DEPTH {
            fs::write(
                deep.path.join(format!("crates/demo/src/depth-{index}.rs")),
                if index + 1 == MAX_MODULE_DEPTH {
                    String::new()
                } else {
                    format!("#[path = \"depth-{}.rs\"] mod next;\n", index + 1)
                },
            )?;
        }
        let (_, findings) = check_root(&deep.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        fs::write(
            deep.path
                .join(format!("crates/demo/src/depth-{}.rs", MAX_MODULE_DEPTH - 1)),
            format!("#[path = \"depth-{MAX_MODULE_DEPTH}.rs\"] mod next;\n"),
        )?;
        fs::write(
            deep.path
                .join(format!("crates/demo/src/depth-{MAX_MODULE_DEPTH}.rs")),
            "",
        )?;
        assert!(check_root(&deep.path).is_err());

        let fanout = FixtureCopy::new("localtx-module-fanout")?;
        let owner = fanout.path.join("crates/demo/src/lib.rs");
        let mut source = fs::read_to_string(&owner)?;
        for index in 0..(MAX_CANONICAL_FILES - 1) {
            source.push_str(&format!(
                "\n#[path = \"fanout-{index}.rs\"] mod fanout_{index};"
            ));
            fs::write(
                fanout
                    .path
                    .join(format!("crates/demo/src/fanout-{index}.rs")),
                "",
            )?;
        }
        fs::write(&owner, &source)?;
        let (_, findings) = check_root(&fanout.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        source.push_str(&format!(
            "\n#[path = \"fanout-{}.rs\"] mod fanout_over;",
            MAX_CANONICAL_FILES - 1
        ));
        fs::write(
            fanout.path.join(format!(
                "crates/demo/src/fanout-{}.rs",
                MAX_CANONICAL_FILES - 1
            )),
            "",
        )?;
        fs::write(&owner, source)?;
        assert!(check_root(&fanout.path).is_err());

        let inline_depth = FixtureCopy::new("localtx-inline-depth")?;
        let owner = inline_depth.path.join("crates/demo/src/lib.rs");
        let base = fs::read_to_string(&owner)?;
        let nested = |count: usize| {
            format!(
                "{base}\n{}{}",
                (0..count)
                    .map(|index| format!("mod inline_{index} {{"))
                    .collect::<String>(),
                "}".repeat(count)
            )
        };
        fs::write(&owner, nested(MAX_MODULE_DEPTH - 1))?;
        let (_, findings) = check_root(&inline_depth.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        fs::write(&owner, nested(MAX_MODULE_DEPTH))?;
        assert!(check_root(&inline_depth.path).is_err());

        let inline_wide = FixtureCopy::new("localtx-inline-wide")?;
        let owner = inline_wide.path.join("crates/demo/src/lib.rs");
        let mut source = fs::read_to_string(&owner)?;
        // Root file + the green fixture's inline `tests` module consume two logical units.
        for index in 0..(MAX_LOGICAL_UNITS - 2) {
            source.push_str(&format!("\nmod inline_wide_{index} {{}}"));
        }
        fs::write(&owner, &source)?;
        let (_, findings) = check_root(&inline_wide.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        source.push_str("\nmod inline_wide_over {}");
        fs::write(&owner, source)?;
        assert!(check_root(&inline_wide.path).is_err());
        Ok(())
    }

    struct FixtureCopy {
        path: PathBuf,
    }
    impl FixtureCopy {
        fn new(prefix: &str) -> anyhow::Result<Self> {
            let path = crate::testutil::unique_tmp(prefix);
            copy_tree(&fixture("green"), &path)?;
            Ok(Self { path })
        }

        fn cargo_check(&self) -> anyhow::Result<std::process::Output> {
            let manifest = self.path.join("Cargo.toml");
            let target = self.path.join("target");
            crate::cmd::cargo_cmd(
                crate::cmd::CargoSubcommand::Check,
                &[
                    "--offline",
                    "--manifest-path",
                    manifest
                        .to_str()
                        .ok_or_else(|| anyhow!("fixture manifest path is not UTF-8"))?,
                ],
                &[(
                    "CARGO_TARGET_DIR",
                    target
                        .to_str()
                        .ok_or_else(|| anyhow!("fixture target path is not UTF-8"))?,
                )],
                Some(&self.path),
            )
            .output()
            .map_err(Into::into)
        }
    }
    impl Drop for FixtureCopy {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn copy_tree(from: &Path, to: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(to)?;
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            let target = to.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_tree(&entry.path(), &target)?;
            } else {
                fs::copy(entry.path(), target)?;
            }
        }
        Ok(())
    }
}
