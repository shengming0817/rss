//! Provider-neutral L2 conformance enrollment semantic gate.
//!
//! The adapter-side macro invocation is the declaration and generates every live wrapper. This
//! gate proves each exact wrapper-to-behavior edge, behavior semantic anchors and digest, tracked
//! source closure, and test-binary reachability. An on-demand diagnostic report may project the
//! validated catalog, but that presentation is not an identity, equality, receipt, or gate carrier.
//!
//! INVARIANT: L2-PROVIDER-CAPABILITY-ENROLLMENT-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "declared_capability_without_behavior_fails|duplicate_unknown_or_wrong_order_enrollment_fails|noop_unrelated_and_decorated_behaviors_fail|testkit_catalog_projection_drift_fails|untracked_invocation_is_outside_canonical_scan|detached_carrier_and_feature_drift_fail_closed|tracked_nonordinary_or_oversized_sources_fail_closed", anti_vacuity = "workspace_provider_capability_wrappers_and_behaviors_are_exact_and_live" }.

use crate::cmd::{ExternalProgram, external_cmd};
use crate::generated_file;
use crate::integration_shards::{IntegrationShard, TargetKind};
use anyhow::{Context, Result, bail, ensure};
use proc_macro2::TokenStream;
use quote::ToTokens;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, Ident, ImplItem, Item, ItemFn, ItemMacro, ItemMod, Path as SynPath, Token,
    Type, braced,
};

const DIAGNOSTIC_OUTPUT: &str = "target/xtask/provider-capability-matrix.json";
const TESTKIT_CATALOG: &str = "crates/testkit/src/eventing_conformance.rs";
const MAX_TRACKED_RUST_FILES: usize = 2_048;
const MAX_TRACKED_RUST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RUST_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
const COMPILE_FAIL_FIXTURES: [&str; 3] = [
    "crates/testkit/tests/ui/provider_catalog_incomplete_set_fail.rs",
    "crates/testkit/tests/ui/provider_catalog_wrong_behavior_output_fail.rs",
    "crates/testkit/tests/ui/provider_catalog_wrong_order_fail.rs",
];
const INTEGRATION_TEST_CFG: &str = "all(test,feature=\"integration\")";

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProviderId {
    Postgres,
    Amqp,
    S3,
}

impl ProviderId {
    const ALL: [Self; 3] = [Self::Postgres, Self::Amqp, Self::S3];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Amqp => "amqp",
            Self::S3 => "s3",
        }
    }

    const fn type_name(self) -> &'static str {
        match self {
            Self::Postgres => "Postgres",
            Self::Amqp => "Amqp",
            Self::S3 => "S3",
        }
    }

    const fn capabilities(self) -> &'static [CapabilityId] {
        match self {
            Self::Postgres => &CapabilityId::ALL,
            Self::Amqp => &[
                CapabilityId::Identity,
                CapabilityId::Fencing,
                CapabilityId::Budget,
                CapabilityId::Ambiguity,
            ],
            Self::S3 => &[
                CapabilityId::Identity,
                CapabilityId::Conflict,
                CapabilityId::ArchiveReceipt,
            ],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CapabilityId {
    Identity,
    Conflict,
    Fencing,
    Budget,
    CommitAck,
    Ambiguity,
    ArchiveReceipt,
}

impl CapabilityId {
    const ALL: [Self; 7] = [
        Self::Identity,
        Self::Conflict,
        Self::Fencing,
        Self::Budget,
        Self::CommitAck,
        Self::Ambiguity,
        Self::ArchiveReceipt,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Conflict => "conflict",
            Self::Fencing => "fencing",
            Self::Budget => "budget",
            Self::CommitAck => "commit-ack",
            Self::Ambiguity => "ambiguity",
            Self::ArchiveReceipt => "archive-receipt",
        }
    }

    const fn type_name(self) -> &'static str {
        match self {
            Self::Identity => "Identity",
            Self::Conflict => "Conflict",
            Self::Fencing => "Fencing",
            Self::Budget => "Budget",
            Self::CommitAck => "CommitAck",
            Self::Ambiguity => "Ambiguity",
            Self::ArchiveReceipt => "ArchiveReceipt",
        }
    }

    const fn macro_token(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Conflict => "conflict",
            Self::Fencing => "fencing",
            Self::Budget => "budget",
            Self::CommitAck => "commit_ack",
            Self::Ambiguity => "ambiguity",
            Self::ArchiveReceipt => "archive_receipt",
        }
    }
}

#[derive(Clone, Copy)]
struct OwnerSpec {
    provider: ProviderId,
    path: &'static str,
    package: &'static str,
    target: &'static str,
    kind: TargetKind,
    shard: IntegrationShard,
}

const OWNERS: [OwnerSpec; 3] = [
    OwnerSpec {
        provider: ProviderId::Postgres,
        path: "adapters/postgres/src/integration_tests/provider_conformance_tests.rs",
        package: "postgres",
        target: "postgres",
        kind: TargetKind::Lib,
        shard: IntegrationShard::PostgresDomain,
    },
    OwnerSpec {
        provider: ProviderId::Amqp,
        path: "adapters/amqp/src/publisher.rs",
        package: "amqp",
        target: "amqp",
        kind: TargetKind::Lib,
        shard: IntegrationShard::EventTransport,
    },
    OwnerSpec {
        provider: ProviderId::S3,
        path: "adapters/s3/tests/dlx_archive_store.rs",
        package: "s3",
        target: "dlx_archive_store",
        kind: TargetKind::Test,
        shard: IntegrationShard::ObjectStorage,
    },
];

pub(crate) fn run(check: bool) -> Result<()> {
    run_at(&crate::workspace_root()?, check)
}

fn run_at(root: &Path, check: bool) -> Result<()> {
    let catalog = validate_catalog(root)?;
    if check {
        return Ok(());
    }
    let output = publish_diagnostic(root, &catalog)?;
    eprintln!(
        "provider capabilities: diagnostic report written to {}",
        output.display()
    );
    Ok(())
}

fn validate_catalog(root: &Path) -> Result<ValidatedProviderCatalog> {
    validate_testkit_catalog(root)?;
    let invocations = discover_invocations(root)?;
    ensure!(
        invocations.len() == OWNERS.len(),
        "expected exactly {} provider catalog invocations, found {}",
        OWNERS.len(),
        invocations.len()
    );

    let mut by_provider = BTreeMap::new();
    for invocation in invocations {
        let provider = parse_provider(&invocation.enrollment.provider)?;
        let owner = owner(provider);
        ensure!(
            !invocation.nested,
            "provider `{}` catalog must be a crate-root item",
            provider.as_str()
        );
        validate_invocation_cfg(provider, &invocation.attrs)?;
        ensure!(
            invocation.path == owner.path,
            "provider `{}` catalog must live in {}, found {}",
            provider.as_str(),
            owner.path,
            invocation.path
        );
        ensure!(
            by_provider.insert(provider.as_str(), invocation).is_none(),
            "duplicate provider catalog `{}`",
            provider.as_str()
        );
    }

    let mut providers = Vec::with_capacity(OWNERS.len());
    let mut runner_set = BTreeSet::new();
    for provider in ProviderId::ALL {
        let owner = owner(provider);
        validate_shard(root, owner)?;
        let invocation = by_provider
            .remove(provider.as_str())
            .with_context(|| format!("missing provider catalog `{}`", provider.as_str()))?;
        validate_error_type(&invocation.enrollment.error)?;
        let entries = validate_capabilities(provider, &invocation.enrollment.capabilities)?;
        let behaviors = provider_behaviors(&invocation.source)?;
        let mut capabilities = Vec::with_capacity(entries.len());
        let mut behavior_set = BTreeSet::new();
        for entry in entries {
            let capability = entry.capability;
            let runner = entry.wrapper;
            ensure!(
                runner_set.insert(format!("{}::{runner}", invocation.path)),
                "runner `{runner}` is enrolled more than once"
            );
            ensure!(
                behavior_set.insert(entry.behavior.clone()),
                "behavior `{}` is enrolled more than once",
                entry.behavior
            );
            validate_wrapper_attrs(provider, capability, &entry.attrs)?;
            let behavior_sha256 =
                validate_behavior(provider, capability, &entry.behavior, &behaviors)?;
            capabilities.push(CatalogCapability {
                capability: capability.as_str(),
                carrier: ValidatedCarrier {
                    package: owner.package,
                    target: owner.target,
                    kind: target_kind(owner.kind),
                    path: owner.path,
                    symbol: runner,
                    behavior: entry.behavior,
                    behavior_sha256,
                    shard: owner.shard.as_str(),
                },
            });
        }
        providers.push(ValidatedProvider {
            provider: provider.as_str(),
            capabilities,
        });
    }
    ensure!(by_provider.is_empty(), "unknown provider catalog remained");

    Ok(ValidatedProviderCatalog { providers })
}

fn validate_testkit_catalog(root: &Path) -> Result<()> {
    let path = root.join(TESTKIT_CATALOG);
    let source = generated_file::read_stable_utf8_file(
        &path,
        MAX_RUST_SOURCE_BYTES,
        "testkit provider catalog source",
    )?;
    validate_testkit_catalog_source(&source)
        .with_context(|| format!("validate provider catalog projection {}", path.display()))
}

fn validate_testkit_catalog_source(source: &str) -> Result<()> {
    let file = syn::parse_file(source).context("parse testkit provider catalog source")?;
    validate_enum_variants(&file, "ProviderId", &["Postgres", "Amqp", "S3"])?;
    validate_enum_variants(
        &file,
        "CapabilityId",
        &[
            "Identity",
            "Conflict",
            "Fencing",
            "Budget",
            "CommitAck",
            "Ambiguity",
            "ArchiveReceipt",
        ],
    )?;
    validate_impl_const(
        &file,
        "ProviderId",
        "ALL",
        "[Self::Postgres, Self::Amqp, Self::S3]",
    )?;
    validate_impl_const(
        &file,
        "CapabilityId",
        "ALL",
        "[
            Self::Identity,
            Self::Conflict,
            Self::Fencing,
            Self::Budget,
            Self::CommitAck,
            Self::Ambiguity,
            Self::ArchiveReceipt,
        ]",
    )?;
    validate_impl_method(
        &file,
        "ProviderId",
        "as_str",
        "{
            match self {
                Self::Postgres => \"postgres\",
                Self::Amqp => \"amqp\",
                Self::S3 => \"s3\",
            }
        }",
    )?;
    validate_impl_method(
        &file,
        "CapabilityId",
        "as_str",
        "{
            match self {
                Self::Identity => \"identity\",
                Self::Conflict => \"conflict\",
                Self::Fencing => \"fencing\",
                Self::Budget => \"budget\",
                Self::CommitAck => \"commit-ack\",
                Self::Ambiguity => \"ambiguity\",
                Self::ArchiveReceipt => \"archive-receipt\",
            }
        }",
    )?;
    validate_impl_method(
        &file,
        "ProviderId",
        "capabilities",
        "{
            match self {
                Self::Postgres => &CapabilityId::ALL,
                Self::Amqp => &[
                    CapabilityId::Identity,
                    CapabilityId::Fencing,
                    CapabilityId::Budget,
                    CapabilityId::Ambiguity,
                ],
                Self::S3 => &[
                    CapabilityId::Identity,
                    CapabilityId::Conflict,
                    CapabilityId::ArchiveReceipt,
                ],
            }
        }",
    )?;
    validate_sealed_complete_sets(&file)
}

fn validate_sealed_complete_sets(file: &syn::File) -> Result<()> {
    let mut collector = SealedCompleteSetCollector::default();
    collector.visit_file(file);
    if let Some(error) = collector.errors.into_iter().next() {
        return Err(error);
    }
    ensure!(
        collector.sets.len() == ProviderId::ALL.len(),
        "testkit catalog must define exactly {} `SealedCompleteSet` impls, found {}",
        ProviderId::ALL.len(),
        collector.sets.len()
    );
    for provider in ProviderId::ALL {
        let expected = provider
            .capabilities()
            .iter()
            .map(|capability| capability.type_name().to_string())
            .collect::<Vec<_>>();
        let actual = collector.sets.get(provider.type_name()).with_context(|| {
            format!(
                "testkit catalog missing `SealedCompleteSet<{}>` exact tuple",
                provider.type_name()
            )
        })?;
        ensure!(
            actual == &expected,
            "testkit catalog `SealedCompleteSet<{}>` exact tuple drifted: expected {expected:?}, found {actual:?}",
            provider.type_name()
        );
    }
    Ok(())
}

#[derive(Default)]
struct SealedCompleteSetCollector {
    sets: BTreeMap<String, Vec<String>>,
    errors: Vec<anyhow::Error>,
}

impl<'ast> Visit<'ast> for SealedCompleteSetCollector {
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if let Err(error) = self.collect_sealed_impl(item) {
            self.errors.push(error);
        }
        visit::visit_item_impl(self, item);
    }
}

impl SealedCompleteSetCollector {
    fn collect_sealed_impl(&mut self, item: &syn::ItemImpl) -> Result<()> {
        let Some((_, trait_path, _)) = &item.trait_ else {
            return Ok(());
        };
        let Some(segment) = trait_path.segments.last() else {
            return Ok(());
        };
        if segment.ident != "SealedCompleteSet" {
            return Ok(());
        }
        let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
            bail!("`SealedCompleteSet` impl must use angle-bracketed provider type");
        };
        ensure!(
            args.args.len() == 1,
            "`SealedCompleteSet` impl must take exactly one provider type argument"
        );
        let syn::GenericArgument::Type(provider_ty) = &args.args[0] else {
            bail!("`SealedCompleteSet` provider argument must be a type");
        };
        let provider = type_path_leaf(provider_ty)
            .context("`SealedCompleteSet` provider argument must be a path type")?;
        let capabilities = tuple_type_leaves(item.self_ty.as_ref())
            .context("`SealedCompleteSet` self type must be an exact capability tuple")?;
        ensure!(
            self.sets.insert(provider.clone(), capabilities).is_none(),
            "duplicate `SealedCompleteSet<{provider}>` impl"
        );
        Ok(())
    }
}

fn type_path_leaf(ty: &Type) -> Result<String> {
    let Type::Path(path) = ty else {
        bail!("expected a path type");
    };
    ensure!(path.qself.is_none(), "qualified self types are not allowed");
    let Some(segment) = path.path.segments.last() else {
        bail!("empty path type");
    };
    ensure!(
        matches!(segment.arguments, syn::PathArguments::None),
        "path type arguments are not allowed"
    );
    Ok(segment.ident.to_string())
}

fn tuple_type_leaves(ty: &Type) -> Result<Vec<String>> {
    match ty {
        Type::Tuple(tuple) => tuple.elems.iter().map(type_path_leaf).collect(),
        Type::Path(_) => Ok(vec![type_path_leaf(ty)?]),
        _ => bail!("expected a tuple or path type"),
    }
}

fn validate_enum_variants(file: &syn::File, name: &str, expected: &[&str]) -> Result<()> {
    let matches = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Enum(item) if item.ident == name => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "testkit catalog must define exactly one `{name}` enum"
    );
    let actual = matches[0]
        .variants
        .iter()
        .map(|variant| {
            ensure!(
                matches!(variant.fields, syn::Fields::Unit) && variant.discriminant.is_none(),
                "testkit catalog `{name}::{}` must remain a unit variant without a discriminant",
                variant.ident
            );
            Ok(variant.ident.to_string())
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        actual
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied()),
        "testkit catalog `{name}` variants/order drifted: expected {expected:?}, found {actual:?}"
    );
    Ok(())
}

fn catalog_impl_items<'a>(file: &'a syn::File, type_name: &str) -> Vec<&'a ImplItem> {
    file.items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(item)
                if item.trait_.is_none()
                    && matches!(
                        item.self_ty.as_ref(),
                        Type::Path(path)
                            if path.qself.is_none() && path.path.is_ident(type_name)
                    ) =>
            {
                Some(item.items.iter())
            }
            _ => None,
        })
        .flatten()
        .collect()
}

fn validate_impl_const(
    file: &syn::File,
    type_name: &str,
    const_name: &str,
    expected: &str,
) -> Result<()> {
    let matches = catalog_impl_items(file, type_name)
        .into_iter()
        .filter_map(|item| match item {
            ImplItem::Const(item) if item.ident == const_name => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "testkit catalog must define exactly one `{type_name}::{const_name}`"
    );
    let expected = syn::parse_str::<syn::Expr>(expected)
        .with_context(|| format!("parse expected `{type_name}::{const_name}` projection"))?;
    ensure!(
        matches[0].expr.to_token_stream().to_string() == expected.to_token_stream().to_string(),
        "testkit catalog `{type_name}::{const_name}` projection drifted"
    );
    Ok(())
}

fn validate_impl_method(
    file: &syn::File,
    type_name: &str,
    method_name: &str,
    expected_block: &str,
) -> Result<()> {
    let matches = catalog_impl_items(file, type_name)
        .into_iter()
        .filter_map(|item| match item {
            ImplItem::Fn(item) if item.sig.ident == method_name => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "testkit catalog must define exactly one `{type_name}::{method_name}`"
    );
    let expected = syn::parse_str::<ItemFn>(&format!("fn expected() {expected_block}"))
        .with_context(|| format!("parse expected `{type_name}::{method_name}` projection"))?;
    ensure!(
        matches[0].block.to_token_stream().to_string()
            == expected.block.to_token_stream().to_string(),
        "testkit catalog `{type_name}::{method_name}` projection drifted"
    );
    Ok(())
}

const fn owner(provider: ProviderId) -> OwnerSpec {
    match provider {
        ProviderId::Postgres => OWNERS[0],
        ProviderId::Amqp => OWNERS[1],
        ProviderId::S3 => OWNERS[2],
    }
}

fn validate_shard(root: &Path, owner: OwnerSpec) -> Result<()> {
    let shard = owner.shard.spec();
    let matches = shard
        .units
        .iter()
        .filter(|unit| {
            unit.package == owner.package && unit.target == owner.target && unit.kind == owner.kind
        })
        .count();
    ensure!(
        matches == 1,
        "provider `{}` carrier {}/{}/{} must occur exactly once in shard `{}`",
        owner.provider.as_str(),
        owner.package,
        owner.target,
        target_kind(owner.kind),
        owner.shard.as_str()
    );
    let feature_scopes = shard
        .local_feature_scopes
        .iter()
        .filter(|scope| scope.package() == owner.package && scope.feature() == "integration")
        .count();
    ensure!(
        feature_scopes == 1,
        "provider `{}` shard `{}` must enable exactly one `{}/integration` feature scope",
        owner.provider.as_str(),
        owner.shard.as_str(),
        owner.package
    );
    validate_carrier_reachability(root, owner)?;
    Ok(())
}

fn validate_carrier_reachability(root: &Path, owner: OwnerSpec) -> Result<()> {
    match owner.provider {
        ProviderId::Postgres => validate_lib_module(
            root,
            "adapters/postgres/src/lib.rs",
            "integration_tests",
            INTEGRATION_TEST_CFG,
        ),
        ProviderId::Amqp => {
            validate_lib_module(
                root,
                "adapters/amqp/src/lib.rs",
                "publisher",
                "feature=\"backend\"",
            )?;
            validate_feature_reachability(
                root,
                "adapters/amqp/Cargo.toml",
                "integration",
                "backend",
            )
        }
        ProviderId::S3 => {
            let path = Path::new(owner.path);
            ensure!(
                path.parent()
                    .is_some_and(|parent| parent.ends_with("adapters/s3/tests"))
                    && path.file_stem().and_then(|stem| stem.to_str()) == Some(owner.target),
                "S3 provider catalog must be the direct Cargo integration-test root for target `{}`",
                owner.target
            );
            Ok(())
        }
    }
}

fn validate_lib_module(
    root: &Path,
    root_source: &str,
    module_name: &str,
    expected_cfg: &str,
) -> Result<()> {
    let path = root.join(root_source);
    let source = generated_file::read_stable_utf8_file(
        &path,
        MAX_RUST_SOURCE_BYTES,
        "provider carrier crate root",
    )?;
    let syntax = syn::parse_file(&source)
        .with_context(|| format!("parse provider carrier crate root {}", path.display()))?;
    let modules = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(module) if module.ident == module_name => Some(module),
            _ => None,
        })
        .collect::<Vec<_>>();
    ensure!(
        modules.len() == 1
            && modules[0].content.is_none()
            && modules[0].attrs.len() == 1
            && cfg_expression(&modules[0].attrs[0]).as_deref() == Some(expected_cfg),
        "provider carrier `{root_source}` must expose exactly `#[cfg({expected_cfg})] mod {module_name};`"
    );
    Ok(())
}

fn validate_feature_reachability(
    root: &Path,
    manifest: &str,
    from: &str,
    required: &str,
) -> Result<()> {
    let path = root.join(manifest);
    let source = generated_file::read_stable_utf8_file(
        &path,
        MAX_RUST_SOURCE_BYTES,
        "provider carrier Cargo manifest",
    )?;
    let manifest: toml::Value = toml::from_str(&source)
        .with_context(|| format!("parse provider carrier manifest {}", path.display()))?;
    let features = manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .context("provider carrier manifest is missing [features]")?;
    let mut pending = vec![from.to_string()];
    let mut visited = BTreeSet::new();
    while let Some(feature) = pending.pop() {
        if !visited.insert(feature.clone()) {
            continue;
        }
        let members = features
            .get(&feature)
            .and_then(toml::Value::as_array)
            .with_context(|| {
                format!("provider carrier feature `{feature}` is missing or not an array")
            })?;
        for member in members {
            let member = member.as_str().with_context(|| {
                format!("provider carrier feature `{feature}` has a non-string member")
            })?;
            if member == required {
                return Ok(());
            }
            if features.contains_key(member) {
                pending.push(member.to_string());
            }
        }
    }
    bail!(
        "provider carrier feature `{from}` must transitively enable `{required}` in {}",
        path.display()
    )
}

const fn target_kind(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::Lib => "lib",
        TargetKind::Test => "test",
    }
}

struct DiscoveredInvocation {
    path: String,
    source: syn::File,
    attrs: Vec<Attribute>,
    nested: bool,
    enrollment: RawEnrollment,
}

fn discover_invocations(root: &Path) -> Result<Vec<DiscoveredInvocation>> {
    validate_compile_fail_fixture_exclusions(root)?;
    let paths = tracked_rust_paths(root)?;
    let mut found = Vec::new();
    for path in paths {
        let relative = repository_label(root, &path)?;
        if COMPILE_FAIL_FIXTURES.contains(&relative.as_str()) {
            continue;
        }
        let source = generated_file::read_stable_utf8_file(
            &path,
            MAX_RUST_SOURCE_BYTES,
            "tracked provider catalog source",
        )
        .with_context(|| format!("read provider catalog source {}", path.display()))?;
        if !source.contains("provider_conformance_catalog!") {
            continue;
        }
        let syntax = syn::parse_file(&source)
            .with_context(|| format!("parse provider catalog source {}", path.display()))?;
        let mut collector = MacroCollector::default();
        collector.visit_file(&syntax);
        for (tokens, attrs, nested) in collector.invocations {
            found.push(DiscoveredInvocation {
                path: relative.clone(),
                source: syntax.clone(),
                attrs,
                nested,
                enrollment: syn::parse2(tokens)
                    .with_context(|| format!("parse provider catalog invocation in {relative}"))?,
            });
        }
    }
    Ok(found)
}

fn validate_compile_fail_fixture_exclusions(root: &Path) -> Result<()> {
    for relative in COMPILE_FAIL_FIXTURES {
        ensure!(
            root.join(relative).is_file(),
            "provider capability compile-fail exclusion `{relative}` does not exist"
        );
    }
    Ok(())
}

fn tracked_rust_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let output = external_cmd(
        ExternalProgram::SystemGit,
        &["ls-files", "-z", "--", "*.rs"],
        &[],
        Some(root),
    )
    .output()
    .context("enumerate tracked Rust sources for provider catalog")?;
    ensure!(
        output.status.success(),
        "`/usr/bin/git ls-files` failed while enumerating provider catalog inputs: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let mut paths = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| {
            let relative =
                std::str::from_utf8(path).context("tracked provider catalog path is not UTF-8")?;
            let relative = Path::new(relative);
            ensure!(
                relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
                "tracked provider catalog path is not canonical: {}",
                relative.display()
            );
            Ok(root.join(relative))
        })
        .collect::<Result<Vec<_>>>()?;
    paths.sort();
    paths.dedup();
    let mut readable_paths = Vec::with_capacity(paths.len());
    let mut total_bytes = 0_u64;
    for path in paths {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect tracked provider catalog source {}", path.display())
                });
            }
        };
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "tracked provider catalog source must be an ordinary non-symlink file: {}",
            path.display()
        );
        ensure!(
            metadata.len() <= MAX_RUST_SOURCE_BYTES,
            "tracked provider catalog source exceeds {} bytes: {}",
            MAX_RUST_SOURCE_BYTES,
            path.display()
        );
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .context("provider catalog tracked Rust byte count overflow")?;
        readable_paths.push(path);
    }
    ensure!(
        readable_paths.len() <= MAX_TRACKED_RUST_FILES,
        "provider catalog tracked Rust input count {} exceeds {}",
        readable_paths.len(),
        MAX_TRACKED_RUST_FILES
    );
    ensure!(
        total_bytes <= MAX_TRACKED_RUST_BYTES,
        "provider catalog tracked Rust inputs exceed {} bytes",
        MAX_TRACKED_RUST_BYTES
    );
    Ok(readable_paths)
}

fn repository_label(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .context("provider catalog carrier escaped workspace")?;
    ensure!(
        relative
            .components()
            .all(|component| matches!(component, Component::Normal(_))),
        "provider catalog carrier is not canonical"
    );
    relative
        .to_str()
        .map(|value| value.replace('\\', "/"))
        .context("provider catalog carrier is not UTF-8")
}

#[derive(Default)]
struct MacroCollector {
    invocations: Vec<(TokenStream, Vec<Attribute>, bool)>,
    depth: usize,
}

impl<'ast> Visit<'ast> for MacroCollector {
    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        self.depth += 1;
        visit::visit_item_mod(self, item);
        self.depth -= 1;
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.depth += 1;
        visit::visit_item_fn(self, item);
        self.depth -= 1;
    }

    fn visit_item_macro(&mut self, item: &'ast ItemMacro) {
        if item
            .mac
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "provider_conformance_catalog")
        {
            self.invocations
                .push((item.mac.tokens.clone(), item.attrs.clone(), self.depth != 0));
        }
        visit::visit_item_macro(self, item);
    }
}

struct RawEnrollment {
    provider: Ident,
    error: Type,
    capabilities: Vec<CapabilityRunner>,
}

impl Parse for RawEnrollment {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let provider_key: Ident = input.parse()?;
        ensure_ident(&provider_key, "provider")?;
        input.parse::<Token![:]>()?;
        let provider = input.parse()?;
        input.parse::<Token![,]>()?;
        let error_key: Ident = input.parse()?;
        ensure_ident(&error_key, "error")?;
        input.parse::<Token![:]>()?;
        let error = input.parse()?;
        input.parse::<Token![,]>()?;
        let capabilities_key: Ident = input.parse()?;
        ensure_ident(&capabilities_key, "capabilities")?;
        input.parse::<Token![:]>()?;
        let content;
        braced!(content in input);
        let pairs = Punctuated::<CapabilityRunner, Token![,]>::parse_terminated(&content)?;
        if !input.is_empty() {
            return Err(input.error("unexpected provider catalog tokens"));
        }
        Ok(Self {
            provider,
            error,
            capabilities: pairs.into_iter().collect(),
        })
    }
}

struct CapabilityRunner {
    capability: Ident,
    attrs: Vec<Attribute>,
    wrapper: Ident,
    behavior: SynPath,
}

impl Parse for CapabilityRunner {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let capability = input.parse()?;
        input.parse::<Token![=>]>()?;
        let content;
        braced!(content in input);
        let attrs = content.call(Attribute::parse_outer)?;
        let wrapper = content.parse()?;
        content.parse::<Token![=>]>()?;
        let behavior = content.parse()?;
        if !content.is_empty() {
            return Err(content.error("unexpected provider capability tokens"));
        }
        Ok(Self {
            capability,
            attrs,
            wrapper,
            behavior,
        })
    }
}

fn ensure_ident(actual: &Ident, expected: &str) -> syn::Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(syn::Error::new(
            actual.span(),
            format!("expected `{expected}`"),
        ))
    }
}

fn parse_provider(ident: &Ident) -> Result<ProviderId> {
    match ident.to_string().as_str() {
        "postgres" => Ok(ProviderId::Postgres),
        "amqp" => Ok(ProviderId::Amqp),
        "s3" => Ok(ProviderId::S3),
        other => bail!("unknown provider `{other}`"),
    }
}

fn validate_invocation_cfg(provider: ProviderId, attrs: &[Attribute]) -> Result<()> {
    match provider {
        ProviderId::Amqp => ensure!(
            attrs.len() == 1 && cfg_expression(&attrs[0]).as_deref() == Some(INTEGRATION_TEST_CFG),
            "AMQP catalog must use exactly #[cfg(all(test, feature = \"integration\"))]"
        ),
        ProviderId::Postgres | ProviderId::S3 => ensure!(
            attrs.is_empty(),
            "provider `{}` catalog cannot be conditionally compiled",
            provider.as_str()
        ),
    }
    Ok(())
}

fn cfg_expression(attr: &Attribute) -> Option<String> {
    let syn::Meta::List(list) = &attr.meta else {
        return None;
    };
    if !list.path.is_ident("cfg") {
        return None;
    }
    Some(
        list.tokens
            .to_string()
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect(),
    )
}

fn parse_capability(ident: &Ident) -> Result<CapabilityId> {
    match ident.to_string().as_str() {
        "identity" => Ok(CapabilityId::Identity),
        "conflict" => Ok(CapabilityId::Conflict),
        "fencing" => Ok(CapabilityId::Fencing),
        "budget" => Ok(CapabilityId::Budget),
        "commit_ack" => Ok(CapabilityId::CommitAck),
        "ambiguity" => Ok(CapabilityId::Ambiguity),
        "archive_receipt" => Ok(CapabilityId::ArchiveReceipt),
        other => {
            let allowed = CapabilityId::ALL.map(CapabilityId::macro_token).join(", ");
            bail!("unknown provider capability `{other}`; expected one of: {allowed}")
        }
    }
}

fn validate_capabilities(
    provider: ProviderId,
    raw: &[CapabilityRunner],
) -> Result<Vec<ValidatedCapability>> {
    ensure!(
        raw.len() == provider.capabilities().len(),
        "provider `{}` must enroll exactly {} capabilities, found {}",
        provider.as_str(),
        provider.capabilities().len(),
        raw.len()
    );
    let mut entries = Vec::with_capacity(raw.len());
    for (raw, expected) in raw.iter().zip(provider.capabilities()) {
        let capability = parse_capability(&raw.capability)?;
        ensure!(
            capability == *expected,
            "provider `{}` capability order/set drift: expected `{}`, found `{}`",
            provider.as_str(),
            expected.as_str(),
            capability.as_str()
        );
        ensure!(
            raw.behavior.leading_colon.is_none() && !raw.behavior.segments.is_empty(),
            "provider capability behavior must be a same-file function path"
        );
        ensure!(
            raw.behavior
                .segments
                .iter()
                .all(|segment| matches!(segment.arguments, syn::PathArguments::None)),
            "provider capability behavior cannot have generic arguments"
        );
        entries.push(ValidatedCapability {
            capability,
            attrs: raw.attrs.clone(),
            wrapper: raw.wrapper.to_string(),
            behavior: path_string(&raw.behavior),
        });
    }
    Ok(entries)
}

struct ValidatedCapability {
    capability: CapabilityId,
    attrs: Vec<Attribute>,
    wrapper: String,
    behavior: String,
}

fn path_string(path: &SynPath) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn validate_error_type(error: &Type) -> Result<()> {
    ensure!(
        matches!(error, Type::Path(path) if path.qself.is_none()),
        "provider catalog error must be a concrete path type"
    );
    Ok(())
}

fn validate_wrapper_attrs(
    provider: ProviderId,
    capability: CapabilityId,
    attrs: &[Attribute],
) -> Result<()> {
    ensure!(
        attrs.len() == 1 && is_tokio_test_attribute(&attrs[0]),
        "provider `{}` capability `{}` wrapper must have exactly one `#[tokio::test(...)]` attribute; cfg, ignore, should_panic, and extra attributes are forbidden",
        provider.as_str(),
        capability.as_str()
    );
    let tokens = attrs[0].meta.to_token_stream().to_string();
    ensure!(
        !tokens.contains("should_panic"),
        "provider capability wrapper cannot use should_panic"
    );
    Ok(())
}

#[derive(Clone)]
struct BehaviorState {
    item: ItemFn,
    live: bool,
}

fn provider_behaviors(file: &syn::File) -> Result<BTreeMap<String, Vec<BehaviorState>>> {
    let mut collector = BehaviorCollector::default();
    collector.visit_file(file);
    Ok(collector.behaviors)
}

#[derive(Default)]
struct BehaviorCollector {
    behaviors: BTreeMap<String, Vec<BehaviorState>>,
    modules: Vec<String>,
    module_live: Vec<bool>,
}

impl<'ast> Visit<'ast> for BehaviorCollector {
    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        let parent_live = self.module_live.last().copied().unwrap_or(true);
        let cfgs = item
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("cfg"))
            .collect::<Vec<_>>();
        let cfg_supported = cfgs.iter().all(|attr| {
            matches!(
                cfg_expression(attr).as_deref(),
                Some(cfg) if cfg == "test" || cfg == INTEGRATION_TEST_CFG
            )
        });
        let cfg_attr_absent = !item
            .attrs
            .iter()
            .any(|attr| attr.path().is_ident("cfg_attr"));
        self.modules.push(item.ident.to_string());
        self.module_live
            .push(parent_live && cfg_supported && cfg_attr_absent);
        visit::visit_item_mod(self, item);
        self.module_live.pop();
        self.modules.pop();
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        let mut segments = self.modules.clone();
        segments.push(item.sig.ident.to_string());
        let name = segments.join("::");
        let live = !has_attr(&item.attrs, "cfg")
            && !has_attr(&item.attrs, "cfg_attr")
            && self.module_live.last().copied().unwrap_or(true);
        self.behaviors.entry(name).or_default().push(BehaviorState {
            item: item.clone(),
            live,
        });
        visit::visit_item_fn(self, item);
    }
}

struct BehaviorSpec {
    path: &'static str,
    operation_anchor: &'static str,
    assertion_anchor: Option<&'static str>,
    trusted_assertion_call: Option<&'static str>,
}

#[allow(
    clippy::unreachable,
    reason = "the typed provider/capability registry closes the supported pair set"
)]
fn behavior_spec(provider: ProviderId, capability: CapabilityId) -> BehaviorSpec {
    match (provider, capability) {
        (ProviderId::Postgres, CapabilityId::Identity) => BehaviorSpec {
            path: "eventing_conformance_outbox_behavior",
            operation_anchor: "connect_pg",
            assertion_anchor: None,
            trusted_assertion_call: Some("eventconf::assert_outbox_relay_conformance"),
        },
        (ProviderId::Postgres, CapabilityId::Conflict) => BehaviorSpec {
            path: "outbox_append_distinguishes_same_fact_from_conflict_behavior",
            operation_anchor: "eventing_test_db(&store).test_write",
            assertion_anchor: Some("OutboxAppendError::Conflict"),
            trusted_assertion_call: None,
        },
        (ProviderId::Postgres, CapabilityId::Fencing) => BehaviorSpec {
            path: "settle_rejects_stale_lease_token_behavior",
            operation_anchor: "rss_outbox_settle_published",
            assertion_anchor: Some("\"lost_lease\""),
            trusted_assertion_call: None,
        },
        (ProviderId::Postgres, CapabilityId::Budget) => BehaviorSpec {
            path: "insufficient_preflight_budget_never_calls_publisher_behavior",
            operation_anchor: "outbox.relay",
            assertion_anchor: Some("*calls.lock().unwrap()"),
            trusted_assertion_call: None,
        },
        (ProviderId::Postgres, CapabilityId::CommitAck) => BehaviorSpec {
            path: "postgres_consumer_commit_ack_behavior",
            operation_anchor: "run_consumer_ackable",
            assertion_anchor: Some("AckAction::Ack"),
            trusted_assertion_call: None,
        },
        (ProviderId::Postgres, CapabilityId::Ambiguity) => BehaviorSpec {
            path: "relay_ambiguous_retries_with_original_event_id_behavior",
            operation_anchor: "outbox.relay",
            assertion_anchor: Some("vec![event_id.clone(),event_id]"),
            trusted_assertion_call: None,
        },
        (ProviderId::Postgres, CapabilityId::ArchiveReceipt) => BehaviorSpec {
            path: "dlx_verified_receipt_concurrent_cas_behavior",
            operation_anchor: "rss_dlx_record_archive_receipt",
            assertion_anchor: Some("outcomes"),
            trusted_assertion_call: None,
        },
        (ProviderId::Amqp, CapabilityId::Identity) => BehaviorSpec {
            path: "publisher_transport_replacement_integration_tests::broker_roundtrip_preserves_message_identity_behavior",
            operation_anchor: "publisher.publish",
            assertion_anchor: Some("delivery.message.id"),
            trusted_assertion_call: None,
        },
        (ProviderId::Amqp, CapabilityId::Fencing) => BehaviorSpec {
            path: "publish_pipeline_red_tests::transport_recovery_is_single_flight_and_generation_fenced_behavior",
            operation_anchor: "slot.install_replacement",
            assertion_anchor: Some("current.generation"),
            trusted_assertion_call: None,
        },
        (ProviderId::Amqp, CapabilityId::Budget) => BehaviorSpec {
            path: "publish_deadline_tests::elapsed_time_is_deducted_from_confirm_budget_behavior",
            operation_anchor: "run_publish_pipeline",
            assertion_anchor: Some("PublishPhase::Confirm"),
            trusted_assertion_call: None,
        },
        (ProviderId::Amqp, CapabilityId::Ambiguity) => BehaviorSpec {
            path: "publisher_transport_replacement_integration_tests::post_send_close_is_ambiguous_and_allows_same_id_retry_behavior",
            operation_anchor: "publisher.publish",
            assertion_anchor: Some("error.is_ambiguous()"),
            trusted_assertion_call: None,
        },
        (ProviderId::S3, CapabilityId::Identity) => BehaviorSpec {
            path: "provider_conformance_cases::identity",
            operation_anchor: "get_ciphertext",
            assertion_anchor: Some("ciphertext.key_ref().to_token()"),
            trusted_assertion_call: None,
        },
        (ProviderId::S3, CapabilityId::Conflict) => BehaviorSpec {
            path: "provider_conformance_cases::conflict",
            operation_anchor: "lifecycle.tick",
            assertion_anchor: Some("DlxLifecycleReason::CanonicalMismatch"),
            trusted_assertion_call: None,
        },
        (ProviderId::S3, CapabilityId::ArchiveReceipt) => BehaviorSpec {
            path: "provider_conformance_cases::archive_receipt",
            operation_anchor: "lifecycle.tick",
            assertion_anchor: Some("vec![\"claim\",\"receipt\",\"reconcile\",\"purge\"]"),
            trusted_assertion_call: None,
        },
        _ => unreachable!("unsupported provider/capability pair"),
    }
}

#[derive(Clone, Default)]
struct ReachableEvidence {
    operations: Vec<String>,
    assertions: Vec<String>,
    calls: BTreeSet<String>,
}

#[derive(Default)]
struct ReachableEvidenceCollector {
    operations: Vec<String>,
    assertions: Vec<String>,
    calls: BTreeSet<String>,
    local_closures: BTreeMap<String, ReachableEvidence>,
}

impl ReachableEvidenceCollector {
    fn evidence(&self) -> ReachableEvidence {
        ReachableEvidence {
            operations: self.operations.clone(),
            assertions: self.assertions.clone(),
            calls: self.calls.clone(),
        }
    }

    fn absorb(&mut self, evidence: ReachableEvidence) {
        self.operations.extend(evidence.operations);
        self.assertions.extend(evidence.assertions);
        self.calls.extend(evidence.calls);
    }
}

impl<'ast> Visit<'ast> for ReachableEvidenceCollector {
    fn visit_expr(&mut self, expression: &'ast Expr) {
        match expression {
            // Do not treat evidence inside a potentially unexecuted control-flow body as proof.
            Expr::If(_)
            | Expr::Match(_)
            | Expr::ForLoop(_)
            | Expr::While(_)
            | Expr::Loop(_)
            | Expr::Closure(_)
            | Expr::Async(_)
            | Expr::Const(_)
            | Expr::TryBlock(_) => return,
            Expr::Call(call) => {
                let path = compact_tokens(&call.func.to_token_stream().to_string());
                self.operations.push(path.clone());
                if matches!(call.func.as_ref(), Expr::Path(_)) {
                    self.calls.insert(path.clone());
                    if let Some(closure_evidence) = self.local_closures.get(&path).cloned() {
                        self.absorb(closure_evidence);
                    }
                }
            }
            Expr::MethodCall(call) => {
                self.operations.push(format!(
                    "{}.{}",
                    compact_tokens(&call.receiver.to_token_stream().to_string()),
                    call.method
                ));
            }
            Expr::Lit(literal) => self
                .operations
                .push(compact_tokens(&literal.to_token_stream().to_string())),
            Expr::Path(path) => self
                .operations
                .push(compact_tokens(&path.to_token_stream().to_string())),
            _ => {}
        }
        visit::visit_expr(self, expression);
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        let compact = compact_tokens(&item.to_token_stream().to_string());
        self.operations.push(compact.clone());
        let macro_name = item
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string());
        if macro_name
            .as_deref()
            .is_some_and(|name| matches!(name, "assert" | "assert_eq" | "assert_ne"))
        {
            self.assertions.push(compact);
        }
        visit::visit_macro(self, item);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let (syn::Pat::Ident(binding), Some(initializer)) = (&local.pat, &local.init)
            && let Expr::Closure(closure) = initializer.expr.as_ref()
        {
            let mut closure_collector = Self::default();
            closure_collector.visit_expr(&closure.body);
            self.local_closures
                .insert(binding.ident.to_string(), closure_collector.evidence());
            return;
        }
        visit::visit_local(self, local);
    }
}

fn validate_behavior(
    provider: ProviderId,
    capability: CapabilityId,
    behavior: &str,
    behaviors: &BTreeMap<String, Vec<BehaviorState>>,
) -> Result<String> {
    let spec = behavior_spec(provider, capability);
    ensure!(
        behavior == spec.path,
        "provider `{}` capability `{}` behavior must be canonical `{}`, found `{behavior}`",
        provider.as_str(),
        capability.as_str(),
        spec.path
    );
    let states = behaviors.get(behavior).with_context(|| {
        format!("declared provider capability behavior `{behavior}` does not exist")
    })?;
    ensure!(
        states.len() == 1,
        "provider capability behavior `{behavior}` resolves ambiguously to {} functions",
        states.len()
    );
    let state = &states[0];
    ensure!(
        state.live,
        "provider capability behavior `{behavior}` is cfg-gated by an unsupported owner"
    );
    let item = &state.item;
    ensure!(
        item.sig.asyncness.is_some()
            && item.sig.inputs.is_empty()
            && item.sig.generics.params.is_empty()
            && item.sig.generics.where_clause.is_none(),
        "provider capability behavior `{behavior}` must be a zero-argument non-generic async function"
    );
    ensure!(
        !item.attrs.iter().any(is_test_attribute)
            && !["ignore", "should_panic", "cfg", "cfg_attr"]
                .iter()
                .any(|name| has_attr(&item.attrs, name)),
        "provider capability behavior `{behavior}` cannot be a test, ignored, should_panic, or cfg-gated"
    );
    ensure!(
        item.block.stmts.len() >= 2,
        "provider capability behavior `{behavior}` must contain an observation/assertion and a successful tail"
    );
    let body = compact_tokens(&item.block.to_token_stream().to_string());
    ensure!(
        !["panic!", "todo!", "unimplemented!"]
            .iter()
            .any(|forbidden| body.contains(forbidden)),
        "provider capability behavior `{behavior}` cannot use panic/todo/unimplemented as evidence"
    );
    ensure!(
        !body.contains("returnOk(())"),
        "provider capability behavior `{behavior}` cannot return success before its evidence"
    );
    ensure!(
        item.block
            .stmts
            .last()
            .is_some_and(
                |statement| compact_tokens(&statement.to_token_stream().to_string()) == "Ok(())"
            ),
        "provider capability behavior `{behavior}` must end in `Ok(())`"
    );
    let mut evidence = ReachableEvidenceCollector::default();
    for statement in &item.block.stmts {
        evidence.visit_stmt(statement);
    }
    ensure!(
        evidence
            .operations
            .iter()
            .any(|operation| operation.contains(spec.operation_anchor)),
        "provider `{}` capability `{}` behavior `{behavior}` lost reachable operation anchor `{}`",
        provider.as_str(),
        capability.as_str(),
        spec.operation_anchor
    );
    if let Some(anchor) = spec.assertion_anchor {
        ensure!(
            evidence
                .assertions
                .iter()
                .any(|assertion| assertion.contains(anchor)),
            "provider `{}` capability `{}` behavior `{behavior}` lost reachable assertion anchor `{anchor}`",
            provider.as_str(),
            capability.as_str()
        );
    }
    if let Some(trusted_call) = spec.trusted_assertion_call {
        ensure!(
            evidence.calls.contains(trusted_call),
            "provider `{}` capability `{}` behavior `{behavior}` lost reachable trusted assertion call `{trusted_call}`",
            provider.as_str(),
            capability.as_str()
        );
    }
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(item.block.to_token_stream().to_string().as_bytes())
    ))
}

fn compact_tokens(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn has_attr(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == name)
    })
}

fn is_test_attribute(attr: &Attribute) -> bool {
    let segments = attr
        .path()
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    matches!(segments.as_slice(), [test] if test == "test")
        || matches!(segments.as_slice(), [runtime, test] if runtime == "tokio" && test == "test")
}

fn is_tokio_test_attribute(attr: &Attribute) -> bool {
    let segments = attr
        .path()
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    matches!(segments.as_slice(), [runtime, test] if runtime == "tokio" && test == "test")
}

fn render_diagnostic(catalog: &ValidatedProviderCatalog) -> Result<Vec<u8>> {
    let report = DiagnosticReport::from(catalog);
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    ensure!(
        !bytes.contains(&b'\r'),
        "rendered provider capability diagnostic contains CR"
    );
    while bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    bytes.push(b'\n');
    Ok(bytes)
}

fn publish_diagnostic(root: &Path, catalog: &ValidatedProviderCatalog) -> Result<PathBuf> {
    let output = root.join(DIAGNOSTIC_OUTPUT);
    generated_file::atomic_replace(&output, &render_diagnostic(catalog)?)?;
    Ok(output)
}

struct ValidatedProviderCatalog {
    providers: Vec<ValidatedProvider>,
}

impl ValidatedProviderCatalog {
    fn enrollment_count(&self) -> usize {
        self.providers
            .iter()
            .map(|provider| provider.capabilities.len())
            .sum()
    }
}

struct ValidatedProvider {
    provider: &'static str,
    capabilities: Vec<CatalogCapability>,
}

struct CatalogCapability {
    capability: &'static str,
    carrier: ValidatedCarrier,
}

struct ValidatedCarrier {
    package: &'static str,
    target: &'static str,
    kind: &'static str,
    path: &'static str,
    symbol: String,
    behavior: String,
    behavior_sha256: String,
    shard: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticReport<'a> {
    provider_count: usize,
    capability_count: usize,
    enrollment_count: usize,
    providers: Vec<DiagnosticProvider<'a>>,
}

impl<'a> From<&'a ValidatedProviderCatalog> for DiagnosticReport<'a> {
    fn from(catalog: &'a ValidatedProviderCatalog) -> Self {
        Self {
            provider_count: catalog.providers.len(),
            capability_count: CapabilityId::ALL.len(),
            enrollment_count: catalog.enrollment_count(),
            providers: catalog
                .providers
                .iter()
                .map(DiagnosticProvider::from)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct DiagnosticProvider<'a> {
    provider: &'a str,
    capabilities: Vec<DiagnosticCapability<'a>>,
}

impl<'a> From<&'a ValidatedProvider> for DiagnosticProvider<'a> {
    fn from(provider: &'a ValidatedProvider) -> Self {
        Self {
            provider: provider.provider,
            capabilities: provider
                .capabilities
                .iter()
                .map(DiagnosticCapability::from)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct DiagnosticCapability<'a> {
    capability: &'a str,
    carrier: DiagnosticCarrier<'a>,
}

impl<'a> From<&'a CatalogCapability> for DiagnosticCapability<'a> {
    fn from(capability: &'a CatalogCapability) -> Self {
        Self {
            capability: capability.capability,
            carrier: DiagnosticCarrier::from(&capability.carrier),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticCarrier<'a> {
    package: &'a str,
    target: &'a str,
    kind: &'a str,
    path: &'a str,
    symbol: &'a str,
    behavior: &'a str,
    behavior_sha256: &'a str,
    shard: &'a str,
}

impl<'a> From<&'a ValidatedCarrier> for DiagnosticCarrier<'a> {
    fn from(carrier: &'a ValidatedCarrier) -> Self {
        Self {
            package: carrier.package,
            target: carrier.target,
            kind: carrier.kind,
            path: carrier.path,
            symbol: &carrier.symbol,
            behavior: &carrier.behavior,
            behavior_sha256: &carrier.behavior_sha256,
            shard: carrier.shard,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TESTKIT_CATALOG_FIXTURE: &str = r#"
        pub enum ProviderId {
            Postgres,
            Amqp,
            S3,
        }

        impl ProviderId {
            pub const ALL: [Self; 3] = [Self::Postgres, Self::Amqp, Self::S3];

            pub const fn as_str(self) -> &'static str {
                match self {
                    Self::Postgres => "postgres",
                    Self::Amqp => "amqp",
                    Self::S3 => "s3",
                }
            }

            pub const fn capabilities(self) -> &'static [CapabilityId] {
                match self {
                    Self::Postgres => &CapabilityId::ALL,
                    Self::Amqp => &[
                        CapabilityId::Identity,
                        CapabilityId::Fencing,
                        CapabilityId::Budget,
                        CapabilityId::Ambiguity,
                    ],
                    Self::S3 => &[
                        CapabilityId::Identity,
                        CapabilityId::Conflict,
                        CapabilityId::ArchiveReceipt,
                    ],
                }
            }
        }

        pub enum CapabilityId {
            Identity,
            Conflict,
            Fencing,
            Budget,
            CommitAck,
            Ambiguity,
            ArchiveReceipt,
        }

        impl CapabilityId {
            pub const ALL: [Self; 7] = [
                Self::Identity,
                Self::Conflict,
                Self::Fencing,
                Self::Budget,
                Self::CommitAck,
                Self::Ambiguity,
                Self::ArchiveReceipt,
            ];

            pub const fn as_str(self) -> &'static str {
                match self {
                    Self::Identity => "identity",
                    Self::Conflict => "conflict",
                    Self::Fencing => "fencing",
                    Self::Budget => "budget",
                    Self::CommitAck => "commit-ack",
                    Self::Ambiguity => "ambiguity",
                    Self::ArchiveReceipt => "archive-receipt",
                }
            }
        }

        pub mod __catalog {
            pub enum Postgres {}
            pub enum Amqp {}
            pub enum S3 {}
            pub enum Identity {}
            pub enum Conflict {}
            pub enum Fencing {}
            pub enum Budget {}
            pub enum CommitAck {}
            pub enum Ambiguity {}
            pub enum ArchiveReceipt {}

            mod private {
                pub trait SealedCompleteSet<Provider> {}

                impl SealedCompleteSet<super::Postgres>
                    for (
                        super::Identity,
                        super::Conflict,
                        super::Fencing,
                        super::Budget,
                        super::CommitAck,
                        super::Ambiguity,
                        super::ArchiveReceipt,
                    )
                {
                }

                impl SealedCompleteSet<super::Amqp>
                    for (
                        super::Identity,
                        super::Fencing,
                        super::Budget,
                        super::Ambiguity,
                    )
                {
                }

                impl SealedCompleteSet<super::S3>
                    for (super::Identity, super::Conflict, super::ArchiveReceipt)
                {
                }
            }
        }
    "#;

    fn parse(raw: &str) -> Result<RawEnrollment> {
        syn::parse_str(raw).map_err(Into::into)
    }

    #[test]
    fn compile_fail_fixture_exclusions_exist() -> Result<()> {
        validate_compile_fail_fixture_exclusions(&crate::workspace_root()?)
    }

    #[test]
    fn testkit_catalog_projection_drift_fails() -> Result<()> {
        validate_testkit_catalog_source(TESTKIT_CATALOG_FIXTURE)?;

        let variant_drift = TESTKIT_CATALOG_FIXTURE.replacen("            S3,\n", "", 1);
        assert!(
            validate_testkit_catalog_source(&variant_drift).is_err(),
            "provider enum drift must fail"
        );

        let wire_drift = TESTKIT_CATALOG_FIXTURE.replacen("\"amqp\"", "\"rabbitmq\"", 1);
        assert!(
            validate_testkit_catalog_source(&wire_drift).is_err(),
            "provider wire mapping drift must fail"
        );

        let subset_drift = TESTKIT_CATALOG_FIXTURE.replacen(
            "CapabilityId::Budget,\n                        CapabilityId::Ambiguity,",
            "CapabilityId::Conflict,\n                        CapabilityId::Ambiguity,",
            1,
        );
        assert!(
            validate_testkit_catalog_source(&subset_drift).is_err(),
            "provider capability subset drift must fail"
        );

        let all_order_drift = TESTKIT_CATALOG_FIXTURE.replacen(
            "Self::Identity,\n                Self::Conflict,",
            "Self::Conflict,\n                Self::Identity,",
            1,
        );
        assert!(
            validate_testkit_catalog_source(&all_order_drift).is_err(),
            "canonical capability order drift must fail"
        );

        let sealed_order_drift = TESTKIT_CATALOG_FIXTURE.replacen(
            "for (super::Identity, super::Conflict, super::ArchiveReceipt)",
            "for (super::Conflict, super::Identity, super::ArchiveReceipt)",
            1,
        );
        assert!(
            validate_testkit_catalog_source(&sealed_order_drift).is_err(),
            "sealed complete-set order drift must fail"
        );
        Ok(())
    }

    #[test]
    fn untracked_invocation_is_outside_canonical_scan() -> Result<()> {
        let root = crate::testutil::unique_tmp("provider-capability-cache");
        let cache = root.join(".cache");
        fs::create_dir_all(&cache)?;
        fs::write(root.join("tracked.rs"), "fn tracked() {}\n")?;
        let init =
            external_cmd(ExternalProgram::SystemGit, &["init"], &[], Some(&root)).output()?;
        assert!(init.status.success());
        let add = external_cmd(
            ExternalProgram::SystemGit,
            &["add", "tracked.rs"],
            &[],
            Some(&root),
        )
        .output()?;
        assert!(add.status.success());
        fs::write(
            cache.join("bait.rs"),
            "testkit::provider_conformance_catalog! {
                provider: s3,
                error: TestError,
                capabilities: {
                    identity => {
                        #[tokio::test]
                        identity_wrapper => provider_conformance_cases::identity
                    },
                    conflict => {
                        #[tokio::test]
                        conflict_wrapper => provider_conformance_cases::conflict
                    },
                    archive_receipt => {
                        #[tokio::test]
                        archive_wrapper => provider_conformance_cases::archive_receipt
                    },
                }
            }",
        )?;

        assert!(
            discover_invocations(&root)?.is_empty(),
            "untracked bait must not enter the canonical source scan"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn detached_carrier_and_feature_drift_fail_closed() -> Result<()> {
        let root = crate::testutil::unique_tmp("provider-capability-reachability");
        fs::create_dir_all(&root)?;
        let lib = root.join("lib.rs");
        fs::write(
            &lib,
            "#[cfg(all(test, feature = \"integration\"))]\nmod integration_tests;\n",
        )?;
        validate_lib_module(&root, "lib.rs", "integration_tests", INTEGRATION_TEST_CFG)?;
        fs::write(&lib, "#[cfg(any())]\nmod integration_tests;\n")?;
        assert!(
            validate_lib_module(&root, "lib.rs", "integration_tests", INTEGRATION_TEST_CFG,)
                .is_err(),
            "detached or cfg-disabled carrier module must fail"
        );

        let manifest = root.join("Cargo.toml");
        fs::write(
            &manifest,
            "[features]\nintegration = [\"integration-test-support\"]\nintegration-test-support = [\"backend\"]\nbackend = []\n",
        )?;
        validate_feature_reachability(&root, "Cargo.toml", "integration", "backend")?;
        fs::write(
            &manifest,
            "[features]\nintegration = [\"integration-test-support\"]\nintegration-test-support = []\nbackend = []\n",
        )?;
        assert!(
            validate_feature_reachability(&root, "Cargo.toml", "integration", "backend").is_err(),
            "integration feature detached from backend must fail"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn tracked_nonordinary_or_oversized_sources_fail_closed() -> Result<()> {
        let root = crate::testutil::unique_tmp("provider-capability-input-bounds");
        fs::create_dir_all(&root)?;
        let source = root.join("tracked.rs");
        fs::write(&source, "fn tracked() {}\n")?;
        assert!(
            external_cmd(ExternalProgram::SystemGit, &["init"], &[], Some(&root))
                .status()?
                .success()
        );
        assert!(
            external_cmd(
                ExternalProgram::SystemGit,
                &["add", "tracked.rs"],
                &[],
                Some(&root)
            )
            .status()?
            .success()
        );

        fs::write(&source, vec![b'x'; MAX_RUST_SOURCE_BYTES as usize + 1])?;
        assert!(
            tracked_rust_paths(&root).is_err(),
            "oversized tracked Rust source must fail before parsing"
        );

        fs::remove_file(&source)?;
        fs::create_dir(&source)?;
        assert!(
            tracked_rust_paths(&root).is_err(),
            "non-ordinary tracked Rust path must fail before reading"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn duplicate_unknown_or_wrong_order_enrollment_fails() -> Result<()> {
        let wrong = parse(
            "provider: s3,
             error: TestError,
             capabilities: {
                conflict => { #[tokio::test] conflict_wrapper => provider_conformance_cases::conflict },
                identity => { #[tokio::test] identity_wrapper => provider_conformance_cases::identity },
                archive_receipt => { #[tokio::test] archive_wrapper => provider_conformance_cases::archive_receipt },
            }",
        )?;
        assert!(
            validate_capabilities(ProviderId::S3, &wrong.capabilities).is_err(),
            "wrong order must fail"
        );
        let duplicate = parse(
            "provider: s3,
             error: TestError,
             capabilities: {
                identity => { #[tokio::test] identity_wrapper => provider_conformance_cases::identity },
                identity => { #[tokio::test] another_wrapper => provider_conformance_cases::identity },
                archive_receipt => { #[tokio::test] archive_wrapper => provider_conformance_cases::archive_receipt },
            }",
        )?;
        assert!(
            validate_capabilities(ProviderId::S3, &duplicate.capabilities).is_err(),
            "duplicate capability must fail"
        );
        assert!(
            syn::parse_str::<RawEnrollment>(
                "provider: s3,
                 error: TestError,
                 capabilities: {
                    unknown => { #[tokio::test] wrapper => provider_conformance_cases::unknown }
                 }"
            )
            .is_ok()
        );
        assert!(
            validate_capabilities(
                ProviderId::S3,
                &parse(
                    "provider: s3,
                     error: TestError,
                     capabilities: {
                        unknown => { #[tokio::test] wrapper => provider_conformance_cases::unknown }
                     }"
                )?
                .capabilities
            )
            .is_err(),
            "unknown capability must fail"
        );
        Ok(())
    }

    #[test]
    fn declared_capability_without_behavior_fails() -> Result<()> {
        let syntax = syn::parse_file(
            "mod provider_conformance_cases {
                async fn another_behavior() -> Result<(), Error> {
                    setup();
                    observe().await?;
                    Ok(())
                }
            }",
        )?;
        let behaviors = provider_behaviors(&syntax)?;
        assert!(
            validate_behavior(
                ProviderId::S3,
                CapabilityId::Identity,
                "provider_conformance_cases::identity",
                &behaviors,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn noop_unrelated_and_decorated_behaviors_fail() -> Result<()> {
        let noop = syn::parse_file(
            "mod provider_conformance_cases {
                async fn identity() -> Result<(), Error> {
                    ready(()).await;
                    let _ = ();
                    Ok(())
                }
            }",
        )?;
        let noop_behaviors = provider_behaviors(&noop)?;
        assert!(
            validate_behavior(
                ProviderId::S3,
                CapabilityId::Identity,
                "provider_conformance_cases::identity",
                &noop_behaviors,
            )
            .is_err(),
            "two-statement semantic noop plus success tail must fail"
        );

        let decorated = syn::parse_file(
            "mod provider_conformance_cases {
                #[tokio::test]
                async fn identity() -> Result<(), Error> {
                    let ciphertext = store.get_ciphertext().await?;
                    assert!(ciphertext.key_ref().to_token() == \"x\");
                    Ok(())
                }
            }",
        )?;
        assert!(
            validate_behavior(
                ProviderId::S3,
                CapabilityId::Identity,
                "provider_conformance_cases::identity",
                &provider_behaviors(&decorated)?,
            )
            .is_err(),
            "decorated behavior must fail"
        );

        let valid = syn::parse_file(
            "mod provider_conformance_cases {
                async fn identity() -> Result<(), Error> {
                    let ciphertext = store.get_ciphertext().await?;
                    assert!(ciphertext.key_ref().to_token() == \"x\");
                    Ok(())
                }
            }",
        )?;
        validate_behavior(
            ProviderId::S3,
            CapabilityId::Identity,
            "provider_conformance_cases::identity",
            &provider_behaviors(&valid)?,
        )?;
        assert!(
            validate_behavior(
                ProviderId::S3,
                CapabilityId::Identity,
                "provider_conformance_cases::unrelated",
                &provider_behaviors(&valid)?,
            )
            .is_err(),
            "unrelated behavior cannot carry identity"
        );

        let unreachable = syn::parse_file(
            "mod provider_conformance_cases {
                async fn identity() -> Result<(), Error> {
                    if false {
                        let ciphertext = store.get_ciphertext().await?;
                        assert!(ciphertext.key_ref().to_token() == \"x\");
                    }
                    Ok(())
                }
            }",
        )?;
        assert!(
            validate_behavior(
                ProviderId::S3,
                CapabilityId::Identity,
                "provider_conformance_cases::identity",
                &provider_behaviors(&unreachable)?,
            )
            .is_err(),
            "evidence hidden in unreachable control flow must fail"
        );

        let good_attr: Attribute = syn::parse_quote!(#[tokio::test(start_paused = true)]);
        validate_wrapper_attrs(
            ProviderId::Amqp,
            CapabilityId::Budget,
            std::slice::from_ref(&good_attr),
        )?;
        for bad in [
            syn::parse_quote!(#[test]),
            syn::parse_quote!(#[ignore]),
            syn::parse_quote!(#[should_panic]),
            syn::parse_quote!(#[cfg(test)]),
        ] {
            assert!(
                validate_wrapper_attrs(ProviderId::Amqp, CapabilityId::Budget, &[bad]).is_err()
            );
        }

        let nested_catalog = syn::parse_file(
            "#[cfg(any())] mod bait {
                testkit::provider_conformance_catalog! {
                    provider: s3,
                    error: TestError,
                    capabilities: {
                        identity => {
                            #[tokio::test]
                            identity_wrapper => provider_conformance_cases::identity
                        },
                        conflict => {
                            #[tokio::test]
                            conflict_wrapper => provider_conformance_cases::conflict
                        },
                        archive_receipt => {
                            #[tokio::test]
                            archive_wrapper => provider_conformance_cases::archive_receipt
                        },
                    }
                }
            }",
        )?;
        let mut catalogs = MacroCollector::default();
        catalogs.visit_file(&nested_catalog);
        assert_eq!(catalogs.invocations.len(), 1);
        assert!(catalogs.invocations[0].2);
        Ok(())
    }

    #[test]
    fn semantic_check_does_not_publish_report() -> Result<()> {
        let root = crate::workspace_root()?;
        let diagnostic = root.join(DIAGNOSTIC_OUTPUT);
        let diagnostic_before = fs::read(&diagnostic).ok();

        run_at(&root, true)?;
        assert_eq!(fs::read(&diagnostic).ok(), diagnostic_before);
        Ok(())
    }

    #[test]
    fn diagnostic_render_is_deterministic_but_not_a_versioned_receipt() -> Result<()> {
        let catalog = validate_catalog(&crate::workspace_root()?)?;
        let first = render_diagnostic(&catalog)?;
        assert_eq!(first, render_diagnostic(&catalog)?);
        assert!(first.ends_with(b"\n"));
        assert!(!first.ends_with(b"\n\n"));
        let rendered = std::str::from_utf8(&first)?;
        for retired in ["\"schemaVersion\"", "\"receipt\"", "\"status\""] {
            assert!(
                !rendered.contains(retired),
                "diagnostic retained retired contract token `{retired}`"
            );
        }
        Ok(())
    }

    #[test]
    fn diagnostic_publish_is_target_local_exact_and_overwrites() -> Result<()> {
        let catalog = validate_catalog(&crate::workspace_root()?)?;
        let rendered = render_diagnostic(&catalog)?;
        let root = crate::testutil::unique_tmp("provider-capability-diagnostic");
        let expected = root.join(DIAGNOSTIC_OUTPUT);
        fs::create_dir_all(expected.parent().context("diagnostic parent missing")?)?;
        fs::write(&expected, b"stale\n")?;

        let path = publish_diagnostic(&root, &catalog)?;
        assert_eq!(path, expected);
        assert_eq!(fs::read(&path)?, rendered);

        fs::write(&expected, b"tampered\n")?;
        let path = publish_diagnostic(&root, &catalog)?;
        assert_eq!(path, expected);
        assert_eq!(fs::read(&path)?, rendered);
        assert!(!root.join("generated").exists());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn workspace_provider_capability_wrappers_and_behaviors_are_exact_and_live() -> Result<()> {
        let catalog = validate_catalog(&crate::workspace_root()?)?;
        let actual = catalog
            .providers
            .iter()
            .map(|provider| {
                (
                    provider.provider,
                    provider
                        .capabilities
                        .iter()
                        .map(|capability| capability.capability)
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        let expected = ProviderId::ALL
            .into_iter()
            .map(|provider| {
                (
                    provider.as_str(),
                    provider
                        .capabilities()
                        .iter()
                        .copied()
                        .map(CapabilityId::as_str)
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        assert_eq!(catalog.providers.len(), ProviderId::ALL.len());
        Ok(())
    }
}
