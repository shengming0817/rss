//! `runtime-deps guard` -- `SharedRuntimeDeps` infra-only field guard.
//!
//! INVARIANT: WIRING-DEPS-INFRA-ONLY-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::config_file_is_required_and_malformed_toml_fails_closed", anti_vacuity = "tests::real_shared_runtime_deps_currently_passes" }.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use quote::ToTokens as _;
use serde::Deserialize;
use syn::{
    Fields, GenericArgument, Item, PathArguments, ReturnType, Type, TypeParamBound, TypePath,
    UseTree,
};

use crate::diagnostic::{Finding, GovernanceCheck, finding};

const CONFIG_PATH: &str = "xtask/runtime-deps-guard.toml";
const STRUCT_NAME: &str = "SharedRuntimeDeps";
const EXACT_DOMAIN_TRANSPORT_ARC: &str = "Arc<dyn distributed::DomainTransport>";
const EXACT_PASSWORD_BLOCKLIST_ARC: &str = "Arc<secure::DigestPasswordBlocklist>";
const EXACT_OIDC_PROVIDER_ARC: &str = "Arc<oidc::OidcProvider>";
const EXACT_POSTGRES_REVOCATION_STORE: &str = "postgres::PgRevocationStore";
const EXACT_SETTINGS_READINESS_INTERVAL: &str =
    "settings_composition::KeyProviderReadinessInterval";
const EXACT_VAULT_SIGNER_ARC: &str = "Arc<vault::VaultSigner>";
const SUPPORTED_EXACT_EXCEPTIONS: &[&str] = &[
    EXACT_DOMAIN_TRANSPORT_ARC,
    EXACT_PASSWORD_BLOCKLIST_ARC,
    EXACT_OIDC_PROVIDER_ARC,
    EXACT_POSTGRES_REVOCATION_STORE,
    EXACT_SETTINGS_READINESS_INTERVAL,
    EXACT_VAULT_SIGNER_ARC,
];
const FORBIDDEN_BROAD_ROOTS: &[&str] = &["std", "core", "alloc"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    MissingSharedRuntimeDeps,
    UnsupportedSharedRuntimeDepsShape,
    EmptySharedRuntimeDeps,
    DisallowedFieldType,
}

pub(crate) struct RuntimeDepsGuard;

impl GovernanceCheck for RuntimeDepsGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "runtime-deps-guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Rule>>)> {
        let root = crate::workspace_root()?;
        let policy = RuntimeDepsPolicy::from_workspace(&root)?;
        let paths = discover_shared_runtime_deps_paths(&root)?;
        let mut findings = Vec::new();
        for path in paths {
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(path.as_path())
                .to_path_buf();
            let content = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("runtime-deps-guard: read {}: {e}", path.display()))?;
            findings.extend(scan_source_with_policy(&rel, &content, &policy)?);
        }
        Ok((
            "SharedRuntimeDeps fields are restricted to infrastructure/value-object types"
                .to_string(),
            findings,
        ))
    }
}

/// Discover every production `SharedRuntimeDeps` under `assemblies/*/src`.
///
/// New assemblies that introduce the carrier are covered automatically; an empty discovery set
/// fails closed so the guard cannot go vacuous.
fn discover_shared_runtime_deps_paths(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut paths = Vec::new();
    for assembly_dir in crate::src_scan::member_dirs(&root.join("assemblies"))? {
        for rs in crate::src_scan::rs_files(&assembly_dir.join("src"))? {
            let content = std::fs::read_to_string(&rs)
                .map_err(|e| anyhow::anyhow!("runtime-deps-guard: read {}: {e}", rs.display()))?;
            if !content.contains(&format!("struct {STRUCT_NAME}")) {
                continue;
            }
            let file = syn::parse_file(&content)
                .with_context(|| format!("runtime-deps-guard: parse {}", rs.display()))?;
            if shared_runtime_deps_struct(&file).is_some() {
                paths.push(rs);
            }
        }
    }
    paths.sort();
    if paths.is_empty() {
        bail!("runtime-deps-guard: no `{STRUCT_NAME}` found under assemblies/*/src");
    }
    Ok(paths)
}

#[cfg(test)]
fn scan_source(path: &Path, content: &str) -> Result<Vec<Finding<Rule>>> {
    let root = crate::workspace_root()?;
    let policy = RuntimeDepsPolicy::from_workspace(&root)?;
    scan_source_with_policy(path, content, &policy)
}

fn scan_source_with_policy(
    path: &Path,
    content: &str,
    policy: &RuntimeDepsPolicy,
) -> Result<Vec<Finding<Rule>>> {
    let file = syn::parse_file(content)
        .with_context(|| format!("runtime-deps-guard: parse {}", path.display()))?;
    let resolver = collect_type_resolver(&file);
    let Some(item) = shared_runtime_deps_struct(&file) else {
        return Ok(vec![finding(
            Rule::MissingSharedRuntimeDeps,
            path.display().to_string(),
            format!("missing `{STRUCT_NAME}` struct; guard would otherwise be vacuous"),
        )]);
    };
    let Fields::Named(fields) = &item.fields else {
        return Ok(vec![finding(
            Rule::UnsupportedSharedRuntimeDepsShape,
            format!("{}:{STRUCT_NAME}", path.display()),
            "`SharedRuntimeDeps` must use named fields",
        )]);
    };
    if fields.named.is_empty() {
        return Ok(vec![finding(
            Rule::EmptySharedRuntimeDeps,
            format!("{}:{STRUCT_NAME}", path.display()),
            "`SharedRuntimeDeps` has no fields; guard would otherwise be vacuous",
        )]);
    }

    let mut findings = Vec::new();
    for field in &fields.named {
        let name = field
            .ident
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<unnamed>".to_string());
        if !is_allowed_field_type(&field.ty, &resolver, policy) {
            let rendered = render_type(&field.ty);
            let resolved = resolved_type_summary(&field.ty, &resolver);
            findings.push(finding(
                Rule::DisallowedFieldType,
                format!("{}:{STRUCT_NAME}.{name}", path.display()),
                format!(
                    "field `{name}` has type `{rendered}` (resolved `{resolved}`); allowed roots: {}; exact exceptions: {}",
                    policy.allowed_roots().join(", "),
                    policy.exact_exceptions().join(", ")
                ),
            ));
        }
    }
    Ok(findings)
}

#[derive(Debug)]
struct RuntimeDepsPolicy {
    allowed_roots: BTreeSet<String>,
    exact_exceptions: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeDepsPolicyToml {
    schema_version: u32,
    allowed_roots: Vec<String>,
    exact_exceptions: Vec<String>,
}

impl RuntimeDepsPolicy {
    fn from_workspace(root: &Path) -> Result<Self> {
        let path = root.join(CONFIG_PATH);
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("runtime-deps-guard: read {}", path.display()))?;
        Self::from_toml_str_with_root(&raw, root)
            .with_context(|| format!("runtime-deps-guard: validate {}", path.display()))
    }

    #[cfg(test)]
    fn from_toml_str(raw: &str) -> Result<Self> {
        let root = crate::workspace_root()?;
        Self::from_toml_str_with_root(raw, &root)
    }

    fn from_toml_str_with_root(raw: &str, root: &Path) -> Result<Self> {
        let config: RuntimeDepsPolicyToml =
            toml::from_str(raw).context("runtime-deps-guard: parse config TOML")?;
        if config.schema_version != 1 {
            bail!(
                "runtime-deps-guard: schemaVersion must be 1, got {}",
                config.schema_version
            );
        }
        if config.allowed_roots.is_empty() {
            bail!("runtime-deps-guard: allowedRoots must not be empty");
        }

        let mut allowed_roots = BTreeSet::new();
        for root_name in config.allowed_roots {
            validate_root_name(&root_name)?;
            if !allowed_roots.insert(root_name.clone()) {
                bail!("runtime-deps-guard: duplicate allowed root `{root_name}`");
            }
            validate_allowed_root(root, &root_name)?;
        }

        let mut exact_exceptions = BTreeSet::new();
        for exception in config.exact_exceptions {
            if exception.trim() != exception || exception.is_empty() {
                bail!("runtime-deps-guard: exact exception must not be empty or padded");
            }
            if !SUPPORTED_EXACT_EXCEPTIONS.contains(&exception.as_str()) {
                bail!("runtime-deps-guard: unsupported exact exception `{exception}`");
            }
            if !exact_exceptions.insert(exception.clone()) {
                bail!("runtime-deps-guard: duplicate exact exception `{exception}`");
            }
        }

        Ok(Self {
            allowed_roots,
            exact_exceptions,
        })
    }

    fn allowed_roots(&self) -> Vec<&str> {
        self.allowed_roots.iter().map(String::as_str).collect()
    }

    fn exact_exceptions(&self) -> Vec<&str> {
        self.exact_exceptions.iter().map(String::as_str).collect()
    }

    fn allows_root(&self, root: &str) -> bool {
        self.allowed_roots.contains(root)
    }

    fn allows_domain_transport_arc(&self) -> bool {
        self.exact_exceptions.contains(EXACT_DOMAIN_TRANSPORT_ARC)
    }

    fn allows_exact_exception(&self, exception: &str) -> bool {
        self.exact_exceptions.contains(exception)
    }
}

fn validate_root_name(root: &str) -> Result<()> {
    if root.is_empty() || root.trim() != root {
        bail!("runtime-deps-guard: allowed root must not be empty or padded");
    }
    let mut chars = root.chars();
    let Some(first) = chars.next() else {
        bail!("runtime-deps-guard: allowed root must not be empty");
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        bail!("runtime-deps-guard: allowed root `{root}` is not a Rust path segment");
    }
    if chars.any(|ch| !(ch == '_' || ch.is_ascii_alphanumeric())) {
        bail!("runtime-deps-guard: allowed root `{root}` is not a Rust path segment");
    }
    Ok(())
}

fn validate_allowed_root(workspace_root: &Path, root: &str) -> Result<()> {
    if FORBIDDEN_BROAD_ROOTS.contains(&root) {
        bail!("runtime-deps-guard: `{root}` is too broad for allowedRoots");
    }
    if crate::layers::DOMAIN_CRATES.contains(&root) {
        bail!("runtime-deps-guard: domain crate `{root}` is forbidden in allowedRoots");
    }
    if crate::layers::SERVICE_CRATES.contains(&root) {
        bail!("runtime-deps-guard: service crate `{root}` is forbidden in allowedRoots");
    }
    if crate::layers::BASIS_CRATES.contains(&root)
        || crate::layers::ENGINE_CRATES.contains(&root)
        || crate::layers::DIPORT_CRATES.contains(&root)
    {
        return Ok(());
    }
    let adapter_manifest = workspace_root
        .join("adapters")
        .join(root)
        .join("Cargo.toml");
    if adapter_manifest.exists() {
        return Ok(());
    }
    bail!(
        "runtime-deps-guard: allowed root `{root}` is neither basis/engine/diport nor an adapter crate"
    );
}

fn shared_runtime_deps_struct(file: &syn::File) -> Option<&syn::ItemStruct> {
    file.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == STRUCT_NAME => Some(item),
        _ => None,
    })
}

#[derive(Default)]
struct TypeResolver {
    use_aliases: BTreeMap<String, Vec<String>>,
    type_aliases: BTreeMap<String, Type>,
}

enum TypeAliasTarget<'a> {
    NotAlias,
    Cycle,
    Found { name: String, ty: &'a Type },
}

impl TypeResolver {
    fn type_alias_target<'a>(
        &'a self,
        type_path: &TypePath,
        alias_stack: &[String],
    ) -> TypeAliasTarget<'a> {
        if type_path.qself.is_some() {
            return TypeAliasTarget::NotAlias;
        }
        let Some(name) = local_type_alias_name(&type_path.path) else {
            return TypeAliasTarget::NotAlias;
        };
        let Some(ty) = self.type_aliases.get(&name) else {
            return TypeAliasTarget::NotAlias;
        };
        if alias_stack.iter().any(|seen| seen == &name) {
            return TypeAliasTarget::Cycle;
        }
        TypeAliasTarget::Found { name, ty }
    }
}

fn collect_type_resolver(file: &syn::File) -> TypeResolver {
    let mut resolver = TypeResolver::default();
    for item in &file.items {
        match item {
            Item::Use(item_use) => {
                collect_use_tree_aliases(
                    &item_use.tree,
                    &mut Vec::new(),
                    &mut resolver.use_aliases,
                );
            }
            Item::Type(item_type) => {
                resolver
                    .type_aliases
                    .insert(item_type.ident.to_string(), item_type.ty.as_ref().clone());
            }
            _ => {}
        }
    }
    resolver
}

fn collect_use_tree_aliases(
    tree: &UseTree,
    prefix: &mut Vec<String>,
    aliases: &mut BTreeMap<String, Vec<String>>,
) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_tree_aliases(&path.tree, prefix, aliases);
            prefix.pop();
        }
        UseTree::Name(name) => {
            let mut full = prefix.clone();
            full.push(name.ident.to_string());
            aliases.insert(name.ident.to_string(), full);
        }
        UseTree::Rename(rename) => {
            let mut full = prefix.clone();
            full.push(rename.ident.to_string());
            aliases.insert(rename.rename.to_string(), full);
        }
        UseTree::Group(group) => {
            for tree in &group.items {
                collect_use_tree_aliases(tree, prefix, aliases);
            }
        }
        UseTree::Glob(_) => {}
    }
}

fn is_allowed_field_type(ty: &Type, resolver: &TypeResolver, policy: &RuntimeDepsPolicy) -> bool {
    if policy.allows_domain_transport_arc()
        && is_exact_domain_transport_arc(ty, resolver, &mut Vec::new())
    {
        return true;
    }
    if policy.allows_exact_exception(EXACT_PASSWORD_BLOCKLIST_ARC)
        && is_exact_arc_of_path(
            ty,
            resolver,
            &["secure", "DigestPasswordBlocklist"],
            &mut Vec::new(),
        )
    {
        return true;
    }
    if policy.allows_exact_exception(EXACT_OIDC_PROVIDER_ARC)
        && is_exact_arc_of_path(ty, resolver, &["oidc", "OidcProvider"], &mut Vec::new())
    {
        return true;
    }
    if policy.allows_exact_exception(EXACT_VAULT_SIGNER_ARC)
        && is_exact_arc_of_path(ty, resolver, &["vault", "VaultSigner"], &mut Vec::new())
    {
        return true;
    }
    if let Some(segments) = resolved_type_path_segments(ty, resolver, &mut Vec::new())
        && segments.first().is_some_and(|root| root == "postgres")
    {
        return policy.allows_root("postgres")
            && (segments == ["postgres", "PgRuntimeHandle"]
                || (segments == ["postgres", "PgRevocationStore"]
                    && policy.allows_exact_exception(EXACT_POSTGRES_REVOCATION_STORE)));
    }
    if let Some(segments) = resolved_type_path_segments(ty, resolver, &mut Vec::new())
        && segments == ["settings_composition", "KeyProviderReadinessInterval"]
    {
        return policy.allows_exact_exception(EXACT_SETTINGS_READINESS_INTERVAL);
    }
    if contains_forbidden_runtime_dep_type(ty, resolver, &mut Vec::new()) {
        return false;
    }
    canonical_type_root(ty, resolver, &mut Vec::new()).is_some_and(|root| policy.allows_root(&root))
}

fn resolved_type_path_segments(
    ty: &Type,
    resolver: &TypeResolver,
    alias_stack: &mut Vec<String>,
) -> Option<Vec<String>> {
    let Type::Path(type_path) = ty else {
        return None;
    };
    match resolver.type_alias_target(type_path, alias_stack) {
        TypeAliasTarget::Found {
            name,
            ty: aliased_ty,
        } => {
            alias_stack.push(name);
            let segments = resolved_type_path_segments(aliased_ty, resolver, alias_stack);
            alias_stack.pop();
            segments
        }
        TypeAliasTarget::Cycle => None,
        TypeAliasTarget::NotAlias if type_path.qself.is_none() => {
            Some(canonical_path_segments(&type_path.path, resolver))
        }
        TypeAliasTarget::NotAlias => None,
    }
}

fn is_exact_arc_of_path(
    ty: &Type,
    resolver: &TypeResolver,
    expected: &[&str],
    alias_stack: &mut Vec<String>,
) -> bool {
    let Type::Path(type_path) = ty else {
        return false;
    };
    match resolver.type_alias_target(type_path, alias_stack) {
        TypeAliasTarget::Found {
            name,
            ty: aliased_ty,
        } => {
            alias_stack.push(name);
            let is_exact = is_exact_arc_of_path(aliased_ty, resolver, expected, alias_stack);
            alias_stack.pop();
            return is_exact;
        }
        TypeAliasTarget::Cycle => return false,
        TypeAliasTarget::NotAlias => {}
    }
    if type_path.qself.is_some() || !path_is_std_arc(&type_path.path, resolver) {
        return false;
    }
    let Some(last) = type_path.path.segments.last() else {
        return false;
    };
    let PathArguments::AngleBracketed(args) = &last.arguments else {
        return false;
    };
    let Some(GenericArgument::Type(Type::Path(inner))) = args.args.first() else {
        return false;
    };
    args.args.len() == 1 && canonical_path_segments(&inner.path, resolver) == expected
}

fn canonical_type_root(
    ty: &Type,
    resolver: &TypeResolver,
    alias_stack: &mut Vec<String>,
) -> Option<String> {
    let Type::Path(type_path) = ty else {
        return None;
    };
    match resolver.type_alias_target(type_path, alias_stack) {
        TypeAliasTarget::Found {
            name,
            ty: aliased_ty,
        } => {
            alias_stack.push(name);
            let root = canonical_type_root(aliased_ty, resolver, alias_stack);
            alias_stack.pop();
            return root;
        }
        TypeAliasTarget::Cycle => return None,
        TypeAliasTarget::NotAlias => {}
    }
    if type_path.qself.is_some() {
        return None;
    }
    canonical_path_segments(&type_path.path, resolver)
        .into_iter()
        .next()
}

fn is_exact_domain_transport_arc(
    ty: &Type,
    resolver: &TypeResolver,
    alias_stack: &mut Vec<String>,
) -> bool {
    let Type::Path(type_path) = ty else {
        return false;
    };
    match resolver.type_alias_target(type_path, alias_stack) {
        TypeAliasTarget::Found {
            name,
            ty: aliased_ty,
        } => {
            alias_stack.push(name);
            let is_exact = is_exact_domain_transport_arc(aliased_ty, resolver, alias_stack);
            alias_stack.pop();
            return is_exact;
        }
        TypeAliasTarget::Cycle => return false,
        TypeAliasTarget::NotAlias => {}
    }
    if type_path.qself.is_some() || !path_is_std_arc(&type_path.path, resolver) {
        return false;
    }
    let Some(last) = type_path.path.segments.last() else {
        return false;
    };
    let PathArguments::AngleBracketed(args) = &last.arguments else {
        return false;
    };
    if args.args.len() != 1 {
        return false;
    }
    let Some(GenericArgument::Type(Type::TraitObject(trait_object))) = args.args.first() else {
        return false;
    };
    if trait_object.dyn_token.is_none() || trait_object.bounds.len() != 1 {
        return false;
    }
    let Some(TypeParamBound::Trait(bound)) = trait_object.bounds.first() else {
        return false;
    };
    canonical_path_segments(&bound.path, resolver) == ["distributed", "DomainTransport"]
}

fn contains_forbidden_runtime_dep_type(
    ty: &Type,
    resolver: &TypeResolver,
    alias_stack: &mut Vec<String>,
) -> bool {
    match ty {
        Type::Array(ty) => contains_forbidden_runtime_dep_type(&ty.elem, resolver, alias_stack),
        Type::BareFn(ty) => {
            ty.inputs
                .iter()
                .any(|arg| contains_forbidden_runtime_dep_type(&arg.ty, resolver, alias_stack))
                || return_type_contains_forbidden_runtime_dep(&ty.output, resolver, alias_stack)
        }
        Type::Group(ty) => contains_forbidden_runtime_dep_type(&ty.elem, resolver, alias_stack),
        Type::ImplTrait(ty) => {
            bounds_contain_forbidden_runtime_dep(&ty.bounds, resolver, alias_stack)
        }
        Type::Paren(ty) => contains_forbidden_runtime_dep_type(&ty.elem, resolver, alias_stack),
        Type::Path(ty) => match resolver.type_alias_target(ty, alias_stack) {
            TypeAliasTarget::Found {
                name,
                ty: aliased_ty,
            } => {
                alias_stack.push(name);
                let contains =
                    contains_forbidden_runtime_dep_type(aliased_ty, resolver, alias_stack);
                alias_stack.pop();
                contains
            }
            TypeAliasTarget::Cycle => true,
            TypeAliasTarget::NotAlias => {
                ty.qself.as_ref().is_some_and(|qself| {
                    contains_forbidden_runtime_dep_type(&qself.ty, resolver, alias_stack)
                }) || path_is_forbidden_runtime_dep(&ty.path, resolver)
                    || path_args_contain_forbidden_runtime_dep(&ty.path, resolver, alias_stack)
            }
        },
        Type::Ptr(ty) => contains_forbidden_runtime_dep_type(&ty.elem, resolver, alias_stack),
        Type::Reference(ty) => contains_forbidden_runtime_dep_type(&ty.elem, resolver, alias_stack),
        Type::Slice(ty) => contains_forbidden_runtime_dep_type(&ty.elem, resolver, alias_stack),
        Type::TraitObject(ty) => {
            bounds_contain_forbidden_runtime_dep(&ty.bounds, resolver, alias_stack)
        }
        Type::Tuple(ty) => ty
            .elems
            .iter()
            .any(|elem| contains_forbidden_runtime_dep_type(elem, resolver, alias_stack)),
        _ => false,
    }
}

fn path_is_forbidden_runtime_dep(path: &syn::Path, resolver: &TypeResolver) -> bool {
    let segments = canonical_path_segments(path, resolver);
    let Some(root) = segments.first() else {
        return false;
    };
    if crate::layers::SERVICE_CRATES.contains(&root.as_str())
        || crate::layers::DOMAIN_CRATES.contains(&root.as_str())
    {
        return true;
    }
    false
}

fn path_args_contain_forbidden_runtime_dep(
    path: &syn::Path,
    resolver: &TypeResolver,
    alias_stack: &mut Vec<String>,
) -> bool {
    path.segments
        .iter()
        .any(|segment| match &segment.arguments {
            PathArguments::None => false,
            PathArguments::AngleBracketed(args) => args.args.iter().any(|arg| match arg {
                GenericArgument::Type(ty) => {
                    contains_forbidden_runtime_dep_type(ty, resolver, alias_stack)
                }
                GenericArgument::AssocType(assoc) => {
                    contains_forbidden_runtime_dep_type(&assoc.ty, resolver, alias_stack)
                }
                GenericArgument::Constraint(constraint) => {
                    bounds_contain_forbidden_runtime_dep(&constraint.bounds, resolver, alias_stack)
                }
                _ => false,
            }),
            PathArguments::Parenthesized(args) => {
                args.inputs
                    .iter()
                    .any(|input| contains_forbidden_runtime_dep_type(input, resolver, alias_stack))
                    || return_type_contains_forbidden_runtime_dep(
                        &args.output,
                        resolver,
                        alias_stack,
                    )
            }
        })
}

fn bounds_contain_forbidden_runtime_dep(
    bounds: &syn::punctuated::Punctuated<TypeParamBound, syn::token::Plus>,
    resolver: &TypeResolver,
    alias_stack: &mut Vec<String>,
) -> bool {
    bounds.iter().any(|bound| match bound {
        TypeParamBound::Trait(bound) => {
            path_is_forbidden_runtime_dep(&bound.path, resolver)
                || path_args_contain_forbidden_runtime_dep(&bound.path, resolver, alias_stack)
        }
        _ => false,
    })
}

fn return_type_contains_forbidden_runtime_dep(
    output: &ReturnType,
    resolver: &TypeResolver,
    alias_stack: &mut Vec<String>,
) -> bool {
    match output {
        ReturnType::Default => false,
        ReturnType::Type(_, ty) => contains_forbidden_runtime_dep_type(ty, resolver, alias_stack),
    }
}

fn path_is_std_arc(path: &syn::Path, resolver: &TypeResolver) -> bool {
    let segments = canonical_path_segments(path, resolver);
    segments == ["std", "sync", "Arc"]
}

fn canonical_path_segments(path: &syn::Path, resolver: &TypeResolver) -> Vec<String> {
    let mut segments: Vec<String> = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let Some(first) = segments.first().cloned() else {
        return segments;
    };
    if let Some(mapped) = resolver.use_aliases.get(&first) {
        let mut resolved = mapped.clone();
        resolved.extend(segments.drain(1..));
        resolved
    } else {
        segments
    }
}

fn local_type_alias_name(path: &syn::Path) -> Option<String> {
    if path.leading_colon.is_some() || path.segments.len() != 1 {
        return None;
    }
    let segment = path.segments.first()?;
    if !matches!(segment.arguments, PathArguments::None) {
        return None;
    }
    Some(segment.ident.to_string())
}

fn resolved_type_summary(ty: &Type, resolver: &TypeResolver) -> String {
    resolved_type_path_segments(ty, resolver, &mut Vec::new())
        .map_or_else(|| render_type(ty), |segments| segments.join("::"))
}

fn render_type(ty: &Type) -> String {
    compact_tokens(&ty.to_token_stream().to_string())
}

fn compact_tokens(raw: &str) -> String {
    let mut out = raw.to_string();
    for (from, to) in [
        (" :: ", "::"),
        (" < ", "<"),
        ("< ", "<"),
        (" > ", ">"),
        (" >", ">"),
        (" , ", ", "),
        ("( ", "("),
        (" )", ")"),
        ("[ ", "["),
        (" ]", "]"),
    ] {
        while out.contains(from) {
            out = out.replace(from, to);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CONFIG: &str = include_str!("../runtime-deps-guard.toml");

    fn valid_policy() -> Result<RuntimeDepsPolicy> {
        RuntimeDepsPolicy::from_toml_str(VALID_CONFIG)
    }

    fn findings(src: &str) -> Result<Vec<Finding<Rule>>> {
        scan_source(Path::new("fixture.rs"), src)
    }

    fn findings_with_policy(src: &str) -> Result<Vec<Finding<Rule>>> {
        scan_source_with_policy(Path::new("fixture.rs"), src, &valid_policy()?)
    }

    fn policy_err(result: Result<RuntimeDepsPolicy>, message: &str) -> Result<anyhow::Error> {
        match result {
            Ok(_) => anyhow::bail!("{message}"),
            Err(err) => Ok(err),
        }
    }

    #[test]
    fn config_accepts_current_policy() -> Result<()> {
        let policy = valid_policy()?;
        assert_eq!(
            policy.allowed_roots(),
            [
                "diport",
                "oidc",
                "postgres",
                "primitives",
                "redis",
                "s3",
                "secure",
                "vault",
                "vocab"
            ]
        );
        assert_eq!(
            policy.exact_exceptions(),
            [
                "Arc<dyn distributed::DomainTransport>",
                "Arc<oidc::OidcProvider>",
                "Arc<secure::DigestPasswordBlocklist>",
                "Arc<vault::VaultSigner>",
                "postgres::PgRevocationStore",
                "settings_composition::KeyProviderReadinessInterval"
            ]
        );
        Ok(())
    }

    #[test]
    fn config_rejects_unknown_fields() -> Result<()> {
        let err = policy_err(
            RuntimeDepsPolicy::from_toml_str(
                r#"
schemaVersion = 1
allowedRoots = ["postgres"]
exactExceptions = ["Arc<dyn distributed::DomainTransport>"]
extra = true
"#,
            ),
            "unknown config fields must fail closed",
        )?;
        assert!(format!("{err:#}").contains("unknown field"), "{err:#}");
        Ok(())
    }

    #[test]
    fn config_file_is_required_and_malformed_toml_fails_closed() -> Result<()> {
        let missing_root = std::env::temp_dir().join(format!(
            "rss-runtime-deps-guard-missing-{}",
            std::process::id()
        ));
        let missing = policy_err(
            RuntimeDepsPolicy::from_workspace(&missing_root),
            "missing config file must fail closed",
        )?;
        assert!(format!("{missing:#}").contains("read"), "{missing:#}");

        let malformed = policy_err(
            RuntimeDepsPolicy::from_toml_str("schemaVersion ="),
            "malformed TOML must fail closed",
        )?;
        assert!(
            format!("{malformed:#}").contains("parse config TOML"),
            "{malformed:#}"
        );
        Ok(())
    }

    #[test]
    fn config_rejects_empty_duplicate_and_overbroad_roots() -> Result<()> {
        for (label, raw) in [
            (
                "empty",
                r#"
schemaVersion = 1
allowedRoots = []
exactExceptions = ["Arc<dyn distributed::DomainTransport>"]
"#,
            ),
            (
                "duplicate",
                r#"
schemaVersion = 1
allowedRoots = ["postgres", "postgres"]
exactExceptions = ["Arc<dyn distributed::DomainTransport>"]
"#,
            ),
            (
                "domain",
                r#"
schemaVersion = 1
allowedRoots = ["settings"]
exactExceptions = ["Arc<dyn distributed::DomainTransport>"]
"#,
            ),
            (
                "service",
                r#"
schemaVersion = 1
allowedRoots = ["distributed"]
exactExceptions = ["Arc<dyn distributed::DomainTransport>"]
"#,
            ),
            (
                "std",
                r#"
schemaVersion = 1
allowedRoots = ["std"]
exactExceptions = ["Arc<dyn distributed::DomainTransport>"]
"#,
            ),
            (
                "typo",
                r#"
schemaVersion = 1
allowedRoots = ["postgress"]
exactExceptions = ["Arc<dyn distributed::DomainTransport>"]
"#,
            ),
        ] {
            let err = policy_err(
                RuntimeDepsPolicy::from_toml_str(raw),
                &format!("{label} root config must fail closed"),
            )?;
            assert!(
                err.to_string().contains("runtime-deps-guard"),
                "{label}: {err:#}"
            );
        }
        Ok(())
    }

    #[test]
    fn config_rejects_unknown_exact_exception() -> Result<()> {
        let err = policy_err(
            RuntimeDepsPolicy::from_toml_str(
                r#"
schemaVersion = 1
allowedRoots = ["postgres"]
exactExceptions = ["Arc<dyn distributed::Other>"]
"#,
            ),
            "unknown exact exception must fail closed",
        )?;
        assert!(err.to_string().contains("exact exception"), "{err:#}");
        Ok(())
    }

    #[test]
    fn current_shared_runtime_deps_fixture_passes() -> Result<()> {
        let findings = findings(include_str!(
            "../tests/fixtures/runtime_deps_guard/current_pass.rs"
        ))?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn postgres_lifecycle_owner_is_rejected_through_qualified_imported_and_type_aliases()
    -> Result<()> {
        for (label, source) in [
            (
                "qualified owner",
                "pub struct SharedRuntimeDeps { pub pg: postgres::PgRuntimeDeps }\n",
            ),
            (
                "imported owner",
                "use postgres::PgRuntimeDeps;\npub struct SharedRuntimeDeps { pub pg: PgRuntimeDeps }\n",
            ),
            (
                "renamed import owner",
                "use postgres::PgRuntimeDeps as PgOwner;\npub struct SharedRuntimeDeps { pub pg: PgOwner }\n",
            ),
            (
                "type alias owner",
                "type PgOwner = postgres::PgRuntimeDeps;\npub struct SharedRuntimeDeps { pub pg: PgOwner }\n",
            ),
        ] {
            let findings = findings(source)?;
            assert_eq!(findings.len(), 1, "{label}: {findings:?}");
            assert_eq!(findings[0].rule, Rule::DisallowedFieldType, "{label}");
            assert!(
                findings[0].detail.contains("PgRuntimeDeps"),
                "{label}: {:?}",
                findings[0]
            );
        }
        Ok(())
    }

    #[test]
    fn postgres_revocation_store_is_the_only_concrete_postgres_store_exception() -> Result<()> {
        let accepted = findings_with_policy(
            "pub struct SharedRuntimeDeps { pub revocation: postgres::PgRevocationStore }\n",
        )?;
        assert!(accepted.is_empty(), "{accepted:?}");

        let rejected =
            findings_with_policy("pub struct SharedRuntimeDeps { pub raw: postgres::PgStore }\n")?;
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(rejected[0].rule, Rule::DisallowedFieldType);
        Ok(())
    }

    #[test]
    fn settings_readiness_value_is_exact_and_does_not_open_the_composition_root() -> Result<()> {
        let accepted = findings_with_policy(
            "pub struct SharedRuntimeDeps { pub readiness: settings_composition::KeyProviderReadinessInterval }\n",
        )?;
        assert!(accepted.is_empty(), "{accepted:?}");

        let rejected = findings_with_policy(
            "pub struct SharedRuntimeDeps { pub service: settings_composition::SettingsModuleDeps }\n",
        )?;
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(rejected[0].rule, Rule::DisallowedFieldType);
        Ok(())
    }

    #[test]
    fn real_shared_runtime_deps_currently_passes() -> Result<()> {
        let root = crate::workspace_root()?;
        let paths = discover_shared_runtime_deps_paths(&root)?;
        let labels: Vec<_> = paths
            .iter()
            .map(|path| {
                path.strip_prefix(&root)
                    .unwrap_or(path.as_path())
                    .display()
                    .to_string()
            })
            .collect();
        assert!(
            labels
                .iter()
                .any(|path| path.ends_with("assemblies/runtime/src/module.rs")),
            "runtime carrier missing: {labels:?}"
        );
        assert!(
            labels
                .iter()
                .any(|path| path.ends_with("assemblies/settingsonly/src/lib.rs")),
            "settingsonly carrier missing: {labels:?}"
        );
        assert!(
            labels
                .iter()
                .any(|path| path.ends_with("assemblies/identityaudit/src/lib.rs")),
            "identityaudit carrier missing: {labels:?}"
        );
        let policy = RuntimeDepsPolicy::from_workspace(&root)?;
        for path in paths {
            let rel = path.strip_prefix(&root).unwrap_or(path.as_path());
            let content = std::fs::read_to_string(&path)?;
            let findings = scan_source_with_policy(rel, &content, &policy)?;
            assert!(findings.is_empty(), "{}: {findings:?}", rel.display());
        }
        Ok(())
    }

    #[test]
    fn settingsonly_shaped_domain_service_field_is_rejected() -> Result<()> {
        let findings = findings(include_str!(
            "../tests/fixtures/runtime_deps_guard/settingsonly_service_red.rs"
        ))?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::DisallowedFieldType);
        assert!(findings[0].detail.contains("settings::SettingsService"));
        Ok(())
    }

    #[test]
    fn oidc_provider_is_allowed_but_identity_service_is_rejected() -> Result<()> {
        let accepted = findings_with_policy(
            "pub struct SharedRuntimeDeps { pub pdp: std::sync::Arc<oidc::OidcProvider> }\n",
        )?;
        assert!(accepted.is_empty(), "{accepted:?}");

        let rejected = findings(include_str!(
            "../tests/fixtures/runtime_deps_guard/identityaudit_service_red.rs"
        ))?;
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].rule, Rule::DisallowedFieldType);
        assert!(rejected[0].detail.contains("identity::IdentityDomain"));
        Ok(())
    }

    #[test]
    fn settings_service_field_is_rejected() -> Result<()> {
        let findings = findings(include_str!(
            "../tests/fixtures/runtime_deps_guard/settings_service_red.rs"
        ))?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::DisallowedFieldType);
        assert!(findings[0].detail.contains("settings"));
        assert!(findings[0].detail.contains("settings::SettingsService"));
        Ok(())
    }

    #[test]
    fn imported_settings_service_field_is_rejected() -> Result<()> {
        let findings = findings(include_str!(
            "../tests/fixtures/runtime_deps_guard/imported_settings_service_red.rs"
        ))?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::DisallowedFieldType);
        assert!(findings[0].detail.contains("settings::SettingsService"));
        Ok(())
    }

    #[test]
    fn arc_exception_does_not_allow_domain_service() -> Result<()> {
        let findings = findings(include_str!(
            "../tests/fixtures/runtime_deps_guard/arc_settings_service_red.rs"
        ))?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::DisallowedFieldType);
        assert!(
            findings[0]
                .detail
                .contains("Arc<settings::SettingsService>")
        );
        Ok(())
    }

    #[test]
    fn distributed_root_is_not_generically_allowed() -> Result<()> {
        let findings = findings(include_str!(
            "../tests/fixtures/runtime_deps_guard/distributed_other_red.rs"
        ))?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::DisallowedFieldType);
        assert!(findings[0].detail.contains("distributed::Locker"));
        Ok(())
    }

    #[test]
    fn exact_exception_accepts_aliases_but_does_not_generalize() -> Result<()> {
        let accepted = findings_with_policy(
            r#"
use std::sync::Arc as SharedArc;
use distributed::DomainTransport;

pub struct SharedRuntimeDeps {
    pub domain_transport: SharedArc<dyn DomainTransport>,
}
"#,
        )?;
        assert!(accepted.is_empty(), "{accepted:?}");

        for (label, src) in [
            (
                "different trait",
                r#"
use std::sync::Arc;

pub struct SharedRuntimeDeps {
    pub domain_transport: Arc<dyn distributed::Other>,
}
"#,
            ),
            (
                "different wrapper",
                r#"
pub struct SharedRuntimeDeps {
    pub domain_transport: Box<dyn distributed::DomainTransport>,
}
"#,
            ),
            (
                "extra bound",
                r#"
use std::sync::Arc;

pub struct SharedRuntimeDeps {
    pub domain_transport: Arc<dyn distributed::DomainTransport + Send>,
}
"#,
            ),
        ] {
            let rejected = findings_with_policy(src)?;
            assert_eq!(rejected.len(), 1, "{label}: {rejected:?}");
            assert_eq!(rejected[0].rule, Rule::DisallowedFieldType);
        }
        Ok(())
    }

    #[test]
    fn allowed_root_generic_does_not_hide_domain_service() -> Result<()> {
        let findings = findings(include_str!(
            "../tests/fixtures/runtime_deps_guard/allowed_root_domain_generic_red.rs"
        ))?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::DisallowedFieldType);
        assert!(
            findings[0]
                .detail
                .contains("diport::Boxed<settings::SettingsService>")
        );
        Ok(())
    }

    #[test]
    fn nested_domain_service_or_repo_types_are_rejected() -> Result<()> {
        let findings = findings_with_policy(
            r#"
use std::sync::Arc;
type RuntimeSettings = settings::SettingsService;
type RuntimeDomain = settings::SettingsDomain;
type AliasA = AliasB;
type AliasB = AliasA;

    pub struct SharedRuntimeDeps {
        pub optional: diport::Boxed<Option<Arc<settings::SettingsService>>>,
        pub repo_result: diport::Boxed<Result<Box<dyn identity::CredentialRepo>, vocab::Error>>,
        pub tupled: diport::Boxed<(contractreg::ContractRegistryService, &'static audit::AuditWriteRepo)>,
        pub callback: diport::Boxed<fn() -> syshealth::HealthRepo>,
        pub alias: diport::Boxed<RuntimeSettings>,
        pub domain_output: diport::Boxed<settings::SettingsDomain>,
        pub domain_alias: diport::Boxed<RuntimeDomain>,
        pub locker: diport::Boxed<distributed::Locker>,
        pub module_result: diport::Boxed<bootstrap::DomainModuleResult>,
        pub cycle: AliasA,
    }
    "#,
        )?;
        assert_eq!(findings.len(), 10, "{findings:?}");
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject.ends_with(".optional"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject.ends_with(".repo_result"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject.ends_with(".tupled"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject.ends_with(".callback"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject.ends_with(".alias"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject.ends_with(".domain_output"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject.ends_with(".domain_alias"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject.ends_with(".locker"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject.ends_with(".module_result"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject.ends_with(".cycle"))
        );
        Ok(())
    }

    #[test]
    fn allowed_root_generic_does_not_hide_all_domain_roots() -> Result<()> {
        let findings = findings(include_str!(
            "../tests/fixtures/runtime_deps_guard/allowed_root_missing_domain_generic_red.rs"
        ))?;
        assert_eq!(findings.len(), 2);
        assert!(findings[0].detail.contains("contractreg"));
        assert!(findings[1].detail.contains("syshealth"));
        Ok(())
    }

    #[test]
    fn type_alias_does_not_hide_domain_service_inside_allowed_root() -> Result<()> {
        let findings = findings(include_str!(
            "../tests/fixtures/runtime_deps_guard/type_alias_domain_generic_red.rs"
        ))?;
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .detail
                .contains("diport::Boxed<RuntimeSettings>")
        );
        Ok(())
    }

    #[test]
    fn missing_shared_runtime_deps_is_rejected() -> Result<()> {
        let findings = findings("pub struct Other { pub pg: postgres::PgRuntimeDeps }\n")?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::MissingSharedRuntimeDeps);
        Ok(())
    }

    #[test]
    fn empty_shared_runtime_deps_is_rejected() -> Result<()> {
        let findings = findings("pub struct SharedRuntimeDeps {}\n")?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::EmptySharedRuntimeDeps);
        Ok(())
    }
}
