//! `runtime-deps guard` -- `SharedRuntimeDeps` infra-only field guard.
//!
//! INVARIANT: WIRING-DEPS-INFRA-ONLY-01 { level = "Medium", exec = "verify", source = "code" }.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use quote::ToTokens as _;
use syn::{
    Fields, GenericArgument, Item, PathArguments, ReturnType, Type, TypeParamBound, TypePath,
    UseTree,
};

use crate::diagnostic::{Finding, GovernanceCheck, finding};

const MODULE_PATH: &str = "assemblies/runtime/src/module.rs";
const STRUCT_NAME: &str = "SharedRuntimeDeps";
const ALLOWED_ROOTS: &[&str] = &[
    "postgres",
    "redis",
    "s3",
    "vault",
    "diport",
    "primitives",
    "secure",
    "vocab",
];
const EXACT_ARC_EXCEPTION: &str = "Arc<dyn distributed::DomainTransport>";

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
        let path = root.join(MODULE_PATH);
        let content = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("runtime-deps-guard: read {}: {e}", path.display()))?;
        let findings = scan_source(Path::new(MODULE_PATH), &content)?;
        Ok((
            "SharedRuntimeDeps fields are restricted to infrastructure/value-object types"
                .to_string(),
            findings,
        ))
    }
}

fn scan_source(path: &Path, content: &str) -> Result<Vec<Finding<Rule>>> {
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
        if !is_allowed_field_type(&field.ty, &resolver) {
            let rendered = render_type(&field.ty);
            let resolved = resolved_type_summary(&field.ty, &resolver);
            findings.push(finding(
                Rule::DisallowedFieldType,
                format!("{}:{STRUCT_NAME}.{name}", path.display()),
                format!(
                    "field `{name}` has type `{rendered}` (resolved `{resolved}`); allowed roots: {}; exact exception: {EXACT_ARC_EXCEPTION}",
                    ALLOWED_ROOTS.join(", ")
                ),
            ));
        }
    }
    Ok(findings)
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

fn is_allowed_field_type(ty: &Type, resolver: &TypeResolver) -> bool {
    if is_exact_domain_transport_arc(ty, resolver, &mut Vec::new()) {
        return true;
    }
    if contains_domain_service_or_repo_type(ty, resolver, &mut Vec::new()) {
        return false;
    }
    canonical_type_root(ty, resolver, &mut Vec::new())
        .is_some_and(|root| ALLOWED_ROOTS.contains(&root.as_str()))
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

fn contains_domain_service_or_repo_type(
    ty: &Type,
    resolver: &TypeResolver,
    alias_stack: &mut Vec<String>,
) -> bool {
    match ty {
        Type::Array(ty) => contains_domain_service_or_repo_type(&ty.elem, resolver, alias_stack),
        Type::BareFn(ty) => {
            ty.inputs
                .iter()
                .any(|arg| contains_domain_service_or_repo_type(&arg.ty, resolver, alias_stack))
                || return_type_contains_domain_service_or_repo(&ty.output, resolver, alias_stack)
        }
        Type::Group(ty) => contains_domain_service_or_repo_type(&ty.elem, resolver, alias_stack),
        Type::ImplTrait(ty) => {
            bounds_contain_domain_service_or_repo(&ty.bounds, resolver, alias_stack)
        }
        Type::Paren(ty) => contains_domain_service_or_repo_type(&ty.elem, resolver, alias_stack),
        Type::Path(ty) => match resolver.type_alias_target(ty, alias_stack) {
            TypeAliasTarget::Found {
                name,
                ty: aliased_ty,
            } => {
                alias_stack.push(name);
                let contains =
                    contains_domain_service_or_repo_type(aliased_ty, resolver, alias_stack);
                alias_stack.pop();
                contains
            }
            TypeAliasTarget::Cycle => true,
            TypeAliasTarget::NotAlias => {
                ty.qself.as_ref().is_some_and(|qself| {
                    contains_domain_service_or_repo_type(&qself.ty, resolver, alias_stack)
                }) || path_is_domain_service_or_repo(&ty.path, resolver)
                    || path_args_contain_domain_service_or_repo(&ty.path, resolver, alias_stack)
            }
        },
        Type::Ptr(ty) => contains_domain_service_or_repo_type(&ty.elem, resolver, alias_stack),
        Type::Reference(ty) => {
            contains_domain_service_or_repo_type(&ty.elem, resolver, alias_stack)
        }
        Type::Slice(ty) => contains_domain_service_or_repo_type(&ty.elem, resolver, alias_stack),
        Type::TraitObject(ty) => {
            bounds_contain_domain_service_or_repo(&ty.bounds, resolver, alias_stack)
        }
        Type::Tuple(ty) => ty
            .elems
            .iter()
            .any(|elem| contains_domain_service_or_repo_type(elem, resolver, alias_stack)),
        _ => false,
    }
}

fn path_is_domain_service_or_repo(path: &syn::Path, resolver: &TypeResolver) -> bool {
    let segments = canonical_path_segments(path, resolver);
    let Some(root) = segments.first() else {
        return false;
    };
    let Some(last) = segments.last() else {
        return false;
    };
    crate::layers::DOMAIN_CRATES.contains(&root.as_str())
        && (last.contains("Service") || last.contains("Repo"))
}

fn path_args_contain_domain_service_or_repo(
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
                    contains_domain_service_or_repo_type(ty, resolver, alias_stack)
                }
                GenericArgument::AssocType(assoc) => {
                    contains_domain_service_or_repo_type(&assoc.ty, resolver, alias_stack)
                }
                GenericArgument::Constraint(constraint) => {
                    bounds_contain_domain_service_or_repo(&constraint.bounds, resolver, alias_stack)
                }
                _ => false,
            }),
            PathArguments::Parenthesized(args) => {
                args.inputs
                    .iter()
                    .any(|input| contains_domain_service_or_repo_type(input, resolver, alias_stack))
                    || return_type_contains_domain_service_or_repo(
                        &args.output,
                        resolver,
                        alias_stack,
                    )
            }
        })
}

fn bounds_contain_domain_service_or_repo(
    bounds: &syn::punctuated::Punctuated<TypeParamBound, syn::token::Plus>,
    resolver: &TypeResolver,
    alias_stack: &mut Vec<String>,
) -> bool {
    bounds.iter().any(|bound| match bound {
        TypeParamBound::Trait(bound) => {
            path_is_domain_service_or_repo(&bound.path, resolver)
                || path_args_contain_domain_service_or_repo(&bound.path, resolver, alias_stack)
        }
        _ => false,
    })
}

fn return_type_contains_domain_service_or_repo(
    output: &ReturnType,
    resolver: &TypeResolver,
    alias_stack: &mut Vec<String>,
) -> bool {
    match output {
        ReturnType::Default => false,
        ReturnType::Type(_, ty) => contains_domain_service_or_repo_type(ty, resolver, alias_stack),
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
    match ty {
        Type::Path(type_path) if type_path.qself.is_none() => {
            canonical_path_segments(&type_path.path, resolver).join("::")
        }
        _ => render_type(ty),
    }
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

    fn findings(src: &str) -> Result<Vec<Finding<Rule>>> {
        scan_source(Path::new("fixture.rs"), src)
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
    fn real_shared_runtime_deps_currently_passes() -> Result<()> {
        let findings = findings(include_str!("../../assemblies/runtime/src/module.rs"))?;
        assert!(findings.is_empty(), "{findings:?}");
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
