//! Fail-closed evidence for the production Postgres provider injection used by active producers.
//!
//! INVARIANT: L2-PRODUCER-PRODUCTION-COMPOSITION-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::runtime_entry_must_call_and_consume_the_generated_domain_wire", anti_vacuity = "tests::workspace_production_composition_is_exact" }——
//! the production `wire` functions must inject the exact Postgres lifecycle/UoW binding into the
//! service constructor that owns each active producer path, and that exact constructor result must
//! enter the live domain. Merely defining or constructing a correct provider elsewhere is not
//! evidence.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use syn::parse::{Parse, ParseStream};
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprCall, ExprMethodCall, Item, ItemFn, Pat, Stmt, Token, UseTree,
    punctuated::Punctuated,
};

const IDENTITY_COMPOSITION: &str = "composition/identity/src/lib.rs";
const SETTINGS_COMPOSITION: &str = "composition/settings/src/lib.rs";
const RUNTIME_ENTRY: &str = "assemblies/runtime/src/lib.rs";
const RUNTIME_MODULES: &str = "assemblies/runtime/src/generated/modules_gen.rs";
const IDENTITY_RUNTIME_MODULE: &str = "assemblies/runtime/src/domains/identity.rs";
const SETTINGS_RUNTIME_MODULE: &str = "assemblies/runtime/src/domains/settings.rs";
const MAX_COMPOSITION_BYTES: u64 = 256 * 1024;
const MAX_RUNTIME_ENTRY_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum ProducerCompositionPort {
    SessionLifecycleLocal,
    PolicyLifecycleLocal,
    RoleBindingLifecycleLocal,
    ConfigUnitOfWorkLocal,
}

impl ProducerCompositionPort {
    pub(crate) fn trait_symbol(self) -> &'static str {
        match self {
            Self::SessionLifecycleLocal => "SessionLifecycleLocal",
            Self::PolicyLifecycleLocal => "PolicyLifecycleLocal",
            Self::RoleBindingLifecycleLocal => "RoleBindingLifecycleLocal",
            Self::ConfigUnitOfWorkLocal => "ConfigUnitOfWorkLocal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProductionCompositionProjection {
    pub(crate) runtime_entry_path: String,
    pub(crate) runtime_entry: String,
    pub(crate) runtime_assembly_path: String,
    pub(crate) runtime_assembly: String,
    pub(crate) runtime_module_path: String,
    pub(crate) runtime_module: String,
    pub(crate) repo_path: String,
    pub(crate) wire: String,
    pub(crate) service_constructor: String,
    pub(crate) provider_factory: String,
}

/// Collect the exact four production injections shared by the nine active producer paths.
pub(crate) fn collect_producer_composition(
    root: &Path,
) -> Result<BTreeMap<ProducerCompositionPort, ProductionCompositionProjection>> {
    let runtime = collect_runtime_lineage(root)?;
    let identity_path = root.join(IDENTITY_COMPOSITION);
    let settings_path = root.join(SETTINGS_COMPOSITION);
    let identity = read_bounded(&identity_path)?;
    let settings = read_bounded(&settings_path)?;

    let mut projections = collect_identity_wire(&identity, IDENTITY_COMPOSITION)?;
    for (port, projection) in collect_settings_wire(&settings, SETTINGS_COMPOSITION)? {
        ensure!(
            projections.insert(port, projection).is_none(),
            "duplicate production composition evidence for {}",
            port.trait_symbol()
        );
    }
    let expected = [
        ProducerCompositionPort::SessionLifecycleLocal,
        ProducerCompositionPort::PolicyLifecycleLocal,
        ProducerCompositionPort::RoleBindingLifecycleLocal,
        ProducerCompositionPort::ConfigUnitOfWorkLocal,
    ];
    ensure!(
        projections.keys().copied().eq(expected),
        "production composition evidence must close the exact four producer ports"
    );
    for (port, projection) in &mut projections {
        let lineage = runtime
            .get(port)
            .with_context(|| format!("missing runtime lineage for {}", port.trait_symbol()))?;
        projection.runtime_entry_path = RUNTIME_ENTRY.to_string();
        projection.runtime_entry = "run_startup".to_string();
        projection.runtime_assembly_path = RUNTIME_MODULES.to_string();
        projection.runtime_assembly = "wire_domains".to_string();
        projection.runtime_module_path = lineage.repo_path.clone();
        projection.runtime_module = "module".to_string();
    }
    Ok(projections)
}

#[derive(Debug, Clone)]
struct RuntimeLineage {
    repo_path: String,
}

fn collect_runtime_lineage(
    root: &Path,
) -> Result<BTreeMap<ProducerCompositionPort, RuntimeLineage>> {
    let entry = read_bounded_with_limit(&root.join(RUNTIME_ENTRY), MAX_RUNTIME_ENTRY_BYTES)?;
    validate_runtime_entry(&entry)?;
    let generated = read_bounded(&root.join(RUNTIME_MODULES))?;
    validate_generated_runtime_modules(&generated)?;
    let identity = read_bounded(&root.join(IDENTITY_RUNTIME_MODULE))?;
    validate_identity_runtime_module(&identity)?;
    let settings = read_bounded(&root.join(SETTINGS_RUNTIME_MODULE))?;
    validate_settings_runtime_module(&settings)?;
    Ok(BTreeMap::from([
        (
            ProducerCompositionPort::SessionLifecycleLocal,
            RuntimeLineage {
                repo_path: IDENTITY_RUNTIME_MODULE.to_string(),
            },
        ),
        (
            ProducerCompositionPort::PolicyLifecycleLocal,
            RuntimeLineage {
                repo_path: IDENTITY_RUNTIME_MODULE.to_string(),
            },
        ),
        (
            ProducerCompositionPort::RoleBindingLifecycleLocal,
            RuntimeLineage {
                repo_path: IDENTITY_RUNTIME_MODULE.to_string(),
            },
        ),
        (
            ProducerCompositionPort::ConfigUnitOfWorkLocal,
            RuntimeLineage {
                repo_path: SETTINGS_RUNTIME_MODULE.to_string(),
            },
        ),
    ]))
}

fn validate_runtime_entry(source: &str) -> Result<()> {
    let syntax = syn::parse_file(source).context("parse production runtime entry")?;
    let run = unique_top_level_function(&syntax.items, "run_startup", RUNTIME_ENTRY)?;
    let phase_calls = run
        .block
        .stmts
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| {
            let Stmt::Local(local) = statement else {
                return None;
            };
            let initializer = local.init.as_ref()?;
            let Expr::Call(call) = peel_expr(&initializer.expr) else {
                return None;
            };
            (path_is_exact_expr(&call.func, &["phase_result"])
                && call.args.first().is_some_and(|argument| {
                    path_is_exact_expr(argument, &["RuntimePhase", "WireDomains"])
                }))
            .then_some((index, local, call))
        })
        .collect::<Vec<_>>();
    let [(_, phase_local, phase_call)] = phase_calls.as_slice() else {
        bail!(
            "{RUNTIME_ENTRY}: run_startup must have one direct WireDomains phase_result binding, found {}",
            phase_calls.len()
        )
    };
    ensure!(
        matches!(phase_local.pat, Pat::Tuple(_))
            && matches!(
                phase_local.init.as_ref().map(|init| init.expr.as_ref()),
                Some(Expr::Try(_))
            ),
        "{RUNTIME_ENTRY}: WireDomains phase_result must be propagated into its production tuple"
    );
    ensure!(
        phase_call.args.len() == 2,
        "{RUNTIME_ENTRY}: WireDomains phase_result must have exact phase and body arguments"
    );
    let body = phase_call
        .args
        .iter()
        .nth(1)
        .and_then(async_block)
        .context(
            "WireDomains phase_result second argument must be one directly awaited async block",
        )?;
    validate_runtime_wire_phase(body)
}

fn async_block(expression: &Expr) -> Option<&syn::Block> {
    let Expr::Await(awaited) = expression else {
        return None;
    };
    let Expr::Async(body) = peel_expr(&awaited.base) else {
        return None;
    };
    Some(&body.block)
}

fn validate_runtime_wire_phase(block: &syn::Block) -> Result<()> {
    let wire_path = ["modules_gen", "wire_domains"];
    ensure!(
        exact_path_call_count_block(block, &wire_path) == 1,
        "{RUNTIME_ENTRY}: WireDomains phase must contain exactly one generated wire_domains call"
    );
    let wire_bindings = block
        .stmts
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| {
            let Stmt::Local(local) = statement else {
                return None;
            };
            let Pat::Ident(binding) = &local.pat else {
                return None;
            };
            let initializer = local.init.as_ref()?;
            exact_awaited_context_call(&initializer.expr, &wire_path, |call| {
                call.args.len() == 2
                    && call
                        .args
                        .first()
                        .is_some_and(|argument| expr_is_shared_ref_ident(argument, "deps"))
                    && call.args.iter().nth(1).is_some_and(|argument| {
                        simple_expr_ident(argument).as_deref() == Some("domain_modules")
                    })
            })
            .then_some((index, binding))
        })
        .collect::<Vec<_>>();
    let [(wire_index, binding)] = wire_bindings.as_slice() else {
        bail!(
            "{RUNTIME_ENTRY}: generated wire_domains must initialize one direct awaited/propagated binding"
        )
    };
    ensure!(
        binding.ident == "domain_bindings"
            && binding.mutability.is_some()
            && binding.subpat.is_none(),
        "{RUNTIME_ENTRY}: generated wire_domains result must be the mutable `domain_bindings` carrier"
    );

    let compose_path = ["bootstrap", "compose_bindings"];
    ensure!(
        exact_path_call_count_block(block, &compose_path) == 1,
        "{RUNTIME_ENTRY}: WireDomains phase must contain exactly one compose_bindings call"
    );
    let consumers = block
        .stmts
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| {
            let Stmt::Local(local) = statement else {
                return None;
            };
            let initializer = local.init.as_ref()?;
            exact_context_try_call(&initializer.expr, &compose_path, |call| {
                call.args.len() == 1
                    && call
                        .args
                        .first()
                        .is_some_and(|argument| expr_is_mut_ref_ident(argument, "domain_bindings"))
            })
            .then_some((index, &local.pat))
        })
        .collect::<Vec<_>>();
    let [(consumer_index, Pat::Tuple(result))] = consumers.as_slice() else {
        bail!(
            "{RUNTIME_ENTRY}: domain_bindings must enter one direct propagated compose_bindings tuple"
        )
    };
    ensure!(
        consumer_index > wire_index
            && result.elems.len() == 2
            && matches!(
                result.elems.first(),
                Some(Pat::Ident(registry))
                    if registry.ident == "registry" && registry.mutability.is_some()
            )
            && matches!(
                result.elems.iter().nth(1),
                Some(Pat::Ident(module))
                    if module.ident == "domains_module" && module.mutability.is_none()
            ),
        "{RUNTIME_ENTRY}: compose_bindings must directly produce `(mut registry, domains_module)` after wire_domains"
    );
    ensure!(
        expr_ident_count_block(block, "domain_bindings") == 1,
        "{RUNTIME_ENTRY}: domain_bindings must have exactly one consumer"
    );
    Ok(())
}

struct ExprList(Punctuated<Expr, Token![,]>);

impl Parse for ExprList {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        Ok(Self(Punctuated::parse_terminated(input)?))
    }
}

fn validate_generated_runtime_modules(source: &str) -> Result<()> {
    let syntax = syn::parse_file(source).context("parse generated runtime modules")?;
    let wire = unique_top_level_function(&syntax.items, "wire_domains", RUNTIME_MODULES)?;
    ensure_wire_domains_signature(wire)?;
    ensure_local_binding_count(&wire.block, "deps", 0, RUNTIME_MODULES)?;
    ensure_local_binding_count(&wire.block, "inputs", 0, RUNTIME_MODULES)?;
    let input_bindings = domain_module_input_bindings(wire)?;
    let tail = tail_expression(&wire.block).context("wire_domains must return Ok(vec![...])")?;
    let Expr::Call(ok) = tail else {
        bail!("wire_domains must end in direct Ok(vec![...])")
    };
    ensure!(
        path_is_exact_expr(&ok.func, &["Ok"]) && ok.args.len() == 1,
        "wire_domains must end in one direct Ok result"
    );
    let Some(Expr::Macro(vector)) = ok.args.first() else {
        bail!("wire_domains Ok result must contain one generated vec! domain list")
    };
    ensure!(
        vector.mac.path.is_ident("vec"),
        "wire_domains domain list must use the generated vec! form"
    );
    let expressions = syn::parse2::<ExprList>(vector.mac.tokens.clone())
        .context("parse generated wire_domains vec entries")?
        .0;
    for domain in ["identity", "settings"] {
        let expected = ["crate", "domains", domain, "module"];
        let binding = input_bindings
            .get(domain)
            .with_context(|| format!("wire_domains does not destructure `{domain}` input"))?;
        let direct = expressions
            .iter()
            .filter(|expression| {
                direct_terminal_call_has_arguments(expression, &expected, "deps", binding)
            })
            .count();
        let total = expressions
            .iter()
            .map(|expression| exact_path_call_count(expression, &expected))
            .sum::<usize>();
        ensure!(
            direct == 1 && total == 1,
            "wire_domains must return exactly one direct crate::domains::{domain}::module(deps, {binding}) result, got direct={direct} total={total}"
        );
    }
    Ok(())
}

fn domain_module_input_bindings(wire: &ItemFn) -> Result<BTreeMap<String, String>> {
    let candidates = wire
        .block
        .stmts
        .iter()
        .filter_map(|statement| {
            let Stmt::Local(local) = statement else {
                return None;
            };
            let Pat::Struct(pattern) = &local.pat else {
                return None;
            };
            let initializer = local.init.as_ref()?;
            (pattern
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "DomainModuleInputs")
                && simple_expr_ident(&initializer.expr).as_deref() == Some("inputs"))
            .then_some(pattern)
        })
        .collect::<Vec<_>>();
    let [pattern] = candidates.as_slice() else {
        bail!(
            "wire_domains must destructure its exact `inputs` parameter once, got {}",
            candidates.len()
        )
    };
    let mut bindings = BTreeMap::new();
    for field in &pattern.fields {
        let syn::Member::Named(member) = &field.member else {
            continue;
        };
        if !matches!(member.to_string().as_str(), "identity" | "settings") {
            continue;
        }
        let Pat::Ident(binding) = field.pat.as_ref() else {
            bail!("wire_domains `{member}` input must use one plain binding")
        };
        ensure!(
            bindings
                .insert(member.to_string(), binding.ident.to_string())
                .is_none(),
            "wire_domains repeats `{member}` input"
        );
    }
    Ok(bindings)
}

fn direct_terminal_call_has_arguments(
    expression: &Expr,
    expected: &[&str],
    deps: &str,
    input: &str,
) -> bool {
    let Some(call) = terminal_call(expression) else {
        return false;
    };
    path_is_exact_expr(&call.func, expected)
        && call.args.len() == 2
        && call.args.first().and_then(simple_expr_ident).as_deref() == Some(deps)
        && call
            .args
            .iter()
            .nth(1)
            .and_then(simple_expr_ident)
            .as_deref()
            == Some(input)
}

fn terminal_call(expression: &Expr) -> Option<&ExprCall> {
    match expression {
        Expr::Call(call) => Some(call),
        Expr::Await(expression) => terminal_call(&expression.base),
        Expr::Try(expression) => terminal_call(&expression.expr),
        Expr::Paren(expression) => terminal_call(&expression.expr),
        Expr::Group(expression) => terminal_call(&expression.expr),
        Expr::MethodCall(call)
            if call.method == "context"
                && call.args.len() == 1
                && matches!(call.args.first(), Some(Expr::Lit(literal)) if matches!(literal.lit, syn::Lit::Str(_))) =>
        {
            terminal_call(&call.receiver)
        }
        _ => None,
    }
}

fn validate_identity_runtime_module(source: &str) -> Result<()> {
    let syntax = syn::parse_file(source).context("parse identity runtime module")?;
    let module = unique_top_level_function(&syntax.items, "module", IDENTITY_RUNTIME_MODULE)?;
    ensure_local_binding_count(&module.block, "deps", 0, IDENTITY_RUNTIME_MODULE)?;
    let module_tail = tail_expression(&module.block).context("identity module tail")?;
    ensure!(
        direct_call_has_argument(module_tail, &["wire_configured"], 0, is_deps_pg_for_domain),
        "identity runtime module must pass deps.pg.for_domain() directly into wire_configured"
    );

    let wire =
        unique_top_level_function(&syntax.items, "wire_configured", IDENTITY_RUNTIME_MODULE)?;
    let composition_binding = wire.block.stmts.iter().find_map(|statement| {
        let Stmt::Local(local) = statement else {
            return None;
        };
        let Pat::Ident(binding) = &local.pat else {
            return None;
        };
        let initializer = local.init.as_ref()?;
        direct_call_has_argument(
            &initializer.expr,
            &["IdentityModuleDeps", "new"],
            0,
            |expr| simple_expr_ident(expr).as_deref() == Some("pg"),
        )
        .then(|| binding.ident.to_string())
    });
    let composition_binding = composition_binding
        .context("identity runtime must bind IdentityModuleDeps::new(pg, ...)")?;
    ensure_local_binding_count(&wire.block, "pg", 0, IDENTITY_RUNTIME_MODULE)?;
    ensure_local_binding_count(
        &wire.block,
        &composition_binding,
        1,
        IDENTITY_RUNTIME_MODULE,
    )?;
    let tail = tail_expression(&wire.block).context("identity wire_configured tail")?;
    ensure!(
        direct_call_has_argument(tail, &["identity_composition", "wire"], 0, |expr| {
            simple_expr_ident(expr).as_deref() == Some(&composition_binding)
        },),
        "identity runtime must pass the exact IdentityModuleDeps binding to identity_composition::wire"
    );
    Ok(())
}

fn validate_settings_runtime_module(source: &str) -> Result<()> {
    let syntax = syn::parse_file(source).context("parse settings runtime module")?;
    let module = unique_top_level_function(&syntax.items, "module", SETTINGS_RUNTIME_MODULE)?;
    ensure_local_binding_count(&module.block, "deps", 0, SETTINGS_RUNTIME_MODULE)?;
    ensure!(
        direct_call_has_argument(
            tail_expression(&module.block).context("settings module tail")?,
            &["wire_from_runtime"],
            0,
            |expr| simple_expr_ident(expr).as_deref() == Some("deps"),
        ),
        "settings runtime module must directly delegate its deps to wire_from_runtime"
    );
    let wire =
        unique_top_level_function(&syntax.items, "wire_from_runtime", SETTINGS_RUNTIME_MODULE)?;
    ensure_local_binding_count(&wire.block, "deps", 0, SETTINGS_RUNTIME_MODULE)?;
    let tail = tail_expression(&wire.block).context("settings wire_from_runtime tail")?;
    ensure!(
        direct_call_has_argument(tail, &["settings_composition", "wire"], 0, |expr| {
            direct_call_has_argument(
                expr,
                &["SettingsModuleDeps", "new"],
                0,
                is_deps_pg_for_domain,
            )
        },),
        "settings runtime must pass SettingsModuleDeps::new(deps.pg.for_domain(), ...) directly to settings_composition::wire"
    );
    Ok(())
}

fn ensure_wire_domains_signature(wire: &ItemFn) -> Result<()> {
    ensure!(
        wire.sig.asyncness.is_some() && wire.sig.inputs.len() == 2,
        "wire_domains must be async with exact deps and inputs parameters"
    );
    let mut parameters = wire.sig.inputs.iter();
    let deps = parameters.next().context("wire_domains deps disappeared")?;
    let inputs = parameters
        .next()
        .context("wire_domains inputs disappeared")?;
    ensure!(
        typed_argument_is(deps, "deps", |ty| {
            matches!(ty, syn::Type::Reference(reference)
                if matches!(reference.elem.as_ref(), syn::Type::Path(path)
                    if path.path.segments.last().is_some_and(|segment| segment.ident == "SharedRuntimeDeps")))
        }),
        "wire_domains first parameter must be `deps: &SharedRuntimeDeps`"
    );
    ensure!(
        typed_argument_is(inputs, "inputs", |ty| {
            matches!(ty, syn::Type::Path(path)
                if path.path.segments.last().is_some_and(|segment| segment.ident == "DomainModuleInputs"))
        }),
        "wire_domains second parameter must be `inputs: DomainModuleInputs`"
    );
    Ok(())
}

fn typed_argument_is(
    argument: &syn::FnArg,
    binding: &str,
    type_matches: impl FnOnce(&syn::Type) -> bool,
) -> bool {
    let syn::FnArg::Typed(argument) = argument else {
        return false;
    };
    matches!(argument.pat.as_ref(), Pat::Ident(pattern) if pattern.ident == binding)
        && type_matches(&argument.ty)
}

fn ensure_local_binding_count(
    block: &syn::Block,
    protected: &str,
    expected: usize,
    repo_path: &str,
) -> Result<()> {
    struct Bindings<'a> {
        protected: &'a str,
        count: usize,
    }
    impl Visit<'_> for Bindings<'_> {
        fn visit_pat_ident(&mut self, pattern: &syn::PatIdent) {
            if pattern.ident == self.protected {
                self.count += 1;
            }
            visit::visit_pat_ident(self, pattern);
        }
    }
    let mut bindings = Bindings {
        protected,
        count: 0,
    };
    bindings.visit_block(block);
    ensure!(
        bindings.count == expected,
        "{repo_path}: protected binding `{protected}` count must be {expected}, got {}",
        bindings.count
    );
    Ok(())
}

fn unique_top_level_function<'a>(
    items: &'a [Item],
    name: &str,
    repo_path: &str,
) -> Result<&'a ItemFn> {
    let functions = items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function)
                if function.sig.ident == name && production_attributes(&function.attrs) =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [function] = functions.as_slice() else {
        bail!(
            "{repo_path}: expected exactly one production `{name}` function, found {}",
            functions.len()
        )
    };
    Ok(*function)
}

fn tail_expression(block: &syn::Block) -> Option<&Expr> {
    match block.stmts.last()? {
        Stmt::Expr(expression, None) => Some(expression),
        _ => None,
    }
}

fn path_is_exact_expr(expression: &Expr, expected: &[&str]) -> bool {
    let Expr::Path(path) = expression else {
        return false;
    };
    path.path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .eq(expected.iter().copied())
}

fn exact_path_call_count(expression: &Expr, expected: &[&str]) -> usize {
    struct Calls<'a> {
        expected: &'a [&'a str],
        count: usize,
    }
    impl Visit<'_> for Calls<'_> {
        fn visit_expr_call(&mut self, call: &ExprCall) {
            if path_is_exact_expr(&call.func, self.expected) {
                self.count += 1;
            }
            visit::visit_expr_call(self, call);
        }
    }
    let mut calls = Calls { expected, count: 0 };
    calls.visit_expr(expression);
    calls.count
}

fn exact_path_call_count_block(block: &syn::Block, expected: &[&str]) -> usize {
    struct Calls<'a> {
        expected: &'a [&'a str],
        count: usize,
    }
    impl Visit<'_> for Calls<'_> {
        fn visit_expr_call(&mut self, call: &ExprCall) {
            if path_is_exact_expr(&call.func, self.expected) {
                self.count += 1;
            }
            visit::visit_expr_call(self, call);
        }
    }
    let mut calls = Calls { expected, count: 0 };
    calls.visit_block(block);
    calls.count
}

fn expr_ident_count_block(block: &syn::Block, expected: &str) -> usize {
    struct Idents<'a> {
        expected: &'a str,
        count: usize,
    }
    impl Visit<'_> for Idents<'_> {
        fn visit_expr_path(&mut self, path: &syn::ExprPath) {
            if path.path.is_ident(self.expected) {
                self.count += 1;
            }
            visit::visit_expr_path(self, path);
        }
    }
    let mut idents = Idents { expected, count: 0 };
    idents.visit_block(block);
    idents.count
}

fn exact_awaited_context_call(
    expression: &Expr,
    expected: &[&str],
    arguments_match: impl FnOnce(&ExprCall) -> bool,
) -> bool {
    let Expr::Try(propagated) = expression else {
        return false;
    };
    let Expr::MethodCall(context) = propagated.expr.as_ref() else {
        return false;
    };
    if context.method != "context"
        || context.args.len() != 1
        || !matches!(context.args.first(), Some(Expr::Lit(literal)) if matches!(literal.lit, syn::Lit::Str(_)))
    {
        return false;
    }
    let Expr::Await(awaited) = context.receiver.as_ref() else {
        return false;
    };
    let Expr::Call(call) = awaited.base.as_ref() else {
        return false;
    };
    path_is_exact_expr(&call.func, expected) && arguments_match(call)
}

fn exact_context_try_call(
    expression: &Expr,
    expected: &[&str],
    arguments_match: impl FnOnce(&ExprCall) -> bool,
) -> bool {
    let Expr::Try(propagated) = expression else {
        return false;
    };
    let Expr::MethodCall(context) = propagated.expr.as_ref() else {
        return false;
    };
    if context.method != "context"
        || context.args.len() != 1
        || !matches!(context.args.first(), Some(Expr::Lit(literal)) if matches!(literal.lit, syn::Lit::Str(_)))
    {
        return false;
    }
    let Expr::Call(call) = context.receiver.as_ref() else {
        return false;
    };
    path_is_exact_expr(&call.func, expected) && arguments_match(call)
}

fn expr_is_shared_ref_ident(expression: &Expr, expected: &str) -> bool {
    matches!(
        expression,
        Expr::Reference(reference)
            if reference.mutability.is_none()
                && simple_expr_ident(&reference.expr).as_deref() == Some(expected)
    )
}

fn expr_is_mut_ref_ident(expression: &Expr, expected: &str) -> bool {
    matches!(
        expression,
        Expr::Reference(reference)
            if reference.mutability.is_some()
                && simple_expr_ident(&reference.expr).as_deref() == Some(expected)
    )
}

fn direct_call_has_argument(
    expression: &Expr,
    expected: &[&str],
    index: usize,
    predicate: impl FnOnce(&Expr) -> bool,
) -> bool {
    let Expr::Call(call) = peel_expr(expression) else {
        return false;
    };
    path_is_exact_expr(&call.func, expected) && call.args.get(index).is_some_and(predicate)
}

fn is_deps_pg_for_domain(expression: &Expr) -> bool {
    let Expr::MethodCall(call) = peel_expr(expression) else {
        return false;
    };
    if call.method != "for_domain" || !call.args.is_empty() {
        return false;
    }
    let Expr::Field(pg) = peel_expr(&call.receiver) else {
        return false;
    };
    matches!(&pg.member, syn::Member::Named(member) if member == "pg")
        && simple_expr_ident(&pg.base).as_deref() == Some("deps")
}

fn read_bounded(path: &Path) -> Result<String> {
    read_bounded_with_limit(path, MAX_COMPOSITION_BYTES)
}

fn read_bounded_with_limit(path: &Path, limit: u64) -> Result<String> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("stat production composition `{}`", path.display()))?;
    ensure!(
        metadata.len() <= limit,
        "production composition `{}` exceeds {limit} bytes",
        path.display(),
    );
    fs::read_to_string(path)
        .with_context(|| format!("read production composition `{}`", path.display()))
}

#[derive(Clone, Copy)]
struct IdentityInjection {
    port: ProducerCompositionPort,
    provider_method: &'static str,
    service_type: &'static str,
    domain_field: &'static str,
}

const IDENTITY_INJECTIONS: &[IdentityInjection] = &[
    IdentityInjection {
        port: ProducerCompositionPort::SessionLifecycleLocal,
        provider_method: "session_lifecycle",
        service_type: "LoginService",
        domain_field: "login",
    },
    IdentityInjection {
        port: ProducerCompositionPort::PolicyLifecycleLocal,
        provider_method: "policy_lifecycle",
        service_type: "PolicyManageService",
        domain_field: "policy_manage",
    },
    IdentityInjection {
        port: ProducerCompositionPort::RoleBindingLifecycleLocal,
        provider_method: "role_binding_lifecycle",
        service_type: "RbacAdminService",
        domain_field: "rbac_admin",
    },
];

fn collect_identity_wire(
    source: &str,
    repo_path: &str,
) -> Result<BTreeMap<ProducerCompositionPort, ProductionCompositionProjection>> {
    let syntax =
        syn::parse_file(source).with_context(|| format!("parse production `{repo_path}`"))?;
    let wire = unique_production_wire(&syntax.items, repo_path)?;
    let imports = canonical_imports(&syntax.items, repo_path)?;
    let pg_domain_deps = ensure_canonical_import(&imports, "postgres::PgDomainDeps", repo_path)?;
    let identity_domain = ensure_canonical_import(&imports, "identity::IdentityDomain", repo_path)?;
    let identity_domain_deps =
        ensure_canonical_import(&imports, "identity::IdentityDomainDeps", repo_path)?;
    validate_wire_deps(
        &syntax.items,
        wire,
        "IdentityModuleDeps",
        &pg_domain_deps,
        repo_path,
    )?;
    ensure!(
        has_pg_destructure(wire, "IdentityModuleDeps"),
        "{repo_path}: wire must destructure `pg` from IdentityModuleDeps"
    );
    let domain_fields =
        unique_struct_constructor_fields(wire, &identity_domain, "new", &identity_domain_deps)
            .with_context(|| format!("{repo_path}: resolve live IdentityDomainDeps"))?;

    let mut projections = BTreeMap::new();
    for injection in IDENTITY_INJECTIONS {
        let canonical_service = format!("identity::{}", injection.service_type);
        let service_binding = ensure_canonical_import(&imports, &canonical_service, repo_path)?;
        let binding =
            unique_provider_binding(wire, injection.provider_method).with_context(|| {
                format!(
                    "{repo_path}: resolve PgDomainDeps::{} binding",
                    injection.provider_method
                )
            })?;
        let constructor = unique_constructor(wire, &service_binding, "new")
            .with_context(|| format!("{repo_path}: resolve {}::new", injection.service_type))?;
        ensure!(
            constructor
                .call
                .args
                .iter()
                .filter(|argument| simple_expr_ident(argument).as_deref() == Some(&binding))
                .count()
                == 1,
            "{repo_path}: {}::new must consume the exact `{binding}` returned by PgDomainDeps::{}",
            injection.service_type,
            injection.provider_method
        );
        ensure!(
            domain_fields.get(injection.domain_field) == Some(&constructor.binding),
            "{repo_path}: {}::new result `{}` must enter IdentityDomainDeps.{}",
            injection.service_type,
            constructor.binding,
            injection.domain_field
        );
        projections.insert(
            injection.port,
            ProductionCompositionProjection {
                runtime_entry_path: String::new(),
                runtime_entry: String::new(),
                runtime_assembly_path: String::new(),
                runtime_assembly: String::new(),
                runtime_module_path: String::new(),
                runtime_module: String::new(),
                repo_path: repo_path.to_string(),
                wire: "wire".to_string(),
                service_constructor: format!("{}::new", injection.service_type),
                provider_factory: format!("PgDomainDeps::{}", injection.provider_method),
            },
        );
    }
    Ok(projections)
}

fn collect_settings_wire(
    source: &str,
    repo_path: &str,
) -> Result<BTreeMap<ProducerCompositionPort, ProductionCompositionProjection>> {
    let syntax =
        syn::parse_file(source).with_context(|| format!("parse production `{repo_path}`"))?;
    let wire = unique_production_wire(&syntax.items, repo_path)?;
    let imports = canonical_imports(&syntax.items, repo_path)?;
    let pg_domain_deps = ensure_canonical_import(&imports, "postgres::PgDomainDeps", repo_path)?;
    validate_wire_deps(
        &syntax.items,
        wire,
        "SettingsModuleDeps",
        &pg_domain_deps,
        repo_path,
    )?;
    let settings_service =
        ensure_canonical_import(&imports, "settings::SettingsService", repo_path)?;
    let settings_domain = ensure_canonical_import(&imports, "settings::SettingsDomain", repo_path)?;
    let arc = ensure_canonical_import(&imports, "std::sync::Arc", repo_path)?;
    ensure!(
        has_pg_destructure(wire, "SettingsModuleDeps"),
        "{repo_path}: wire must destructure `pg` from SettingsModuleDeps"
    );

    let (configs, writer) = unique_settings_bundle_bindings(wire)
        .with_context(|| format!("{repo_path}: resolve PgDomainDeps::settings_bundle bindings"))?;
    let constructor = unique_constructor(wire, &settings_service, "with_postgres")
        .with_context(|| format!("{repo_path}: resolve SettingsService::with_postgres"))?;
    ensure!(
        constructor
            .call
            .args
            .first()
            .and_then(simple_expr_ident)
            .as_deref()
            == Some(&configs),
        "{repo_path}: SettingsService::with_postgres must consume the exact config reader from PgDomainDeps::settings_bundle"
    );
    ensure!(
        constructor
            .call
            .args
            .iter()
            .nth(1)
            .and_then(simple_expr_ident)
            .as_deref()
            == Some(&writer),
        "{repo_path}: SettingsService::with_postgres must consume the exact writer from PgDomainDeps::settings_bundle"
    );
    let domain_constructor = unique_constructor(wire, &settings_domain, "new")
        .with_context(|| format!("{repo_path}: resolve live SettingsDomain::new"))?;
    let config_argument = domain_constructor
        .call
        .args
        .first()
        .context("SettingsDomain::new must receive the config service as its first argument")?;
    ensure!(
        expression_is_wrapper_of(config_argument, &arc, "new", &constructor.binding),
        "{repo_path}: SettingsService::with_postgres result `{}` must enter SettingsDomain::new through Arc::new",
        constructor.binding
    );
    Ok(BTreeMap::from([(
        ProducerCompositionPort::ConfigUnitOfWorkLocal,
        ProductionCompositionProjection {
            runtime_entry_path: String::new(),
            runtime_entry: String::new(),
            runtime_assembly_path: String::new(),
            runtime_assembly: String::new(),
            runtime_module_path: String::new(),
            runtime_module: String::new(),
            repo_path: repo_path.to_string(),
            wire: "wire".to_string(),
            service_constructor: "SettingsService::with_postgres".to_string(),
            provider_factory: "PgDomainDeps::settings_bundle".to_string(),
        },
    )]))
}

fn unique_production_wire<'a>(items: &'a [Item], repo_path: &str) -> Result<&'a ItemFn> {
    let wires = items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function)
                if function.sig.ident == "wire" && production_attributes(&function.attrs) =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [wire] = wires.as_slice() else {
        bail!(
            "{repo_path}: expected exactly one cfg-production `wire` function, found {}",
            wires.len()
        )
    };
    Ok(*wire)
}

fn production_attributes(attributes: &[Attribute]) -> bool {
    !attributes
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg"))
}

fn validate_wire_deps(
    items: &[Item],
    wire: &ItemFn,
    deps_type: &str,
    pg_domain_deps: &str,
    repo_path: &str,
) -> Result<()> {
    ensure!(
        matches!(&wire.vis, syn::Visibility::Public(_)),
        "{repo_path}: production wire must be public"
    );
    let deps_inputs = wire
        .sig
        .inputs
        .iter()
        .filter(|input| {
            let syn::FnArg::Typed(input) = input else {
                return false;
            };
            simple_pat_ident(&input.pat).as_deref() == Some("deps")
                && matches!(
                    input.ty.as_ref(),
                    syn::Type::Path(path)
                        if path_last(&path.path).as_deref() == Some(deps_type)
                )
        })
        .count();
    ensure!(
        deps_inputs == 1,
        "{repo_path}: wire must take exactly one `deps: {deps_type}` input"
    );

    let structs = items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(item) if item.ident == deps_type => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [deps] = structs.as_slice() else {
        bail!(
            "{repo_path}: expected exactly one `{deps_type}` definition, found {}",
            structs.len()
        )
    };
    let pg_fields = deps
        .fields
        .iter()
        .filter(|field| field.ident.as_ref().is_some_and(|ident| ident == "pg"))
        .filter(|field| {
            matches!(
                &field.ty,
                syn::Type::Path(path)
                    if path.path.segments.first().is_some_and(|segment| segment.ident == pg_domain_deps)
            )
        })
        .count();
    ensure!(
        pg_fields == 1,
        "{repo_path}: `{deps_type}.pg` must have the canonical imported PgDomainDeps type"
    );

    ensure!(
        !wire
            .block
            .stmts
            .iter()
            .any(|statement| matches!(statement, Stmt::Item(_) | Stmt::Macro(_))),
        "{repo_path}: local items/macros in production wire are opaque for composition evidence"
    );
    Ok(())
}

fn canonical_imports(items: &[Item], repo_path: &str) -> Result<BTreeMap<String, String>> {
    let mut imports = BTreeMap::new();
    for item in items {
        match item {
            Item::Use(item) => {
                collect_imports(&item.tree, Vec::new(), &mut imports, repo_path)?;
            }
            Item::Struct(item) => reject_protected_local_name(&item.ident.to_string(), repo_path)?,
            Item::Enum(item) => reject_protected_local_name(&item.ident.to_string(), repo_path)?,
            Item::Trait(item) => reject_protected_local_name(&item.ident.to_string(), repo_path)?,
            Item::Type(item) => reject_protected_local_name(&item.ident.to_string(), repo_path)?,
            Item::Mod(item) => reject_protected_local_name(&item.ident.to_string(), repo_path)?,
            _ => {}
        }
    }
    Ok(imports)
}

fn collect_imports(
    tree: &UseTree,
    mut prefix: Vec<String>,
    imports: &mut BTreeMap<String, String>,
    repo_path: &str,
) -> Result<()> {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_imports(&path.tree, prefix, imports, repo_path)
        }
        UseTree::Name(name) => {
            prefix.push(name.ident.to_string());
            insert_import(
                imports,
                name.ident.to_string(),
                prefix.join("::"),
                repo_path,
            )
        }
        UseTree::Rename(rename) => {
            prefix.push(rename.ident.to_string());
            if rename.rename == "_" {
                return Ok(());
            }
            insert_import(
                imports,
                rename.rename.to_string(),
                prefix.join("::"),
                repo_path,
            )
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_imports(item, prefix.clone(), imports, repo_path)?;
            }
            Ok(())
        }
        UseTree::Glob(_) => bail!("{repo_path}: glob imports are opaque for composition evidence"),
    }
}

fn insert_import(
    imports: &mut BTreeMap<String, String>,
    binding: String,
    canonical: String,
    repo_path: &str,
) -> Result<()> {
    if let Some(previous) = imports.insert(binding.clone(), canonical.clone()) {
        bail!(
            "{repo_path}: import binding `{binding}` is ambiguous between `{previous}` and `{canonical}`"
        )
    }
    Ok(())
}

fn ensure_canonical_import(
    imports: &BTreeMap<String, String>,
    canonical: &str,
    repo_path: &str,
) -> Result<String> {
    let bindings = imports
        .iter()
        .filter(|(_, imported)| imported.as_str() == canonical)
        .map(|(binding, _)| binding.clone())
        .collect::<Vec<_>>();
    let [binding] = bindings.as_slice() else {
        bail!(
            "{repo_path}: expected exactly one import of `{canonical}`, found {}",
            bindings.len()
        )
    };
    Ok(binding.clone())
}

fn reject_protected_local_name(name: &str, repo_path: &str) -> Result<()> {
    ensure!(
        !matches!(
            name,
            "LoginService"
                | "PolicyManageService"
                | "RbacAdminService"
                | "SettingsService"
                | "IdentityDomain"
                | "IdentityDomainDeps"
                | "SettingsDomain"
                | "PgDomainDeps"
                | "Arc"
        ),
        "{repo_path}: local `{name}` shadows a protected composition carrier"
    );
    Ok(())
}

fn expression_has_opaque_syntax(expression: &Expr) -> bool {
    #[derive(Default)]
    struct OpaqueSyntax {
        macros: usize,
        closures: usize,
    }
    impl<'ast> Visit<'ast> for OpaqueSyntax {
        fn visit_macro(&mut self, _node: &'ast syn::Macro) {
            self.macros += 1;
        }

        fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {
            self.closures += 1;
        }
    }
    let mut opaque = OpaqueSyntax::default();
    opaque.visit_expr(expression);
    opaque.macros != 0 || opaque.closures != 0
}

fn has_pg_destructure(wire: &ItemFn, deps_type: &str) -> bool {
    wire.block.stmts.iter().any(|statement| {
        let Stmt::Local(local) = statement else {
            return false;
        };
        let Pat::Struct(pattern) = &local.pat else {
            return false;
        };
        path_last(&pattern.path).as_deref() == Some(deps_type)
            && pattern.fields.iter().any(|field| {
                matches!(&field.member, syn::Member::Named(ident) if ident == "pg")
                    && simple_pat_ident(&field.pat).as_deref() == Some("pg")
            })
            && local
                .init
                .as_ref()
                .and_then(|init| simple_expr_ident(&init.expr))
                .as_deref()
                == Some("deps")
    })
}

fn unique_provider_binding(wire: &ItemFn, method: &str) -> Result<String> {
    let mut bindings = Vec::new();
    let mut foreign_receivers = Vec::new();
    for statement in &wire.block.stmts {
        let Stmt::Local(local) = statement else {
            continue;
        };
        let Some(binding) = simple_pat_ident(&local.pat) else {
            continue;
        };
        let Some(init) = &local.init else {
            continue;
        };
        let target_calls = method_calls(&init.expr)
            .into_iter()
            .filter(|call| call.method == method)
            .collect::<Vec<_>>();
        if !target_calls.is_empty() {
            ensure!(
                !expression_has_opaque_syntax(&init.expr),
                "provider binding `{binding}` for `{method}` contains opaque macro/closure syntax"
            );
        }
        for call in target_calls {
            if simple_expr_ident(&call.receiver).as_deref() == Some("pg") {
                bindings.push(binding.clone());
            } else {
                foreign_receivers.push(binding.clone());
            }
        }
    }
    ensure!(
        foreign_receivers.is_empty(),
        "provider method `{method}` is called on a non-`pg` receiver"
    );
    let [binding] = bindings.as_slice() else {
        bail!(
            "provider method `pg.{method}` must initialize exactly one direct binding, found {}",
            bindings.len()
        )
    };
    Ok(binding.clone())
}

fn unique_settings_bundle_bindings(wire: &ItemFn) -> Result<(String, String)> {
    let mut candidates = Vec::new();
    for statement in &wire.block.stmts {
        let Stmt::Local(local) = statement else {
            continue;
        };
        let Pat::Tuple(tuple) = &local.pat else {
            continue;
        };
        let Some(init) = &local.init else {
            continue;
        };
        let calls = method_calls(&init.expr);
        let bundle_count = calls
            .iter()
            .filter(|call| {
                call.method == "settings_bundle"
                    && simple_expr_ident(&call.receiver).as_deref() == Some("pg")
            })
            .count();
        let into_parts_count = calls
            .iter()
            .filter(|call| call.method == "into_parts")
            .count();
        if bundle_count == 1 && into_parts_count == 1 && tuple.elems.len() == 4 {
            ensure!(
                !expression_has_opaque_syntax(&init.expr),
                "settings_bundle binding contains opaque macro/closure syntax"
            );
            let configs = tuple.elems.first().and_then(simple_pat_ident);
            let writer = tuple.elems.iter().nth(1).and_then(simple_pat_ident);
            if let (Some(configs), Some(writer)) = (configs, writer) {
                candidates.push((configs, writer));
            }
        }
    }
    let [candidate] = candidates.as_slice() else {
        bail!(
            "pg.settings_bundle(...).into_parts() must initialize exactly one four-part tuple, found {}",
            candidates.len()
        )
    };
    Ok(candidate.clone())
}

#[derive(Clone)]
struct ConstructorBinding {
    binding: String,
    call: ExprCall,
}

fn unique_constructor(wire: &ItemFn, service: &str, method: &str) -> Result<ConstructorBinding> {
    let mut calls = Vec::new();
    for statement in &wire.block.stmts {
        let Stmt::Local(local) = statement else {
            continue;
        };
        let Some(binding) = simple_pat_ident(&local.pat) else {
            continue;
        };
        let Some(init) = &local.init else {
            continue;
        };
        let matching = function_calls(&init.expr)
            .into_iter()
            .filter(|call| {
                matches!(
                    function_path(&call.func).as_deref(),
                    Some([owner, leaf]) if owner == service && leaf == method
                )
            })
            .collect::<Vec<_>>();
        if !matching.is_empty() {
            ensure!(
                !expression_has_opaque_syntax(&init.expr),
                "{service}::{method} binding contains opaque macro/closure syntax"
            );
            calls.extend(matching.into_iter().map(|call| ConstructorBinding {
                binding: binding.clone(),
                call,
            }));
        }
    }
    let [call] = calls.as_slice() else {
        bail!(
            "{service}::{method} must occur exactly once in a direct production binding, found {}",
            calls.len()
        )
    };
    Ok(call.clone())
}

fn unique_struct_constructor_fields(
    wire: &ItemFn,
    service: &str,
    method: &str,
    input: &str,
) -> Result<BTreeMap<String, String>> {
    let constructor = unique_constructor(wire, service, method)?;
    ensure!(
        constructor.call.args.len() == 1,
        "{service}::{method} must receive exactly one `{input}` value"
    );
    let argument = constructor
        .call
        .args
        .first()
        .context("constructor argument count was checked above")?;
    let Expr::Struct(value) = peel_expr(argument) else {
        bail!("{service}::{method} must receive a direct `{input}` struct literal")
    };
    ensure!(
        value.path.leading_colon.is_none()
            && value.path.segments.len() == 1
            && path_last(&value.path).as_deref() == Some(input),
        "{service}::{method} must receive the canonical `{input}` struct"
    );
    ensure!(
        value.rest.is_none(),
        "{input} update syntax is opaque for composition evidence"
    );
    let mut fields = BTreeMap::new();
    for field in &value.fields {
        let syn::Member::Named(member) = &field.member else {
            bail!("{input} must use named fields")
        };
        let binding = simple_expr_ident(&field.expr)
            .with_context(|| format!("{input}.{member} must receive a direct binding"))?;
        ensure!(
            fields.insert(member.to_string(), binding).is_none(),
            "{input}.{member} is duplicated"
        );
    }
    Ok(fields)
}

fn expression_is_wrapper_of(expression: &Expr, wrapper: &str, method: &str, binding: &str) -> bool {
    let Expr::Call(call) = peel_expr(expression) else {
        return false;
    };
    matches!(
        function_path(&call.func).as_deref(),
        Some([owner, leaf]) if owner == wrapper && leaf == method
    ) && call.args.len() == 1
        && call.args.first().and_then(simple_expr_ident).as_deref() == Some(binding)
}

fn method_calls(expression: &Expr) -> Vec<ExprMethodCall> {
    #[derive(Default)]
    struct Collector {
        calls: Vec<ExprMethodCall>,
    }
    impl<'ast> Visit<'ast> for Collector {
        fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
            self.calls.push(node.clone());
            visit::visit_expr_method_call(self, node);
        }

        fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}
        fn visit_macro(&mut self, _node: &'ast syn::Macro) {}
    }
    let mut collector = Collector::default();
    collector.visit_expr(expression);
    collector.calls
}

fn function_calls(expression: &Expr) -> Vec<ExprCall> {
    #[derive(Default)]
    struct Collector {
        calls: Vec<ExprCall>,
    }
    impl<'ast> Visit<'ast> for Collector {
        fn visit_expr_call(&mut self, node: &'ast ExprCall) {
            self.calls.push(node.clone());
            visit::visit_expr_call(self, node);
        }

        fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}
        fn visit_macro(&mut self, _node: &'ast syn::Macro) {}
    }
    let mut collector = Collector::default();
    collector.visit_expr(expression);
    collector.calls
}

fn function_path(expression: &Expr) -> Option<Vec<String>> {
    let Expr::Path(path) = peel_expr(expression) else {
        return None;
    };
    Some(
        path.path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect(),
    )
}

fn simple_expr_ident(expression: &Expr) -> Option<String> {
    let Expr::Path(path) = peel_expr(expression) else {
        return None;
    };
    (path.qself.is_none() && path.path.leading_colon.is_none() && path.path.segments.len() == 1)
        .then(|| path.path.segments[0].ident.to_string())
}

fn simple_pat_ident(pattern: &Pat) -> Option<String> {
    let Pat::Ident(pattern) = pattern else {
        return None;
    };
    pattern.subpat.is_none().then(|| pattern.ident.to_string())
}

fn path_last(path: &syn::Path) -> Option<String> {
    path.segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn peel_expr(expression: &Expr) -> &Expr {
    match expression {
        Expr::Await(value) => peel_expr(&value.base),
        Expr::Group(value) => peel_expr(&value.expr),
        Expr::Paren(value) => peel_expr(&value.expr),
        Expr::Try(value) => peel_expr(&value.expr),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn identity_wire(session_argument: &str, domain_login: &str) -> String {
        format!(
            r#"
            use std::sync::Arc;
            use identity::{{
                IdentityDomain, IdentityDomainDeps, LoginService, PolicyManageService,
                RbacAdminService,
            }};
            use postgres::PgDomainDeps;
            pub struct IdentityModuleDeps {{ pg: PgDomainDeps }}

            pub fn wire(deps: IdentityModuleDeps) {{
                let IdentityModuleDeps {{ pg, .. }} = deps;
                let lifecycle = Arc::from(DynSessionLifecycle::new_box(
                    pg.session_lifecycle(boxed_clock(&clock)),
                ));
                let policy_lifecycle = Arc::from(DynPolicyLifecycle::new_box(
                    pg.policy_lifecycle(boxed_clock(&clock)),
                ));
                let binding_lifecycle = Arc::from(DynRoleBindingLifecycle::new_box(
                    pg.role_binding_lifecycle(boxed_clock(&clock)),
                ));
                let login = Arc::new(LoginService::new(
                    credentials,
                    {session_argument},
                    refresh,
                    password_policy,
                    clock,
                    session_ttl,
                ));
                let rbac = Arc::new(RbacAdminService::new(roles, binding_lifecycle, clock));
                let policy = Arc::new(PolicyManageService::new(
                    policies,
                    policy_lifecycle,
                    clock,
                ));
                let domain = IdentityDomain::new(IdentityDomainDeps {{
                    login: {domain_login},
                    rbac_admin: rbac,
                    policy_manage: policy,
                }});
            }}
            "#
        )
    }

    #[test]
    fn identity_wire_rejects_an_uninjected_correct_provider() -> anyhow::Result<()> {
        let valid = identity_wire("lifecycle", "login");
        assert!(collect_identity_wire(&valid, IDENTITY_COMPOSITION).is_ok());
        let source = identity_wire("other_lifecycle", "login");

        assert!(
            collect_identity_wire(&source, IDENTITY_COMPOSITION).is_err(),
            "an existing correct provider must not close evidence unless that exact binding is injected"
        );
        Ok(())
    }

    #[test]
    fn identity_wire_rejects_a_constructed_service_dropped_before_the_domain() {
        let source = identity_wire("lifecycle", "decoy_login");

        assert!(
            collect_identity_wire(&source, IDENTITY_COMPOSITION).is_err(),
            "constructing LoginService is not live composition evidence unless that exact result enters IdentityDomainDeps.login"
        );
    }

    #[test]
    fn settings_wire_rejects_a_writer_from_another_provider() -> anyhow::Result<()> {
        let source = |writer: &str, domain_config: &str| {
            format!(
                r#"
            use std::sync::Arc;
            use postgres::PgDomainDeps;
            use settings::{{SettingsDomain, SettingsService}};
            pub struct SettingsModuleDeps {{ pg: PgDomainDeps }}

            pub async fn wire(deps: SettingsModuleDeps) {{
                let SettingsModuleDeps {{ pg, .. }} = deps;
                let (configs, writer, secrets, secret_writer) = pg
                    .settings_bundle(clock, protections)
                    .into_parts();
                let config_svc = SettingsService::with_postgres(
                    configs,
                    {writer},
                    empty_flag_store(),
                    service_clock,
                );
                let domain = SettingsDomain::new(
                    Arc::new({domain_config}),
                    secret_repo,
                    secret_uow,
                );
            }}
        "#
            )
        };
        assert!(
            collect_settings_wire(&source("writer", "config_svc"), SETTINGS_COMPOSITION).is_ok()
        );

        assert!(
            collect_settings_wire(&source("other_writer", "config_svc"), SETTINGS_COMPOSITION)
                .is_err(),
            "the settings_bundle writer itself must reach SettingsService::with_postgres"
        );
        assert!(
            collect_settings_wire(&source("writer", "decoy_config_svc"), SETTINGS_COMPOSITION)
                .is_err(),
            "the exact SettingsService result must reach SettingsDomain::new"
        );
        Ok(())
    }

    #[test]
    fn workspace_production_composition_is_exact() -> anyhow::Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("xtask must live below the workspace root")?;
        let projections = collect_producer_composition(root)?;
        assert_eq!(projections.len(), 4);
        assert_eq!(
            projections
                .keys()
                .map(|port| port.trait_symbol())
                .collect::<Vec<_>>(),
            [
                "SessionLifecycleLocal",
                "PolicyLifecycleLocal",
                "RoleBindingLifecycleLocal",
                "ConfigUnitOfWorkLocal",
            ]
        );
        Ok(())
    }

    #[test]
    fn runtime_decoy_domain_module_cannot_close_production_composition() -> anyhow::Result<()> {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("xtask must live below the workspace root")?;
        let root = crate::testutil::unique_tmp("producer-composition-runtime-decoy");
        for relative in [
            IDENTITY_COMPOSITION,
            SETTINGS_COMPOSITION,
            IDENTITY_RUNTIME_MODULE,
            SETTINGS_RUNTIME_MODULE,
        ] {
            let destination = root.join(relative);
            fs::create_dir_all(destination.parent().context("composition parent")?)?;
            fs::copy(workspace.join(relative), destination)?;
        }
        let generated = root.join("assemblies/runtime/src/generated/modules_gen.rs");
        fs::create_dir_all(generated.parent().context("generated modules parent")?)?;
        fs::write(
            generated,
            r#"
            pub async fn wire_domains(
                deps: &SharedRuntimeDeps,
                inputs: crate::domains::DomainModuleInputs,
            ) -> anyhow::Result<Vec<DomainBinding>> {
                let crate::domains::DomainModuleInputs {
                    settings,
                    identity,
                    audit,
                } = inputs;
                Ok(vec![
                    decoy(crate::domains::identity::module(deps, identity).await?),
                    crate::domains::settings::module(deps, settings).await?,
                    crate::domains::audit::module(deps, audit).await?,
                ])
            }
            "#,
        )?;

        let result = collect_producer_composition(&root);
        fs::remove_dir_all(root)?;
        assert!(
            result.is_err(),
            "a reusable composition wire is not production evidence when runtime assembly calls a decoy domain module"
        );
        Ok(())
    }

    #[test]
    fn runtime_assembly_rejects_shadowed_deps() -> anyhow::Result<()> {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("xtask must live below the workspace root")?;
        let source = fs::read_to_string(workspace.join(RUNTIME_MODULES))?;
        let shadowed = source.replacen(
            "    let crate::domains::DomainModuleInputs {",
            "    let deps = decoy_deps;\n    let crate::domains::DomainModuleInputs {",
            1,
        );
        assert!(
            validate_generated_runtime_modules(&shadowed).is_err(),
            "shadowing the protected runtime deps binding must fail closed"
        );
        Ok(())
    }

    #[test]
    fn runtime_entry_must_call_and_consume_the_generated_domain_wire() -> anyhow::Result<()> {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("xtask must live below the workspace root")?;
        let invalid_entries = [
            (
                "missing",
                r#"
                async fn run_startup() -> anyhow::Result<()> {
                    let (mut registry, pg_readiness_period, domain_module) =
                        phase_result(RuntimePhase::WireDomains, async {
                            Ok::<_, anyhow::Error>((registry, period, module))
                        }.await)?;
                    Ok(())
                }
                "#,
            ),
            (
                "decoy",
                r#"
                async fn run_startup() -> anyhow::Result<()> {
                    let (mut registry, pg_readiness_period, domain_module) =
                        phase_result(RuntimePhase::WireDomains, async {
                            let mut domain_bindings = decoy::wire_domains(&deps, domain_modules)
                                .await
                                .context("wire generated domains")?;
                            let (mut registry, domains_module) =
                                bootstrap::compose_bindings(&mut domain_bindings)
                                    .context("compose generated domains")?;
                            Ok::<_, anyhow::Error>((registry, period, domains_module))
                        }.await)?;
                    Ok(())
                }
                "#,
            ),
            (
                "discarded",
                r#"
                async fn run_startup() -> anyhow::Result<()> {
                    let (mut registry, pg_readiness_period, domain_module) =
                        phase_result(RuntimePhase::WireDomains, async {
                            modules_gen::wire_domains(&deps, domain_modules)
                                .await
                                .context("wire generated domains")?;
                            Ok::<_, anyhow::Error>((registry, period, module))
                        }.await)?;
                    Ok(())
                }
                "#,
            ),
            (
                "conditional",
                r#"
                async fn run_startup() -> anyhow::Result<()> {
                    let (mut registry, pg_readiness_period, domain_module) =
                        phase_result(RuntimePhase::WireDomains, async {
                            if enabled {
                                let mut domain_bindings =
                                    modules_gen::wire_domains(&deps, domain_modules)
                                        .await
                                        .context("wire generated domains")?;
                                let (mut registry, domains_module) =
                                    bootstrap::compose_bindings(&mut domain_bindings)
                                        .context("compose generated domains")?;
                            }
                            Ok::<_, anyhow::Error>((registry, period, module))
                        }.await)?;
                    Ok(())
                }
                "#,
            ),
        ];
        for (case, runtime_entry) in invalid_entries {
            let root =
                crate::testutil::unique_tmp(&format!("producer-composition-runtime-entry-{case}"));
            for relative in [
                IDENTITY_COMPOSITION,
                SETTINGS_COMPOSITION,
                RUNTIME_MODULES,
                IDENTITY_RUNTIME_MODULE,
                SETTINGS_RUNTIME_MODULE,
            ] {
                let destination = root.join(relative);
                fs::create_dir_all(destination.parent().context("composition parent")?)?;
                fs::copy(workspace.join(relative), destination)?;
            }
            let runtime = root.join("assemblies/runtime/src/lib.rs");
            fs::create_dir_all(runtime.parent().context("runtime entry parent")?)?;
            fs::write(runtime, runtime_entry)?;

            let result = collect_producer_composition(&root);
            fs::remove_dir_all(root)?;
            assert!(
                result.is_err(),
                "runtime entry mutation `{case}` must invalidate production composition evidence"
            );
        }
        Ok(())
    }
}
