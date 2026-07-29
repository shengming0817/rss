//! `runtime-root guard` -- runtime composition-root responsibility ratchet.
//!
//! INVARIANT: RUNTIME-ROOT-RATCHET-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::policy_rejects_truncation_growth_unknown_fields_and_baseline_tampering + tests::merge_base_prefix_rejects_synchronized_policy_ledger_and_root_growth + tests::policy_free_merge_base_is_rejected_without_bootstrap + tests::runtime_plan_and_live_construction_are_forbidden_in_root + tests::workspace_inputs_are_required_and_parse_fail_closed", anti_vacuity = "tests::real_workspace_root_matches_latest_ratchet" } -- the runtime crate root stays a thin lifecycle entrypoint, its responsibility metrics can only decrease, immutable history is verified against the `/usr/bin/git` merge base, production `include!` cannot hide responsibilities, and RuntimePlan/live construction cannot move back into the root.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use proc_macro2::{TokenStream, TokenTree};
use serde::Deserialize;
use syn::spanned::Spanned as _;
use syn::visit::Visit as _;

use crate::diagnostic::{Finding, GovernanceCheck, finding};

const POLICY_PATH: &str = "xtask/runtime-root-ratchet.toml";
const ROOT_PATH: &str = "assemblies/runtime/src/lib.rs";
const PRE_1794_REVISION: &str = "pre-1794";
const ISSUE_1794_REVISION: &str = "issue-1794";
const ISSUE_1795_REVISION: &str = "issue-1795";
const ISSUE_1797_REVISION: &str = "issue-1797";
const DEFAULT_BASE: &str = "origin/develop";
pub(crate) const BASE_ENV: &str = "RSS_RUNTIME_ROOT_BASE";

const RUNTIME_PLAN_CALLS: &[&str] = &[
    "bundled",
    "compile",
    "domain_execution_plan",
    "listener_execution_plan",
    "placement_execution_plan",
    "provider_execution_plan",
];
const LIVE_CONSTRUCTION_CALLS: &[&str] = &[
    "build_providers",
    "compose_bindings",
    "finalize_listener_plan",
    "from_placement",
    "wire_domains",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Metrics {
    raw_lines: usize,
    top_level_functions: usize,
    top_level_types: usize,
    top_level_const_static: usize,
    impl_methods: usize,
    public_modules: usize,
    public_reexports: usize,
    inline_production_modules: usize,
}

const PRE_1794_METRICS: Metrics = Metrics {
    raw_lines: 9_428,
    top_level_functions: 123,
    top_level_types: 43,
    top_level_const_static: 28,
    impl_methods: 59,
    public_modules: 8,
    public_reexports: 12,
    inline_production_modules: 0,
};

// Keeping the landed checkpoint compiled into the guard prevents later policy revisions from
// rewriting the historical ratchet tail.
const ISSUE_1794_METRICS: Metrics = Metrics {
    raw_lines: 260,
    top_level_functions: 11,
    top_level_types: 1,
    top_level_const_static: 2,
    impl_methods: 3,
    public_modules: 8,
    public_reexports: 10,
    inline_production_modules: 0,
};

const ISSUE_1795_METRICS: Metrics = Metrics {
    raw_lines: 260,
    top_level_functions: 11,
    top_level_types: 1,
    top_level_const_static: 2,
    impl_methods: 3,
    public_modules: 8,
    public_reexports: 9,
    inline_production_modules: 0,
};

const ISSUE_1797_METRICS: Metrics = Metrics {
    raw_lines: 259,
    top_level_functions: 11,
    top_level_types: 1,
    top_level_const_static: 2,
    impl_methods: 3,
    public_modules: 8,
    public_reexports: 9,
    inline_production_modules: 0,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LandedRevision {
    revision: &'static str,
    previous_revision: Option<&'static str>,
    metrics: Metrics,
}

// This compiled ledger is the independent, append-only commitment for the TOML history. A future
// ratchet revision is not considered landed until it is appended here as well as to the policy.
// Exact length and value equality make deleting or rewriting any previously landed tail fail
// closed even if `currentRevision` is rolled back in the policy at the same time.
const LANDED_HISTORY: &[LandedRevision] = &[
    LandedRevision {
        revision: PRE_1794_REVISION,
        previous_revision: None,
        metrics: PRE_1794_METRICS,
    },
    LandedRevision {
        revision: ISSUE_1794_REVISION,
        previous_revision: Some(PRE_1794_REVISION),
        metrics: ISSUE_1794_METRICS,
    },
    LandedRevision {
        revision: ISSUE_1795_REVISION,
        previous_revision: Some(ISSUE_1794_REVISION),
        metrics: ISSUE_1795_METRICS,
    },
    LandedRevision {
        revision: ISSUE_1797_REVISION,
        previous_revision: Some(ISSUE_1795_REVISION),
        metrics: ISSUE_1797_METRICS,
    },
];

impl Metrics {
    fn fields(self) -> [(&'static str, usize); 8] {
        [
            ("rawLines", self.raw_lines),
            ("topLevelFunctions", self.top_level_functions),
            ("topLevelTypes", self.top_level_types),
            ("topLevelConstStatic", self.top_level_const_static),
            ("implMethods", self.impl_methods),
            ("publicModules", self.public_modules),
            ("publicReexports", self.public_reexports),
            ("inlineProductionModules", self.inline_production_modules),
        ]
    }

    fn render(self) -> String {
        self.fields()
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyFile {
    schema_version: u32,
    current_revision: String,
    history: Vec<PolicyRevision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyRevision {
    revision: String,
    previous_revision: Option<String>,
    raw_lines: usize,
    top_level_functions: usize,
    top_level_types: usize,
    top_level_const_static: usize,
    impl_methods: usize,
    public_modules: usize,
    public_reexports: usize,
    inline_production_modules: usize,
}

impl PolicyRevision {
    fn metrics(&self) -> Metrics {
        Metrics {
            raw_lines: self.raw_lines,
            top_level_functions: self.top_level_functions,
            top_level_types: self.top_level_types,
            top_level_const_static: self.top_level_const_static,
            impl_methods: self.impl_methods,
            public_modules: self.public_modules,
            public_reexports: self.public_reexports,
            inline_production_modules: self.inline_production_modules,
        }
    }
}

#[derive(Debug)]
struct RuntimeRootPolicy {
    current_revision: String,
    history: Vec<PolicyRevision>,
    latest_metrics: Metrics,
}

impl RuntimeRootPolicy {
    fn from_workspace(root: &Path) -> Result<Self> {
        let path = root.join(POLICY_PATH);
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("runtime-root guard reads {}", path.display()))?;
        Self::from_toml_str(&raw)
            .with_context(|| format!("runtime-root guard validates {}", path.display()))
    }

    fn from_toml_str(raw: &str) -> Result<Self> {
        Self::from_toml_str_with_landed_history(raw, LANDED_HISTORY)
    }

    fn from_toml_str_with_landed_history(
        raw: &str,
        landed_history: &[LandedRevision],
    ) -> Result<Self> {
        let policy = parse_policy_file(raw)?;
        if landed_history.len() < 2 {
            bail!("runtime-root guard: compiled landed-history commitment is truncated");
        }
        if policy.history.len() != landed_history.len() {
            bail!(
                "runtime-root guard: policy history length {} differs from compiled landed-history commitment {}; append both ledgers together and never delete a landed tail",
                policy.history.len(),
                landed_history.len()
            );
        }
        for (index, (revision, landed)) in policy.history.iter().zip(landed_history).enumerate() {
            if revision.revision != landed.revision
                || revision.previous_revision.as_deref() != landed.previous_revision
                || revision.metrics() != landed.metrics
            {
                bail!(
                    "runtime-root guard: landed history revision {} drift; expected `{}` after {:?} with {}, got `{}` after {:?} with {}",
                    index + 1,
                    landed.revision,
                    landed.previous_revision,
                    landed.metrics.render(),
                    revision.revision,
                    revision.previous_revision,
                    revision.metrics().render()
                );
            }
        }
        let last = policy.history.last().context("non-empty policy history")?;
        if last.revision != policy.current_revision {
            bail!(
                "runtime-root guard: currentRevision `{}` does not match last history revision `{}`",
                policy.current_revision,
                last.revision
            );
        }
        let latest_metrics = last.metrics();

        Ok(Self {
            current_revision: policy.current_revision,
            history: policy.history,
            latest_metrics,
        })
    }

    fn latest_metrics(&self) -> Metrics {
        self.latest_metrics
    }
}

fn parse_policy_file(raw: &str) -> Result<PolicyFile> {
    let policy: PolicyFile =
        toml::from_str(raw).context("runtime-root guard parses policy TOML")?;
    if policy.schema_version != 1 {
        bail!(
            "runtime-root guard: schemaVersion must be 1, got {}",
            policy.schema_version
        );
    }
    if policy.history.is_empty() {
        bail!("runtime-root guard: history must be non-empty");
    }
    if policy.current_revision.trim() != policy.current_revision
        || policy.current_revision.is_empty()
    {
        bail!("runtime-root guard: currentRevision must be non-empty and unpadded");
    }
    let mut seen = BTreeSet::new();
    for revision in &policy.history {
        if revision.revision.trim() != revision.revision || revision.revision.is_empty() {
            bail!("runtime-root guard: revision names must be non-empty and unpadded");
        }
        if !seen.insert(revision.revision.clone()) {
            bail!(
                "runtime-root guard: duplicate history revision `{}`",
                revision.revision
            );
        }
    }
    if policy.history[0].previous_revision.is_some() {
        bail!("runtime-root guard: first revision must not have previousRevision");
    }
    for pair in policy.history.windows(2) {
        if pair[1].previous_revision.as_deref() != Some(pair[0].revision.as_str()) {
            bail!(
                "runtime-root guard: revision `{}` must name `{}` as previousRevision",
                pair[1].revision,
                pair[0].revision
            );
        }
        let previous = pair[0].metrics();
        let next = pair[1].metrics();
        for ((field, previous), (_, next)) in previous.fields().into_iter().zip(next.fields()) {
            if next > previous {
                bail!(
                    "runtime-root guard: revision `{}` raises {field} from {previous} to {next}",
                    pair[1].revision
                );
            }
        }
    }
    let last = policy.history.last().context("non-empty policy history")?;
    if last.revision != policy.current_revision {
        bail!(
            "runtime-root guard: currentRevision `{}` does not match last history revision `{}`",
            policy.current_revision,
            last.revision
        );
    }
    Ok(policy)
}

fn validate_immutable_history_prefix(base: &PolicyFile, current: &[PolicyRevision]) -> Result<()> {
    anyhow::ensure!(
        current.len() >= base.history.len(),
        "runtime-root guard: current history truncates the merge-base immutable prefix"
    );
    for (index, (base, current)) in base.history.iter().zip(current).enumerate() {
        anyhow::ensure!(
            base == current,
            "runtime-root guard: merge-base immutable history revision {} drift",
            index + 1
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    MetricDrift,
    StartupDelegation,
    RootResponsibility,
}

pub(crate) struct RuntimeRootGuard;

impl GovernanceCheck for RuntimeRootGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "runtime-root guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Rule>>)> {
        let root = crate::workspace_root()?;
        inspect_workspace(&root)
    }
}

fn inspect_workspace(root: &Path) -> Result<(String, Vec<Finding<Rule>>)> {
    let policy = RuntimeRootPolicy::from_workspace(root)?;
    let path = root.join(ROOT_PATH);
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("runtime-root guard reads {}", path.display()))?;
    let (metrics, findings) = inspect_source(ROOT_PATH, &source, policy.latest_metrics())?;
    validate_history_against_merge_base(root, &policy)?;
    Ok((
        format!(
            "{} satisfies {} ({})",
            ROOT_PATH,
            policy.current_revision,
            metrics.render()
        ),
        findings,
    ))
}

fn resolve_base_from(environment: Option<String>) -> Result<String> {
    let base = environment.unwrap_or_else(|| DEFAULT_BASE.to_owned());
    anyhow::ensure!(
        !base.is_empty() && !base.starts_with('-'),
        "runtime-root guard: invalid {BASE_ENV} base ref `{base}`"
    );
    anyhow::ensure!(
        !matches!(
            base.trim(),
            "HEAD" | "@" | "HEAD~0" | "HEAD^0" | "@~0" | "@^0"
        ),
        "runtime-root guard: self-referential base ref `{base}` is forbidden"
    );
    Ok(base)
}

fn git_output(root: &Path, args: &[&str]) -> Result<std::process::Output> {
    crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        args,
        &[],
        Some(root),
    )
    .output()
    .with_context(|| format!("runtime-root guard runs /usr/bin/git {}", args.join(" ")))
}

fn git_stdout(root: &Path, args: &[&str]) -> Result<String> {
    let output = git_output(root, args)?;
    anyhow::ensure!(
        output.status.success(),
        "runtime-root guard: /usr/bin/git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    String::from_utf8(output.stdout).context("runtime-root guard: git output is not UTF-8")
}

fn git_object_exists(root: &Path, object: &str) -> Result<bool> {
    let output = git_output(root, &["cat-file", "-e", object])?;
    if output.status.success() {
        return Ok(true);
    }
    if output.status.code() == Some(1) || output.status.code() == Some(128) {
        return Ok(false);
    }
    bail!(
        "runtime-root guard: git cat-file failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn validate_history_against_merge_base(root: &Path, current: &RuntimeRootPolicy) -> Result<()> {
    let base = resolve_base_from(std::env::var(BASE_ENV).ok())?;
    validate_history_against_base_ref(root, current, &base)
}

fn validate_history_against_base_ref(
    root: &Path,
    current: &RuntimeRootPolicy,
    base: &str,
) -> Result<()> {
    let commitish = format!("{base}^{{commit}}");
    let resolved = git_stdout(root, &["rev-parse", "--verify", "--quiet", &commitish])?;
    let resolved = resolved.trim();
    anyhow::ensure!(
        !resolved.is_empty(),
        "runtime-root guard: base ref resolved empty"
    );
    let merge_base = git_stdout(root, &["merge-base", resolved, "HEAD"])?;
    let merge_base = merge_base.trim();
    anyhow::ensure!(
        !merge_base.is_empty(),
        "runtime-root guard: git merge-base returned no commit"
    );

    let policy_object = format!("{merge_base}:{POLICY_PATH}");
    anyhow::ensure!(
        git_object_exists(root, &policy_object)?,
        "runtime-root guard: merge-base `{merge_base}` is missing protected policy `{POLICY_PATH}`; seed the policy on the base ref before appending a revision"
    );
    let base_raw = git_stdout(root, &["show", &policy_object])?;
    let base_policy =
        parse_policy_file(&base_raw).context("runtime-root guard validates merge-base policy")?;
    validate_immutable_history_prefix(&base_policy, &current.history)
}

fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn attrs_may_be_production(attrs: &[syn::Attribute]) -> bool {
    !attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .parse_args::<syn::Meta>()
                .is_ok_and(|meta| !cfg_can_be_live(&meta))
    })
}

fn cfg_can_be_live(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) if path.is_ident("test") => false,
        syn::Meta::NameValue(value)
            if value.path.is_ident("feature")
                && matches!(&value.value, syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(feature),
                    ..
                }) if feature.value() == "integration") =>
        {
            false
        }
        syn::Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
            let nested = list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .unwrap_or_default();
            if list.path.is_ident("all") {
                nested.iter().all(cfg_can_be_live)
            } else {
                nested.iter().any(cfg_can_be_live)
            }
        }
        syn::Meta::List(list) if list.path.is_ident("not") => true,
        _ => true,
    }
}

fn is_public(visibility: &syn::Visibility) -> bool {
    matches!(visibility, syn::Visibility::Public(_))
}

fn use_tree_leaf_count(tree: &syn::UseTree) -> usize {
    match tree {
        syn::UseTree::Path(path) => use_tree_leaf_count(&path.tree),
        syn::UseTree::Group(group) => group.items.iter().map(use_tree_leaf_count).sum(),
        syn::UseTree::Name(_) | syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => 1,
    }
}

fn use_tree_contains_glob(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Path(path) => use_tree_contains_glob(&path.tree),
        syn::UseTree::Group(group) => group.items.iter().any(use_tree_contains_glob),
        syn::UseTree::Glob(_) => true,
        syn::UseTree::Name(_) | syn::UseTree::Rename(_) => false,
    }
}

fn metrics_of_file(source: &str, file: &syn::File) -> Metrics {
    let mut metrics = Metrics {
        raw_lines: source.lines().count(),
        top_level_functions: 0,
        top_level_types: 0,
        top_level_const_static: 0,
        impl_methods: 0,
        public_modules: 0,
        public_reexports: 0,
        inline_production_modules: 0,
    };
    for item in &file.items {
        if !attrs_may_be_production(item_attrs(item)) {
            continue;
        }
        match item {
            syn::Item::Fn(_) => metrics.top_level_functions += 1,
            syn::Item::Enum(_)
            | syn::Item::Struct(_)
            | syn::Item::Trait(_)
            | syn::Item::TraitAlias(_)
            | syn::Item::Type(_)
            | syn::Item::Union(_) => metrics.top_level_types += 1,
            syn::Item::Const(_) | syn::Item::Static(_) => metrics.top_level_const_static += 1,
            syn::Item::Impl(item) => {
                metrics.impl_methods += item
                    .items
                    .iter()
                    .filter(|entry| {
                        matches!(entry, syn::ImplItem::Fn(method) if attrs_may_be_production(&method.attrs))
                    })
                    .count();
            }
            syn::Item::Mod(item) if item.content.is_some() => {
                metrics.inline_production_modules += 1;
            }
            _ => {}
        }
        metrics.public_modules +=
            usize::from(matches!(item, syn::Item::Mod(module) if is_public(&module.vis)));
        if let syn::Item::Use(reexport) = item
            && is_public(&reexport.vis)
        {
            metrics.public_reexports += use_tree_leaf_count(&reexport.tree);
        }
    }
    metrics
}

fn inspect_source(
    path: &str,
    source: &str,
    ceiling: Metrics,
) -> Result<(Metrics, Vec<Finding<Rule>>)> {
    let file = syn::parse_file(source)
        .with_context(|| format!("runtime-root guard parses production Rust {path}"))?;
    let metrics = metrics_of_file(source, &file);
    let mut findings = Vec::new();
    for ((field, actual), (_, limit)) in metrics.fields().into_iter().zip(ceiling.fields()) {
        if actual != limit {
            findings.push(finding(
                Rule::MetricDrift,
                format!("{path}:{field}"),
                format!("latest ratchet inventory={limit}, actual={actual}"),
            ));
        }
    }

    let mut semantics = RootSemantics::new(path);
    semantics.visit_file(&file);
    findings.extend(semantics.finish());
    Ok((metrics, findings))
}

struct RootSemantics<'a> {
    path: &'a str,
    function_depth: usize,
    current_top_function: Option<String>,
    run_startup_functions: usize,
    direct_run_startup_delegates: usize,
    phase_execute_calls: usize,
    run_startup_phase_execute_calls: usize,
    runtime_plan_values: BTreeSet<String>,
    forbidden: BTreeSet<String>,
}

impl<'a> RootSemantics<'a> {
    fn new(path: &'a str) -> Self {
        Self {
            path,
            function_depth: 0,
            current_top_function: None,
            run_startup_functions: 0,
            direct_run_startup_delegates: 0,
            phase_execute_calls: 0,
            run_startup_phase_execute_calls: 0,
            runtime_plan_values: BTreeSet::new(),
            forbidden: BTreeSet::new(),
        }
    }

    fn report(&mut self, span: proc_macro2::Span, detail: impl Into<String>) {
        self.forbidden.insert(format!(
            "{}:{}: {}",
            self.path,
            span.start().line,
            detail.into()
        ));
    }

    fn finish(self) -> Vec<Finding<Rule>> {
        let mut findings = Vec::new();
        if self.run_startup_functions != 1
            || self.direct_run_startup_delegates != 1
            || self.phase_execute_calls != 1
            || self.run_startup_phase_execute_calls != 1
        {
            findings.push(finding(
                Rule::StartupDelegation,
                self.path,
                format!(
                    "expected one single-expression top-level run_startup owning the only direct phase::execute call; run_startup={}, direct_delegates={}, global_calls={}, owned_calls={}",
                    self.run_startup_functions,
                    self.direct_run_startup_delegates,
                    self.phase_execute_calls,
                    self.run_startup_phase_execute_calls
                ),
            ));
        }
        findings.extend(self.forbidden.into_iter().map(|detail| {
            finding(
                Rule::RootResponsibility,
                self.path,
                format!("production root responsibility escaped its phase owner: {detail}"),
            )
        }));
        findings
    }
}

impl<'ast> syn::visit::Visit<'ast> for RootSemantics<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if attrs_may_be_production(item_attrs(item)) {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let top_level = self.function_depth == 0;
        let prior = self.current_top_function.clone();
        if top_level {
            let name = item.sig.ident.to_string();
            self.run_startup_functions += usize::from(name == "run_startup");
            self.direct_run_startup_delegates += usize::from(
                name == "run_startup"
                    && matches!(item.block.stmts.as_slice(), [syn::Stmt::Expr(expr, _)] if direct_phase_delegate(expr)),
            );
            if LIVE_CONSTRUCTION_CALLS.contains(&name.as_str()) {
                self.report(
                    item.sig.ident.span(),
                    format!("forbidden root function `{name}`"),
                );
            }
            self.current_top_function = Some(name);
        }
        for input in &item.sig.inputs {
            if let syn::FnArg::Typed(argument) = input
                && type_may_be_runtime_plan(&argument.ty)
            {
                collect_pattern_idents(&argument.pat, &mut self.runtime_plan_values);
            }
        }
        self.function_depth += 1;
        syn::visit::visit_item_fn(self, item);
        self.function_depth -= 1;
        self.current_top_function = prior;
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !attrs_may_be_production(&item.attrs) {
            return;
        }
        let name = item.sig.ident.to_string();
        if LIVE_CONSTRUCTION_CALLS.contains(&name.as_str()) {
            self.report(
                item.sig.ident.span(),
                format!("forbidden root impl method `{name}`"),
            );
        }
        syn::visit::visit_impl_item_fn(self, item);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        let typed_as_plan = matches!(
            &local.pat,
            syn::Pat::Type(typed) if type_may_be_runtime_plan(&typed.ty)
        );
        let aliases_plan = local.init.as_ref().is_some_and(|init| {
            expression_names_runtime_plan(&init.expr, &self.runtime_plan_values)
        });
        if typed_as_plan || aliases_plan {
            collect_pattern_idents(&local.pat, &mut self.runtime_plan_values);
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = transparent(&call.func) {
            let segments = path_segments(&path.path);
            if segments == ["phase", "execute"] {
                self.phase_execute_calls += 1;
                self.run_startup_phase_execute_calls += usize::from(
                    self.function_depth == 1
                        && self.current_top_function.as_deref() == Some("run_startup"),
                );
            }
            if segments.iter().any(|segment| segment == "RuntimePlan")
                || segments.last().is_some_and(|name| {
                    RUNTIME_PLAN_CALLS.contains(&name.as_str())
                        || LIVE_CONSTRUCTION_CALLS.contains(&name.as_str())
                })
            {
                self.report(
                    call.span(),
                    format!("forbidden call `{}`", segments.join("::")),
                );
            }
            if segments.last().is_some_and(|name| name == "drop")
                && call.args.iter().any(|argument| {
                    expression_names_runtime_plan(argument, &self.runtime_plan_values)
                })
            {
                self.report(
                    call.span(),
                    "RuntimePlan may not be dropped in the crate root",
                );
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        let receiver = compact_tokens(&call.receiver);
        if LIVE_CONSTRUCTION_CALLS.contains(&method.as_str())
            || RUNTIME_PLAN_CALLS.contains(&method.as_str())
            || method == "drop"
                && expression_names_runtime_plan(&call.receiver, &self.runtime_plan_values)
        {
            self.report(
                call.span(),
                format!("forbidden method call `{receiver}.{method}`"),
            );
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments = path_segments(path);
        if segments.iter().any(|segment| segment == "RuntimePlan") {
            self.report(
                path.span(),
                "RuntimePlan reference belongs to the phase owner",
            );
        }
        if segments.last().is_some_and(|name| {
            RUNTIME_PLAN_CALLS.contains(&name.as_str())
                || LIVE_CONSTRUCTION_CALLS.contains(&name.as_str())
        }) {
            self.report(
                path.span(),
                format!("forbidden callable path `{}`", segments.join("::")),
            );
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let tokens = compact_tokens(&item.tree);
        if is_public(&item.vis) && use_tree_contains_glob(&item.tree) {
            self.report(
                item.span(),
                "public wildcard re-export has an unbounded root surface",
            );
        } else if tokens.contains("RuntimePlan")
            || RUNTIME_PLAN_CALLS.iter().any(|name| tokens.contains(name))
            || LIVE_CONSTRUCTION_CALLS
                .iter()
                .any(|name| tokens.contains(name))
        {
            self.report(item.span(), format!("forbidden import `{tokens}`"));
        }
        syn::visit::visit_item_use(self, item);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mac
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "include")
        {
            self.report(
                mac.span(),
                "production include! may not inject an unscanned root responsibility",
            );
        }
        let tokens = code_tokens(mac.tokens.clone());
        if tokens.contains("phase::execute")
            || tokens.contains("RuntimePlan")
            || RUNTIME_PLAN_CALLS.iter().any(|name| tokens.contains(name))
            || LIVE_CONSTRUCTION_CALLS
                .iter()
                .any(|name| tokens.contains(name))
        {
            self.report(
                mac.span(),
                "macro tokens may not hide startup delegation or live construction",
            );
        }
        syn::visit::visit_macro(self, mac);
    }
}

fn type_may_be_runtime_plan(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Group(group) => type_may_be_runtime_plan(&group.elem),
        syn::Type::Paren(paren) => type_may_be_runtime_plan(&paren.elem),
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident.to_string().ends_with("Plan")),
        syn::Type::Reference(reference) => type_may_be_runtime_plan(&reference.elem),
        _ => false,
    }
}

fn collect_pattern_idents(pattern: &syn::Pat, output: &mut BTreeSet<String>) {
    match pattern {
        syn::Pat::Ident(ident) => {
            output.insert(ident.ident.to_string());
            if let Some((_, subpattern)) = &ident.subpat {
                collect_pattern_idents(subpattern, output);
            }
        }
        syn::Pat::Paren(paren) => collect_pattern_idents(&paren.pat, output),
        syn::Pat::Reference(reference) => collect_pattern_idents(&reference.pat, output),
        syn::Pat::Slice(slice) => {
            for element in &slice.elems {
                collect_pattern_idents(element, output);
            }
        }
        syn::Pat::Struct(structure) => {
            for field in &structure.fields {
                collect_pattern_idents(&field.pat, output);
            }
        }
        syn::Pat::Tuple(tuple) => {
            for element in &tuple.elems {
                collect_pattern_idents(element, output);
            }
        }
        syn::Pat::TupleStruct(tuple) => {
            for element in &tuple.elems {
                collect_pattern_idents(element, output);
            }
        }
        syn::Pat::Type(typed) => collect_pattern_idents(&typed.pat, output),
        _ => {}
    }
}

fn expression_names_runtime_plan(
    expression: &syn::Expr,
    runtime_plan_values: &BTreeSet<String>,
) -> bool {
    match transparent(expression) {
        syn::Expr::Path(path) => {
            let segments = path_segments(&path.path);
            segments.iter().any(|segment| segment == "RuntimePlan")
                || segments.last().is_some_and(|name| {
                    runtime_plan_values.contains(name)
                        || name.to_ascii_lowercase().contains("runtime_plan")
                        || name.to_ascii_lowercase().ends_with("plan")
                })
        }
        syn::Expr::Reference(reference) => {
            expression_names_runtime_plan(&reference.expr, runtime_plan_values)
        }
        _ => false,
    }
}

fn transparent(expr: &syn::Expr) -> &syn::Expr {
    match expr {
        syn::Expr::Group(group) => transparent(&group.expr),
        syn::Expr::Paren(paren) => transparent(&paren.expr),
        _ => expr,
    }
}

fn direct_phase_delegate(expr: &syn::Expr) -> bool {
    match transparent(expr) {
        syn::Expr::Await(awaited) => direct_phase_delegate(&awaited.base),
        syn::Expr::MethodCall(method) => direct_phase_delegate(&method.receiver),
        syn::Expr::Return(returned) => returned.expr.as_deref().is_some_and(direct_phase_delegate),
        syn::Expr::Try(tried) => direct_phase_delegate(&tried.expr),
        syn::Expr::Call(call) => {
            matches!(transparent(&call.func), syn::Expr::Path(path) if path_segments(&path.path) == ["phase", "execute"])
        }
        _ => false,
    }
}

fn path_segments(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect()
}

fn compact_tokens(value: &impl quote::ToTokens) -> String {
    value
        .to_token_stream()
        .to_string()
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn code_tokens(tokens: TokenStream) -> String {
    fn collect(tokens: TokenStream, output: &mut String) {
        for token in tokens {
            match token {
                TokenTree::Ident(ident) => output.push_str(&ident.to_string()),
                TokenTree::Punct(punct) => output.push(punct.as_char()),
                TokenTree::Group(group) => collect(group.stream(), output),
                TokenTree::Literal(_) => {}
            }
        }
    }
    let mut output = String::new();
    collect(tokens, &mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_POLICY: &str = include_str!("../runtime-root-ratchet.toml");

    fn policy_error(raw: &str) -> Result<anyhow::Error> {
        error_from_result(RuntimeRootPolicy::from_toml_str(raw))
    }

    fn policy_error_with_landed_history(
        raw: &str,
        landed_history: &[LandedRevision],
    ) -> Result<anyhow::Error> {
        error_from_result(RuntimeRootPolicy::from_toml_str_with_landed_history(
            raw,
            landed_history,
        ))
    }

    fn error_from_result<T>(result: Result<T>) -> Result<anyhow::Error> {
        match result {
            Ok(_) => bail!("policy unexpectedly passed"),
            Err(error) => Ok(error),
        }
    }

    fn run_test_git(root: &Path, args: &[&str]) -> Result<()> {
        let output = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::SystemGit,
            args,
            &[],
            Some(root),
        )
        .output()
        .with_context(|| format!("test git {}", args.join(" ")))?;
        anyhow::ensure!(
            output.status.success(),
            "test git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    }

    fn replace_history_metric(
        raw: &str,
        revision: &str,
        field: &str,
        replacement: usize,
    ) -> Result<String> {
        let revision_marker = format!("[[history]]\nrevision = \"{revision}\"");
        let revision_start = raw
            .find(&revision_marker)
            .context("history revision marker")?;
        let revision_end = raw[revision_start + revision_marker.len()..]
            .find("[[history]]")
            .map_or(raw.len(), |offset| {
                revision_start + revision_marker.len() + offset
            });
        let field_marker = format!("{field} = ");
        let field_start = raw[revision_start..revision_end]
            .find(&field_marker)
            .map(|offset| revision_start + offset + field_marker.len())
            .context("history metric marker")?;
        let field_end = raw[field_start..]
            .find('\n')
            .map_or(raw.len(), |offset| field_start + offset);
        let mut rewritten = raw.to_owned();
        rewritten.replace_range(field_start..field_end, &replacement.to_string());
        Ok(rewritten)
    }

    fn render_history_revision(revision: &str, previous: &str, metrics: Metrics) -> String {
        format!(
            "[[history]]\nrevision = \"{revision}\"\npreviousRevision = \"{previous}\"\nrawLines = {}\ntopLevelFunctions = {}\ntopLevelTypes = {}\ntopLevelConstStatic = {}\nimplMethods = {}\npublicModules = {}\npublicReexports = {}\ninlineProductionModules = {}\n",
            metrics.raw_lines,
            metrics.top_level_functions,
            metrics.top_level_types,
            metrics.top_level_const_static,
            metrics.impl_methods,
            metrics.public_modules,
            metrics.public_reexports,
            metrics.inline_production_modules,
        )
    }

    fn canonical_source(extra: &str) -> String {
        format!(
            "async fn run_startup(inputs: &mut Inputs) -> Result<(), Error> {{ phase::execute(inputs).await.map(|_| ()) }}\n{extra}"
        )
    }

    #[test]
    fn policy_accepts_committed_schema_and_frozen_baseline() -> Result<()> {
        let policy = RuntimeRootPolicy::from_toml_str(VALID_POLICY)?;
        assert_eq!(policy.history.len(), LANDED_HISTORY.len());
        assert_eq!(policy.history[0].metrics(), PRE_1794_METRICS);
        assert_eq!(policy.history[1].metrics(), ISSUE_1794_METRICS);
        assert_eq!(policy.history[2].metrics(), ISSUE_1795_METRICS);
        assert_eq!(policy.history[3].metrics(), ISSUE_1797_METRICS);
        assert_eq!(policy.current_revision, ISSUE_1797_REVISION);
        Ok(())
    }

    #[test]
    fn policy_rejects_truncation_growth_unknown_fields_and_baseline_tampering() -> Result<()> {
        let second = VALID_POLICY
            .match_indices("[[history]]")
            .nth(1)
            .context("committed policy lacks second history entry")?
            .0;
        let truncated = &VALID_POLICY[..second];
        assert!(
            policy_error(truncated).is_ok(),
            "history truncation must fail closed"
        );

        let growth = replace_history_metric(
            VALID_POLICY,
            ISSUE_1794_REVISION,
            "topLevelFunctions",
            PRE_1794_METRICS.top_level_functions + 1,
        )?;
        assert!(
            format!("{:#}", policy_error(&growth)?).contains("raises topLevelFunctions"),
            "metric growth must fail closed"
        );

        let unknown =
            VALID_POLICY.replacen("schemaVersion = 1", "schemaVersion = 1\nextra = true", 1);
        assert!(
            format!("{:#}", policy_error(&unknown)?).contains("unknown field"),
            "unknown fields must fail closed"
        );

        let baseline = VALID_POLICY.replacen("rawLines = 9428", "rawLines = 9427", 1);
        assert!(
            format!("{:#}", policy_error(&baseline)?).contains("landed history revision 1 drift"),
            "first entry tampering must fail closed"
        );

        let rewritten_checkpoint = replace_history_metric(
            VALID_POLICY,
            ISSUE_1797_REVISION,
            "publicReexports",
            ISSUE_1797_METRICS.public_reexports - 1,
        )?;
        assert!(
            format!("{:#}", policy_error(&rewritten_checkpoint)?)
                .contains("landed history revision 4 drift"),
            "landed issue checkpoint tampering must fail closed"
        );
        Ok(())
    }

    #[test]
    fn policy_chain_detects_deleted_first_middle_and_tail_entries() -> Result<()> {
        let deleted_tail = VALID_POLICY
            .split_once("[[history]]\nrevision = \"issue-1794\"")
            .context("issue-1794 entry")?
            .0;
        assert!(policy_error(deleted_tail).is_ok());

        let deleted_first = VALID_POLICY.replacen(
            "[[history]]\nrevision = \"pre-1794\"\nrawLines = 9428\ntopLevelFunctions = 123\ntopLevelTypes = 43\ntopLevelConstStatic = 28\nimplMethods = 59\npublicModules = 8\npublicReexports = 12\ninlineProductionModules = 0\n\n",
            "",
            1,
        );
        assert!(policy_error(&deleted_first).is_ok());

        let fifth = format!(
            "{}\n{}",
            VALID_POLICY.replace(
                "currentRevision = \"issue-1797\"",
                "currentRevision = \"post-1797\""
            ),
            render_history_revision("post-1797", ISSUE_1797_REVISION, ISSUE_1797_METRICS),
        );
        const POST_1797: LandedRevision = LandedRevision {
            revision: "post-1797",
            previous_revision: Some(ISSUE_1797_REVISION),
            metrics: ISSUE_1797_METRICS,
        };
        let five_landed = [
            LANDED_HISTORY[0],
            LANDED_HISTORY[1],
            LANDED_HISTORY[2],
            LANDED_HISTORY[3],
            POST_1797,
        ];
        RuntimeRootPolicy::from_toml_str_with_landed_history(&fifth, &five_landed)?;

        let rolled_back_tail = fifth
            .replace(
                "currentRevision = \"post-1797\"",
                "currentRevision = \"issue-1797\"",
            )
            .split_once("[[history]]\nrevision = \"post-1797\"")
            .context("post-1797 entry")?
            .0
            .to_owned();
        assert!(
            format!(
                "{:#}",
                policy_error_with_landed_history(&rolled_back_tail, &five_landed)?
            )
            .contains("history length"),
            "deleting a landed tail and rolling currentRevision back must fail closed"
        );

        let rewritten_tail = replace_history_metric(
            &fifth,
            "post-1797",
            "publicReexports",
            ISSUE_1797_METRICS.public_reexports - 1,
        )?;
        assert!(
            format!(
                "{:#}",
                policy_error_with_landed_history(&rewritten_tail, &five_landed)?
            )
            .contains("landed history revision 5 drift"),
            "rewriting a future landed tail must fail closed"
        );
        let middle_start = fifth
            .find("[[history]]\nrevision = \"issue-1794\"")
            .context("middle entry start")?;
        let middle_end = fifth[middle_start + 1..]
            .find("[[history]]\nrevision = \"issue-1795\"")
            .map(|offset| middle_start + 1 + offset)
            .context("middle entry end")?;
        let deleted_middle = format!("{}{}", &fifth[..middle_start], &fifth[middle_end..]);
        assert!(policy_error_with_landed_history(&deleted_middle, &five_landed).is_ok());
        Ok(())
    }

    #[test]
    fn policy_rejects_malformed_duplicate_and_current_revision_drift() -> Result<()> {
        assert!(format!("{:#}", policy_error("schemaVersion =")?).contains("parses policy TOML"));
        let duplicate =
            VALID_POLICY.replacen("revision = \"issue-1794\"", "revision = \"pre-1794\"", 1);
        assert!(format!("{:#}", policy_error(&duplicate)?).contains("duplicate"));
        let stale = VALID_POLICY.replacen(
            "currentRevision = \"issue-1797\"",
            "currentRevision = \"pre-1794\"",
            1,
        );
        assert!(format!("{:#}", policy_error(&stale)?).contains("does not match"));
        Ok(())
    }

    #[test]
    fn workspace_inputs_are_required_and_parse_fail_closed() -> Result<()> {
        static NEXT_FIXTURE: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);
        let nonce = NEXT_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "rss-runtime-root-guard-{}-{nonce}",
            std::process::id()
        ));

        let missing_policy = error_from_result(inspect_workspace(&root))?;
        assert!(format!("{missing_policy:#}").contains("runtime-root-ratchet.toml"));

        std::fs::create_dir_all(root.join("xtask"))?;
        std::fs::write(root.join(POLICY_PATH), VALID_POLICY)?;
        let missing_root = error_from_result(inspect_workspace(&root))?;
        assert!(format!("{missing_root:#}").contains(ROOT_PATH));

        let runtime_root = root.join(ROOT_PATH);
        std::fs::create_dir_all(runtime_root.parent().context("runtime root parent")?)?;
        std::fs::write(&runtime_root, "fn {")?;
        let malformed_root = error_from_result(inspect_workspace(&root))?;
        assert!(format!("{malformed_root:#}").contains("parses production Rust"));

        std::fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn metric_inventory_excludes_test_responsibilities_but_counts_raw_lines() -> Result<()> {
        let source = r#"pub mod live;
pub use live::{Entry, Other as Alias};
pub struct Root;
const LIVE: usize = 1;
fn production() {}
impl Root { fn a(&self) {} #[cfg(test)] fn test_method(&self) {} }
#[cfg(test)] mod tests { pub fn bait() {} }
#[cfg(test)] pub struct TestType;
"#;
        let file = syn::parse_file(source)?;
        assert_eq!(
            metrics_of_file(source, &file),
            Metrics {
                raw_lines: 8,
                top_level_functions: 1,
                top_level_types: 1,
                top_level_const_static: 1,
                impl_methods: 1,
                public_modules: 1,
                public_reexports: 2,
                inline_production_modules: 0,
            }
        );
        Ok(())
    }

    #[test]
    fn source_parse_and_every_metric_growth_fail_closed() -> Result<()> {
        assert!(inspect_source("bad.rs", "fn {", PRE_1794_METRICS).is_err());
        let source = canonical_source(
            "pub mod external;\npub use external::Entry;\npub struct Root;\nconst LIVE: usize = 1;\nimpl Root { fn method(&self) {} }\nmod inline { fn owned() {} }",
        );
        let file = syn::parse_file(&source)?;
        let actual = metrics_of_file(&source, &file);
        for (field, actual_value) in actual.fields() {
            let mut ceiling = actual;
            match field {
                "rawLines" => ceiling.raw_lines = ceiling.raw_lines.saturating_sub(1),
                "topLevelFunctions" => {
                    ceiling.top_level_functions = ceiling.top_level_functions.saturating_sub(1)
                }
                "topLevelTypes" => ceiling.top_level_types = 0,
                "topLevelConstStatic" => ceiling.top_level_const_static = 0,
                "implMethods" => ceiling.impl_methods = 0,
                "publicModules" => ceiling.public_modules = 0,
                "publicReexports" => ceiling.public_reexports = 0,
                "inlineProductionModules" => ceiling.inline_production_modules = 0,
                _ => unreachable!(),
            }
            if actual_value > 0 {
                let (_, findings) = inspect_source("fixture.rs", &source, ceiling)?;
                assert!(
                    findings
                        .iter()
                        .any(|finding| finding.rule == Rule::MetricDrift),
                    "{field} growth escaped"
                );
            }
        }
        let mut stale_latest = actual;
        stale_latest.raw_lines += 1;
        let (_, findings) = inspect_source("fixture.rs", &source, stale_latest)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::MetricDrift),
            "latest revision must equal the workspace instead of acting as a loose ceiling"
        );
        Ok(())
    }

    #[test]
    fn startup_delegation_rejects_missing_duplicate_alias_macro_and_test_bait() -> Result<()> {
        let generous = PRE_1794_METRICS;
        let green = canonical_source(
            r#"#[cfg(test)] mod tests {
fn run_startup() { phase::execute(); }
fn bait() { let _ = "phase::execute(inputs)"; }
}
struct Fixture;
impl Fixture {
    #[cfg(test)]
    fn wire_domains() { RuntimePlan::compile(); }
}"#,
        );
        let (_, green_findings) = inspect_source("fixture.rs", &green, generous)?;
        assert!(
            green_findings
                .iter()
                .all(|finding| finding.rule == Rule::MetricDrift),
            "{green_findings:#?}"
        );

        for red in [
            "async fn run_startup() {}",
            "async fn run_startup() { phase::execute(); phase::execute(); }",
            "async fn other() { phase::execute(); }",
            "async fn run_startup() { fn dead() { phase::execute(); } }",
            "async fn run_startup() { let dead = || phase::execute(); }",
            "async fn run_startup() { if false { phase::execute(); } }",
            "async fn run_startup() { crate::phase::execute(); }",
            "macro_rules! hidden { () => { phase::execute() } }\nasync fn run_startup() { hidden!(); }",
            "// phase::execute()\nasync fn run_startup() { let _ = \"phase::execute()\"; }",
        ] {
            let (_, findings) = inspect_source("fixture.rs", red, generous)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::StartupDelegation),
                "startup weakening escaped: {red}\n{findings:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_plan_and_live_construction_are_forbidden_in_root() -> Result<()> {
        for extra in [
            "fn bad() { let _ = crate::plan::RuntimePlan::bundled(); }",
            "fn bad(runtime_plan: Plan) { runtime_plan.listener_execution_plan(); }",
            "fn bad(candidate: Plan) { candidate.provider_execution_plan(); }",
            "fn bad() { compose_bindings(); }",
            "fn bad() { crate::routes::finalize_listener_plan(); }",
            "fn compose_bindings() {}",
            "struct Fixture; impl Fixture { fn from_placement() {} }",
            "fn bad(runtime_plan: Plan) { drop(runtime_plan); }",
            "fn bad(candidate: Plan) { core::mem::drop(candidate); }",
            "fn bad(runtime_plan: Plan) { let renamed = runtime_plan; drop(renamed); }",
            "fn bad() { let compile_plan = crate::plan::RuntimePlan::compile; compile_plan(); }",
            "fn bad() { let compose = crate::routes::compose_bindings; compose(); }",
            "macro_rules! bad { () => { RuntimePlan::compile() } }",
            "macro_rules! bad { () => { candidate.listener_execution_plan() } }",
            "use crate::plan::RuntimePlan as Hidden;",
            "use crate::plan::RuntimePlan::compile as compile_plan;",
            "use crate::routes::compose_bindings as compose;",
            "pub use crate::phase::*;",
            "include!(\"root_live.rs\");",
        ] {
            let source = canonical_source(extra);
            let (_, findings) = inspect_source("fixture.rs", &source, PRE_1794_METRICS)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::RootResponsibility),
                "root responsibility escaped: {extra}\n{findings:#?}"
            );
        }

        let bait = canonical_source(
            r#"// RuntimePlan::compile and compose_bindings are documentation, not code.
fn docs() { let _ = "RuntimePlan::compile compose_bindings"; }"#,
        );
        let (_, bait_findings) = inspect_source("fixture.rs", &bait, PRE_1794_METRICS)?;
        assert!(
            bait_findings
                .iter()
                .all(|finding| finding.rule != Rule::RootResponsibility),
            "comment/string bait must not become semantic evidence: {bait_findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn merge_base_prefix_rejects_synchronized_policy_ledger_and_root_growth() -> Result<()> {
        let base = parse_policy_file(VALID_POLICY)?;
        let grown_metrics = Metrics {
            raw_lines: 500,
            ..ISSUE_1794_METRICS
        };
        let grown = replace_history_metric(
            VALID_POLICY,
            ISSUE_1794_REVISION,
            "rawLines",
            grown_metrics.raw_lines,
        )?;
        let grown = replace_history_metric(
            &grown,
            ISSUE_1795_REVISION,
            "rawLines",
            grown_metrics.raw_lines,
        )?;
        let grown = replace_history_metric(
            &grown,
            ISSUE_1797_REVISION,
            "rawLines",
            grown_metrics.raw_lines,
        )?;
        let landed = [
            LANDED_HISTORY[0],
            LandedRevision {
                revision: ISSUE_1794_REVISION,
                previous_revision: Some(PRE_1794_REVISION),
                metrics: grown_metrics,
            },
            LandedRevision {
                revision: ISSUE_1795_REVISION,
                previous_revision: Some(ISSUE_1794_REVISION),
                metrics: Metrics {
                    public_reexports: ISSUE_1795_METRICS.public_reexports,
                    ..grown_metrics
                },
            },
            LandedRevision {
                revision: ISSUE_1797_REVISION,
                previous_revision: Some(ISSUE_1795_REVISION),
                metrics: Metrics {
                    public_reexports: ISSUE_1797_METRICS.public_reexports,
                    ..grown_metrics
                },
            },
        ];
        let current = RuntimeRootPolicy::from_toml_str_with_landed_history(&grown, &landed)?;
        assert!(validate_immutable_history_prefix(&base, &current.history).is_err());
        Ok(())
    }

    #[test]
    fn policy_free_merge_base_is_rejected_without_bootstrap() -> Result<()> {
        static NEXT_FIXTURE: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);
        let nonce = NEXT_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "rss-runtime-root-policy-free-base-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root)?;
        run_test_git(&root, &["init", "-b", "main"])?;
        run_test_git(
            &root,
            &["config", "user.email", "runtime-root@test.invalid"],
        )?;
        run_test_git(&root, &["config", "user.name", "runtime-root-test"])?;
        std::fs::write(root.join("README.md"), "protected base without policy\n")?;
        run_test_git(&root, &["add", "README.md"])?;
        run_test_git(&root, &["commit", "-m", "base"])?;
        run_test_git(&root, &["branch", "protected"])?;

        std::fs::create_dir_all(root.join("xtask"))?;
        std::fs::write(root.join(POLICY_PATH), VALID_POLICY)?;
        run_test_git(&root, &["add", POLICY_PATH])?;
        run_test_git(&root, &["commit", "-m", "subject adds policy"])?;

        let current = RuntimeRootPolicy::from_toml_str(VALID_POLICY)?;
        let error = error_from_result(validate_history_against_base_ref(
            &root,
            &current,
            "protected",
        ))?;
        assert!(
            format!("{error:#}").contains("missing protected policy"),
            "policy-free merge base must fail closed: {error:#}"
        );
        std::fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn real_workspace_root_matches_latest_ratchet() -> Result<()> {
        let root = crate::workspace_root()?;
        let policy = RuntimeRootPolicy::from_workspace(&root)?;
        let source = std::fs::read_to_string(root.join(ROOT_PATH))?;
        let (metrics, findings) = inspect_source(ROOT_PATH, &source, policy.latest_metrics())?;
        assert!(metrics.raw_lines > 0, "metric anti-vacuity");
        assert!(
            metrics.top_level_functions > 0,
            "responsibility anti-vacuity"
        );
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }
}
