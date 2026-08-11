use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::OnceLock;
use syn::visit::{self, Visit};
use workspacefacts::WorkspaceFacts;

type MetadataLoader = dyn Fn(&Path) -> std::result::Result<Vec<u8>, String>;

/// Bounded cargo-metadata stderr retained in command diagnostics.
const METADATA_STDERR_CHAR_LIMIT: usize = 4096;

#[derive(Clone, Debug)]
enum FactsInitError {
    Load(String),
    Facts(String),
}

impl std::fmt::Display for FactsInitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Load(message) => write!(formatter, "{message}"),
            Self::Facts(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for FactsInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// 一条 xtask command 内的 lazy workspace facts owner；成功与失败都只加载一次。
pub(crate) struct CommandWorkspaceFacts {
    root: PathBuf,
    metadata_loader: Box<MetadataLoader>,
    facts: OnceLock<std::result::Result<WorkspaceFacts, FactsInitError>>,
}

impl CommandWorkspaceFacts {
    pub(crate) fn new(root: &Path) -> Self {
        Self::with_loader(root, |root| {
            run_cargo_metadata(
                root,
                &["--locked", "--all-features", "--format-version", "1"],
            )
        })
    }

    /// Fixture workspaces intentionally omit `--locked`; flags and failure diagnostics stay single-sourced.
    #[cfg(test)]
    pub(crate) fn for_test_fixture(root: &Path) -> Self {
        Self::with_loader(root, |root| {
            run_cargo_metadata(root, &["--format-version", "1", "--all-features"])
        })
    }

    #[cfg(test)]
    pub(crate) fn with_metadata_loader(
        root: &Path,
        metadata_loader: impl Fn(&Path) -> std::result::Result<Vec<u8>, String> + 'static,
    ) -> Self {
        Self::with_loader(root, metadata_loader)
    }

    fn with_loader(
        root: &Path,
        metadata_loader: impl Fn(&Path) -> std::result::Result<Vec<u8>, String> + 'static,
    ) -> Self {
        Self {
            root: root.to_path_buf(),
            metadata_loader: Box::new(metadata_loader),
            facts: OnceLock::new(),
        }
    }

    pub(crate) fn get(&self) -> Result<&WorkspaceFacts> {
        match self.facts.get_or_init(|| {
            let bytes = (self.metadata_loader)(&self.root).map_err(|message| {
                FactsInitError::Load(sanitize_metadata_diagnostic(&self.root, &message))
            })?;
            let json = String::from_utf8(bytes).map_err(|error| {
                FactsInitError::Load(sanitize_metadata_diagnostic(
                    &self.root,
                    &format!("cargo metadata stdout is not UTF-8: {error}"),
                ))
            })?;
            WorkspaceFacts::from_metadata_json(&self.root, &json).map_err(|error| {
                FactsInitError::Facts(sanitize_metadata_diagnostic(&self.root, &error.to_string()))
            })
        }) {
            Ok(facts) => Ok(facts),
            Err(error) => Err(anyhow::Error::new(error.clone())),
        }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

fn run_cargo_metadata(root: &Path, args: &[&str]) -> std::result::Result<Vec<u8>, String> {
    let output =
        crate::cmd::cargo_cmd(crate::cmd::CargoSubcommand::Metadata, args, &[], Some(root))
            .output()
            .map_err(|error| format!("execute cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format_metadata_command_failure(
            root,
            output.status,
            &output.stderr,
        ));
    }
    Ok(output.stdout)
}

fn format_metadata_command_failure(root: &Path, status: ExitStatus, stderr: &[u8]) -> String {
    let stderr = truncate_chars(&String::from_utf8_lossy(stderr), METADATA_STDERR_CHAR_LIMIT);
    sanitize_metadata_diagnostic(
        root,
        &format!("cargo metadata failed (status={status}): {stderr}"),
    )
}

fn truncate_chars(input: &str, limit: usize) -> String {
    if input.chars().count() <= limit {
        return input.to_owned();
    }
    let mut bounded = input.chars().take(limit).collect::<String>();
    bounded.push_str("…[truncated]");
    bounded
}

fn sanitize_metadata_diagnostic(root: &Path, message: &str) -> String {
    let mut sanitized = message.replace(root.to_string_lossy().as_ref(), ".");
    if let Ok(canonical) = std::fs::canonicalize(root) {
        sanitized = sanitized.replace(canonical.to_string_lossy().as_ref(), ".");
    }
    sanitized
}

/// INVARIANT: WORKSPACEFACTS-COMMAND-FUNNEL-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "tests::command_funnel_rejects_direct_metadata_tree_and_aliases", anti_vacuity = "tests::real_xtask_command_funnel_is_single_owned" } -- production Cargo graph acquisition is owned only by this module; tests are not production evidence.
pub(crate) fn validate_command_funnel(root: &Path) -> Result<()> {
    let source_root = root.join("xtask/src");
    let mut files = Vec::new();
    collect_rust_files(&source_root, &mut files)?;
    let owner = source_root.join("workspace_facts.rs");
    let command_owner = source_root.join("cmd.rs");
    let mut violations = Vec::new();
    for path in files {
        let source = std::fs::read_to_string(&path)?;
        for protocol in command_funnel_violations_with_command_owner(
            &source,
            path == owner,
            path == command_owner,
        )
        .map_err(|error| anyhow::anyhow!("parse {}: {error}", path.display()))?
        {
            violations.push(format!("{}: {protocol}", path.display()));
        }
    }
    anyhow::ensure!(
        violations.is_empty(),
        "WorkspaceFacts command funnel violation(s):\n{}",
        violations.join("\n")
    );
    Ok(())
}

#[cfg(test)]
fn command_funnel_violations(
    source: &str,
    allow_owned_metadata: bool,
) -> syn::Result<Vec<&'static str>> {
    command_funnel_violations_with_command_owner(source, allow_owned_metadata, false)
}

fn command_funnel_violations_with_command_owner(
    source: &str,
    allow_owned_metadata: bool,
    allow_raw_command_constructor: bool,
) -> syn::Result<Vec<&'static str>> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = CargoGraphCommandVisitor {
        allow_owned_metadata,
        allow_raw_command_constructor,
        ..CargoGraphCommandVisitor::default()
    };
    visitor.collect_item_bindings(&syntax.items);
    visitor.visit_file(&syntax);
    if allow_owned_metadata && visitor.owned_metadata_calls != 1 {
        visitor
            .violations
            .push("workspace facts owner must execute cargo metadata exactly once");
    }
    Ok(visitor.violations)
}

fn collect_rust_files(dir: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    let metadata = std::fs::symlink_metadata(dir)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "command funnel source root must be a real directory: {}",
        dir.display()
    );
    let mut entries = std::fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        anyhow::ensure!(
            !file_type.is_symlink(),
            "command funnel rejects symlink source: {}",
            path.display()
        );
        if file_type.is_dir() {
            collect_rust_files(&path, output)?;
        } else if file_type.is_file() && path.extension().is_some_and(|extension| extension == "rs")
        {
            output.push(path);
        } else {
            anyhow::ensure!(
                file_type.is_file(),
                "command funnel rejects non-regular source entry: {}",
                path.display()
            );
        }
    }
    Ok(())
}

struct CargoGraphCommandVisitor {
    allow_owned_metadata: bool,
    allow_raw_command_constructor: bool,
    owned_metadata_calls: usize,
    string_bindings: BTreeMap<String, Vec<String>>,
    cargo_command_bindings: BTreeSet<String>,
    command_aliases: BTreeSet<String>,
    cargo_subcommand_aliases: BTreeSet<String>,
    external_cmd_aliases: BTreeSet<String>,
    violations: Vec<&'static str>,
}

impl Default for CargoGraphCommandVisitor {
    fn default() -> Self {
        Self {
            allow_owned_metadata: false,
            allow_raw_command_constructor: false,
            owned_metadata_calls: 0,
            string_bindings: BTreeMap::new(),
            cargo_command_bindings: BTreeSet::new(),
            command_aliases: BTreeSet::from(["Command".to_owned()]),
            cargo_subcommand_aliases: BTreeSet::from(["CargoSubcommand".to_owned()]),
            external_cmd_aliases: BTreeSet::from(["external_cmd".to_owned()]),
            violations: Vec::new(),
        }
    }
}

impl CargoGraphCommandVisitor {
    fn record_graph_subcommand_path(&mut self, path: &syn::Path) {
        let mut segments = path.segments.iter().rev();
        let variant = segments.next().map(|segment| segment.ident.to_string());
        let owner = segments.next().map(|segment| segment.ident.to_string());
        let forbidden = owner
            .as_deref()
            .is_some_and(|owner| self.cargo_subcommand_aliases.contains(owner))
            && match variant.as_deref() {
                Some("Metadata") => {
                    if self.allow_owned_metadata {
                        self.owned_metadata_calls += 1;
                        false
                    } else {
                        true
                    }
                }
                Some("Tree") => true,
                _ => false,
            };
        if forbidden {
            self.violations
                .push("direct CargoSubcommand::Metadata/Tree");
        }
    }

    fn collect_item_bindings(&mut self, items: &[syn::Item]) {
        for item in items {
            if let syn::Item::Const(item) = item
                && let Some(values) = expression_strings(&item.expr, &self.string_bindings)
            {
                self.string_bindings.insert(item.ident.to_string(), values);
            }
            if let syn::Item::Use(item) = item {
                collect_command_aliases(&item.tree, &mut Vec::new(), &mut self.command_aliases);
                collect_cargo_subcommand_aliases(
                    &item.tree,
                    &mut Vec::new(),
                    &mut self.cargo_subcommand_aliases,
                );
                collect_external_cmd_aliases(
                    &item.tree,
                    &mut Vec::new(),
                    &mut self.external_cmd_aliases,
                );
            }
        }
    }

    fn method_chain_is_raw_graph_command(&self, call: &syn::ExprMethodCall) -> bool {
        let mut arguments = Vec::new();
        let mut expression = &*call.receiver;
        arguments.extend(call.args.iter().flat_map(|argument| {
            expression_strings(argument, &self.string_bindings).unwrap_or_default()
        }));
        while let syn::Expr::MethodCall(parent) = expression {
            arguments.extend(parent.args.iter().flat_map(|argument| {
                expression_strings(argument, &self.string_bindings).unwrap_or_default()
            }));
            expression = &parent.receiver;
        }
        let cargo_command = match expression {
            syn::Expr::Call(_) => expression_is_cargo_command(
                expression,
                &self.string_bindings,
                &self.command_aliases,
            ),
            syn::Expr::Path(path) => path
                .path
                .get_ident()
                .is_some_and(|ident| self.cargo_command_bindings.contains(&ident.to_string())),
            _ => false,
        };
        if !cargo_command {
            return false;
        }
        arguments
            .iter()
            .any(|argument| matches!(argument.as_str(), "metadata" | "tree"))
    }
}

impl<'ast> Visit<'ast> for CargoGraphCommandVisitor {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !has_test_cfg(&item.attrs) {
            let saved_strings = self.string_bindings.clone();
            let saved_commands = self.cargo_command_bindings.clone();
            let saved_aliases = self.command_aliases.clone();
            let saved_cargo_aliases = self.cargo_subcommand_aliases.clone();
            let saved_external_aliases = self.external_cmd_aliases.clone();
            if let Some((_, items)) = &item.content {
                self.collect_item_bindings(items);
            }
            visit::visit_item_mod(self, item);
            self.string_bindings = saved_strings;
            self.cargo_command_bindings = saved_commands;
            self.command_aliases = saved_aliases;
            self.cargo_subcommand_aliases = saved_cargo_aliases;
            self.external_cmd_aliases = saved_external_aliases;
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !has_test_cfg(&item.attrs) {
            let saved_strings = self.string_bindings.clone();
            let saved_commands = self.cargo_command_bindings.clone();
            let saved_aliases = self.command_aliases.clone();
            let saved_cargo_aliases = self.cargo_subcommand_aliases.clone();
            let saved_external_aliases = self.external_cmd_aliases.clone();
            visit::visit_item_fn(self, item);
            self.string_bindings = saved_strings;
            self.cargo_command_bindings = saved_commands;
            self.command_aliases = saved_aliases;
            self.cargo_subcommand_aliases = saved_cargo_aliases;
            self.external_cmd_aliases = saved_external_aliases;
        }
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        let saved_strings = self.string_bindings.clone();
        let saved_commands = self.cargo_command_bindings.clone();
        let saved_aliases = self.command_aliases.clone();
        let saved_cargo_aliases = self.cargo_subcommand_aliases.clone();
        let saved_external_aliases = self.external_cmd_aliases.clone();
        let items = block
            .stmts
            .iter()
            .filter_map(|statement| match statement {
                syn::Stmt::Item(item) => Some(item.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        self.collect_item_bindings(&items);
        visit::visit_block(self, block);
        self.string_bindings = saved_strings;
        self.cargo_command_bindings = saved_commands;
        self.command_aliases = saved_aliases;
        self.cargo_subcommand_aliases = saved_cargo_aliases;
        self.external_cmd_aliases = saved_external_aliases;
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        self.record_graph_subcommand_path(&expression.path);
        visit::visit_expr_path(self, expression);
    }

    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if !self.allow_raw_command_constructor
            && expression_is_command_constructor(expression, &self.command_aliases)
        {
            self.violations
                .push("raw std::process::Command constructor outside cmd owner");
        }
        if external_interpreter_can_forward_cargo_graph(
            expression,
            &self.string_bindings,
            &self.external_cmd_aliases,
        ) {
            self.violations
                .push("shell/python forwarding can execute cargo metadata/tree");
        }
        visit::visit_expr_call(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        if self.method_chain_is_raw_graph_command(expression) {
            self.violations.push("raw cargo metadata/tree command");
        }
        visit::visit_expr_method_call(self, expression);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(init) = &local.init
            && let syn::Pat::Ident(binding) = &local.pat
        {
            let name = binding.ident.to_string();
            if let Some(values) = expression_strings(&init.expr, &self.string_bindings) {
                self.string_bindings.insert(name.clone(), values);
            } else {
                self.string_bindings.remove(&name);
            }
            if expression_is_cargo_command(&init.expr, &self.string_bindings, &self.command_aliases)
            {
                self.cargo_command_bindings.insert(name);
            } else {
                self.cargo_command_bindings.remove(&name);
            }
        }
        visit::visit_local(self, local);
    }
}

fn expression_is_command_constructor(
    expression: &syn::ExprCall,
    command_aliases: &BTreeSet<String>,
) -> bool {
    let syn::Expr::Path(constructor) = expression.func.as_ref() else {
        return false;
    };
    let mut segments = constructor.path.segments.iter().rev();
    segments
        .next()
        .is_some_and(|segment| segment.ident == "new")
        && segments
            .next()
            .is_some_and(|segment| command_aliases.contains(&segment.ident.to_string()))
}

fn expression_is_cargo_command(
    expression: &syn::Expr,
    bindings: &BTreeMap<String, Vec<String>>,
    command_aliases: &BTreeSet<String>,
) -> bool {
    let syn::Expr::Call(call) = expression else {
        return false;
    };
    let syn::Expr::Path(constructor) = call.func.as_ref() else {
        return false;
    };
    let mut segments = constructor.path.segments.iter().rev();
    let is_command_new = segments
        .next()
        .is_some_and(|segment| segment.ident == "new")
        && segments
            .next()
            .is_some_and(|segment| command_aliases.contains(&segment.ident.to_string()));
    is_command_new
        && call.args.first().is_some_and(|argument| {
            expression_strings(argument, bindings)
                .is_some_and(|values| values.iter().any(|value| value == "cargo"))
        })
}

fn collect_command_aliases(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    aliases: &mut BTreeSet<String>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_command_aliases(&path.tree, prefix, aliases);
            prefix.pop();
        }
        syn::UseTree::Name(name)
            if prefix.as_slice() == ["std", "process"] && name.ident == "Command" =>
        {
            aliases.insert("Command".to_owned());
        }
        syn::UseTree::Rename(rename)
            if prefix.as_slice() == ["std", "process"] && rename.ident == "Command" =>
        {
            aliases.insert(rename.rename.to_string());
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_command_aliases(item, prefix, aliases);
            }
        }
        _ => {}
    }
}

fn collect_cargo_subcommand_aliases(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    aliases: &mut BTreeSet<String>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_cargo_subcommand_aliases(&path.tree, prefix, aliases);
            prefix.pop();
        }
        syn::UseTree::Name(name) if name.ident == "CargoSubcommand" => {
            aliases.insert("CargoSubcommand".to_owned());
        }
        syn::UseTree::Rename(rename) if rename.ident == "CargoSubcommand" => {
            aliases.insert(rename.rename.to_string());
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_cargo_subcommand_aliases(item, prefix, aliases);
            }
        }
        _ => {}
    }
}

fn collect_external_cmd_aliases(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    aliases: &mut BTreeSet<String>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_external_cmd_aliases(&path.tree, prefix, aliases);
            prefix.pop();
        }
        syn::UseTree::Name(name) if name.ident == "external_cmd" => {
            aliases.insert("external_cmd".to_owned());
        }
        syn::UseTree::Rename(rename) if rename.ident == "external_cmd" => {
            aliases.insert(rename.rename.to_string());
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_external_cmd_aliases(item, prefix, aliases);
            }
        }
        _ => {}
    }
}

fn external_interpreter_can_forward_cargo_graph(
    expression: &syn::ExprCall,
    bindings: &BTreeMap<String, Vec<String>>,
    external_cmd_aliases: &BTreeSet<String>,
) -> bool {
    let syn::Expr::Path(function) = expression.func.as_ref() else {
        return false;
    };
    if function
        .path
        .segments
        .last()
        .is_none_or(|segment| !external_cmd_aliases.contains(&segment.ident.to_string()))
    {
        return false;
    }
    let Some(program) = expression.args.first() else {
        return false;
    };
    let syn::Expr::Path(program) = program else {
        return false;
    };
    let Some(program) = program
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
    else {
        return false;
    };
    if !matches!(program.as_str(), "SystemShell" | "SystemPython") {
        return false;
    }
    let Some(arguments) = expression.args.iter().nth(1) else {
        return true;
    };
    let Some(arguments) = expression_strings(arguments, bindings) else {
        return true;
    };
    let command = arguments.join(" ");
    command.contains("cargo metadata") || command.contains("cargo tree")
}

fn has_test_cfg(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attribute| {
        attribute.path().is_ident("test")
            || (attribute.path().is_ident("cfg") && cfg_requires_test(&attribute.meta))
    })
}

fn cfg_requires_test(meta: &syn::Meta) -> bool {
    let syn::Meta::List(list) = meta else {
        return false;
    };
    let Ok(predicate) = syn::parse2::<syn::Meta>(list.tokens.clone()) else {
        return false;
    };
    cfg_predicate_requires_test(&predicate)
}

fn cfg_predicate_requires_test(meta: &syn::Meta) -> bool {
    if let syn::Meta::Path(path) = meta {
        return path.is_ident("test");
    }
    let syn::Meta::List(list) = meta else {
        return false;
    };
    let parser = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated;
    let Ok(children) = syn::parse::Parser::parse2(parser, list.tokens.clone()) else {
        return false;
    };
    if list.path.is_ident("all") {
        children.iter().any(cfg_predicate_requires_test)
    } else if list.path.is_ident("any") {
        !children.is_empty() && children.iter().all(cfg_predicate_requires_test)
    } else {
        false
    }
}

fn expression_strings(
    expression: &syn::Expr,
    bindings: &BTreeMap<String, Vec<String>>,
) -> Option<Vec<String>> {
    match expression {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(value),
            ..
        }) => Some(vec![value.value()]),
        syn::Expr::Path(path) => path
            .path
            .get_ident()
            .and_then(|ident| bindings.get(&ident.to_string()).cloned()),
        syn::Expr::Array(array) => array.elems.iter().try_fold(Vec::new(), |mut out, item| {
            out.extend(expression_strings(item, bindings)?);
            Some(out)
        }),
        syn::Expr::Reference(reference) => expression_strings(&reference.expr, bindings),
        syn::Expr::Paren(paren) => expression_strings(&paren.expr, bindings),
        syn::Expr::Group(group) => expression_strings(&group.expr, bindings),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CommandWorkspaceFacts, METADATA_STDERR_CHAR_LIMIT, command_funnel_violations,
        format_metadata_command_failure, sanitize_metadata_diagnostic, validate_command_funnel,
    };
    use anyhow::{Context as _, bail, ensure};
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;
    use std::process::ExitStatus;
    use std::rc::Rc;
    use workspacefacts::testing::{
        metadata_json, path_package, path_package_id, resolve_node, target,
    };

    #[test]
    fn command_funnel_rejects_direct_metadata_tree_and_aliases() -> anyhow::Result<()> {
        for source in [
            "fn bad() { cargo_cmd(CargoSubcommand::Metadata, &[], &[], None); }",
            "fn bad() { use crate::cmd::CargoSubcommand as C; cargo_cmd(C::Metadata, &[], &[], None); }",
            "fn bad() { external_cmd(ExternalProgram::SystemShell, &[\"-c\", \"cargo tree\"], &[], None); }",
            "fn bad(args: &[&str]) { external_cmd(ExternalProgram::SystemShell, args, &[], None); }",
            "fn bad(args: &[&str]) { external_cmd(ExternalProgram::SystemPython, args, &[], None); }",
            "fn bad(args: &[&str]) { use crate::cmd::external_cmd as run; run(ExternalProgram::SystemShell, args, &[], None); }",
            "fn bad(args: &[&str]) { use crate::cmd::{external_cmd as run}; run(ExternalProgram::SystemPython, args, &[], None); }",
            "fn bad() { std::process::Command::new(\"cargo\").arg(\"tree\"); }",
            "fn bad(program: String, arg: String) { std::process::Command::new(program).arg(arg); }",
            "fn bad() { use std::process::Command as Process; Process::new(\"cargo\").arg(\"metadata\"); }",
            "fn bad() { std::process::Command::new(\"cargo\").args([\"tree\"]); }",
            "fn bad() { let command = \"metadata\"; std::process::Command::new(\"cargo\").arg(command); }",
            "fn bad() { let mut cargo = std::process::Command::new(\"cargo\"); cargo.arg(\"tree\"); }",
            "fn bad() { const SUB: &str = \"tree\"; std::process::Command::new(\"cargo\").arg(SUB); }",
            "#[cfg(not(test))] fn bad() { std::process::Command::new(\"cargo\").arg(\"tree\"); }",
            "#[cfg(any(test, unix))] fn bad() { std::process::Command::new(\"cargo\").arg(\"tree\"); }",
            "#[cfg(feature = \"contest\")] fn bad() { std::process::Command::new(\"cargo\").arg(\"tree\"); }",
        ] {
            ensure!(!command_funnel_violations(source, false)?.is_empty());
        }
        ensure!(command_funnel_violations(
            "#[cfg(test)] mod tests { fn fixture() { std::process::Command::new(\"cargo\").arg(\"tree\"); } }"
            , false
        )?
        .is_empty());
        ensure!(command_funnel_violations(
            "fn green() { Foo::new(\"cargo\").arg(\"tree\"); } fn shadow() { let cargo = NotACommand; cargo.arg(\"tree\"); }",
            false,
        )?
        .is_empty());
        ensure!(
            command_funnel_violations(
                "fn owner() { cargo_cmd(CargoSubcommand::Metadata, &[], &[], None); }",
                true,
            )?
            .is_empty()
        );
        ensure!(
            !command_funnel_violations(
                "fn owner() { cargo_cmd(CargoSubcommand::Tree, &[], &[], None); }",
                true,
            )?
            .is_empty()
        );
        ensure!(
            !command_funnel_violations(
                "fn owner() { cargo_cmd(CargoSubcommand::Metadata, &[], &[], None); cargo_cmd(CargoSubcommand::Metadata, &[], &[], None); }",
                true,
            )?
            .is_empty()
        );
        Ok(())
    }

    #[test]
    fn real_xtask_command_funnel_is_single_owned() -> anyhow::Result<()> {
        validate_command_funnel(&crate::workspace_root()?)
    }

    #[cfg(unix)]
    #[test]
    fn command_funnel_rejects_symlink_sources() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;
        let root = crate::testutil::unique_tmp("workspacefacts-command-funnel-symlink");
        let source = root.join("xtask/src");
        std::fs::create_dir_all(&source)?;
        std::fs::write(
            source.join("workspace_facts.rs"),
            "fn owner() { cargo_cmd(CargoSubcommand::Metadata, &[], &[], None); }",
        )?;
        let outside = root.join("outside.rs");
        std::fs::write(&outside, "fn bait() {}")?;
        symlink(&outside, source.join("linked.rs"))?;
        let error = validate_command_funnel(&root)
            .err()
            .context("symlink source must fail closed")?;
        ensure!(error.to_string().contains("rejects symlink source"));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn command_scope_oncelock_caches_success_and_failure() -> anyhow::Result<()> {
        let success_calls = Rc::new(Cell::new(0));
        let success_counter = Rc::clone(&success_calls);
        let success =
            CommandWorkspaceFacts::with_metadata_loader(Path::new("/workspace"), move |_| {
                success_counter.set(success_counter.get() + 1);
                Ok(single_package_metadata())
            });
        // OnceLock success path: repeated get() shares one loader invocation
        ensure!(success.get().is_ok());
        ensure!(success.get().is_ok());
        ensure!(success.get().is_ok());
        ensure!(success_calls.get() == 1);

        let failure_calls = Rc::new(Cell::new(0));
        let failure_counter = Rc::clone(&failure_calls);
        let failure =
            CommandWorkspaceFacts::with_metadata_loader(Path::new("/workspace"), move |_| {
                failure_counter.set(failure_counter.get() + 1);
                Err("synthetic metadata failure".to_owned())
            });
        // OnceLock failure path: repeated get() shares one loader invocation
        ensure!(failure.get().is_err());
        ensure!(failure.get().is_err());
        ensure!(failure.get().is_err());
        ensure!(failure_calls.get() == 1);
        let Err(err) = failure.get() else {
            bail!("failure path");
        };
        ensure!(
            err.source().is_none(),
            "Load init error has no underlying source"
        );
        Ok(())
    }

    #[test]
    fn facts_init_error_does_not_restore_unsanitized_source_chain() -> anyhow::Result<()> {
        let facts = CommandWorkspaceFacts::with_metadata_loader(Path::new("/workspace"), |_| {
            Ok(b"{not-json".to_vec())
        });
        let Err(err) = facts.get() else {
            bail!("invalid metadata must fail");
        };
        ensure!(
            err.source().is_none(),
            "command boundary must not expose the unsanitized WorkspaceFacts source: {err:#}"
        );
        let display = format!("{err}");
        ensure!(
            !display.contains("/workspace"),
            "Facts diagnostic must strip absolute root: {display}"
        );
        Ok(())
    }

    #[test]
    fn unused_command_scope_is_zero_load() {
        let calls = Rc::new(Cell::new(0));
        let counter = Rc::clone(&calls);
        let _unused =
            CommandWorkspaceFacts::with_metadata_loader(Path::new("/workspace"), move |_| {
                counter.set(counter.get() + 1);
                Ok(single_package_metadata())
            });
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn metadata_failure_diagnostics_are_bounded_and_root_sanitized() -> anyhow::Result<()> {
        let root = crate::testutil::unique_tmp("workspace-facts-metadata-diag");
        fs::create_dir_all(&root)?;
        let root_display = root.to_string_lossy().into_owned();
        let status = ExitStatus::from_raw(1 << 8);
        let oversized = format!(
            "{root_display}/Cargo.toml: {}",
            "x".repeat(METADATA_STDERR_CHAR_LIMIT + 256)
        );
        let diagnostic = format_metadata_command_failure(&root, status, oversized.as_bytes());
        assert!(
            diagnostic.contains("status="),
            "status must remain actionable: {diagnostic}"
        );
        assert!(
            !diagnostic.contains(&root_display),
            "absolute root must be stripped: {diagnostic}"
        );
        if let Ok(canonical) = fs::canonicalize(&root) {
            assert!(
                !diagnostic.contains(canonical.to_string_lossy().as_ref()),
                "canonical root must be stripped: {diagnostic}"
            );
        }
        assert!(
            diagnostic.chars().count() <= METADATA_STDERR_CHAR_LIMIT + 64,
            "stderr must stay bounded: len={}",
            diagnostic.chars().count()
        );
        assert!(
            diagnostic.ends_with("…[truncated]"),
            "truncated stderr must be explicit: {diagnostic}"
        );
        assert!(
            diagnostic.contains("Cargo.toml"),
            "context must remain after sanitize: {diagnostic}"
        );

        let injected_root = root_display.clone();
        let injected = CommandWorkspaceFacts::with_metadata_loader(&root, move |_| {
            Err(format!(
                "injected loader boom under {injected_root}/secret.toml"
            ))
        });
        let Err(err) = injected.get() else {
            bail!("injected loader failure");
        };
        let display = format!("{err:#}");
        assert!(
            !display.contains(&root_display),
            "injected loader errors must sanitize root: {display}"
        );
        assert!(
            display.contains("injected loader boom"),
            "context must remain: {display}"
        );

        let metadata_root = root.join("metadata-root");
        let metadata = String::from_utf8(single_package_metadata())?
            .replace("/workspace", metadata_root.to_string_lossy().as_ref());
        let invalid_facts = CommandWorkspaceFacts::with_metadata_loader(&root, move |_| {
            Ok(metadata.as_bytes().to_vec())
        });
        let Err(err) = invalid_facts.get() else {
            bail!("workspace root mismatch must fail");
        };
        let display = format!("{err:#}");
        assert!(
            !display.contains(&root_display),
            "WorkspaceFacts source chain must not restore the absolute root: {display}"
        );
        assert!(
            display.contains("metadata workspace root mismatch"),
            "sanitized WorkspaceFacts context must remain: {display}"
        );

        fs::write(root.join("Cargo.toml"), "this is not = [valid")?;
        let malformed = CommandWorkspaceFacts::for_test_fixture(&root);
        let Err(err) = malformed.get() else {
            bail!("malformed Cargo.toml metadata");
        };
        let display = format!("{err:#}");
        assert!(
            display.contains("status="),
            "malformed Cargo.toml must keep status: {display}"
        );
        assert!(
            !display.contains(&root_display),
            "malformed Cargo.toml must sanitize root: {display}"
        );
        assert!(
            display.chars().count() <= METADATA_STDERR_CHAR_LIMIT + 64,
            "malformed Cargo.toml stderr must stay bounded: len={}",
            display.chars().count()
        );
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }
    #[test]
    fn sanitize_helper_strips_root_and_canonical_prefixes() {
        let root = Path::new("/tmp/workspace-facts-sanitize-root");
        let message = format!("boom {} and again {}", root.display(), root.display());
        let sanitized = sanitize_metadata_diagnostic(root, &message);
        assert!(!sanitized.contains(root.to_string_lossy().as_ref()));
        assert!(sanitized.contains("boom"));
    }

    fn single_package_metadata() -> Vec<u8> {
        let path = "/workspace/crates/leaf";
        let package = path_package(
            "leaf",
            path,
            vec![target(
                "leaf",
                "lib",
                &format!("{path}/src/lib.rs"),
                true,
                &[],
            )],
            vec![],
            serde_json::json!({}),
        );
        let id = path_package_id(path);
        metadata_json(
            "/workspace",
            vec![package],
            vec![id.clone()],
            vec![resolve_node(&id, &[])],
        )
        .into_bytes()
    }
}
