//! Assembly manifest committed codegen for modules and typed provider catalogs.
//!
//! INVARIANT: ASSEMBLY-MODULES-CODEGEN-01 { level = "Hard", exec = "check", source = "codegen", golden = "assemblies/runtime/src/generated/modules_gen.rs", synthetic_red = "assembly_codegen::tests::check_rejects_manifest_domain_drift", anti_vacuity = "assembly_codegen::tests::generated_runtime_modules_are_non_empty_and_check_clean" } —— `assembly.toml` 是 domain 组合顺序单源；生成物 committed 并由 verify 字节级守漂移，red/green 测试证明门不恒真。
//! INVARIANT: ASSEMBLY-PROVIDERS-CODEGEN-01 { level = "Hard", exec = "check", source = "codegen", golden = "assemblies/runtime/src/generated/providers_gen.rs", synthetic_red = "assembly_codegen::tests::assembly_provider_codegen_rejects_closed_registry_mismatches_before_output", anti_vacuity = "assembly_codegen::tests::assembly_provider_codegen_generated_provider_catalogs_are_non_empty_and_check_clean" } —— active provider catalog is role-sorted typed `checked` evidence; the independent drift gate rejects invalid manifests, missing/tampered/orphan outputs, marker crossover, symlinks, and dynamic construction syntax.
//! INVARIANT: ASSEMBLY-GENERATED-LF-CHECKOUT-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "assembly_codegen::tests::generated_lf_checkout_guard_rejects_missing_weakened_and_overridden_attributes", anti_vacuity = "assembly_codegen::tests::generated_lf_checkout_guard_accepts_canonical_repository" } —— generator-owned tracked paths 的 Git 最终有效属性必须精确为 `text=set,eol=lf`，避免 raw-byte digest 随 checkout 平台漂移。

use anyhow::{Context, Result, bail, ensure};
#[cfg(test)]
use assembly_schema::AssemblyManifest;
use assembly_schema::{
    AssemblyDomain, AssemblyListenerKind, CanonicalAssemblyManifestV2, DiportPort,
    GENERATED_MODULE_OWNERSHIP_MARKER, GENERATED_PROVIDER_OWNERSHIP_MARKER, LifecycleChannel,
    ProviderConstructor, ProviderConsumer, ProviderDurability, ProviderFactorySymbol,
    ProviderFailurePosture, ProviderLifecycle, ProviderRole, ProviderScope,
};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::contract::GovernedContract;
use crate::contract::governance::ContractGovernanceIr;

const GENERATED_PATHSPEC: &str = "assemblies/*/src/generated/**";
const GENERATED_LF_ATTRIBUTE_RULE: &str = "assemblies/*/src/generated/** text eol=lf";
const OWNERSHIP_MARKER: &str = GENERATED_MODULE_OWNERSHIP_MARKER;

/// Closed finish input/materializer shape for generated provider role constructors.
/// Generation and syntax validation both read this table — no dual hardcode paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProviderFinishShape {
    input_type: &'static str,
    /// Method name called as `let output = output.{materializer}();`, if any.
    materializer: Option<&'static str>,
    /// Move-only provider value materialized alongside lifecycle evidence, if any.
    bound_value: Option<(&'static str, &'static str)>,
}

const DEFAULT_PROVIDER_FINISH_SHAPE: ProviderFinishShape = ProviderFinishShape {
    input_type: "bootstrap::DomainModuleResult",
    materializer: None,
    bound_value: None,
};

const LISTENER_PDP_FINISH_SHAPE: ProviderFinishShape = ProviderFinishShape {
    input_type: "ListenerPdpJwksLifecycle",
    materializer: Some("into_output"),
    bound_value: None,
};

const LISTENER_RATE_LIMITER_FINISH_SHAPE: ProviderFinishShape = ProviderFinishShape {
    input_type: "redis::RedisRateLimiterCapability",
    materializer: None,
    bound_value: Some(("redis::RedisRateLimiter", "into_limiter")),
};

const fn provider_finish_shape(role: ProviderRole) -> ProviderFinishShape {
    match role {
        ProviderRole::ListenerPdp => LISTENER_PDP_FINISH_SHAPE,
        ProviderRole::ListenerRateLimiter => LISTENER_RATE_LIMITER_FINISH_SHAPE,
        _ => DEFAULT_PROVIDER_FINISH_SHAPE,
    }
}

fn finish_matches_provider_shape(finish: &syn::ImplItemFn, shape: ProviderFinishShape) -> bool {
    let inputs = finish.sig.inputs.iter().collect::<Vec<_>>();
    if inputs.len() != 2 {
        return false;
    }
    let expected_input = format!("output:{}", shape.input_type);
    if compact_tokens(inputs[1]) != expected_input {
        return false;
    }
    let body = compact_tokens(&finish.block);
    let lifecycle_matches = match shape.materializer {
        Some(method) => body.contains(&format!("letoutput=output.{method}();")),
        None => !body.contains("letoutput=output."),
    };
    let value_matches = match shape.bound_value {
        Some((_, method)) => body.contains(&format!("letvalue=output.{method}();")),
        None => !body.contains("letvalue=output."),
    };
    lifecycle_matches && value_matches
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactKind {
    Modules,
    Providers,
}

impl ArtifactKind {
    const fn generated_rel(self) -> &'static str {
        match self {
            Self::Modules => "src/generated/modules_gen.rs",
            Self::Providers => "src/generated/providers_gen.rs",
        }
    }

    const fn ownership_marker(self) -> &'static str {
        match self {
            Self::Modules => GENERATED_MODULE_OWNERSHIP_MARKER,
            Self::Providers => GENERATED_PROVIDER_OWNERSHIP_MARKER,
        }
    }

    const fn noun(self) -> &'static str {
        match self {
            Self::Modules => "modules",
            Self::Providers => "providers",
        }
    }

    const fn command(self) -> &'static str {
        match self {
            Self::Modules => "generate-modules",
            Self::Providers => "generate-providers",
        }
    }
}

struct Target {
    path: PathBuf,
    content: Vec<u8>,
    actual: Option<Vec<u8>>,
}

struct GenerationPlan {
    targets: Vec<Target>,
    owned_orphans: Vec<PathBuf>,
}

pub(crate) fn run(check: bool) -> Result<()> {
    let root = crate::workspace_root()?;
    if check {
        return check_root(&root);
    }
    verify_generated_lf_checkout(&root)?;
    generate_root(&root, false)
}

pub(crate) fn run_providers(check: bool) -> Result<()> {
    let root = crate::workspace_root()?;
    if check {
        return check_provider_root(&root);
    }
    verify_generated_lf_checkout(&root)?;
    generate_providers_root(&root, false)
}

/// Run the complete modules gate, including effective LF policy and owned-orphan detection.
pub(crate) fn check_root(root: &Path) -> Result<()> {
    verify_generated_lf_checkout(root)?;
    generate_root(root, true)
}

/// Run the complete provider catalog gate independently from module generation.
pub(crate) fn check_provider_root(root: &Path) -> Result<()> {
    verify_generated_lf_checkout(root)?;
    generate_providers_root(root, true)
}

fn verify_generated_lf_checkout(root: &Path) -> Result<()> {
    let listed = git_stdout(root, &["ls-files", "-z", "--", GENERATED_PATHSPEC])?;
    let paths = listed
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| std::str::from_utf8(path).context("generator-owned tracked path 不是 UTF-8"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(!paths.is_empty(), "generator-owned tracked path 集合为空");
    let targets = paths.iter().map(|path| root.join(path)).collect::<Vec<_>>();
    crate::generated_file::verify_lf_checkout(root, GENERATED_LF_ATTRIBUTE_RULE, &targets)
        .map_err(|stage| anyhow::anyhow!("generated LF checkout failed: {stage:?}"))
}

fn git_stdout(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        args,
        &[],
        Some(root),
    )
    .output()
    .with_context(|| format!("执行 git {} 失败", args.join(" ")))?;
    ensure!(
        output.status.success(),
        "git {} 失败: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

pub(crate) fn generate_root(root: &Path, check: bool) -> Result<()> {
    generate_artifact_root(root, check, ArtifactKind::Modules)
}

pub(crate) fn generate_providers_root(root: &Path, check: bool) -> Result<()> {
    generate_artifact_root(root, check, ArtifactKind::Providers)
}

fn generate_artifact_root(root: &Path, check: bool, kind: ArtifactKind) -> Result<()> {
    let contract_governance = ContractGovernanceIr::load_consumer_workspace(root)?;
    let plan = contract_governance
        .read(|contracts| plan_generation_with_contracts(root, kind, contracts))?;
    let drift: Vec<&Path> = plan
        .targets
        .iter()
        .filter(|target| target.actual.as_deref() != Some(target.content.as_slice()))
        .map(|target| target.path.as_path())
        .collect();

    if check {
        if drift.is_empty() && plan.owned_orphans.is_empty() {
            eprintln!("assembly {} --check: 无漂移", kind.command());
            return Ok(());
        }
        for path in &drift {
            eprintln!("  派生漂移: {}", relative_label(root, path));
        }
        for path in &plan.owned_orphans {
            eprintln!("  孤儿派生文件: {}", relative_label(root, path));
        }
        bail!(
            "assembly {} 派生漂移：{} 个目标不一致，{} 个孤儿；运行 `cargo xtask assembly {}`",
            kind.noun(),
            drift.len(),
            plan.owned_orphans.len(),
            kind.command(),
        );
    }

    let mut transaction = AssemblyGenerationTransaction::new(root, plan)?;
    let result = contract_governance.commit(|| transaction.apply(root));
    if let Err(error) = result {
        transaction.rollback().with_context(|| {
            format!(
                "assembly {} generation failed and rollback was incomplete; original error: {error:#}",
                kind.noun()
            )
        })?;
        return Err(error);
    }
    Ok(())
}

enum AssemblyChange {
    Target(usize),
    Orphan(usize),
}

struct AssemblyGenerationTransaction {
    plan: GenerationPlan,
    orphan_originals: Vec<Vec<u8>>,
    touched: Vec<AssemblyChange>,
}

impl AssemblyGenerationTransaction {
    fn new(root: &Path, plan: GenerationPlan) -> Result<Self> {
        let orphan_originals = plan
            .owned_orphans
            .iter()
            .map(|path| {
                ensure_output_path_has_no_symlinks(path)?;
                fs::read(path)
                    .with_context(|| format!("读取 assembly orphan {}", relative_label(root, path)))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            plan,
            orphan_originals,
            touched: Vec::new(),
        })
    }

    fn apply(&mut self, root: &Path) -> Result<()> {
        self.apply_with_hook(root, |_, _| Ok(()))
    }

    fn apply_with_hook(
        &mut self,
        root: &Path,
        mut before_change: impl FnMut(usize, &Path) -> Result<()>,
    ) -> Result<()> {
        for target in &self.plan.targets {
            let current = match fs::read(&target.path) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            };
            if current != target.actual {
                bail!(
                    "assembly output changed after planning: {}",
                    target.path.display()
                );
            }
        }
        for (orphan, expected) in self.plan.owned_orphans.iter().zip(&self.orphan_originals) {
            if fs::read(orphan).with_context(|| format!("读取孤儿 {}", orphan.display()))?
                != *expected
            {
                bail!(
                    "assembly orphan changed after planning: {}",
                    orphan.display()
                );
            }
        }

        let mut change_index = 0;
        for (index, target) in self.plan.targets.iter().enumerate() {
            if target.actual.as_deref() != Some(target.content.as_slice()) {
                before_change(change_index, &target.path)?;
                change_index += 1;
                ensure_output_path_has_no_symlinks(&target.path)?;
                crate::generated_file::atomic_replace(&target.path, &target.content)
                    .with_context(|| format!("原子写入 {} 失败", target.path.display()))?;
                self.touched.push(AssemblyChange::Target(index));
                eprintln!("  generated {}", relative_label(root, &target.path));
            }
        }
        for (index, orphan) in self.plan.owned_orphans.iter().enumerate() {
            before_change(change_index, orphan)?;
            change_index += 1;
            ensure_output_path_has_no_symlinks(orphan)?;
            fs::remove_file(orphan)
                .with_context(|| format!("删除孤儿 {} 失败", orphan.display()))?;
            self.touched.push(AssemblyChange::Orphan(index));
            eprintln!("  removed orphan {}", relative_label(root, orphan));
        }
        Ok(())
    }

    fn rollback(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        for change in self.touched.drain(..).rev() {
            let (path, original) = match change {
                AssemblyChange::Target(index) => {
                    let target = &self.plan.targets[index];
                    (&target.path, target.actual.as_deref())
                }
                AssemblyChange::Orphan(index) => (
                    &self.plan.owned_orphans[index],
                    Some(self.orphan_originals[index].as_slice()),
                ),
            };
            let restored = match original {
                Some(bytes) => crate::generated_file::atomic_replace(path, bytes),
                None => match fs::remove_file(path) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(error.into()),
                },
            };
            if let Err(error) = restored {
                failures.push(format!("{}: {error:#}", path.display()));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            bail!(
                "assembly generation rollback failures:\n{}",
                failures.join("\n")
            )
        }
    }
}

pub(crate) fn check_governed_target(
    root: &Path,
    assembly: &crate::assembly_governance::GovernedAssembly,
) -> Result<()> {
    let assembly_name = assembly.manifest().name();
    let contract_governance = ContractGovernanceIr::load_consumer_workspace(root)?;
    let target = contract_governance
        .read(|contracts| plan_target(root, assembly, ArtifactKind::Modules, contracts))?;
    if target.actual.as_deref() != Some(target.content.as_slice()) {
        bail!("assembly `{assembly_name}` modules carrier 漂移");
    }
    Ok(())
}

#[cfg(test)]
fn check_target(root: &Path, assembly_name: &str) -> Result<()> {
    let ir =
        crate::assembly_governance::AssemblyGovernanceIr::<crate::assembly_governance::Core>::load(
            root,
        )?;
    let assembly = ir
        .assembly(assembly_name)
        .with_context(|| format!("assembly `{assembly_name}` 缺 governed manifest"))?;
    check_governed_target(root, assembly)
}

fn plan_generation_with_contracts(
    root: &Path,
    kind: ArtifactKind,
    contracts: &[GovernedContract],
) -> Result<GenerationPlan> {
    let ir =
        crate::assembly_governance::AssemblyGovernanceIr::<crate::assembly_governance::Core>::load(
            root,
        )?;

    let mut targets = Vec::new();
    let mut owned_files = Vec::new();
    for target in ir.targets() {
        owned_files.extend(discover_owned_files(target.dir(), kind)?);
    }
    for assembly in ir.assemblies() {
        targets.push(plan_target(root, assembly, kind, contracts)?);
    }

    let target_paths = targets
        .iter()
        .map(|target| target.path.as_path())
        .collect::<std::collections::BTreeSet<_>>();
    let mut owned_orphans = owned_files
        .into_iter()
        .filter(|path| !target_paths.contains(path.as_path()))
        .collect::<Vec<_>>();
    owned_orphans.sort();
    Ok(GenerationPlan {
        targets,
        owned_orphans,
    })
}

fn plan_target(
    _root: &Path,
    assembly: &crate::assembly_governance::GovernedAssembly,
    kind: ArtifactKind,
    contracts: &[GovernedContract],
) -> Result<Target> {
    let assembly_dir = &assembly.dir();
    let output_path = assembly_dir.join(kind.generated_rel());
    ensure_output_path_has_no_symlinks(&output_path)?;
    if kind == ArtifactKind::Providers {
        ensure_provider_catalog_linked(assembly_dir)?;
    }
    let source_label = assembly.source_label();
    ensure_safe_source_label(source_label)?;
    let manifest = assembly.manifest();
    let content = match kind {
        ArtifactKind::Modules => {
            let framework_routes = framework_http_routes(manifest, contracts)?;
            render_modules(manifest, &framework_routes, source_label)?
        }
        ArtifactKind::Providers => render_providers(manifest, source_label)?,
    };
    let actual = read_owned_target(&output_path, kind)?;
    Ok(Target {
        path: output_path,
        content: content.into_bytes(),
        actual,
    })
}

fn ensure_safe_source_label(source_label: &str) -> Result<()> {
    if source_label.chars().any(char::is_control) {
        bail!("manifest source path 含控制字符，拒绝渲染 generated Rust");
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("生成器路径禁止符号链接：{}", path.display())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("读取 {} 元数据失败", path.display())),
    }
}

fn ensure_output_path_has_no_symlinks(path: &Path) -> Result<()> {
    let generated_dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} 无 generated 父目录", path.display()))?;
    let src_dir = generated_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} 无 src 父目录", path.display()))?;
    let assembly_dir = src_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} 无 assembly 父目录", path.display()))?;
    for candidate in [assembly_dir, src_dir, generated_dir, path] {
        reject_symlink(candidate)?;
    }
    Ok(())
}

fn discover_owned_files(assembly_dir: &Path, kind: ArtifactKind) -> Result<Vec<PathBuf>> {
    let generated_dir = assembly_dir.join("src/generated");
    let expected_path = assembly_dir.join(kind.generated_rel());
    let metadata = match fs::symlink_metadata(&generated_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("读取 {} 元数据失败", generated_dir.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "generated 路径必须是无符号链接的目录：{}",
            generated_dir.display()
        );
    }

    let mut entries = fs::read_dir(&generated_dir)
        .with_context(|| format!("读取 {} 失败", generated_dir.display()))?
        .collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(fs::DirEntry::path);
    let mut owned = Vec::new();
    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("读取 {} 类型失败", path.display()))?;
        if file_type.is_symlink() || !file_type.is_file() {
            bail!("generated 下只允许无符号链接的普通文件：{}", path.display());
        }
        let bytes = fs::read(&path).with_context(|| format!("读取 {} 失败", path.display()))?;
        let first_line = bytes
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default();
        if first_line == kind.ownership_marker().as_bytes() {
            owned.push(path);
        } else if path == expected_path {
            ensure_owned(&path, &bytes, kind)?;
        }
    }
    Ok(owned)
}

fn ensure_provider_catalog_linked(assembly_dir: &Path) -> Result<()> {
    let lib_path = assembly_dir.join("src/lib.rs");
    reject_symlink(&lib_path)?;
    let source = fs::read_to_string(&lib_path).with_context(|| {
        format!(
            "读取 provider catalog assembly root {} 失败",
            lib_path.display()
        )
    })?;
    let syntax = syn::parse_file(&source)
        .with_context(|| format!("解析 {} Rust AST 失败", lib_path.display()))?;
    ensure!(
        !syntax
            .attrs
            .iter()
            .any(|attribute| meta_may_apply_cfg(&attribute.meta)),
        "{} 禁止 crate-level `cfg` 或可展开为 `cfg` 的 `cfg_attr`，避免 provider catalog compile-link 证明被条件移除",
        lib_path.display()
    );

    let linked_modules = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(module) if module.ident == "providers_gen" => Some(module),
            _ => None,
        })
        .filter(|module| {
            matches!(module.vis, syn::Visibility::Inherited)
                && module.content.is_none()
                && module.attrs.len() == 1
                && module.attrs.iter().all(|attribute| {
                    let syn::Meta::NameValue(meta) = &attribute.meta else {
                        return false;
                    };
                    if !meta.path.is_ident("path") {
                        return false;
                    }
                    matches!(
                        &meta.value,
                        syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Str(value),
                            ..
                        }) if value.value() == "generated/providers_gen.rs"
                    )
                })
        })
        .count();
    ensure!(
        linked_modules == 1,
        "{} 必须唯一私有编译 `#[path = \"generated/providers_gen.rs\"] mod providers_gen;`",
        lib_path.display()
    );

    let catalog_assertions = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Const(item) if item.ident == "_" => Some(item),
            _ => None,
        })
        .filter(|item| provider_catalog_non_empty_assertion(item))
        .count();
    ensure!(
        catalog_assertions == 1,
        "{} 必须唯一 const 断言 `!providers_gen::PROVIDER_CATALOG.is_empty()`",
        lib_path.display()
    );
    Ok(())
}

fn meta_may_apply_cfg(meta: &syn::Meta) -> bool {
    if meta.path().is_ident("cfg") {
        return true;
    }
    let syn::Meta::List(list) = meta else {
        return false;
    };
    if !list.path.is_ident("cfg_attr") {
        return false;
    }
    let nested = list.parse_args_with(
        syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
    );
    match nested {
        Ok(attributes) => attributes.iter().skip(1).any(meta_may_apply_cfg),
        Err(_) => true,
    }
}

fn provider_catalog_non_empty_assertion(item: &syn::ItemConst) -> bool {
    if !item.attrs.is_empty() || !matches!(item.vis, syn::Visibility::Inherited) {
        return false;
    }
    let syn::Type::Tuple(tuple) = item.ty.as_ref() else {
        return false;
    };
    if !tuple.elems.is_empty() {
        return false;
    }
    let syn::Expr::Macro(expression) = item.expr.as_ref() else {
        return false;
    };
    if !expression.mac.path.is_ident("assert") {
        return false;
    }
    let Ok(syn::Expr::Unary(negated)) = syn::parse2::<syn::Expr>(expression.mac.tokens.clone())
    else {
        return false;
    };
    if !matches!(negated.op, syn::UnOp::Not(_)) {
        return false;
    }
    let syn::Expr::MethodCall(call) = negated.expr.as_ref() else {
        return false;
    };
    call.method == "is_empty"
        && call.args.is_empty()
        && matches!(
            call.receiver.as_ref(),
            syn::Expr::Path(path)
                if path.path.segments.len() == 2
                    && path.path.segments[0].ident == "providers_gen"
                    && path.path.segments[1].ident == "PROVIDER_CATALOG"
        )
}

fn read_owned_target(path: &Path, kind: ArtifactKind) -> Result<Option<Vec<u8>>> {
    if !path.exists() {
        return Ok(None);
    }
    if !path.is_file() {
        bail!("生成目标不是普通文件：{}", path.display());
    }
    let bytes = fs::read(path).with_context(|| format!("读取 {} 失败", path.display()))?;
    ensure_owned(path, &bytes, kind)?;
    Ok(Some(bytes))
}

fn ensure_owned(path: &Path, bytes: &[u8], kind: ArtifactKind) -> Result<()> {
    let first_line = bytes
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    if first_line != kind.ownership_marker().as_bytes() {
        bail!(
            "拒绝覆盖或删除非本生成器文件：{}（缺 ownership marker）",
            path.display()
        );
    }
    Ok(())
}

fn render_providers(manifest: &CanonicalAssemblyManifestV2, source_label: &str) -> Result<String> {
    let providers = active_providers(manifest);

    let mut code = format!(
        "{GENERATED_PROVIDER_OWNERSHIP_MARKER}\n// Source: {source_label}\n// Source-Manifest-Digest: {}\n\nuse assembly_schema::{{\n    AssemblyDomain, DiportPort, LifecycleChannel, ProviderActivation, ProviderCatalogEntry,\n    ProviderConstructor, ProviderConsumer, ProviderDurability, ProviderFactorySymbol, ProviderRole,\n}};\n\npub(crate) const ASSEMBLY_NAMESPACE: &str = {:?};\n\npub(crate) const PROVIDER_CATALOG: &[ProviderCatalogEntry] = &[\n",
        manifest.manifest_digest(),
        manifest.name()
    );
    for provider in &providers {
        let factory = provider.id.factory_symbol().with_context(|| {
            format!(
                "active provider role `{}` has no factory symbol",
                provider.id.as_str()
            )
        })?;
        code.push_str("    ProviderCatalogEntry::checked(\n");
        code.push_str(&format!(
            "        ProviderRole::{},\n",
            provider_role_variant(provider.id)
        ));
        code.push_str(&format!(
            "        {},\n",
            provider_activation_expression(provider.id.activation())
        ));
        code.push_str(&format!(
            "        DiportPort::{},\n",
            port_variant(provider.port)
        ));
        code.push_str(&format!(
            "        ProviderConstructor::{},\n",
            constructor_variant(provider.provider)
        ));
        code.push_str(&format!(
            "        ProviderFactorySymbol::{},\n",
            factory_variant(factory)
        ));
        code.push_str(&format!("        {:?},\n", provider.provider_crate));
        code.push_str("        &[");
        for feature in &provider.required_features {
            code.push_str(&format!("{feature:?}, "));
        }
        code.push_str("],\n");
        code.push_str(&format!(
            "        ProviderConsumer::{},\n",
            consumer_variant(provider.consumer)
        ));
        code.push_str(&format!(
            "        ProviderDurability::{},\n",
            durability_variant(provider.durability)
        ));
        match provider.scope {
            Some(scope) => code.push_str(&format!(
                "        Some(assembly_schema::ProviderScope::{}),\n",
                scope_variant(scope)
            )),
            None => code.push_str("        None,\n"),
        }
        match provider.failure_posture {
            Some(posture) => code.push_str(&format!(
                "        Some(assembly_schema::ProviderFailurePosture::{}),\n",
                failure_posture_variant(posture)
            )),
            None => code.push_str("        None,\n"),
        }
        code.push_str("        &[");
        for output in &provider.outputs {
            code.push_str(&format!("LifecycleChannel::{}, ", channel_variant(*output)));
        }
        code.push_str("],\n");
        code.push_str("    ),\n");
    }
    code.push_str("];\n");
    if providers
        .iter()
        .any(|provider| provider.id == ProviderRole::ListenerPdp)
    {
        render_listener_pdp_lifecycle(&mut code);
    }
    let emits_role_batches = matches!(manifest.name(), "settingsonly" | "identityaudit");
    if emits_role_batches {
        render_provider_role_batches(&mut code, manifest.name(), &providers)?;
    }
    let formatted = crate::codegen::format_rust(&code)?;
    validate_provider_catalog_syntax(&formatted, manifest.name(), &providers, emits_role_batches)?;
    Ok(formatted)
}

fn active_providers(
    manifest: &CanonicalAssemblyManifestV2,
) -> Vec<&assembly_schema::DiportProvider> {
    let mut providers = manifest
        .diport_providers()
        .iter()
        .filter(|provider| provider.lifecycle == ProviderLifecycle::Active)
        .collect::<Vec<_>>();
    providers.sort_by_key(|provider| provider.id.as_str());
    providers
}

fn render_listener_pdp_lifecycle(code: &mut String) {
    code.push_str(
        "\nstruct ListenerPdpJwksEntry {\n\
             probe: (primitives::ProbeName, Box<dyn bootstrap::HealthProbe>),\n\
             resource: Box<diport::DynManagedResource<'static>>,\n\
         }\n\
         \n#[must_use = \"listener PDP JWKS lifecycle must be committed through its typed provider transaction\"]\n\
         pub(crate) struct ListenerPdpJwksLifecycle {\n\
             head: ListenerPdpJwksEntry,\n\
             tail: Vec<ListenerPdpJwksEntry>,\n\
         }\n\
         \nimpl ListenerPdpJwksLifecycle {\n\
             pub(crate) fn single(\n\
                 probe: (primitives::ProbeName, Box<dyn bootstrap::HealthProbe>),\n\
                 resource: Box<diport::DynManagedResource<'static>>,\n\
             ) -> Self {\n\
                 Self {\n\
                     head: ListenerPdpJwksEntry { probe, resource },\n\
                     tail: Vec::new(),\n\
                 }\n\
             }\n\
             \n             #[allow(dead_code, reason = \"single-entry assemblies share the canonical carrier API\")]\n\
             pub(crate) fn merge(mut self, other: Self) -> Self {\n\
                 self.tail.push(other.head);\n\
                 self.tail.extend(other.tail);\n\
                 self\n\
             }\n\
             \n             pub(crate) fn into_output(self) -> bootstrap::DomainModuleResult {\n\
                 let (probes, resources) = std::iter::once(self.head)\n\
                     .chain(self.tail)\n\
                     .map(|entry| (entry.probe, entry.resource))\n\
                     .unzip();\n\
                 bootstrap::DomainModuleResult {\n\
                     probes,\n\
                     resources,\n\
                     workers: Vec::new(),\n\
                 }\n\
             }\n\
         }\n",
    );
}

fn render_provider_role_batches(
    code: &mut String,
    assembly_name: &str,
    providers: &[&assembly_schema::DiportProvider],
) -> Result<()> {
    ensure!(
        !providers.is_empty(),
        "{assembly_name} provider role batches require a non-empty active catalog"
    );
    let scoped = |template: &str| template.replace("__ASSEMBLY__", assembly_name);

    code.push_str("\npub(crate) struct ProviderRoleBatches {\n");
    for provider in providers {
        let field = provider.id.as_str().replace('-', "_");
        let constructor = format!("{}Constructor", provider_role_variant(provider.id));
        code.push_str(&format!("    {field}: Option<{constructor}>,\n"));
    }
    code.push_str(
        "}\n\
         \npub(crate) struct CompletedProviderRoles {\n\
             probe_bindings: Vec<runtimeexec::inventory::ProviderProbeBinding>,\n\
         }\n\
         \nimpl CompletedProviderRoles {\n\
             pub(crate) fn into_probe_bindings(self) -> Vec<runtimeexec::inventory::ProviderProbeBinding> { self.probe_bindings }\n\
         }\n\
         \nimpl ProviderRoleBatches {\n",
    );
    code.push_str(&scoped(
        "    pub(crate) fn exact_join(plans: &[assembly_schema::ProviderPlan]) -> anyhow::Result<Self> {\n\
                 anyhow::ensure!(plans.len() == PROVIDER_CATALOG.len(), \"__ASSEMBLY__ RuntimePlan/generated provider catalog count drift\");\n\
                 let mut batches = Self {\n",
    ));
    for provider in providers {
        let field = provider.id.as_str().replace('-', "_");
        code.push_str(&format!("            {field}: None,\n"));
    }
    code.push_str(&scoped(
        "        };\n\
                 for entry in PROVIDER_CATALOG {\n\
                     let mut matching = plans.iter().filter(|plan| plan.id() == entry.role().as_str());\n\
                     let plan = matching.next().ok_or_else(|| anyhow::anyhow!(\"__ASSEMBLY__ RuntimePlan omits generated provider role '{}'\", entry.role().as_str()))?;\n\
                     anyhow::ensure!(matching.next().is_none(), \"__ASSEMBLY__ RuntimePlan duplicates generated provider role '{}'\", entry.role().as_str());\n\
                     anyhow::ensure!(plan.constructor() == entry.evidence().constructor() && plan.outputs() == entry.evidence().outputs(), \"__ASSEMBLY__ RuntimePlan disagrees with generated provider role '{}'\", entry.role().as_str());\n\
                     match entry.role() {\n",
    ));
    for provider in providers {
        let role = provider_role_variant(provider.id);
        let field = provider.id.as_str().replace('-', "_");
        let constructor = format!("{role}Constructor");
        code.push_str(&scoped(&format!(
            "                ProviderRole::{role} => anyhow::ensure!(batches.{field}.replace({constructor} {{ entry }}).is_none(), \"__ASSEMBLY__ generated provider role '{{}}' is duplicated\", entry.role().as_str()),\n"
        )));
    }
    code.push_str(&scoped(
        "                _ => anyhow::bail!(\"__ASSEMBLY__ generated provider catalog contains unsupported role '{}'\", entry.role().as_str()),\n\
                     }\n\
                 }\n\
                 batches.require_complete()?;\n\
                 Ok(batches)\n\
             }\n\
             fn require_complete(&self) -> anyhow::Result<()> {\n",
    ));
    for provider in providers {
        let field = provider.id.as_str().replace('-', "_");
        code.push_str(&scoped(&format!(
            "        anyhow::ensure!(self.{field}.is_some(), \"__ASSEMBLY__ generated provider role '{}' is missing\");\n",
            provider.id.as_str()
        )));
    }
    code.push_str("        Ok(())\n    }\n");
    for provider in providers {
        let field = provider.id.as_str().replace('-', "_");
        let constructor = format!("{}Constructor", provider_role_variant(provider.id));
        code.push_str(&scoped(&format!(
            "    pub(crate) fn {field}(&mut self) -> anyhow::Result<{constructor}> {{\n        self.{field}.take().ok_or_else(|| anyhow::anyhow!(\"__ASSEMBLY__ provider constructor '{role}' was consumed more than once\"))\n    }}\n",
            role = provider.id.as_str()
        )));
    }
    code.push_str(
        "    #[allow(clippy::too_many_arguments)]\n    // reason: generated exact-join closure has one move-only receipt per declared provider role.\n    pub(crate) fn finish(\n        self,\n        inventory: &bootstrap::DomainModuleResult,\n",
    );
    for provider in providers {
        let field = provider.id.as_str().replace('-', "_");
        let receipt = format!("{}Receipt", provider_role_variant(provider.id));
        code.push_str(&format!("        {field}: {receipt},\n"));
    }
    code.push_str("    ) -> anyhow::Result<CompletedProviderRoles> {\n");
    code.push_str("        let mut staged = [0_usize; 3];\n");
    code.push_str("        let mut probe_bindings = Vec::with_capacity(PROVIDER_CATALOG.len());\n");
    for provider in providers {
        let field = provider.id.as_str().replace('-', "_");
        let receipt = format!("{}Receipt", provider_role_variant(provider.id));
        code.push_str(&format!(
            "        let {receipt} {{ probes, resources, workers, probe_names }} = {field};\n        staged[0] += probes;\n        staged[1] += resources;\n        staged[2] += workers;\n        probe_bindings.push(runtimeexec::inventory::ProviderProbeBinding::from_probe_receipt(\"{}\", probe_names)?);\n",
            provider.id.as_str(),
        ));
    }
    code.push_str("        if ");
    for (index, provider) in providers.iter().enumerate() {
        if index != 0 {
            code.push_str(" || ");
        }
        code.push_str(&format!(
            "self.{}.is_some()",
            provider.id.as_str().replace('-', "_")
        ));
    }
    code.push_str(&scoped(
        " {\n\
                     anyhow::bail!(\"__ASSEMBLY__ provider role receipt came from a different exact-join generation\");\n\
                 }\n\
                 anyhow::ensure!(inventory.probes.len() == staged[0] && inventory.resources.len() == staged[1] && inventory.workers.len() == staged[2], \"__ASSEMBLY__ transaction provider lifecycle output differs from exact receipts\");\n\
                 Ok(CompletedProviderRoles { probe_bindings })\n\
             }\n\
         }\n",
    ));

    code.push_str(&scoped(
        "\nfn lifecycle_channels(output: &bootstrap::DomainModuleResult) -> Vec<LifecycleChannel> {\n\
             let mut channels = Vec::new();\n\
             if !output.probes.is_empty() { channels.push(LifecycleChannel::Probes); }\n\
             if !output.resources.is_empty() { channels.push(LifecycleChannel::Resources); }\n\
             if !output.workers.is_empty() { channels.push(LifecycleChannel::Workers); }\n\
             channels\n\
         }\n\
         \nfn validate_lifecycle_output(entry: &ProviderCatalogEntry, output: &bootstrap::DomainModuleResult) -> anyhow::Result<()> {\n\
             let actual = lifecycle_channels(output);\n\
             anyhow::ensure!(actual == entry.evidence().outputs(), \"__ASSEMBLY__ provider role '{}' lifecycle mismatch: expected {:?}, actual {:?}\", entry.role().as_str(), entry.evidence().outputs(), actual);\n\
             Ok(())\n\
         }\n",
    ));

    for provider in providers {
        let role = provider_role_variant(provider.id);
        let constructor = format!("{role}Constructor");
        let batch = format!("{role}Batch");
        let receipt = format!("{role}Receipt");
        let shape = provider_finish_shape(provider.id);
        let unwrap_output = match shape.materializer {
            Some(method) => format!("                     let output = output.{method}();\n"),
            None => String::new(),
        };
        code.push_str(&format!(
            "\npub(crate) struct {constructor} {{\n    entry: &'static ProviderCatalogEntry,\n}}\n\
             pub(crate) struct {receipt} {{\n    probes: usize,\n    resources: usize,\n    workers: usize,\n    probe_names: Vec<primitives::ProbeName>,\n}}\n\
             impl {receipt} {{\n\
                 fn transfer_lifecycle(output: bootstrap::DomainModuleResult, inventory: &mut bootstrap::DomainModuleResult) -> Self {{\n\
                     let probe_names = output.probes.iter().map(|(name, _)| name.clone()).collect();\n\
                     let receipt = Self {{ probes: output.probes.len(), resources: output.resources.len(), workers: output.workers.len(), probe_names }};\n\
                     inventory.merge(output);\n\
                     receipt\n\
                 }}\n\
             }}\n",
        ));
        match shape.bound_value {
            Some((value_type, value_materializer)) => code.push_str(&format!(
                r#"pub(crate) struct {batch} {{
    lifecycle: bootstrap::DomainModuleResult,
    value: {value_type},
}}
#[cfg(test)]
pub(crate) struct {batch}ForTest(bootstrap::DomainModuleResult);
impl {constructor} {{
    pub(crate) fn finish(self, output: {input_type}) -> anyhow::Result<{batch}> {{
        let value = output.{value_materializer}();
        let lifecycle = bootstrap::DomainModuleResult::default();
        validate_lifecycle_output(self.entry, &lifecycle)?;
        Ok({batch} {{ lifecycle, value }})
    }}
}}
#[cfg(test)]
impl {constructor} {{
    pub(crate) fn finish_for_test(self, output: bootstrap::DomainModuleResult) -> anyhow::Result<{batch}ForTest> {{
        validate_lifecycle_output(self.entry, &output)?;
        Ok({batch}ForTest(output))
    }}
}}
impl {batch} {{
    pub(crate) fn transfer(self, inventory: &mut bootstrap::DomainModuleResult) -> ({receipt}, {value_type}) {{
        ({receipt}::transfer_lifecycle(self.lifecycle, inventory), self.value)
    }}
}}
#[cfg(test)]
impl {batch}ForTest {{
    pub(crate) fn transfer(self, inventory: &mut bootstrap::DomainModuleResult) -> {receipt} {{
        {receipt}::transfer_lifecycle(self.0, inventory)
    }}
}}
"#,
                input_type = shape.input_type,
            )),
            None => code.push_str(&format!(
                "pub(crate) struct {batch}(bootstrap::DomainModuleResult);\n\
                 impl {constructor} {{\n\
                     pub(crate) fn finish(self, output: {input_type}) -> anyhow::Result<{batch}> {{\n\
{unwrap_output}\
                         validate_lifecycle_output(self.entry, &output)?;\n\
                         Ok({batch}(output))\n\
                     }}\n\
                 }}\n\
                 impl {batch} {{\n\
                     pub(crate) fn transfer(self, inventory: &mut bootstrap::DomainModuleResult) -> {receipt} {{\n\
                         {receipt}::transfer_lifecycle(self.0, inventory)\n\
                     }}\n\
                 }}\n",
                input_type = shape.input_type,
            )),
        }
    }
    Ok(())
}

fn validate_provider_catalog_syntax(
    source: &str,
    assembly_name: &str,
    providers: &[&assembly_schema::DiportProvider],
    emits_role_batches: bool,
) -> Result<()> {
    let syntax = syn::parse_file(source).context("解析 provider catalog Rust AST 失败")?;
    let Some((syn::Item::Use(import), remaining)) = syntax.items.split_first() else {
        bail!("provider catalog 缺少固定 import");
    };
    let Some((syn::Item::Const(namespace), remaining)) = remaining.split_first() else {
        bail!("provider catalog 缺少 generated assembly namespace");
    };
    ensure!(
        namespace.attrs.is_empty()
            && compact_tokens(&namespace.vis) == "pub(crate)"
            && namespace.ident == "ASSEMBLY_NAMESPACE"
            && compact_tokens(namespace.ty.as_ref()) == "&str"
            && matches!(
                namespace.expr.as_ref(),
                syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(value), .. })
                    if value.value() == assembly_name
            ),
        "generated assembly namespace 必须由 manifest name 铸造为 crate-private &str"
    );
    let Some((syn::Item::Const(catalog), role_batch_items)) = remaining.split_first() else {
        bail!("provider catalog 缺少唯一 const catalog");
    };
    let import_tokens = compact_tokens(&import.tree);
    ensure!(
        import_tokens
            == "assembly_schema::{AssemblyDomain,DiportPort,LifecycleChannel,ProviderActivation,ProviderCatalogEntry,ProviderConstructor,ProviderConsumer,ProviderDurability,ProviderFactorySymbol,ProviderRole,}",
        "provider catalog import 集合漂移：{import_tokens}"
    );
    ensure!(
        catalog.attrs.is_empty(),
        "live provider catalog const 禁止 cfg/allow 属性"
    );
    ensure!(
        compact_tokens(&catalog.vis) == "pub(crate)",
        "provider catalog 必须保持 crate-private"
    );
    ensure!(
        catalog.ident == "PROVIDER_CATALOG",
        "provider catalog const 名称漂移"
    );
    ensure!(
        compact_tokens(catalog.ty.as_ref()) == "&[ProviderCatalogEntry]",
        "provider catalog const 类型漂移"
    );
    let syn::Expr::Reference(reference) = catalog.expr.as_ref() else {
        bail!("provider catalog 必须是不可变 slice reference");
    };
    ensure!(
        reference.mutability.is_none(),
        "provider catalog 禁止可变 reference"
    );
    let syn::Expr::Array(entries) = reference.expr.as_ref() else {
        bail!("provider catalog 必须是 checked entry array");
    };
    let mut roles = Vec::new();
    for entry in &entries.elems {
        validate_provider_catalog_entry(entry)?;
        roles.push(provider_catalog_entry_role_variant(entry)?);
    }
    let expected_roles = providers
        .iter()
        .map(|provider| provider_role_variant(provider.id))
        .collect::<Vec<_>>();
    ensure!(
        roles == expected_roles,
        "provider catalog role 集合必须直接匹配 typed provider IR: expected={expected_roles:?} actual={roles:?}"
    );

    let mut remaining = role_batch_items;
    if providers
        .iter()
        .any(|provider| provider.id == ProviderRole::ListenerPdp)
    {
        let expected = listener_pdp_lifecycle_items()?;
        ensure!(
            remaining.len() >= expected.len(),
            "provider catalog 缺少 generated listener-PDP lifecycle carrier"
        );
        for (actual, expected) in remaining.iter().zip(&expected) {
            ensure!(
                compact_tokens(actual) == compact_tokens(expected),
                "generated listener-PDP lifecycle carrier 漂移"
            );
        }
        remaining = &remaining[expected.len()..];
    }

    if !emits_role_batches {
        ensure!(
            remaining.is_empty(),
            "provider catalog data-only target 含额外 generated item"
        );
        return Ok(());
    }
    validate_provider_role_batch_syntax(remaining, providers)
}

fn listener_pdp_lifecycle_items() -> Result<Vec<syn::Item>> {
    let mut source = String::new();
    render_listener_pdp_lifecycle(&mut source);
    Ok(syn::parse_file(&source)
        .context("解析 canonical listener-PDP lifecycle carrier 失败")?
        .items)
}

fn provider_catalog_entry_role_variant(expression: &syn::Expr) -> Result<String> {
    let syn::Expr::Call(call) = expression else {
        bail!("provider catalog array 只允许 checked call");
    };
    let Some(syn::Expr::Path(role)) = call.args.first() else {
        bail!("provider catalog role 必须是闭合 enum variant");
    };
    role.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
        .context("provider catalog role 缺少 variant")
}

fn generated_test_only_item(item: &syn::Item) -> bool {
    let attrs = match item {
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        _ => return false,
    };
    attrs.len() == 1 && compact_tokens(&attrs[0]) == "#[cfg(test)]"
}

fn validate_provider_role_batch_syntax(
    items: &[syn::Item],
    providers: &[&assembly_schema::DiportProvider],
) -> Result<()> {
    let roles = providers
        .iter()
        .map(|provider| provider_role_variant(provider.id))
        .collect::<Vec<_>>();
    let mut expected_structs = vec![
        "CompletedProviderRoles".to_owned(),
        "ProviderRoleBatches".to_owned(),
    ];
    let mut expected_impls = vec![
        (
            "ProviderRoleBatches".to_owned(),
            std::iter::once("exact_join".to_owned())
                .chain(std::iter::once("require_complete".to_owned()))
                .chain(roles.iter().map(|role| pascal_to_snake(role)))
                .chain(std::iter::once("finish".to_owned()))
                .collect::<Vec<_>>(),
        ),
        (
            "CompletedProviderRoles".to_owned(),
            vec!["into_probe_bindings".to_owned()],
        ),
    ];
    for role in &roles {
        expected_structs.extend([
            format!("{role}Constructor"),
            format!("{role}Batch"),
            format!("{role}Receipt"),
        ]);
        expected_impls.extend([
            (format!("{role}Constructor"), vec!["finish".to_owned()]),
            (format!("{role}Batch"), vec!["transfer".to_owned()]),
            (
                format!("{role}Receipt"),
                vec!["transfer_lifecycle".to_owned()],
            ),
        ]);
    }
    expected_structs.sort();
    expected_impls.sort_by(|left, right| left.0.cmp(&right.0));
    for (_, methods) in &mut expected_impls {
        methods.sort();
    }

    let mut structs = Vec::new();
    let mut impls = Vec::new();
    let mut functions = Vec::new();
    let mut exact_residual_guard = false;
    let mut finish_shapes = std::collections::BTreeMap::<String, ProviderFinishShape>::new();
    let mut finish_shapes_ok = std::collections::BTreeMap::<String, bool>::new();
    for provider in providers {
        let target = format!("{}Constructor", provider_role_variant(provider.id));
        finish_shapes.insert(target.clone(), provider_finish_shape(provider.id));
        finish_shapes_ok.insert(target, false);
    }
    for item in items {
        if generated_test_only_item(item) {
            continue;
        }
        match item {
            syn::Item::Struct(item) => {
                ensure!(
                    item.attrs.is_empty(),
                    "generated provider role struct 禁止属性"
                );
                ensure!(
                    compact_tokens(&item.vis) == "pub(crate)",
                    "generated provider role struct 必须 crate-private"
                );
                ensure!(
                    item.fields
                        .iter()
                        .all(|field| matches!(field.vis, syn::Visibility::Inherited)),
                    "generated provider role fields 必须 private"
                );
                structs.push(item.ident.to_string());
            }
            syn::Item::Impl(item) => {
                ensure!(
                    item.attrs.is_empty() && item.trait_.is_none(),
                    "generated provider role 只允许无属性 inherent impl"
                );
                let syn::Type::Path(target) = item.self_ty.as_ref() else {
                    bail!("generated provider role impl target 必须是闭合类型");
                };
                let target = target
                    .path
                    .get_ident()
                    .map(ToString::to_string)
                    .context("generated provider role impl target 必须是单段类型")?;
                if target == "ProviderRoleBatches"
                    && let Some(syn::ImplItem::Fn(finish)) = item.items.iter().find(
                        |member| matches!(member, syn::ImplItem::Fn(method) if method.sig.ident == "finish"),
                    )
                {
                    let body = compact_tokens(&finish.block);
                    exact_residual_guard = [
                        "inventory.probes.len()==staged[0]",
                        "inventory.resources.len()==staged[1]",
                        "inventory.workers.len()==staged[2]",
                    ]
                    .iter()
                    .all(|required| body.contains(required))
                        && !body.contains(">=staged[");
                }
                if let Some(shape) = finish_shapes.get(&target).copied()
                    && let Some(syn::ImplItem::Fn(finish)) = item.items.iter().find(
                        |member| matches!(member, syn::ImplItem::Fn(method) if method.sig.ident == "finish"),
                    )
                {
                    let matched = finish_matches_provider_shape(finish, shape);
                    if finish_shapes_ok.contains_key(&target) {
                        finish_shapes_ok.insert(target.clone(), matched);
                    }
                    ensure!(
                        matched,
                        "generated provider role '{target}' finish 必须匹配 closed ProviderFinishShape"
                    );
                }
                let mut methods = item
                    .items
                    .iter()
                    .map(|member| match member {
                        syn::ImplItem::Fn(method)
                            if method.attrs.is_empty()
                                || (target == "ProviderRoleBatches"
                                    && method.sig.ident == "finish"
                                    && method.attrs.len() == 1
                                    && compact_tokens(&method.attrs[0])
                                        == "#[allow(clippy::too_many_arguments)]") =>
                        {
                            Ok(method.sig.ident.to_string())
                        }
                        _ => bail!("generated provider role impl 只允许无属性 method"),
                    })
                    .collect::<Result<Vec<_>>>()?;
                methods.sort();
                impls.push((target, methods));
            }
            syn::Item::Fn(item) => {
                ensure!(
                    item.attrs.is_empty() && matches!(item.vis, syn::Visibility::Inherited),
                    "generated provider role helper 必须 private 且无属性"
                );
                functions.push(item.sig.ident.to_string());
            }
            _ => bail!("provider catalog generated role batches 含额外 item"),
        }
    }
    structs.sort();
    impls.sort_by(|left, right| left.0.cmp(&right.0));
    functions.sort();
    ensure!(
        structs == expected_structs,
        "generated provider role struct 集合漂移"
    );
    ensure!(
        impls == expected_impls,
        "generated provider role impl 集合漂移"
    );
    ensure!(
        functions == ["lifecycle_channels", "validate_lifecycle_output"],
        "generated provider role helper 集合漂移"
    );
    ensure!(
        exact_residual_guard,
        "generated provider role finish 必须逐通道精确拒绝 residual lifecycle output"
    );
    ensure!(
        finish_shapes_ok.values().all(|ok| *ok),
        "generated provider role finish shapes must match closed ProviderFinishShape table: {finish_shapes_ok:?}"
    );
    Ok(())
}

fn pascal_to_snake(value: &str) -> String {
    let mut snake = String::new();
    for (index, character) in value.chars().enumerate() {
        if character.is_ascii_uppercase() && index != 0 {
            snake.push('_');
        }
        snake.push(character.to_ascii_lowercase());
    }
    snake
}

fn validate_provider_catalog_entry(expression: &syn::Expr) -> Result<()> {
    let syn::Expr::Call(call) = expression else {
        bail!("provider catalog array 只允许 checked call");
    };
    ensure!(
        matches!(
            call.func.as_ref(),
            syn::Expr::Path(path)
                if exact_path(&path.path, &["ProviderCatalogEntry", "checked"])
        ),
        "provider catalog entry 只允许 ProviderCatalogEntry::checked"
    );
    ensure!(
        call.args.len() == 12,
        "ProviderCatalogEntry::checked 参数数量必须为 12"
    );
    let args = call.args.iter().collect::<Vec<_>>();
    ensure_enum_variant(args[0], "ProviderRole")?;
    ensure_provider_activation(args[1])?;
    ensure_enum_variant(args[2], "DiportPort")?;
    ensure_enum_variant(args[3], "ProviderConstructor")?;
    ensure_enum_variant(args[4], "ProviderFactorySymbol")?;
    ensure!(
        matches!(
            args[5],
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(_),
                ..
            })
        ),
        "provider crate 必须是字符串字面量"
    );
    ensure_string_slice(args[6])?;
    ensure_enum_variant(args[7], "ProviderConsumer")?;
    ensure_enum_variant(args[8], "ProviderDurability")?;
    ensure_optional_enum_variant(args[9], "ProviderScope")?;
    ensure_optional_enum_variant(args[10], "ProviderFailurePosture")?;
    ensure_enum_slice(args[11], "LifecycleChannel")?;
    Ok(())
}

fn ensure_provider_activation(expression: &syn::Expr) -> Result<()> {
    if ensure_enum_variant(expression, "ProviderActivation").is_ok() {
        return Ok(());
    }
    let syn::Expr::Call(call) = expression else {
        bail!("provider activation 必须是闭合 ProviderActivation variant")
    };
    ensure!(
        matches!(call.func.as_ref(), syn::Expr::Path(path)
            if exact_path(&path.path, &["ProviderActivation", "DomainLocal"]))
            && call.args.len() == 1,
        "DomainLocal activation 必须有一个 typed domain"
    );
    ensure_enum_variant(
        call.args.first().context("DomainLocal domain missing")?,
        "AssemblyDomain",
    )
}

fn ensure_enum_variant(expression: &syn::Expr, enum_name: &str) -> Result<()> {
    ensure!(
        matches!(
            expression,
            syn::Expr::Path(path)
                if path.path.segments.len() == 2
                    && path.path.segments[0].ident == enum_name
                    && matches!(path.path.segments[0].arguments, syn::PathArguments::None)
                    && matches!(path.path.segments[1].arguments, syn::PathArguments::None)
        ),
        "provider catalog 参数必须是 {enum_name} 的闭合 variant"
    );
    Ok(())
}

fn ensure_string_slice(expression: &syn::Expr) -> Result<()> {
    let array = immutable_array_reference(expression, "requiredFeatures")?;
    ensure!(
        array.elems.iter().all(|element| matches!(
            element,
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(_),
                ..
            })
        )),
        "requiredFeatures 只允许字符串字面量"
    );
    Ok(())
}

fn ensure_optional_enum_variant(expression: &syn::Expr, enum_name: &str) -> Result<()> {
    if matches!(
        expression,
        syn::Expr::Path(path) if exact_path(&path.path, &["None"])
    ) {
        return Ok(());
    }
    let syn::Expr::Call(call) = expression else {
        bail!("provider catalog optional 参数必须是 None 或 Some({enum_name}::<variant>)");
    };
    ensure!(
        matches!(
            call.func.as_ref(),
            syn::Expr::Path(path) if exact_path(&path.path, &["Some"])
        ) && call.args.len() == 1,
        "provider catalog optional 参数必须是 None 或 Some({enum_name}::<variant>)"
    );
    ensure_schema_enum_variant(&call.args[0], enum_name)
}

fn ensure_schema_enum_variant(expression: &syn::Expr, enum_name: &str) -> Result<()> {
    ensure!(
        matches!(
            expression,
            syn::Expr::Path(path)
                if path.qself.is_none()
                    && path.path.leading_colon.is_none()
                    && path.path.segments.len() == 3
                    && path.path.segments[0].ident == "assembly_schema"
                    && path.path.segments[1].ident == enum_name
                    && path
                        .path
                        .segments
                        .iter()
                        .all(|segment| matches!(segment.arguments, syn::PathArguments::None))
        ),
        "provider catalog optional 参数必须是 None 或 Some(assembly_schema::{enum_name}::<variant>)"
    );
    Ok(())
}

fn ensure_enum_slice(expression: &syn::Expr, enum_name: &str) -> Result<()> {
    let array = immutable_array_reference(expression, "outputs")?;
    for element in &array.elems {
        ensure_enum_variant(element, enum_name)?;
    }
    Ok(())
}

fn immutable_array_reference<'a>(
    expression: &'a syn::Expr,
    label: &str,
) -> Result<&'a syn::ExprArray> {
    let syn::Expr::Reference(reference) = expression else {
        bail!("{label} 必须是不可变 array reference");
    };
    ensure!(reference.mutability.is_none(), "{label} 禁止可变 reference");
    let syn::Expr::Array(array) = reference.expr.as_ref() else {
        bail!("{label} 必须是 array");
    };
    Ok(array)
}

fn exact_path(path: &syn::Path, segments: &[&str]) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == segments.len()
        && path
            .segments
            .iter()
            .zip(segments)
            .all(|(actual, expected)| {
                actual.ident == *expected && matches!(actual.arguments, syn::PathArguments::None)
            })
}

fn compact_tokens(tokens: &impl quote::ToTokens) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

const fn provider_role_variant(role: ProviderRole) -> &'static str {
    match role {
        ProviderRole::DeviceCertificateStore => "DeviceCertificateStore",
        ProviderRole::DeviceCommandStore => "DeviceCommandStore",
        ProviderRole::DeviceDraftArtifactSource => "DeviceDraftArtifactSource",
        ProviderRole::DeviceMqttSession => "DeviceMqttSession",
        ProviderRole::DeviceRevocationStore => "DeviceRevocationStore",
        ProviderRole::EventPublisher => "EventPublisher",
        ProviderRole::EventSubscriber => "EventSubscriber",
        ProviderRole::IdentitySigner => "IdentitySigner",
        ProviderRole::SettingsKeyProvider => "SettingsKeyProvider",
        ProviderRole::SettingsSecretResolver => "SettingsSecretResolver",
        ProviderRole::ListenerPdp => "ListenerPdp",
        ProviderRole::ServiceTokenReplayStore => "ServiceTokenReplayStore",
        ProviderRole::AuthAuditSink => "AuthAuditSink",
        ProviderRole::ListenerRateLimiter => "ListenerRateLimiter",
        ProviderRole::DistributedLockStore => "DistributedLockStore",
        ProviderRole::DistributedCasStore => "DistributedCasStore",
        ProviderRole::DistributedCasStoreAlternative => "DistributedCasStoreAlternative",
        ProviderRole::RuntimeObjectStore => "RuntimeObjectStore",
        ProviderRole::DlxLifecycleRepository => "DlxLifecycleRepository",
        ProviderRole::DlxArchiveStore => "DlxArchiveStore",
        ProviderRole::DlxArchiveKeyProvider => "DlxArchiveKeyProvider",
        ProviderRole::DlxHotKeyProvider => "DlxHotKeyProvider",
    }
}

const fn port_variant(port: DiportPort) -> &'static str {
    match port {
        DiportPort::CertificateReconcileRepository => "CertificateReconcileRepository",
        DiportPort::DeviceCommandStore => "DeviceCommandStore",
        DiportPort::CertificateArtifactSource => "CertificateArtifactSource",
        DiportPort::MqttSession => "MqttSession",
        DiportPort::RevocationStore => "RevocationStore",
        DiportPort::Publisher => "Publisher",
        DiportPort::AckableSubscriber => "AckableSubscriber",
        DiportPort::Signer => "Signer",
        DiportPort::KeyProvider => "KeyProvider",
        DiportPort::SecretResolver => "SecretResolver",
        DiportPort::Pdp => "Pdp",
        DiportPort::ServiceTokenReplayStore => "ServiceTokenReplayStore",
        DiportPort::AuditSink => "AuditSink",
        DiportPort::RateLimiter => "RateLimiter",
        DiportPort::Lock => "Lock",
        DiportPort::Cas => "Cas",
        DiportPort::ObjectStore => "ObjectStore",
        DiportPort::DlxLifecycleRepository => "DlxLifecycleRepository",
        DiportPort::DlxArchiveStore => "DlxArchiveStore",
    }
}

const fn constructor_variant(constructor: ProviderConstructor) -> &'static str {
    match constructor {
        ProviderConstructor::PostgresDeviceCertificateRepository => {
            "PostgresDeviceCertificateRepository"
        }
        ProviderConstructor::PostgresDeviceCommandStore => "PostgresDeviceCommandStore",
        ProviderConstructor::IdentityDraftArtifactSimulator => "IdentityDraftArtifactSimulator",
        ProviderConstructor::MqttSession => "MqttSession",
        ProviderConstructor::PostgresRevocationStore => "PostgresRevocationStore",
        ProviderConstructor::RedisRateLimiter => "RedisRateLimiter",
        ProviderConstructor::AmqpPublisher => "AmqpPublisher",
        ProviderConstructor::AmqpSubscriber => "AmqpSubscriber",
        ProviderConstructor::RedisLockStore => "RedisLockStore",
        ProviderConstructor::RedisCasStore => "RedisCasStore",
        ProviderConstructor::PostgresCasStore => "PostgresCasStore",
        ProviderConstructor::PostgresAuthAuditSink => "PostgresAuthAuditSink",
        ProviderConstructor::PostgresServiceTokenReplayStore => "PostgresServiceTokenReplayStore",
        ProviderConstructor::PostgresDlxLifecycleRepository => "PostgresDlxLifecycleRepository",
        ProviderConstructor::VaultSigner => "VaultSigner",
        ProviderConstructor::VaultKeyProvider => "VaultKeyProvider",
        ProviderConstructor::VaultSecretResolver => "VaultSecretResolver",
        ProviderConstructor::OidcProvider => "OidcProvider",
        ProviderConstructor::S3Store => "S3Store",
        ProviderConstructor::S3VerifiedDlxArchiveStore => "S3VerifiedDlxArchiveStore",
    }
}

const fn factory_variant(factory: ProviderFactorySymbol) -> &'static str {
    match factory {
        ProviderFactorySymbol::IdentityPostgresDeviceCertificateStore => {
            "IdentityPostgresDeviceCertificateStore"
        }
        ProviderFactorySymbol::IdentityPostgresDeviceCommandStore => {
            "IdentityPostgresDeviceCommandStore"
        }
        ProviderFactorySymbol::IdentityDraftArtifactSimulator => "IdentityDraftArtifactSimulator",
        ProviderFactorySymbol::IdentityMqttSession => "IdentityMqttSession",
        ProviderFactorySymbol::DeviceloopPostgresRevocationStore => {
            "DeviceloopPostgresRevocationStore"
        }
        ProviderFactorySymbol::EventexecAmqpPublisher => "EventexecAmqpPublisher",
        ProviderFactorySymbol::EventexecAmqpSubscriber => "EventexecAmqpSubscriber",
        ProviderFactorySymbol::IdentityVaultSigner => "IdentityVaultSigner",
        ProviderFactorySymbol::SettingsVaultKeyProvider => "SettingsVaultKeyProvider",
        ProviderFactorySymbol::SettingsVaultSecretResolver => "SettingsVaultSecretResolver",
        ProviderFactorySymbol::HttpserveOidcPdp => "HttpserveOidcPdp",
        ProviderFactorySymbol::OidcPostgresServiceTokenReplayStore => {
            "OidcPostgresServiceTokenReplayStore"
        }
        ProviderFactorySymbol::HttpservePostgresAuthAuditSink => "HttpservePostgresAuthAuditSink",
        ProviderFactorySymbol::HttpserveRedisRateLimiter => "HttpserveRedisRateLimiter",
        ProviderFactorySymbol::DistributedRedisLockStore => "DistributedRedisLockStore",
        ProviderFactorySymbol::DistributedPostgresCasStore => "DistributedPostgresCasStore",
        ProviderFactorySymbol::RuntimeS3ObjectStore => "RuntimeS3ObjectStore",
        ProviderFactorySymbol::EventexecPostgresDlxLifecycleRepository => {
            "EventexecPostgresDlxLifecycleRepository"
        }
        ProviderFactorySymbol::EventexecS3DlxArchiveStore => "EventexecS3DlxArchiveStore",
        ProviderFactorySymbol::EventexecVaultArchiveKeyProvider => {
            "EventexecVaultArchiveKeyProvider"
        }
        ProviderFactorySymbol::EventexecVaultHotKeyProvider => "EventexecVaultHotKeyProvider",
    }
}

const fn consumer_variant(consumer: ProviderConsumer) -> &'static str {
    match consumer {
        ProviderConsumer::Deviceloop => "Deviceloop",
        ProviderConsumer::Eventexec => "Eventexec",
        ProviderConsumer::Identity => "Identity",
        ProviderConsumer::Settings => "Settings",
        ProviderConsumer::Httpserve => "Httpserve",
        ProviderConsumer::Oidc => "Oidc",
        ProviderConsumer::Distributed => "Distributed",
        ProviderConsumer::Runtime => "Runtime",
    }
}

const fn durability_variant(durability: ProviderDurability) -> &'static str {
    match durability {
        ProviderDurability::EphemeralMemory => "EphemeralMemory",
        ProviderDurability::Persistent => "Persistent",
    }
}

const fn scope_variant(scope: ProviderScope) -> &'static str {
    match scope {
        ProviderScope::ProcessLocal => "ProcessLocal",
        ProviderScope::ClusterGlobal => "ClusterGlobal",
    }
}

const fn failure_posture_variant(posture: ProviderFailurePosture) -> &'static str {
    match posture {
        ProviderFailurePosture::FailOpen => "FailOpen",
        ProviderFailurePosture::FailClosed => "FailClosed",
    }
}

#[allow(clippy::cognitive_complexity)]
fn render_modules(
    manifest: &CanonicalAssemblyManifestV2,
    framework_routes: &[(String, AssemblyListenerKind)],
    source_label: &str,
) -> Result<String> {
    let manifest_digest = manifest.manifest_digest();
    let is_runtime = manifest.name() == "runtime";
    let typed_domain_inputs = is_runtime || manifest.typed_domain_inputs();
    let wire_domains_signature = if is_runtime {
        "pub async fn wire_domains(\n    deps: &SharedRuntimeDeps,\n    providers: crate::LocalDomainProviderCatalog,\n    inputs: PreparedLocalDomainInputs,\n) -> Result<Vec<DomainBinding>, DomainWiringFailure>"
    } else if typed_domain_inputs {
        "pub async fn wire_domains(\n    deps: &SharedRuntimeDeps,\n    inputs: crate::domains::DomainModuleInputs,\n) -> anyhow::Result<Vec<DomainBinding>>"
    } else {
        "pub async fn wire_domains(deps: &SharedRuntimeDeps) -> anyhow::Result<Vec<DomainBinding>>"
    };
    let mut code = format!(
        "{OWNERSHIP_MARKER}\n// Source: {source_label}\n// Source-Manifest-Digest: {manifest_digest}\n\nuse anyhow::Context as _;\nuse bootstrap::DomainBinding;\n\nuse crate::SharedRuntimeDeps;\n\n"
    );
    if is_runtime {
        code.push_str("use crate::domains::DomainWiringFailure;\n\n");
    }
    if is_runtime {
        code.push_str("pub const ASSEMBLY_DOMAINS: &[assembly_schema::AssemblyDomain] = &[\n");
        for domain in manifest.domains() {
            code.push_str(&format!(
                "    assembly_schema::AssemblyDomain::{},\n",
                domain_variant(*domain)
            ));
        }
        code.push_str("];\n\n");

        code.push_str("pub(crate) struct PreparedLocalDomainInputs {\n    inputs: Vec<LocalDomainModuleInput>,\n}\n\npub(crate) enum LocalDomainModuleInput {\n");
        for domain in manifest.domains() {
            let module = module_name(*domain)?;
            code.push_str(&format!(
                "    {}(crate::domains::{module}::{}ModuleInput),\n",
                domain_variant(*domain),
                domain_variant(*domain)
            ));
        }
        code.push_str("}\n\nimpl PreparedLocalDomainInputs {\n    pub(crate) fn from_snapshot(\n        execution: &crate::plan::DomainExecutionPlan,\n        mapper: &crate::config::ServingConfigMapper<'_>,\n        keyprovider_readiness_interval: settings_composition::KeyProviderReadinessInterval,\n        token_profiles: &crate::config::TokenProfilesConfig,\n    ) -> anyhow::Result<Self> {\n        let mut inputs = Vec::with_capacity(execution.local_domains().len());\n        for domain in execution.local_domains() {\n            inputs.push(match domain {\n");
        for domain in manifest.domains() {
            let module = module_name(*domain)?;
            let variant = domain_variant(*domain);
            let constructor = match domain {
                AssemblyDomain::Settings => format!(
                    "crate::domains::{module}::{variant}ModuleInput::new(keyprovider_readiness_interval)"
                ),
                AssemblyDomain::Identity => format!(
                    "crate::domains::{module}::{variant}ModuleInput::from_mapper(mapper, token_profiles.primary_identity_profile()?)?"
                ),
                AssemblyDomain::Audit => {
                    format!("crate::domains::{module}::{variant}ModuleInput::from_mapper(mapper)?")
                }
                other => bail!(
                    "runtime input generator does not support domain '{}'",
                    other.as_str()
                ),
            };
            code.push_str(&format!(
                "                assembly_schema::AssemblyDomain::{variant} => LocalDomainModuleInput::{variant}({constructor}),\n"
            ));
        }
        code.push_str("                other => anyhow::bail!(\"runtime generated unsupported local domain '{}'\", other.as_str()),\n            });\n        }\n        Ok(Self { inputs })\n    }\n\n    pub(crate) fn into_inputs(self) -> impl Iterator<Item = LocalDomainModuleInput> {\n        self.inputs.into_iter()\n    }\n");
        if manifest.domains().contains(&AssemblyDomain::Settings) {
            code.push_str("\n    pub(crate) fn settings_readiness_interval(&self) -> anyhow::Result<settings_composition::KeyProviderReadinessInterval> {\n        self.inputs.iter().find_map(|input| match input {\n            LocalDomainModuleInput::Settings(input) => Some(input.readiness_interval()),\n            _ => None,\n        }).ok_or_else(|| anyhow::anyhow!(\"settings local execution input is not active\"))\n    }\n");
        }
        if manifest.domains().contains(&AssemblyDomain::Identity) {
            code.push_str("\n    #[cfg(test)]\n    pub(crate) fn identity_for_test(&self) -> &crate::domains::identity::IdentityModuleInput {\n        self.inputs.iter().find_map(|input| match input {\n            LocalDomainModuleInput::Identity(input) => Some(input),\n            _ => None,\n        }).unwrap_or_else(|| unreachable!(\"all-local test plan contains identity\"))\n    }\n");
        }
        code.push_str("}\n\n");
    }
    code.push_str(&format!("{wire_domains_signature} {{\n"));
    if typed_domain_inputs && !is_runtime {
        code.push_str("    let crate::domains::DomainModuleInputs {\n");
        for domain in manifest.domains() {
            let module = module_name(*domain)?;
            code.push_str(&format!("        {module},\n"));
        }
        code.push_str("    } = inputs;\n");
    }
    if is_runtime {
        code.push_str("    let mut bindings = Vec::new();\n");
        code.push_str(
            "    for input in inputs.into_inputs() {\n        let result = match input {\n",
        );
    } else {
        code.push_str("    Ok(vec![\n");
    }
    for domain in manifest.domains() {
        let module = module_name(*domain)?;
        if is_runtime {
            let provider_argument =
                if assembly_schema::has_domain_local_provider_activation(*domain) {
                    "&providers, "
                } else {
                    ""
                };
            code.push_str(&format!(
                "            LocalDomainModuleInput::{domain_variant}(input) => crate::domains::{module}::module(deps, {provider_argument}input)\n                .await\n                .context(\"wire domain '{module}'\"),\n",
                domain_variant = domain_variant(*domain),
            ));
        } else if typed_domain_inputs {
            code.push_str(&format!(
                "        crate::domains::{module}::module(deps, {module})\n            .await\n            .context(\"wire domain '{module}'\")?,\n"
            ));
        } else {
            code.push_str(&format!(
                "        crate::domains::{module}::module(deps)\n            .await\n            .context(\"wire domain '{module}'\")?,\n"
            ));
        }
    }
    if is_runtime {
        code.push_str("        };\n        match result {\n            Ok(binding) => bindings.push(binding),\n            Err(source) => return Err(DomainWiringFailure { source, bindings }),\n        }\n    }\n    Ok(bindings)\n");
    } else {
        code.push_str("    ])\n");
    }
    code.push_str(
        "}\n\npub const DOMAIN_LISTENER_BINDINGS: &[bootstrap::DomainListenerBinding] = &[\n",
    );
    for listener in manifest.listeners() {
        for domain in &listener.domains {
            code.push_str(&format!(
                "    bootstrap::DomainListenerBinding {{ domain: \"{}\", listener: bootstrap::ListenerKind::{} }},\n",
                domain.as_str(),
                listener_variant(listener.kind)
            ));
        }
    }
    code.push_str(
        "];

#[cfg(test)]
",
    );
    if is_runtime {
        code.push_str("pub(crate) async fn wire_test_domains(execution: &crate::plan::DomainExecutionPlan) -> anyhow::Result<Vec<DomainBinding>> {\n");
    } else {
        code.push_str(
            "pub(crate) async fn wire_test_domains() -> anyhow::Result<Vec<DomainBinding>> {\n",
        );
    }
    render_test_domain_wiring(manifest, &mut code)?;
    code.push_str("}\n\n");
    if manifest.name() == "runtime" || !framework_routes.is_empty() {
        code.push_str("pub const FRAMEWORK_HTTP_ROUTES: &[bootstrap::FrameworkHttpRoute] = &[\n");
        for (route, listener) in framework_routes {
            code.push_str(&format!(
                "    bootstrap::FrameworkHttpRoute::new(bootstrap::ListenerKind::{}, {route}),\n",
                listener_variant(*listener),
            ));
        }
        code.push_str("];\n\n");
        code.push_str(
            "pub fn register_framework_routes(routes: &impl bootstrap::FrameworkRoutes, registry: &mut bootstrap::Registry) -> Result<(), bootstrap::KernelError> {\n",
        );
        if framework_routes.is_empty() {
            code.push_str("    let _ = (routes, registry);\n    Ok(())\n}\n");
        } else {
            code.push_str("    bootstrap::FrameworkRoutes::register(routes, registry)\n}\n");
        }
    }
    crate::codegen::format_rust(&code)
}

fn render_test_domain_wiring(
    manifest: &CanonicalAssemblyManifestV2,
    code: &mut String,
) -> Result<()> {
    let is_runtime = manifest.name() == "runtime";
    if is_runtime {
        code.push_str("    let mut bindings = Vec::new();\n");
    } else {
        code.push_str("    Ok(vec![\n");
    }
    for domain in manifest.domains() {
        let module = module_name(*domain)?;
        if is_runtime {
            code.push_str(&format!(
                "    if execution.contains(assembly_schema::AssemblyDomain::{variant}) {{\n        bindings.push(\n            crate::domains::{module}::tests::test_binding(crate::domains::{module}::tests::test_input()?)\n                .await\n                .context(\"wire test domain '{module}'\")?,\n        );\n    }}\n",
                variant = domain_variant(*domain),
            ));
        } else {
            code.push_str(&format!(
                "        crate::domains::{module}::tests::test_binding()\n            .await\n            .context(\"wire test domain '{module}'\")?,\n"
            ));
        }
    }
    if is_runtime {
        code.push_str("    Ok(bindings)\n");
    } else {
        code.push_str("    ])\n");
    }
    Ok(())
}

fn framework_http_routes(
    manifest: &CanonicalAssemblyManifestV2,
    contracts: &[GovernedContract],
) -> Result<Vec<(String, AssemblyListenerKind)>> {
    use crate::contract::manifest::{ContractKind, Lifecycle};

    let by_id = contracts
        .iter()
        .map(|contract| (contract.manifest().id.as_str(), contract))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut routes = Vec::new();
    for mount in manifest.framework_contracts() {
        let contract_id = &mount.id;
        let contract = by_id
            .get(contract_id.as_str())
            .with_context(|| format!("unknown framework contract `{contract_id}`"))?;
        if contract.manifest().lifecycle != Lifecycle::Active
            || !contract.owner().is_framework_owned()
        {
            bail!("framework contract `{contract_id}` must be active and framework-owned")
        }
        if contract.manifest().kind == ContractKind::Http {
            routes.push((
                crate::codegen::rendered_http_route_evidence_path(contract)?,
                mount.listener,
            ));
        }
    }
    Ok(routes)
}

fn listener_variant(kind: AssemblyListenerKind) -> &'static str {
    match kind {
        AssemblyListenerKind::Primary => "Primary",
        AssemblyListenerKind::Internal => "Internal",
        AssemblyListenerKind::Admin => "Admin",
        AssemblyListenerKind::Health => "Health",
    }
}

pub(crate) fn domain_variant(domain: AssemblyDomain) -> &'static str {
    match domain {
        AssemblyDomain::Identity => "Identity",
        AssemblyDomain::Settings => "Settings",
        AssemblyDomain::Audit => "Audit",
        AssemblyDomain::Contractreg => "Contractreg",
        AssemblyDomain::Syshealth => "Syshealth",
    }
}

fn provider_activation_expression(activation: assembly_schema::ProviderActivation) -> String {
    match activation {
        assembly_schema::ProviderActivation::Process => "ProviderActivation::Process".to_owned(),
        assembly_schema::ProviderActivation::LocalEventExecution => {
            "ProviderActivation::LocalEventExecution".to_owned()
        }
        assembly_schema::ProviderActivation::DomainLocal(domain) => format!(
            "ProviderActivation::DomainLocal(AssemblyDomain::{})",
            domain_variant(domain)
        ),
    }
}

fn channel_variant(channel: LifecycleChannel) -> &'static str {
    match channel {
        LifecycleChannel::Probes => "Probes",
        LifecycleChannel::Resources => "Resources",
        LifecycleChannel::Workers => "Workers",
    }
}

fn module_name(domain: AssemblyDomain) -> Result<&'static str> {
    match domain {
        AssemblyDomain::Identity => Ok("identity"),
        AssemblyDomain::Settings => Ok("settings"),
        AssemblyDomain::Audit => Ok("audit"),
        AssemblyDomain::Contractreg => {
            bail!("domain `contractreg` 尚无 runtime::domains::contractreg::module factory")
        }
        AssemblyDomain::Syshealth => {
            bail!("domain `syshealth` 尚无 runtime::domains::syshealth::module factory")
        }
    }
}

fn relative_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE_PROVIDER: &str = r#"{ id = "listener-rate-limiter", port = "diport::RateLimiter", provider = "redis::RedisRateLimiter", providerCrate = "redis", requiredFeatures = ["backend"], consumer = "httpserve", lifecycle = "active", durability = "persistent", scope = "cluster-global", failurePosture = "fail-open", purpose = "test", outputs = [] }"#;
    const PDP_PROVIDER: &str = r#"{ id = "listener-pdp", port = "diport::Pdp", provider = "oidc::OidcProvider", providerCrate = "oidc", requiredFeatures = ["backend"], consumer = "httpserve", lifecycle = "active", durability = "persistent", purpose = "authorization", outputs = ["probes", "resources"] }"#;

    fn validate_provider_catalog_for_manifest(
        source: &str,
        manifest: &CanonicalAssemblyManifestV2,
    ) -> Result<()> {
        let providers = active_providers(manifest);
        validate_provider_catalog_syntax(
            source,
            manifest.name(),
            &providers,
            matches!(manifest.name(), "settingsonly" | "identityaudit"),
        )
    }

    fn manifest(domains: &str) -> String {
        format!(
            r#"schemaVersion = 2
name = "runtime"
profile = "production"
domains = [{domains}]
topology = "durable-shared"
frameworkContracts = []
workflowActivations = []

diportProviders = [{RATE_PROVIDER}, {PDP_PROVIDER}]

[[listeners]]
kind = "primary"
domains = [{domains}]
"#
        )
    }

    fn test_root(prefix: &str) -> Result<PathBuf> {
        let root = crate::testutil::unique_tmp(prefix);
        let workspace = crate::workspace_root()?;
        for name in ["identityaudit", "runtime", "settingsonly"] {
            let target = root.join("assemblies").join(name);
            fs::create_dir_all(&target)?;
            let source = workspace.join("assemblies").join(name);
            fs::copy(source.join("Cargo.toml"), target.join("Cargo.toml"))?;
            if name != "runtime" {
                let domains = if name == "identityaudit" {
                    r#""identity", "audit""#
                } else {
                    r#""settings""#
                };
                fs::write(
                    target.join("assembly.toml"),
                    manifest(domains).replace("name = \"runtime\"", &format!("name = \"{name}\"")),
                )?;
            }
        }
        seed_contract_governance_workspace(&workspace, &root)?;
        Ok(root)
    }

    fn seed_contract_governance_workspace(workspace: &Path, root: &Path) -> Result<()> {
        copy_tree(&workspace.join("contracts"), &root.join("contracts"))?;
        let relay = root.join("assemblies/runtime/src/event_transport.rs");
        fs::create_dir_all(relay.parent().context("runtime relay parent")?)?;
        fs::copy(
            workspace.join("assemblies/runtime/src/event_transport.rs"),
            relay,
        )?;
        Ok(())
    }

    fn copy_tree(source: &Path, target: &Path) -> Result<()> {
        fs::create_dir_all(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let source_path = entry.path();
            let target_path = target.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_tree(&source_path, &target_path)?;
            } else {
                fs::copy(source_path, target_path)?;
            }
        }
        Ok(())
    }

    fn write_manifest(root: &Path, domains: &str) -> Result<()> {
        fs::write(
            root.join("assemblies/runtime/assembly.toml"),
            manifest(domains),
        )?;
        Ok(())
    }

    fn output(root: &Path) -> PathBuf {
        root.join("assemblies/runtime/src/generated/modules_gen.rs")
    }

    fn assert_runtime_uses_typed_domain_inputs(rendered: &str, domains: &[&str]) {
        assert!(rendered.contains("inputs: PreparedLocalDomainInputs"));
        assert!(rendered.contains("pub(crate) struct PreparedLocalDomainInputs"));
        assert!(rendered.contains("pub(crate) enum LocalDomainModuleInput"));
        assert!(rendered.contains("providers: crate::LocalDomainProviderCatalog"));
        assert!(rendered.contains("for input in inputs.into_inputs()"));
        for domain in domains {
            let variant = match *domain {
                "settings" => "Settings",
                "identity" => "Identity",
                "audit" => "Audit",
                other => panic!("unsupported runtime fixture domain {other}"),
            };
            assert!(rendered.contains(&format!("LocalDomainModuleInput::{variant}(input)")));
            let call = if *domain == "audit" {
                format!("domains::{domain}::module(deps, input)")
            } else {
                format!("domains::{domain}::module(deps, &providers, input)")
            };
            assert!(rendered.contains(&call));
        }
    }

    fn assert_non_runtime_preserves_shared_deps_signature(rendered: &str, domains: &[&str]) {
        assert!(rendered.contains("pub async fn wire_domains(deps: &SharedRuntimeDeps)"));
        assert!(!rendered.contains("DomainModuleInputs"));
        for domain in domains {
            assert!(rendered.contains(&format!("domains::{domain}::module(deps)")));
            assert!(!rendered.contains(&format!("inputs.{domain}")));
            assert!(rendered.contains(&format!("domains::{domain}::tests::test_binding()")));
            assert!(!rendered.contains(&format!("domains::{domain}::tests::test_input()")));
        }
    }

    fn init_git_with_generated_file(root: &Path) -> Result<()> {
        let generated = output(root);
        fs::create_dir_all(
            generated
                .parent()
                .ok_or_else(|| anyhow::anyhow!("generated test path has no parent"))?,
        )?;
        fs::write(&generated, format!("{OWNERSHIP_MARKER}\n"))?;
        git_stdout(root, &["init", "--quiet"])?;
        git_stdout(
            root,
            &[
                "add",
                "--",
                "assemblies/runtime/src/generated/modules_gen.rs",
            ],
        )?;
        Ok(())
    }

    #[test]
    fn generated_lf_checkout_guard_rejects_missing_weakened_and_overridden_attributes() -> Result<()>
    {
        let root = test_root("assembly-generated-lf-red")?;
        init_git_with_generated_file(&root)?;

        assert!(verify_generated_lf_checkout(&root).is_err());
        fs::write(
            root.join(".gitattributes"),
            "assemblies/*/src/generated/** text=auto eol=lf\n",
        )?;
        assert!(verify_generated_lf_checkout(&root).is_err());
        fs::write(
            root.join(".gitattributes"),
            "assemblies/*/src/generated/** text eol=lf\nassemblies/runtime/src/generated/modules_gen.rs -text eol=crlf\n",
        )?;
        assert!(verify_generated_lf_checkout(&root).is_err());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn generated_lf_checkout_guard_accepts_canonical_repository() -> Result<()> {
        let root = test_root("assembly-generated-lf-green")?;
        init_git_with_generated_file(&root)?;
        fs::write(
            root.join(".gitattributes"),
            format!("{GENERATED_LF_ATTRIBUTE_RULE}\n"),
        )?;

        verify_generated_lf_checkout(&root)?;

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::cognitive_complexity)] // reason: one golden test intentionally checks the complete generated carrier shape.
    fn render_modules_golden_preserves_manifest_order() -> Result<()> {
        let source = manifest(r#""settings", "identity", "audit""#);
        let parsed = AssemblyManifest::from_toml_str(&source)?.canonicalize_v2()?;
        let rendered = render_modules(&parsed, &[], "assemblies/runtime/assembly.toml")?;
        assert!(rendered.starts_with(OWNERSHIP_MARKER));
        assert!(rendered.contains("// Source: assemblies/runtime/assembly.toml"));
        assert!(rendered.contains("// Source-Manifest-Digest: sha256:"));
        assert!(!rendered.contains("Source-SHA256"));
        assert!(rendered.contains(
            "pub async fn wire_domains(\n    deps: &SharedRuntimeDeps,\n    providers: crate::LocalDomainProviderCatalog,\n    inputs: PreparedLocalDomainInputs,\n)"
        ));
        assert!(
            rendered.contains("pub const ASSEMBLY_DOMAINS: &[assembly_schema::AssemblyDomain]")
        );
        assert!(rendered.contains("use crate::domains::DomainWiringFailure;"));
        assert!(!rendered.contains("pub struct DomainWiringFailure"));
        assert!(rendered.contains("Result<Vec<DomainBinding>, DomainWiringFailure>"));
        assert!(
            rendered
                .contains("Err(source) => return Err(DomainWiringFailure { source, bindings })")
        );
        assert!(rendered.contains("for input in inputs.into_inputs()"));
        assert!(!rendered.contains("placement.is_local"));
        assert!(!rendered.contains("let _ = identity"));
        assert!(!rendered.contains("let _ = settings"));
        assert!(!rendered.contains("let _ = audit"));
        assert_eq!(rendered.matches("::module(deps, ").count(), 3);
        assert!(rendered.contains("domains::settings::module(deps, &providers, input)"));
        assert!(rendered.contains("domains::identity::module(deps, &providers, input)"));
        assert!(rendered.contains("domains::audit::module(deps, input)"));
        assert_eq!(rendered.matches(".context(\"wire domain '").count(), 3);
        assert!(rendered.contains("pub(crate) async fn wire_test_domains"));
        assert!(rendered.contains("let mut bindings = Vec::new();"));
        // Production wiring has one closed-enum loop push; test wiring has one
        // generated push per manifest domain.
        assert_eq!(rendered.matches("bindings.push(").count(), 4);
        assert!(rendered.contains("Ok(bindings)"));
        assert!(rendered.contains("pub const DOMAIN_LISTENER_BINDINGS"));
        assert!(rendered.contains("bootstrap::ListenerKind::Primary"));
        assert!(!rendered.contains("PROVIDER_OUTPUT_BINDINGS"));
        let compact = rendered
            .chars()
            .filter(|character| !character.is_whitespace() && *character != ',')
            .collect::<String>();
        assert!(rendered.contains("domains::settings::tests::test_binding"));
        assert!(compact.contains(
            "crate::domains::settings::tests::test_binding(crate::domains::settings::tests::test_input()?)"
        ));
        assert!(compact.contains(
            "domains::identity::tests::test_binding(crate::domains::identity::tests::test_input()?)"
        ));
        assert!(compact.contains(
            "domains::audit::tests::test_binding(crate::domains::audit::tests::test_input()?)"
        ));
        assert_eq!(rendered.matches("::tests::test_binding()").count(), 0);
        let identity = rendered
            .find("domains::identity")
            .ok_or_else(|| anyhow::anyhow!("missing identity call"))?;
        let settings = rendered
            .find("domains::settings")
            .ok_or_else(|| anyhow::anyhow!("missing settings call"))?;
        let audit = rendered
            .find("domains::audit")
            .ok_or_else(|| anyhow::anyhow!("missing audit call"))?;
        assert!(settings < identity && identity < audit);
        let test_settings = rendered
            .find("domains::settings::tests::test_binding")
            .ok_or_else(|| anyhow::anyhow!("missing settings test call"))?;
        let test_identity = rendered
            .find("domains::identity::tests::test_binding")
            .ok_or_else(|| anyhow::anyhow!("missing identity test call"))?;
        let test_audit = rendered
            .find("domains::audit::tests::test_binding")
            .ok_or_else(|| anyhow::anyhow!("missing audit test call"))?;
        assert!(test_settings < test_identity && test_identity < test_audit);
        assert!(
            !rendered.contains("redis::RedisRateLimiter"),
            "provider catalog belongs exclusively to providers_gen.rs"
        );
        assert!(!rendered.contains("std::env"));
        syn::parse_file(&rendered)?;
        Ok(())
    }

    #[test]
    fn typed_non_runtime_manifest_moves_domain_inputs_by_value() -> Result<()> {
        let source = fs::read_to_string(
            crate::workspace_root()?.join("assemblies/deviceidentity/assembly.toml"),
        )?;
        let parsed = AssemblyManifest::from_toml_str(&source)?.canonicalize_v2()?;
        let rendered = render_modules(&parsed, &[], "assemblies/deviceidentity/assembly.toml")?;

        assert!(rendered.contains(
            "pub async fn wire_domains(\n    deps: &SharedRuntimeDeps,\n    inputs: crate::domains::DomainModuleInputs,\n)"
        ));
        assert!(rendered.contains("let crate::domains::DomainModuleInputs { identity } = inputs;"));
        assert!(rendered.contains("crate::domains::identity::module(deps, identity)"));
        assert!(!rendered.contains("PlacementExecutionPlan"));
        Ok(())
    }

    #[test]
    fn render_modules_ignores_toml_layout_and_set_order() -> Result<()> {
        let first_source = manifest(r#""identity""#);
        let equivalent_source = manifest(r#""identity""#)
            .replace(
                "schemaVersion = 2\nname = \"runtime\"\nprofile = \"demo\"\ndomains = [\"identity\"]\ntopology = \"durable-shared\"\nframeworkContracts = []\nworkflowActivations = []",
                "workflowActivations = []\nframeworkContracts = []\ntopology = \"durable-shared\"\ndomains = [\"identity\"]\nprofile = \"demo\"\nname = \"runtime\"\nschemaVersion = 2",
            )
            .replace(
                &format!("diportProviders = [{RATE_PROVIDER}, {PDP_PROVIDER}]"),
                &format!("diportProviders = [{PDP_PROVIDER}, {RATE_PROVIDER}]"),
            );
        let first = AssemblyManifest::from_toml_str(&first_source)?.canonicalize_v2()?;
        let equivalent = AssemblyManifest::from_toml_str(&equivalent_source)?.canonicalize_v2()?;

        assert_eq!(first.manifest_digest(), equivalent.manifest_digest());
        assert_eq!(
            render_modules(&first, &[], "assemblies/runtime/assembly.toml")?,
            render_modules(&equivalent, &[], "assemblies/runtime/assembly.toml")?
        );
        Ok(())
    }

    #[test]
    fn framework_routes_render_as_typed_expected_evidence_and_single_funnel() -> Result<()> {
        let source = manifest(r#""identity""#).replace(
            "frameworkContracts = []",
            "frameworkContracts = [{ id = \"framework.status\", listener = \"admin\" }]",
        ) + "\n[[listeners]]\nkind = \"admin\"\ndomains = []\n";
        let parsed = AssemblyManifest::from_toml_str(&source)?.canonicalize_v2()?;
        let rendered = render_modules(
            &parsed,
            &[(
                "::generated::http::framework_v1::status::ROUTE.evidence()".to_string(),
                AssemblyListenerKind::Admin,
            )],
            "assemblies/runtime/assembly.toml",
        )?;
        assert!(rendered.contains("pub const FRAMEWORK_HTTP_ROUTES"));
        assert!(rendered.contains("bootstrap::FrameworkHttpRoute::new("));
        assert!(rendered.contains("::generated::http::framework_v1::status::ROUTE.evidence()"));
        assert!(rendered.contains("bootstrap::FrameworkRoutes::register(routes, registry)"));
        assert!(!rendered.contains("contract_id =="));
        Ok(())
    }

    #[test]
    fn generated_runtime_modules_are_non_empty_and_check_clean() -> Result<()> {
        let root = test_root("assembly-modules-green")?;
        write_manifest(&root, r#""settings", "identity", "audit""#)?;
        generate_root(&root, false)?;
        generate_root(&root, true)?;
        let first = fs::read(output(&root))?;
        generate_root(&root, false)?;
        assert_eq!(fs::read(output(&root))?, first);
        assert!(
            first
                .windows(b"domains::settings".len())
                .any(|w| w == b"domains::settings")
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn multiple_assemblies_generate_independent_targets() -> Result<()> {
        let root = test_root("assembly-modules-multiple")?;
        write_manifest(&root, r#""identity", "audit""#)?;
        let settingsonly = root.join("assemblies/settingsonly");
        fs::create_dir_all(&settingsonly)?;
        fs::write(
            settingsonly.join("assembly.toml"),
            manifest(r#""settings""#).replace("name = \"runtime\"", "name = \"settingsonly\""),
        )?;
        let identityaudit = root.join("assemblies/identityaudit");
        fs::create_dir_all(&identityaudit)?;
        fs::write(
            identityaudit.join("assembly.toml"),
            manifest(r#""identity", "audit""#)
                .replace("name = \"runtime\"", "name = \"identityaudit\""),
        )?;

        generate_root(&root, false)?;
        generate_root(&root, true)?;

        let runtime = fs::read_to_string(output(&root))?;
        let settings = fs::read_to_string(settingsonly.join("src/generated/modules_gen.rs"))?;
        let identity_audit =
            fs::read_to_string(identityaudit.join("src/generated/modules_gen.rs"))?;
        assert!(runtime.contains("domains::identity"));
        assert!(runtime.contains("domains::audit"));
        assert!(!runtime.contains("domains::settings"));
        assert_runtime_uses_typed_domain_inputs(&runtime, &["identity", "audit"]);
        assert!(settings.contains("domains::settings"));
        assert!(!settings.contains("domains::identity"));
        assert!(!settings.contains("domains::audit"));
        assert_non_runtime_preserves_shared_deps_signature(&settings, &["settings"]);
        let identity = identity_audit
            .find("domains::identity")
            .ok_or_else(|| anyhow::anyhow!("identityaudit missing identity"))?;
        let audit = identity_audit
            .find("domains::audit")
            .ok_or_else(|| anyhow::anyhow!("identityaudit missing audit"))?;
        assert!(identity < audit);
        assert!(!identity_audit.contains("domains::settings"));
        assert_non_runtime_preserves_shared_deps_signature(&identity_audit, &["identity", "audit"]);

        fs::write(
            settingsonly.join("assembly.toml"),
            manifest(r#""settings", "audit""#)
                .replace("name = \"runtime\"", "name = \"settingsonly\""),
        )?;
        assert!(generate_root(&root, true).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn check_rejects_manifest_domain_drift() -> Result<()> {
        let root = test_root("assembly-modules-red")?;
        write_manifest(&root, r#""identity", "settings", "audit""#)?;
        generate_root(&root, false)?;
        write_manifest(&root, r#""settings", "identity", "audit""#)?;
        assert!(generate_root(&root, true).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn single_target_check_ignores_unrelated_assembly_drift() -> Result<()> {
        let root = test_root("assembly-modules-target-isolation")?;
        write_manifest(&root, r#""identity""#)?;
        let other = root.join("assemblies/settingsonly");
        fs::create_dir_all(&other)?;
        fs::write(
            other.join("assembly.toml"),
            manifest(r#""settings""#).replace("name = \"runtime\"", "name = \"settingsonly\""),
        )?;
        generate_root(&root, false)?;
        fs::write(
            other.join("assembly.toml"),
            manifest(r#""settings", "audit""#)
                .replace("name = \"runtime\"", "name = \"settingsonly\""),
        )?;
        check_target(&root, "runtime")?;
        assert!(check_target(&root, "settingsonly").is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn duplicate_and_unsupported_domains_fail_before_output() -> Result<()> {
        let root = test_root("assembly-modules-invalid")?;
        write_manifest(&root, r#""identity", "identity""#)?;
        let duplicate_error = generate_root(&root, false)
            .err()
            .ok_or_else(|| anyhow::anyhow!("duplicate domains unexpectedly accepted"))?;
        let duplicate_message = format!("{duplicate_error:#}");
        assert!(duplicate_message.contains("field=domains"));
        assert!(duplicate_message.contains("duplicate"));
        assert!(!output(&root).exists());
        write_manifest(&root, r#""contractreg""#)?;
        assert!(generate_root(&root, false).is_err());
        assert!(!output(&root).exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn source_path_control_characters_are_rejected_before_render() -> Result<()> {
        let root = crate::testutil::unique_tmp("assembly-modules-source-path");
        let injected = root.join("assemblies/evil\ncompile_error!(\"injected\");");
        fs::create_dir_all(&injected)?;
        fs::write(injected.join("assembly.toml"), manifest(r#""identity""#))?;
        let error = generate_root(&root, false)
            .err()
            .ok_or_else(|| anyhow::anyhow!("control-character path unexpectedly accepted"))?;
        assert!(!format!("{error:#}").is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn check_rejects_missing_and_tampered_output_without_repairing() -> Result<()> {
        let root = test_root("assembly-modules-tamper")?;
        write_manifest(&root, r#""identity""#)?;
        assert!(generate_root(&root, true).is_err());
        generate_root(&root, false)?;
        let tampered = format!("{OWNERSHIP_MARKER}\n// tampered\n");
        fs::write(output(&root), &tampered)?;
        assert!(generate_root(&root, true).is_err());
        assert_eq!(fs::read_to_string(output(&root))?, tampered);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn owned_orphan_check_fails_and_write_cleans() -> Result<()> {
        let root = test_root("assembly-modules-orphan")?;
        write_manifest(&root, r#""identity""#)?;
        let orphan = root.join("assemblies/old/src/generated/modules_gen.rs");
        let orphan_parent = orphan
            .parent()
            .ok_or_else(|| anyhow::anyhow!("orphan path has no parent"))?;
        fs::create_dir_all(orphan_parent)?;
        fs::write(&orphan, format!("{OWNERSHIP_MARKER}\n"))?;
        assert!(generate_root(&root, true).is_err());
        assert!(orphan.exists());
        generate_root(&root, false)?;
        assert!(!orphan.exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn non_owned_target_is_never_overwritten_or_deleted() -> Result<()> {
        let root = test_root("assembly-modules-non-owned")?;
        write_manifest(&root, r#""identity""#)?;
        let target = output(&root);
        let target_parent = target
            .parent()
            .ok_or_else(|| anyhow::anyhow!("output path has no parent"))?;
        fs::create_dir_all(target_parent)?;
        fs::write(&target, "// handwritten\n")?;
        assert!(generate_root(&root, false).is_err());
        assert_eq!(fs::read_to_string(target)?, "// handwritten\n");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_assembly_is_rejected() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = crate::testutil::unique_tmp("assembly-modules-symlink");
        fs::create_dir_all(root.join("assemblies"))?;
        let outside = crate::testutil::unique_tmp("assembly-modules-symlink-target");
        fs::create_dir_all(&outside)?;
        symlink(&outside, root.join("assemblies/runtime"))?;
        assert!(generate_root(&root, false).is_err());
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_manifest_is_rejected() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = test_root("assembly-modules-manifest-symlink")?;
        let outside = crate::testutil::unique_tmp("assembly-modules-manifest-target");
        fs::write(&outside, manifest(r#""identity""#))?;
        symlink(&outside, root.join("assemblies/runtime/assembly.toml"))?;
        assert!(generate_root(&root, false).is_err());
        assert!(!output(&root).exists());
        fs::remove_dir_all(root)?;
        fs::remove_file(outside)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_output_parent_is_rejected() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = test_root("assembly-modules-output-symlink")?;
        write_manifest(&root, r#""identity""#)?;
        let outside = crate::testutil::unique_tmp("assembly-modules-output-target");
        fs::create_dir_all(&outside)?;
        fs::remove_dir_all(root.join("assemblies/runtime/src"))?;
        symlink(&outside, root.join("assemblies/runtime/src"))?;
        assert!(generate_root(&root, false).is_err());
        assert!(!outside.join("generated/modules_gen.rs").exists());
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }

    fn provider_fixture_root(name: &str) -> Result<PathBuf> {
        let root = crate::testutil::unique_tmp(&format!("assembly-provider-codegen-{name}"));
        let workspace = crate::workspace_root()?;
        for assembly in ["identityaudit", "runtime", "settingsonly"] {
            let assembly_dir = root.join("assemblies").join(assembly);
            fs::create_dir_all(&assembly_dir)?;
            fs::copy(
                workspace
                    .join("assemblies")
                    .join(assembly)
                    .join("Cargo.toml"),
                assembly_dir.join("Cargo.toml"),
            )?;
            if assembly == "runtime" {
                let source = fs::read_to_string(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("fixtures/assembly-provider-codegen")
                        .join(name)
                        .join("assembly.toml"),
                )?
                .replace("profile = \"demo\"", "profile = \"production\"")
                .replace(
                    "purpose = \"SECRET_BAIT must never enter generated Rust\"\noutputs = [\"resources\"]",
                    "purpose = \"SECRET_BAIT must never enter generated Rust\"\noutputs = [\"probes\", \"resources\", \"workers\"]",
                );
                fs::write(assembly_dir.join("assembly.toml"), source)?;
            } else {
                fs::copy(
                    workspace
                        .join("assemblies")
                        .join(assembly)
                        .join("assembly.toml"),
                    assembly_dir.join("assembly.toml"),
                )?;
            }
            write_provider_catalog_link(&assembly_dir)?;
        }
        seed_contract_governance_workspace(&workspace, &root)?;
        Ok(root)
    }

    fn write_provider_catalog_link(assembly_dir: &Path) -> Result<()> {
        fs::create_dir_all(assembly_dir.join("src"))?;
        fs::write(
            assembly_dir.join("src/lib.rs"),
            r#"#[path = "generated/providers_gen.rs"]
mod providers_gen;
const _: () = assert!(!providers_gen::PROVIDER_CATALOG.is_empty());
"#,
        )?;
        Ok(())
    }

    fn provider_output(root: &Path) -> PathBuf {
        root.join("assemblies/runtime/src/generated/providers_gen.rs")
    }

    #[test]
    fn assembly_provider_codegen_generated_provider_catalogs_are_non_empty_and_check_clean()
    -> Result<()> {
        let root = provider_fixture_root("green")?;
        generate_providers_root(&root, false)?;
        generate_providers_root(&root, true)?;
        let rendered = fs::read_to_string(provider_output(&root))?;

        assert!(rendered.starts_with(GENERATED_PROVIDER_OWNERSHIP_MARKER));
        assert!(rendered.contains("ProviderCatalogEntry::checked("));
        assert!(rendered.contains("ProviderRole::ListenerRateLimiter"));
        assert!(rendered.contains("ProviderFactorySymbol::HttpserveRedisRateLimiter"));
        assert!(rendered.contains("ProviderConsumer::Eventexec"));
        assert!(rendered.contains("ProviderConsumer::Settings"));
        assert!(rendered.contains("pub(crate) const ASSEMBLY_NAMESPACE: &str = \"runtime\";"));
        assert!(rendered.contains("ProviderDurability::Persistent"));
        assert!(rendered.contains("Some(assembly_schema::ProviderScope::ClusterGlobal)"));
        assert!(rendered.contains("Some(assembly_schema::ProviderFailurePosture::FailOpen)"));
        assert!(rendered.contains("&[]"));
        assert!(!rendered.contains("SECRET_BAIT"));
        for banned in [
            "std::env",
            "Secret",
            "Config",
            "Any",
            "TypeId",
            "HashMap",
            "BTreeMap",
            "callback",
            "service_locator",
        ] {
            assert!(
                !rendered.contains(banned),
                "generated provider catalog contains banned token `{banned}`"
            );
        }
        let source = fs::read_to_string(root.join("assemblies/runtime/assembly.toml"))?;
        let manifest = AssemblyManifest::from_toml_str(&source)?.canonicalize_v2()?;
        validate_provider_catalog_for_manifest(&rendered, &manifest)?;
        let dlx = rendered
            .find("ProviderRole::DlxArchiveKeyProvider")
            .context("missing DLX archive key provider")?;
        let dlx_hot = rendered
            .find("ProviderRole::DlxHotKeyProvider")
            .context("missing DLX hot key provider")?;
        let limiter = rendered
            .find("ProviderRole::ListenerRateLimiter")
            .context("missing listener rate limiter")?;
        let settings = rendered
            .find("ProviderRole::SettingsKeyProvider")
            .context("missing settings key provider")?;
        assert!(dlx < dlx_hot && dlx_hot < limiter && limiter < settings);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn settingsonly_provider_codegen_emits_sealed_role_batches() -> Result<()> {
        let root = crate::workspace_root()?;
        let source = fs::read_to_string(root.join("assemblies/settingsonly/assembly.toml"))?;
        let manifest = AssemblyManifest::from_toml_str(&source)?.canonicalize_v2()?;
        let rendered = render_providers(&manifest, "assemblies/settingsonly/assembly.toml")?;

        for required in [
            "pub(crate) struct ProviderRoleBatches",
            "pub(crate) struct ListenerPdpConstructor",
            "pub(crate) struct ListenerPdpBatch",
            "pub(crate) struct ListenerPdpReceipt",
            "pub(crate) struct DlxHotKeyProviderConstructor",
            "pub(crate) struct DlxHotKeyProviderBatch",
            "pub(crate) struct DlxHotKeyProviderReceipt",
            "pub(crate) fn exact_join(",
            "pub(crate) fn finish(",
        ] {
            assert!(
                rendered.contains(required),
                "settingsonly generated provider output omitted `{required}`"
            );
        }
        assert!(rendered.contains("ProviderRole::ListenerPdp"));
        assert!(rendered.contains("ProviderRole::DlxArchiveKeyProvider"));
        assert!(rendered.contains("ProviderRole::DlxHotKeyProvider"));
        assert!(rendered.contains("generated provider role 'dlx-hot-key-provider' is missing"));
        assert!(rendered.contains("generated provider role '{}' is duplicated"));
        assert!(rendered.contains("ProviderRole::ListenerRateLimiter"));
        assert!(rendered.contains("ProviderRole::SettingsKeyProvider"));
        assert!(rendered.contains("ProviderRole::SettingsSecretResolver"));
        let compact_rendered = rendered.split_whitespace().collect::<String>();
        let listener_shape = provider_finish_shape(ProviderRole::ListenerPdp);
        let rate_limiter_shape = provider_finish_shape(ProviderRole::ListenerRateLimiter);
        let default_shape = provider_finish_shape(ProviderRole::SettingsKeyProvider);
        assert_eq!(listener_shape, LISTENER_PDP_FINISH_SHAPE);
        assert_eq!(rate_limiter_shape, LISTENER_RATE_LIMITER_FINISH_SHAPE);
        assert_eq!(default_shape, DEFAULT_PROVIDER_FINISH_SHAPE);
        let typed_listener_pdp = format!("output:{}", listener_shape.input_type);
        let listener_materializer = listener_shape
            .materializer
            .expect("ListenerPdp finish shape must declare into_output");
        assert!(
            compact_rendered.contains(&typed_listener_pdp)
                && compact_rendered
                    .contains(&format!("letoutput=output.{listener_materializer}();")),
            "listener-pdp constructor must consume the sealed JWKS lifecycle receipt via closed shape"
        );
        assert!(compact_rendered.contains("output:redis::RedisRateLimiterCapability"));
        assert!(compact_rendered.contains("letvalue=output.into_limiter();"));
        assert!(
            compact_rendered.contains(
                "implDlxHotKeyProviderConstructor{pub(crate)fnfinish(self,output:bootstrap::DomainModuleResult,"
            ),
            "ordinary roles must finish on DomainModuleResult from closed shape"
        );
        assert!(
            !compact_rendered.contains(
                "implDlxHotKeyProviderConstructor{pub(crate)fnfinish(self,output:ListenerPdpJwksLifecycle,"
            ),
            "ordinary roles must not inherit ListenerPdp finish input"
        );
        let mut ordinary_role_with_listener_shape = rendered.clone();
        let start = ordinary_role_with_listener_shape
            .find("impl DlxHotKeyProviderConstructor")
            .expect("DLX hot constructor impl");
        let relative = ordinary_role_with_listener_shape[start..]
            .find("output: bootstrap::DomainModuleResult")
            .expect("DLX hot output type");
        let output_start = start + relative;
        ordinary_role_with_listener_shape.replace_range(
            output_start..output_start + "output: bootstrap::DomainModuleResult".len(),
            "output: ListenerPdpJwksLifecycle",
        );
        assert!(
            validate_provider_catalog_for_manifest(&ordinary_role_with_listener_shape, &manifest)
                .is_err(),
            "synthetic red: ordinary role inherited the listener-PDP lifecycle shape"
        );
        let mut untyped_listener_pdp = rendered.clone();
        untyped_listener_pdp = untyped_listener_pdp.replacen(
            &format!("output: {}", listener_shape.input_type),
            &format!("output: {}", default_shape.input_type),
            1,
        );
        assert!(
            validate_provider_catalog_for_manifest(&untyped_listener_pdp, &manifest).is_err(),
            "synthetic red: untyped listener-pdp lifecycle output was accepted"
        );
        let mut dematerialized = rendered.clone();
        dematerialized = dematerialized.replacen(
            &format!("let output = output.{listener_materializer}();\n"),
            "",
            1,
        );
        assert!(
            validate_provider_catalog_for_manifest(&dematerialized, &manifest).is_err(),
            "synthetic red: ListenerPdp finish without materializer was accepted"
        );
        let mut aliased_materializer = rendered.clone();
        aliased_materializer = aliased_materializer.replacen(
            &format!("let output = output.{listener_materializer}();"),
            "let output = output.into_module();",
            1,
        );
        assert!(
            validate_provider_catalog_for_manifest(&aliased_materializer, &manifest).is_err(),
            "synthetic red: ListenerPdp finish materializer alias was accepted"
        );
        for channel in ["probes", "resources", "workers"] {
            let exact = format!("inventory.{channel}.len()==staged");
            assert!(
                compact_rendered.contains(&exact),
                "anti-vacuity: generated finish omitted exact {channel} residual guard"
            );
            let marker = format!("inventory.{channel}.len()");
            let start = rendered
                .find(&marker)
                .context("missing residual channel marker")?;
            let operator = rendered[start..]
                .find("==")
                .map(|offset| start + offset)
                .context("missing exact residual operator")?;
            let mut weakened = rendered.clone();
            weakened.replace_range(operator..operator + 2, ">=");
            assert!(
                validate_provider_catalog_for_manifest(&weakened, &manifest).is_err(),
                "synthetic red: weakened {channel} residual guard was accepted"
            );
        }
        Ok(())
    }

    #[test]
    fn listener_pdp_lifecycle_carrier_is_one_generated_shape_for_every_consumer() -> Result<()> {
        let root = crate::workspace_root()?;
        for assembly in ["runtime", "identityaudit", "settingsonly"] {
            let source =
                fs::read_to_string(root.join("assemblies").join(assembly).join("assembly.toml"))?;
            let manifest = AssemblyManifest::from_toml_str(&source)?.canonicalize_v2()?;
            let rendered =
                render_providers(&manifest, &format!("assemblies/{assembly}/assembly.toml"))?;
            let compact = rendered.split_whitespace().collect::<String>();

            for required in [
                "structListenerPdpJwksEntry{probe:(primitives::ProbeName,Box<dynbootstrap::HealthProbe>),resource:Box<diport::DynManagedResource<'static>>,}",
                "pub(crate)structListenerPdpJwksLifecycle{head:ListenerPdpJwksEntry,tail:Vec<ListenerPdpJwksEntry>,}",
                "pub(crate)fnsingle(",
                "pub(crate)fnmerge(mutself,other:Self)->Self",
                "pub(crate)fninto_output(self)->bootstrap::DomainModuleResult",
            ] {
                assert!(
                    compact.contains(required),
                    "{assembly} generated carrier omitted canonical shape `{required}`"
                );
            }
            for forbidden in [
                "derive(Clone",
                "derive(Copy",
                "derive(Default",
                "synthetic_for_test",
                "crate::providers::ListenerPdpJwksLifecycle",
            ] {
                assert!(
                    !rendered.contains(forbidden),
                    "{assembly} generated carrier retained forbidden escape `{forbidden}`"
                );
            }
            validate_provider_catalog_for_manifest(&rendered, &manifest)?;
            for (name, mutated) in [
                (
                    "public field",
                    rendered.replacen(
                        "    head: ListenerPdpJwksEntry,",
                        "    pub(crate) head: ListenerPdpJwksEntry,",
                        1,
                    ),
                ),
                (
                    "Default derivation",
                    rendered.replacen("#[must_use =", "#[derive(Default)]\n#[must_use =", 1),
                ),
                (
                    "Clone/Copy derivation",
                    rendered.replacen("#[must_use =", "#[derive(Clone, Copy)]\n#[must_use =", 1),
                ),
                (
                    "empty Vec carrier",
                    rendered.replacen(
                        "    head: ListenerPdpJwksEntry,\n    tail: Vec<ListenerPdpJwksEntry>,",
                        "    entries: Vec<ListenerPdpJwksEntry>,",
                        1,
                    ),
                ),
                (
                    "raw module constructor",
                    rendered.replacen(
                        "        probe: (primitives::ProbeName, Box<dyn bootstrap::HealthProbe>),",
                        "        output: bootstrap::DomainModuleResult,",
                        1,
                    ),
                ),
                (
                    "surplus worker materialization",
                    rendered.replacen(
                        "            workers: Vec::new(),",
                        "            workers: output.workers,",
                        1,
                    ),
                ),
            ] {
                assert!(
                    validate_provider_catalog_for_manifest(&mutated, &manifest).is_err(),
                    "synthetic red: {assembly} accepted {name} in canonical carrier"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn provider_finish_shape_is_closed_over_all_typed_roles() {
        for role in [
            ProviderRole::DeviceCertificateStore,
            ProviderRole::DeviceCommandStore,
            ProviderRole::DeviceDraftArtifactSource,
            ProviderRole::DeviceMqttSession,
            ProviderRole::DeviceRevocationStore,
            ProviderRole::EventPublisher,
            ProviderRole::EventSubscriber,
            ProviderRole::IdentitySigner,
            ProviderRole::SettingsKeyProvider,
            ProviderRole::SettingsSecretResolver,
            ProviderRole::ListenerPdp,
            ProviderRole::ServiceTokenReplayStore,
            ProviderRole::AuthAuditSink,
            ProviderRole::ListenerRateLimiter,
            ProviderRole::DistributedLockStore,
            ProviderRole::DistributedCasStore,
            ProviderRole::DistributedCasStoreAlternative,
            ProviderRole::RuntimeObjectStore,
            ProviderRole::DlxLifecycleRepository,
            ProviderRole::DlxArchiveStore,
            ProviderRole::DlxArchiveKeyProvider,
            ProviderRole::DlxHotKeyProvider,
        ] {
            let shape = provider_finish_shape(role);
            if role == ProviderRole::ListenerPdp {
                assert_eq!(shape, LISTENER_PDP_FINISH_SHAPE);
                assert_eq!(shape.input_type, "ListenerPdpJwksLifecycle");
                assert_eq!(shape.materializer, Some("into_output"));
            } else if role == ProviderRole::ListenerRateLimiter {
                assert_eq!(shape, LISTENER_RATE_LIMITER_FINISH_SHAPE);
                assert_eq!(shape.input_type, "redis::RedisRateLimiterCapability");
                assert_eq!(
                    shape.bound_value,
                    Some(("redis::RedisRateLimiter", "into_limiter"))
                );
            } else {
                assert_eq!(shape, DEFAULT_PROVIDER_FINISH_SHAPE);
                assert_eq!(shape.materializer, None);
                assert_eq!(shape.bound_value, None);
            }
        }
    }

    #[test]
    fn identityaudit_provider_role_renderer_names_only_diagnostics() -> Result<()> {
        let root = crate::workspace_root()?;
        let source = fs::read_to_string(root.join("assemblies/identityaudit/assembly.toml"))?;
        let manifest = AssemblyManifest::from_toml_str(&source)?.canonicalize_v2()?;
        let mut providers = manifest
            .diport_providers()
            .iter()
            .filter(|provider| provider.lifecycle == ProviderLifecycle::Active)
            .collect::<Vec<_>>();
        providers.sort_by_key(|provider| provider.id.as_str());
        let mut rendered =
            "const PROVIDER_DATA: &str = \"settingsonly-must-remain-data\";\n".to_owned();

        render_provider_role_batches(&mut rendered, manifest.name(), &providers)?;

        assert!(rendered.contains("settingsonly-must-remain-data"));
        assert!(
            rendered.contains("identityaudit RuntimePlan/generated provider catalog count drift")
        );
        assert!(!rendered.contains("__ASSEMBLY__"));
        Ok(())
    }

    #[test]
    fn assembly_provider_codegen_optional_metadata_uses_qualified_paths_for_every_matrix()
    -> Result<()> {
        let root = provider_fixture_root("green")?;
        let source = fs::read_to_string(root.join("assemblies/runtime/assembly.toml"))?;
        let manifest = AssemblyManifest::from_toml_str(&source)?.canonicalize_v2()?;
        let rendered = render_providers(&manifest, "assemblies/runtime/assembly.toml")?;

        assert!(rendered.contains("Some(assembly_schema::ProviderScope::ClusterGlobal)"));
        assert!(rendered.contains("Some(assembly_schema::ProviderFailurePosture::FailClosed)"));
        assert!(!rendered.contains("ProviderFailurePosture,"));
        assert!(!rendered.contains("ProviderScope,"));
        let scope_only = rendered.replace(
            "Some(assembly_schema::ProviderFailurePosture::FailClosed)",
            "None",
        );
        let posture_only = rendered.replace(
            "Some(assembly_schema::ProviderScope::ClusterGlobal)",
            "None",
        );
        let all_none = scope_only.replace(
            "Some(assembly_schema::ProviderScope::ClusterGlobal)",
            "None",
        );
        validate_provider_catalog_for_manifest(&scope_only, &manifest)?;
        validate_provider_catalog_for_manifest(&posture_only, &manifest)?;
        validate_provider_catalog_for_manifest(&all_none, &manifest)?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn assembly_provider_codegen_rejects_closed_registry_mismatches_before_output() -> Result<()> {
        for name in [
            "missing-factory",
            "wrong-output",
            "unknown-consumer",
            "wrong-port",
            "wrong-crate",
            "wrong-features",
            "wrong-durability",
            "unknown-constructor",
            "unknown-output",
        ] {
            let root = provider_fixture_root(name)?;
            assert!(
                generate_providers_root(&root, false).is_err(),
                "fixture `{name}` unexpectedly generated"
            );
            assert!(
                !provider_output(&root).exists(),
                "fixture `{name}` wrote partial output"
            );
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DuplicateFactoryFixture {
        providers: Vec<DuplicateFactoryEntry>,
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DuplicateFactoryEntry {
        role: ProviderRole,
        factory: ProviderFactorySymbol,
    }

    #[test]
    fn assembly_provider_codegen_duplicate_factory_fixture_fails_checked_entry() -> Result<()> {
        let root = provider_fixture_root("duplicate-factory")?;
        let source = fs::read_to_string(root.join("assemblies/runtime/assembly.toml"))?;
        let manifest = AssemblyManifest::from_toml_str(&source)?.canonicalize_v2()?;
        let fixture: DuplicateFactoryFixture = toml::from_str(&fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/assembly-provider-codegen/duplicate-factory/registry.toml"),
        )?)?;

        let unique_factories = fixture
            .providers
            .iter()
            .map(|entry| entry.factory)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(fixture.providers.len(), 2);
        assert_eq!(unique_factories.len(), 1);

        let mut accepted = Vec::new();
        for entry in fixture.providers {
            let provider = manifest
                .diport_providers()
                .iter()
                .find(|provider| provider.id == entry.role)
                .with_context(|| format!("missing fixture role `{}`", entry.role.as_str()))?;
            let provider_crate: &'static str =
                Box::leak(provider.provider_crate.clone().into_boxed_str());
            let required_features: &'static [&'static str] = Box::leak(
                provider
                    .required_features
                    .iter()
                    .map(|feature| {
                        let value: &'static mut str = Box::leak(feature.clone().into_boxed_str());
                        &*value
                    })
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            );
            let outputs: &'static [LifecycleChannel] =
                Box::leak(provider.outputs.clone().into_boxed_slice());
            accepted.push(std::panic::catch_unwind(|| {
                assembly_schema::ProviderCatalogEntry::checked(
                    provider.id,
                    provider.id.activation(),
                    provider.port,
                    provider.provider,
                    entry.factory,
                    provider_crate,
                    required_features,
                    provider.consumer,
                    provider.durability,
                    provider.scope,
                    provider.failure_posture,
                    outputs,
                )
            }));
        }
        assert!(accepted[0].is_ok());
        assert!(accepted[1].is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn assembly_provider_codegen_plans_every_assembly_before_any_write() -> Result<()> {
        let root = provider_fixture_root("green")?;
        let invalid_dir = root.join("assemblies/settingsonly");
        fs::create_dir_all(&invalid_dir)?;
        let invalid_source = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/assembly-provider-codegen/wrong-output/assembly.toml"),
        )?
        .replace("name = \"runtime\"", "name = \"settingsonly\"");
        fs::write(invalid_dir.join("assembly.toml"), invalid_source)?;
        write_provider_catalog_link(&invalid_dir)?;

        assert!(generate_providers_root(&root, false).is_err());
        assert!(!provider_output(&root).exists());
        assert!(!invalid_dir.join("src/generated/providers_gen.rs").exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn assembly_provider_codegen_is_deterministic_for_manifest_set_reorder() -> Result<()> {
        let root = provider_fixture_root("green")?;
        let source = fs::read_to_string(root.join("assemblies/runtime/assembly.toml"))?;
        let mut manifest = AssemblyManifest::from_toml_str(&source)?;
        let canonical = manifest.clone().canonicalize_v2()?;
        let first = render_providers(&canonical, "assemblies/runtime/assembly.toml")?;
        manifest.diport_providers.reverse();
        for provider in &mut manifest.diport_providers {
            provider.required_features.reverse();
            provider.outputs.reverse();
        }
        let reordered = manifest.canonicalize_v2()?;
        assert_eq!(
            first,
            render_providers(&reordered, "assemblies/runtime/assembly.toml")?
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn assembly_provider_codegen_rejects_unlinked_or_comment_bait_catalogs() -> Result<()> {
        let root = provider_fixture_root("green")?;
        let lib = root.join("assemblies/runtime/src/lib.rs");
        fs::write(
            &lib,
            "// #[path = \"generated/providers_gen.rs\"] mod providers_gen;\n\
             // const _: () = assert!(!providers_gen::PROVIDER_CATALOG.is_empty());\n",
        )?;
        assert!(generate_providers_root(&root, false).is_err());

        fs::write(
            &lib,
            "#[path = \"generated/providers_gen.rs\"]\nmod providers_gen;\n",
        )?;
        assert!(generate_providers_root(&root, false).is_err());

        fs::write(
            &lib,
            "#[cfg(any())]\n#[path = \"generated/providers_gen.rs\"]\nmod providers_gen;\n\
             #[cfg(any())]\n\
             const _: () = assert!(!providers_gen::PROVIDER_CATALOG.is_empty());\n",
        )?;
        assert!(generate_providers_root(&root, false).is_err());
        assert!(!provider_output(&root).exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn assembly_provider_codegen_rejects_crate_level_conditional_compile_link() -> Result<()> {
        for (name, attribute) in [
            ("crate-cfg", "#![cfg(any())]"),
            ("crate-cfg-attr", "#![cfg_attr(all(), cfg(any()))]"),
            (
                "nested-crate-cfg-attr",
                "#![cfg_attr(all(), cfg_attr(all(), cfg(any())))]",
            ),
        ] {
            let root = provider_fixture_root("green")?;
            let lib = root.join("assemblies/runtime/src/lib.rs");
            let source = fs::read_to_string(&lib)?;
            fs::write(&lib, format!("{attribute}\n{source}"))?;

            assert!(
                generate_providers_root(&root, false).is_err(),
                "synthetic-red `{name}` unexpectedly generated"
            );
            assert!(
                !provider_output(&root).exists(),
                "synthetic-red `{name}` wrote partial output"
            );
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn assembly_provider_codegen_allows_non_conditional_crate_attributes() -> Result<()> {
        let root = provider_fixture_root("green")?;
        let lib = root.join("assemblies/runtime/src/lib.rs");
        let source = fs::read_to_string(&lib)?;
        fs::write(
            &lib,
            format!("#![cfg_attr(all(), allow(dead_code))]\n{source}"),
        )?;

        generate_providers_root(&root, false)?;
        assert!(provider_output(&root).exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn assembly_provider_codegen_closed_ast_rejects_dynamic_or_extra_items() -> Result<()> {
        let root = provider_fixture_root("green")?;
        let source = fs::read_to_string(root.join("assemblies/runtime/assembly.toml"))?;
        let manifest = AssemblyManifest::from_toml_str(&source)?.canonicalize_v2()?;
        let rendered = render_providers(&manifest, "assemblies/runtime/assembly.toml")?;

        let extra_const =
            format!("{rendered}\nconst SECRET: Option<&str> = option_env!(\"RSS_PASSWORD\");\n");
        assert!(validate_provider_catalog_for_manifest(&extra_const, &manifest).is_err());
        assert!(
            validate_provider_catalog_for_manifest(
                &rendered.replacen(
                    "\"vault\"",
                    "option_env!(\"RSS_PROVIDER\").unwrap_or(\"vault\")",
                    1
                ),
                &manifest,
            )
            .is_err()
        );
        assert!(
            validate_provider_catalog_for_manifest(
                &rendered.replacen("ProviderCatalogEntry::checked", "build_provider", 1),
                &manifest,
            )
            .is_err()
        );
        assert!(
            validate_provider_catalog_for_manifest(
                &rendered.replacen("None", "Some(scope_from_env())", 1),
                &manifest,
            )
            .is_err()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn assembly_provider_codegen_check_detects_tamper_missing_and_owned_orphan() -> Result<()> {
        let root = provider_fixture_root("green")?;
        assert!(generate_providers_root(&root, true).is_err());
        generate_providers_root(&root, false)?;
        let target = provider_output(&root);
        fs::write(
            &target,
            format!("{GENERATED_PROVIDER_OWNERSHIP_MARKER}\n// tampered\n"),
        )?;
        assert!(generate_providers_root(&root, true).is_err());
        generate_providers_root(&root, false)?;
        let source = fs::read_to_string(root.join("assemblies/runtime/assembly.toml"))?;
        let manifest = AssemblyManifest::from_toml_str(&source)?.canonicalize_v2()?;
        validate_provider_catalog_for_manifest(&fs::read_to_string(&target)?, &manifest)?;
        generate_providers_root(&root, true)?;

        fs::remove_file(&target)?;
        assert!(generate_providers_root(&root, true).is_err());
        generate_providers_root(&root, false)?;
        fs::remove_file(root.join("assemblies/runtime/assembly.toml"))?;
        assert!(generate_providers_root(&root, true).is_err());
        assert!(target.exists());
        // Global generation cannot reinterpret a missing production identity as an orphan.
        // Both modes fail at the same ratchet and leave the prior output untouched.
        assert!(generate_providers_root(&root, false).is_err());
        assert!(target.exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn assembly_provider_codegen_markers_are_isolated() -> Result<()> {
        let root = provider_fixture_root("green")?;
        let target = provider_output(&root);
        fs::create_dir_all(
            target
                .parent()
                .context("provider output must have generated parent")?,
        )?;
        fs::write(&target, format!("{GENERATED_MODULE_OWNERSHIP_MARKER}\n"))?;
        assert!(generate_providers_root(&root, false).is_err());
        assert_eq!(
            fs::read_to_string(&target)?,
            format!("{GENERATED_MODULE_OWNERSHIP_MARKER}\n")
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn assembly_provider_codegen_rejects_symlink_output_path() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = provider_fixture_root("green")?;
        let outside = crate::testutil::unique_tmp("assembly-provider-codegen-symlink-target");
        fs::create_dir_all(&outside)?;
        fs::remove_dir_all(root.join("assemblies/runtime/src"))?;
        symlink(&outside, root.join("assemblies/runtime/src"))?;
        assert!(generate_providers_root(&root, false).is_err());
        assert!(!outside.join("generated/providers_gen.rs").exists());
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn assembly_provider_codegen_rejects_symlink_ancestry_and_abnormal_orphans() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = provider_fixture_root("green")?;
        let outside = crate::testutil::unique_tmp("assembly-provider-codegen-assemblies-target");
        fs::rename(root.join("assemblies"), &outside)?;
        symlink(&outside, root.join("assemblies"))?;
        assert!(generate_providers_root(&root, false).is_err());
        fs::remove_file(root.join("assemblies"))?;
        fs::rename(&outside, root.join("assemblies"))?;

        generate_providers_root(&root, false)?;
        let target = provider_output(&root);
        fs::remove_file(&target)?;
        symlink("missing-provider-catalog", &target)?;
        assert!(generate_providers_root(&root, false).is_err());
        fs::remove_file(&target)?;

        fs::write(
            root.join("assemblies/runtime/src/generated/foreign.rs"),
            format!("{GENERATED_PROVIDER_OWNERSHIP_MARKER}\n"),
        )?;
        assert!(generate_providers_root(&root, true).is_err());
        generate_providers_root(&root, false)?;
        assert!(
            !root
                .join("assemblies/runtime/src/generated/foreign.rs")
                .exists()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn assembly_transaction_restores_prior_outputs_after_late_failure() -> Result<()> {
        let root = crate::testutil::unique_tmp("assembly-transaction-rollback");
        fs::create_dir_all(&root)?;
        let first = root.join("first.rs");
        let second = root.join("second.rs");
        fs::write(&first, b"old-first\n")?;
        fs::write(&second, b"old-second\n")?;
        let plan = GenerationPlan {
            targets: vec![
                Target {
                    path: first.clone(),
                    content: b"new-first\n".to_vec(),
                    actual: Some(b"old-first\n".to_vec()),
                },
                Target {
                    path: second.clone(),
                    content: b"new-second\n".to_vec(),
                    actual: Some(b"old-second\n".to_vec()),
                },
            ],
            owned_orphans: Vec::new(),
        };
        let mut transaction = AssemblyGenerationTransaction::new(&root, plan)?;

        let error = transaction
            .apply_with_hook(&root, |index, _| {
                if index == 1 {
                    bail!("synthetic final output failure")
                }
                Ok(())
            })
            .expect_err("late failure must abort the batch");
        assert!(error.to_string().contains("synthetic final output failure"));
        transaction.rollback()?;
        assert_eq!(fs::read(&first)?, b"old-first\n");
        assert_eq!(fs::read(&second)?, b"old-second\n");
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
