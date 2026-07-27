//! Assembly manifest committed codegen for modules and typed provider catalogs.
//!
//! INVARIANT: ASSEMBLY-MODULES-CODEGEN-01 { level = "Hard", exec = "verify", source = "codegen", golden = "assemblies/runtime/src/generated/modules_gen.rs", synthetic_red = "assembly_codegen::tests::check_rejects_manifest_domain_drift", anti_vacuity = "assembly_codegen::tests::generated_runtime_modules_are_non_empty_and_check_clean" } —— `assembly.toml` 是 domain 组合顺序单源；生成物 committed 并由 verify 字节级守漂移，red/green 测试证明门不恒真。
//! INVARIANT: ASSEMBLY-PROVIDERS-CODEGEN-01 { level = "Hard", exec = "verify", source = "codegen", golden = "assemblies/runtime/src/generated/providers_gen.rs", synthetic_red = "assembly_codegen::tests::assembly_provider_codegen_rejects_closed_registry_mismatches_before_output", anti_vacuity = "assembly_codegen::tests::assembly_provider_codegen_generated_provider_catalogs_are_non_empty_and_check_clean" } —— active provider catalog is role-sorted typed `checked` evidence; the independent drift gate rejects invalid manifests, missing/tampered/orphan outputs, marker crossover, symlinks, and dynamic construction syntax.
//! INVARIANT: ASSEMBLY-GENERATED-LF-CHECKOUT-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "assembly_codegen::tests::generated_lf_checkout_guard_rejects_missing_weakened_and_overridden_attributes", anti_vacuity = "assembly_codegen::tests::generated_lf_checkout_guard_accepts_canonical_repository" } —— generator-owned tracked paths 的 Git 最终有效属性必须精确为 `text=set,eol=lf`，避免 raw-byte digest 随 checkout 平台漂移。

use anyhow::{Context, Result, bail, ensure};
use assembly_schema::{
    AssemblyDomain, AssemblyListenerKind, AssemblyManifest, CanonicalAssemblyManifestV1,
    DiportPort, GENERATED_MODULE_OWNERSHIP_MARKER, GENERATED_PROVIDER_OWNERSHIP_MARKER,
    LifecycleChannel, ProviderConstructor, ProviderConsumer, ProviderDurability,
    ProviderFactorySymbol, ProviderFailurePosture, ProviderLifecycle, ProviderRole, ProviderScope,
};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const MANIFEST_NAME: &str = "assembly.toml";
const GENERATED_PATHSPEC: &str = "assemblies/*/src/generated/**";
const GENERATED_LF_ATTRIBUTE_RULE: &str = "assemblies/*/src/generated/** text eol=lf";
const OWNERSHIP_MARKER: &str = GENERATED_MODULE_OWNERSHIP_MARKER;

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
    let plan = plan_generation(root, kind)?;
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

    for target in &plan.targets {
        if target.actual.as_deref() != Some(target.content.as_slice()) {
            ensure_output_path_has_no_symlinks(&target.path)?;
            crate::generated_file::atomic_replace(&target.path, &target.content)
                .with_context(|| format!("原子写入 {} 失败", target.path.display()))?;
            eprintln!("  generated {}", relative_label(root, &target.path));
        }
    }
    for orphan in &plan.owned_orphans {
        ensure_output_path_has_no_symlinks(orphan)?;
        fs::remove_file(orphan).with_context(|| format!("删除孤儿 {} 失败", orphan.display()))?;
        eprintln!("  removed orphan {}", relative_label(root, orphan));
    }
    Ok(())
}

pub(crate) fn check_target(root: &Path, assembly_name: &str) -> Result<()> {
    let assembly_dir = root.join("assemblies").join(assembly_name);
    let target = plan_target(root, &assembly_dir, ArtifactKind::Modules)?
        .with_context(|| format!("assembly `{assembly_name}` 缺 {MANIFEST_NAME}"))?;
    if target.actual.as_deref() != Some(target.content.as_slice()) {
        bail!("assembly `{assembly_name}` modules carrier 漂移");
    }
    Ok(())
}

fn plan_generation(root: &Path, kind: ArtifactKind) -> Result<GenerationPlan> {
    let assemblies_root = root.join("assemblies");
    reject_symlink(root)?;
    reject_symlink(&assemblies_root)?;
    let mut entries = fs::read_dir(&assemblies_root)
        .with_context(|| format!("读取 {} 失败", assemblies_root.display()))?
        .collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(fs::DirEntry::path);

    let mut targets = Vec::new();
    let mut owned_files = Vec::new();
    for entry in entries {
        let file_type = entry
            .file_type()
            .with_context(|| format!("读取 {} 类型失败", entry.path().display()))?;
        if file_type.is_symlink() {
            bail!("assemblies 下禁止符号链接：{}", entry.path().display());
        }
        if !file_type.is_dir() {
            continue;
        }

        let assembly_dir = entry.path();
        owned_files.extend(discover_owned_files(&assembly_dir, kind)?);
        let Some(target) = plan_target(root, &assembly_dir, kind)? else {
            continue;
        };
        targets.push(target);
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

fn plan_target(root: &Path, assembly_dir: &Path, kind: ArtifactKind) -> Result<Option<Target>> {
    let manifest_path = assembly_dir.join(MANIFEST_NAME);
    let output_path = assembly_dir.join(kind.generated_rel());
    reject_symlink(&manifest_path)?;
    ensure_output_path_has_no_symlinks(&output_path)?;
    if !manifest_path.is_file() {
        return Ok(None);
    }
    if kind == ArtifactKind::Providers {
        ensure_provider_catalog_linked(assembly_dir)?;
    }
    let source = fs::read(&manifest_path)
        .with_context(|| format!("读取 {} 失败", manifest_path.display()))?;
    let source_text = std::str::from_utf8(&source)
        .with_context(|| format!("{} 不是 UTF-8", manifest_path.display()))?;
    let parsed = AssemblyManifest::from_toml_str(source_text)
        .with_context(|| format!("解析 {} 失败", manifest_path.display()))?;
    let source_label = relative_label(root, &manifest_path);
    ensure_safe_source_label(&source_label)?;
    let manifest = parsed
        .canonicalize_v1()
        .with_context(|| format!("编译 {source_label} canonical v1 失败"))?;
    let content = match kind {
        ArtifactKind::Modules => {
            let framework_routes = framework_http_routes(root, &manifest)?;
            render_modules(&manifest, &framework_routes, &source_label)?
        }
        ArtifactKind::Providers => render_providers(&manifest, &source_label)?,
    };
    let actual = read_owned_target(&output_path, kind)?;
    Ok(Some(Target {
        path: output_path,
        content: content.into_bytes(),
        actual,
    }))
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

fn render_providers(manifest: &CanonicalAssemblyManifestV1, source_label: &str) -> Result<String> {
    let mut providers = manifest
        .diport_providers()
        .iter()
        .filter(|provider| provider.lifecycle == ProviderLifecycle::Active)
        .collect::<Vec<_>>();
    providers.sort_by_key(|provider| provider.id.as_str());

    let mut code = format!(
        "{GENERATED_PROVIDER_OWNERSHIP_MARKER}\n// Source: {source_label}\n// Source-Manifest-Digest: {}\n\nuse assembly_schema::{{\n    DiportPort, LifecycleChannel, ProviderCatalogEntry, ProviderConstructor, ProviderConsumer,\n    ProviderDurability, ProviderFactorySymbol, ProviderRole,\n}};\n\npub(crate) const PROVIDER_CATALOG: &[ProviderCatalogEntry] = &[\n",
        manifest.manifest_digest()
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
    if matches!(manifest.name(), "settingsonly" | "identityaudit") {
        render_provider_role_batches(&mut code, manifest.name(), &providers)?;
    }
    let formatted = crate::codegen::format_rust(&code)?;
    validate_provider_catalog_syntax(&formatted)?;
    Ok(formatted)
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
            "        let {receipt} {{ probes, resources, workers, probe_names }} = {field};\n        staged[0] += probes;\n        staged[1] += resources;\n        staged[2] += workers;\n        probe_bindings.push(runtimeexec::inventory::ProviderProbeBinding::new(\"{}\", probe_names)?);\n",
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
                 anyhow::ensure!(inventory.probes.len() >= staged[0] && inventory.resources.len() >= staged[1] && inventory.workers.len() >= staged[2], \"__ASSEMBLY__ transaction omits transferred provider lifecycle output\");\n\
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
        code.push_str(&format!(
            "\npub(crate) struct {constructor} {{\n    entry: &'static ProviderCatalogEntry,\n}}\n\
             pub(crate) struct {batch}(bootstrap::DomainModuleResult);\n\
             pub(crate) struct {receipt} {{\n    probes: usize,\n    resources: usize,\n    workers: usize,\n    probe_names: Vec<primitives::ProbeName>,\n}}\n\
             impl {constructor} {{\n\
                 pub(crate) fn finish(self, output: bootstrap::DomainModuleResult) -> anyhow::Result<{batch}> {{\n\
                     validate_lifecycle_output(self.entry, &output)?;\n\
                     Ok({batch}(output))\n\
                 }}\n\
             }}\n\
             impl {batch} {{\n\
                 pub(crate) fn transfer(self, inventory: &mut bootstrap::DomainModuleResult) -> {receipt} {{\n\
                     let probe_names = self.0.probes.iter().map(|(name, _)| name.clone()).collect();\n\
                     let receipt = {receipt} {{ probes: self.0.probes.len(), resources: self.0.resources.len(), workers: self.0.workers.len(), probe_names }};\n\
                     inventory.merge(self.0);\n\
                     receipt\n\
                 }}\n\
             }}\n"
        ));
    }
    Ok(())
}

fn validate_provider_catalog_syntax(source: &str) -> Result<()> {
    let syntax = syn::parse_file(source).context("解析 provider catalog Rust AST 失败")?;
    let Some((syn::Item::Use(import), remaining)) = syntax.items.split_first() else {
        bail!("provider catalog 缺少固定 import");
    };
    let Some((syn::Item::Const(catalog), role_batch_items)) = remaining.split_first() else {
        bail!("provider catalog 缺少唯一 const catalog");
    };
    let import_tokens = compact_tokens(&import.tree);
    ensure!(
        import_tokens
            == "assembly_schema::{DiportPort,LifecycleChannel,ProviderCatalogEntry,ProviderConstructor,ProviderConsumer,ProviderDurability,ProviderFactorySymbol,ProviderRole,}",
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
    if role_batch_items.is_empty() {
        return Ok(());
    }
    validate_provider_role_batch_syntax(role_batch_items, &roles)
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

fn validate_provider_role_batch_syntax(items: &[syn::Item], roles: &[String]) -> Result<()> {
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
    for role in roles {
        expected_structs.extend([
            format!("{role}Constructor"),
            format!("{role}Batch"),
            format!("{role}Receipt"),
        ]);
        expected_impls.extend([
            (format!("{role}Constructor"), vec!["finish".to_owned()]),
            (format!("{role}Batch"), vec!["transfer".to_owned()]),
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
    for item in items {
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
        call.args.len() == 11,
        "ProviderCatalogEntry::checked 参数数量必须为 11"
    );
    let args = call.args.iter().collect::<Vec<_>>();
    ensure_enum_variant(args[0], "ProviderRole")?;
    ensure_enum_variant(args[1], "DiportPort")?;
    ensure_enum_variant(args[2], "ProviderConstructor")?;
    ensure_enum_variant(args[3], "ProviderFactorySymbol")?;
    ensure!(
        matches!(
            args[4],
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(_),
                ..
            })
        ),
        "provider crate 必须是字符串字面量"
    );
    ensure_string_slice(args[5])?;
    ensure_enum_variant(args[6], "ProviderConsumer")?;
    ensure_enum_variant(args[7], "ProviderDurability")?;
    ensure_optional_enum_variant(args[8], "ProviderScope")?;
    ensure_optional_enum_variant(args[9], "ProviderFailurePosture")?;
    ensure_enum_slice(args[10], "LifecycleChannel")?;
    Ok(())
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
    }
}

const fn port_variant(port: DiportPort) -> &'static str {
    match port {
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
        ProviderConstructor::PostgresRevocationStore => "PostgresRevocationStore",
        ProviderConstructor::RatelimitGovernorLimiter => "RatelimitGovernorLimiter",
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
        ProviderFactorySymbol::HttpserveGovernorRateLimiter => "HttpserveGovernorRateLimiter",
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

fn render_modules(
    manifest: &CanonicalAssemblyManifestV1,
    framework_routes: &[(String, AssemblyListenerKind)],
    source_label: &str,
) -> Result<String> {
    let manifest_digest = manifest.manifest_digest();
    let is_runtime = manifest.name() == "runtime";
    let wire_domains_signature = if is_runtime {
        "pub async fn wire_domains(\n    deps: &SharedRuntimeDeps,\n    inputs: crate::domains::DomainModuleInputs,\n    placement: &crate::plan::PlacementExecutionPlan,\n) -> Result<Vec<DomainBinding>, DomainWiringFailure>"
    } else {
        "pub async fn wire_domains(deps: &SharedRuntimeDeps) -> anyhow::Result<Vec<DomainBinding>>"
    };
    let mut code = format!(
        "{OWNERSHIP_MARKER}\n// Source: {source_label}\n// Source-Manifest-Digest: {manifest_digest}\n\nuse anyhow::Context as _;\nuse bootstrap::DomainBinding;\n\nuse crate::SharedRuntimeDeps;\n\n"
    );
    if is_runtime {
        code.push_str("use crate::domains::DomainWiringFailure;\n\n");
    }
    code.push_str(&format!("{wire_domains_signature} {{\n"));
    if is_runtime {
        code.push_str("    let crate::domains::DomainModuleInputs {\n");
        for domain in manifest.domains() {
            let module = module_name(*domain)?;
            code.push_str(&format!("        {module},\n"));
        }
        code.push_str("    } = inputs;\n");
    }
    if is_runtime {
        code.push_str("    let mut bindings = Vec::new();\n");
    } else {
        code.push_str("    Ok(vec![\n");
    }
    for domain in manifest.domains() {
        let module = module_name(*domain)?;
        if is_runtime {
            code.push_str(&format!(
                "    if placement.is_local(assembly_schema::AssemblyDomain::{domain_variant}) {{\n        match crate::domains::{module}::module(deps, {module})\n            .await\n            .context(\"wire domain '{module}'\")\n        {{\n            Ok(binding) => bindings.push(binding),\n            Err(source) => return Err(DomainWiringFailure {{ source, bindings }}),\n        }}\n    }} else {{\n        let _ = {module};\n    }}\n",
                domain_variant = domain_variant(*domain),
            ));
        } else {
            code.push_str(&format!(
                "        crate::domains::{module}::module(deps)\n            .await\n            .context(\"wire domain '{module}'\")?,\n"
            ));
        }
    }
    if is_runtime {
        code.push_str("    Ok(bindings)\n");
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
pub(crate) async fn wire_test_domains() -> anyhow::Result<Vec<DomainBinding>> {\n",
    );
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
    manifest: &CanonicalAssemblyManifestV1,
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
                "    bindings.push(\n        crate::domains::{module}::tests::test_binding(crate::domains::{module}::tests::test_input()?)\n            .await\n            .context(\"wire test domain '{module}'\")?,\n    );\n"
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
    root: &Path,
    manifest: &CanonicalAssemblyManifestV1,
) -> Result<Vec<(String, AssemblyListenerKind)>> {
    use crate::contract::manifest::{ContractKind, ContractOwner, Lifecycle};

    let contracts = crate::contract::discover(&root.join("contracts"))?;
    let by_id = contracts
        .iter()
        .map(|contract| (contract.manifest.id.as_str(), contract))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut routes = Vec::new();
    for mount in manifest.framework_contracts() {
        let contract_id = &mount.id;
        let contract = by_id
            .get(contract_id.as_str())
            .with_context(|| format!("unknown framework contract `{contract_id}`"))?;
        if contract.manifest.lifecycle != Lifecycle::Active
            || contract.manifest.owner != ContractOwner::Framework
        {
            bail!("framework contract `{contract_id}` must be active and framework-owned")
        }
        if contract.manifest.kind == ContractKind::Http {
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

    const RATE_PROVIDER: &str = r#"{ id = "listener-rate-limiter", port = "diport::RateLimiter", provider = "ratelimit::GovernorLimiter", providerCrate = "ratelimit", consumer = "httpserve", lifecycle = "active", durability = "ephemeral-memory", purpose = "test", outputs = [] }"#;
    const PDP_PROVIDER: &str = r#"{ id = "listener-pdp", port = "diport::Pdp", provider = "oidc::OidcProvider", providerCrate = "oidc", requiredFeatures = ["backend"], consumer = "httpserve", lifecycle = "active", durability = "persistent", purpose = "authorization", outputs = ["resources"] }"#;

    fn manifest(domains: &str) -> String {
        format!(
            r#"name = "runtime"
profile = "demo"
domains = [{domains}]
topology = "durable-shared"
frameworkContracts = []

diportProviders = [{RATE_PROVIDER}, {PDP_PROVIDER}]

[[listeners]]
kind = "primary"
domains = [{domains}]
"#
        )
    }

    fn test_root(prefix: &str) -> Result<PathBuf> {
        let root = crate::testutil::unique_tmp(prefix);
        fs::create_dir_all(root.join("assemblies/runtime"))?;
        Ok(root)
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
        assert!(rendered.contains("inputs: crate::domains::DomainModuleInputs"));
        assert!(rendered.contains("let crate::domains::DomainModuleInputs {"));
        assert!(!rendered.contains("DomainModuleInputs { .. }"));
        for domain in domains {
            assert!(rendered.contains(&format!("domains::{domain}::module(deps, {domain})")));
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
        let parsed = AssemblyManifest::from_toml_str(&source)?.canonicalize_v1()?;
        let rendered = render_modules(&parsed, &[], "assemblies/runtime/assembly.toml")?;
        assert!(rendered.starts_with(OWNERSHIP_MARKER));
        assert!(rendered.contains("// Source: assemblies/runtime/assembly.toml"));
        assert!(rendered.contains("// Source-Manifest-Digest: sha256:"));
        assert!(!rendered.contains("Source-SHA256"));
        assert!(rendered.contains(
            "pub async fn wire_domains(\n    deps: &SharedRuntimeDeps,\n    inputs: crate::domains::DomainModuleInputs,\n    placement: &crate::plan::PlacementExecutionPlan,\n)"
        ));
        assert!(rendered.contains("use crate::domains::DomainWiringFailure;"));
        assert!(!rendered.contains("pub struct DomainWiringFailure"));
        assert!(rendered.contains("Result<Vec<DomainBinding>, DomainWiringFailure>"));
        assert!(
            rendered
                .contains("Err(source) => return Err(DomainWiringFailure { source, bindings })")
        );
        assert!(
            rendered.contains("if placement.is_local(assembly_schema::AssemblyDomain::Settings)")
        );
        assert!(
            rendered.contains("if placement.is_local(assembly_schema::AssemblyDomain::Identity)")
        );
        assert!(rendered.contains("if placement.is_local(assembly_schema::AssemblyDomain::Audit)"));
        assert!(rendered.contains(
            "let crate::domains::DomainModuleInputs {\n        settings,\n        identity,\n        audit,\n    } = inputs;"
        ));
        assert!(!rendered.contains("DomainModuleInputs { .. }"));
        assert_eq!(rendered.matches("::module(deps, ").count(), 3);
        assert!(rendered.contains("domains::settings::module(deps, settings)"));
        assert!(rendered.contains("domains::identity::module(deps, identity)"));
        assert!(rendered.contains("domains::audit::module(deps, audit)"));
        assert_eq!(rendered.matches(".context(\"wire domain '").count(), 3);
        assert!(rendered.contains("pub(crate) async fn wire_test_domains"));
        assert!(rendered.contains("let mut bindings = Vec::new();"));
        assert_eq!(rendered.matches("bindings.push(").count(), 6);
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
            !rendered.contains("ratelimit::GovernorLimiter"),
            "provider catalog belongs exclusively to providers_gen.rs"
        );
        assert!(!rendered.contains("std::env"));
        syn::parse_file(&rendered)?;
        Ok(())
    }

    #[test]
    fn render_modules_ignores_toml_layout_and_set_order() -> Result<()> {
        let first_source = manifest(r#""identity""#);
        let equivalent_source = manifest(r#""identity""#)
            .replace(
                "name = \"runtime\"\nprofile = \"demo\"\ndomains = [\"identity\"]\ntopology = \"durable-shared\"\nframeworkContracts = []",
                "frameworkContracts = []\ntopology = \"durable-shared\"\ndomains = [\"identity\"]\nprofile = \"demo\"\nname = \"runtime\"",
            )
            .replace(
                &format!("diportProviders = [{RATE_PROVIDER}, {PDP_PROVIDER}]"),
                &format!("diportProviders = [{PDP_PROVIDER}, {RATE_PROVIDER}]"),
            );
        let first = AssemblyManifest::from_toml_str(&first_source)?.canonicalize_v1()?;
        let equivalent = AssemblyManifest::from_toml_str(&equivalent_source)?.canonicalize_v1()?;

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
        let parsed = AssemblyManifest::from_toml_str(&source)?.canonicalize_v1()?;
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
        assert!(format!("{error:#}").contains("控制字符"));
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
        let root = crate::testutil::unique_tmp("assembly-modules-orphan");
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
        symlink(&outside, root.join("assemblies/runtime/src"))?;
        assert!(generate_root(&root, false).is_err());
        assert!(!outside.join("generated/modules_gen.rs").exists());
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }

    fn provider_fixture_root(name: &str) -> Result<PathBuf> {
        let root = crate::testutil::unique_tmp(&format!("assembly-provider-codegen-{name}"));
        let assembly_dir = root.join("assemblies/runtime");
        fs::create_dir_all(&assembly_dir)?;
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/assembly-provider-codegen")
                .join(name)
                .join("assembly.toml"),
            assembly_dir.join("assembly.toml"),
        )?;
        write_provider_catalog_link(&assembly_dir)?;
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
        assert!(rendered.contains("ProviderFactorySymbol::HttpserveGovernorRateLimiter"));
        assert!(rendered.contains("ProviderConsumer::Eventexec"));
        assert!(rendered.contains("ProviderConsumer::Settings"));
        assert!(rendered.contains("ProviderDurability::EphemeralMemory"));
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
            "fn ",
            "callback",
            "service_locator",
        ] {
            assert!(
                !rendered.contains(banned),
                "generated provider catalog contains banned token `{banned}`"
            );
        }
        validate_provider_catalog_syntax(&rendered)?;

        let dlx = rendered
            .find("ProviderRole::DlxArchiveKeyProvider")
            .context("missing DLX archive key provider")?;
        let limiter = rendered
            .find("ProviderRole::ListenerRateLimiter")
            .context("missing listener rate limiter")?;
        let settings = rendered
            .find("ProviderRole::SettingsKeyProvider")
            .context("missing settings key provider")?;
        assert!(dlx < limiter && limiter < settings);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn settingsonly_provider_codegen_emits_sealed_role_batches() -> Result<()> {
        let root = crate::workspace_root()?;
        let source = fs::read_to_string(root.join("assemblies/settingsonly/assembly.toml"))?;
        let manifest = AssemblyManifest::from_toml_str(&source)?.canonicalize_v1()?;
        let rendered = render_providers(&manifest, "assemblies/settingsonly/assembly.toml")?;

        for required in [
            "pub(crate) struct ProviderRoleBatches",
            "pub(crate) struct ListenerPdpConstructor",
            "pub(crate) struct ListenerPdpBatch",
            "pub(crate) struct ListenerPdpReceipt",
            "pub(crate) fn exact_join(",
            "pub(crate) fn finish(",
        ] {
            assert!(
                rendered.contains(required),
                "settingsonly generated provider output omitted `{required}`"
            );
        }
        assert!(rendered.contains("ProviderRole::ListenerPdp"));
        assert!(rendered.contains("ProviderRole::ListenerRateLimiter"));
        assert!(rendered.contains("ProviderRole::SettingsKeyProvider"));
        assert!(rendered.contains("ProviderRole::SettingsSecretResolver"));
        Ok(())
    }

    #[test]
    fn identityaudit_provider_role_renderer_names_only_diagnostics() -> Result<()> {
        let root = crate::workspace_root()?;
        let source = fs::read_to_string(root.join("assemblies/identityaudit/assembly.toml"))?;
        let manifest = AssemblyManifest::from_toml_str(&source)?.canonicalize_v1()?;
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
        let manifest = AssemblyManifest::from_toml_str(&source)?.canonicalize_v1()?;
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
        validate_provider_catalog_syntax(&scope_only)?;
        validate_provider_catalog_syntax(&posture_only)?;
        validate_provider_catalog_syntax(&all_none)?;
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
        let manifest = AssemblyManifest::from_toml_str(&source)?.canonicalize_v1()?;
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
        let canonical = manifest.clone().canonicalize_v1()?;
        let first = render_providers(&canonical, "assemblies/runtime/assembly.toml")?;
        manifest.diport_providers.reverse();
        for provider in &mut manifest.diport_providers {
            provider.required_features.reverse();
            provider.outputs.reverse();
        }
        let reordered = manifest.canonicalize_v1()?;
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
        let manifest = AssemblyManifest::from_toml_str(&source)?.canonicalize_v1()?;
        let rendered = render_providers(&manifest, "assemblies/runtime/assembly.toml")?;

        let extra_const =
            format!("{rendered}\nconst SECRET: Option<&str> = option_env!(\"RSS_PASSWORD\");\n");
        assert!(validate_provider_catalog_syntax(&extra_const).is_err());
        assert!(
            validate_provider_catalog_syntax(&rendered.replacen(
                "\"vault\"",
                "option_env!(\"RSS_PROVIDER\").unwrap_or(\"vault\")",
                1
            ))
            .is_err()
        );
        assert!(
            validate_provider_catalog_syntax(&rendered.replacen(
                "ProviderCatalogEntry::checked",
                "build_provider",
                1
            ))
            .is_err()
        );
        assert!(
            validate_provider_catalog_syntax(&rendered.replacen(
                "None",
                "Some(scope_from_env())",
                1
            ))
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
        validate_provider_catalog_syntax(&fs::read_to_string(&target)?)?;
        generate_providers_root(&root, true)?;

        fs::remove_file(&target)?;
        assert!(generate_providers_root(&root, true).is_err());
        generate_providers_root(&root, false)?;
        fs::remove_file(root.join("assemblies/runtime/assembly.toml"))?;
        assert!(generate_providers_root(&root, true).is_err());
        assert!(target.exists());
        generate_providers_root(&root, false)?;
        assert!(!target.exists());
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
        fs::remove_file(root.join("assemblies/runtime/assembly.toml"))?;
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
}
