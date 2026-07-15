//! `assembly generate-modules` — assembly manifest domain 顺序表 codegen。
//!
//! INVARIANT: ASSEMBLY-MODULES-CODEGEN-01 { level = "Hard", exec = "verify", source = "codegen", golden = "assemblies/runtime/src/generated/modules_gen.rs", synthetic_red = "assembly_codegen::tests::check_rejects_manifest_domain_drift", anti_vacuity = "assembly_codegen::tests::generated_runtime_modules_are_non_empty_and_check_clean" } —— `assembly.toml` 是 domain 组合顺序单源；生成物 committed 并由 verify 字节级守漂移，red/green 测试证明门不恒真。
//! INVARIANT: ASSEMBLY-GENERATED-LF-CHECKOUT-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "assembly_codegen::tests::generated_lf_checkout_guard_rejects_missing_weakened_and_overridden_attributes", anti_vacuity = "assembly_codegen::tests::generated_lf_checkout_guard_accepts_canonical_repository" } —— generator-owned tracked paths 的 Git 最终有效属性必须精确为 `text=set,eol=lf`，避免 raw-byte digest 随 checkout 平台漂移。

use anyhow::{Context, Result, bail, ensure};
use assembly_schema::{
    AssemblyDomain, AssemblyListenerKind, AssemblyManifest, CanonicalAssemblyManifestV1,
    GENERATED_MODULE_OWNERSHIP_MARKER, LifecycleChannel,
};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const MANIFEST_NAME: &str = "assembly.toml";
const GENERATED_REL: &str = "src/generated/modules_gen.rs";
const GENERATED_PATHSPEC: &str = "assemblies/*/src/generated/**";
const GENERATED_LF_ATTRIBUTE_RULE: &str = "assemblies/*/src/generated/** text eol=lf";
const OWNERSHIP_MARKER: &str = GENERATED_MODULE_OWNERSHIP_MARKER;

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

/// Run the complete modules gate, including effective LF policy and owned-orphan detection.
pub(crate) fn check_root(root: &Path) -> Result<()> {
    verify_generated_lf_checkout(root)?;
    generate_root(root, true)
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
    let plan = plan_generation(root)?;
    let drift: Vec<&Path> = plan
        .targets
        .iter()
        .filter(|target| target.actual.as_deref() != Some(target.content.as_slice()))
        .map(|target| target.path.as_path())
        .collect();

    if check {
        if drift.is_empty() && plan.owned_orphans.is_empty() {
            eprintln!("assembly generate-modules --check: 无漂移");
            return Ok(());
        }
        for path in &drift {
            eprintln!("  派生漂移: {}", relative_label(root, path));
        }
        for path in &plan.owned_orphans {
            eprintln!("  孤儿派生文件: {}", relative_label(root, path));
        }
        bail!(
            "assembly modules 派生漂移：{} 个目标不一致，{} 个孤儿；运行 `cargo xtask assembly generate-modules`",
            drift.len(),
            plan.owned_orphans.len()
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
    let target = plan_target(root, &assembly_dir)?
        .with_context(|| format!("assembly `{assembly_name}` 缺 {MANIFEST_NAME}"))?;
    if target.actual.as_deref() != Some(target.content.as_slice()) {
        bail!("assembly `{assembly_name}` modules carrier 漂移");
    }
    Ok(())
}

fn plan_generation(root: &Path) -> Result<GenerationPlan> {
    let assemblies_root = root.join("assemblies");
    let mut entries = fs::read_dir(&assemblies_root)
        .with_context(|| format!("读取 {} 失败", assemblies_root.display()))?
        .collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(fs::DirEntry::path);

    let mut targets = Vec::new();
    let mut orphan_candidates = Vec::new();
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
        let output_path = assembly_dir.join(GENERATED_REL);
        let Some(target) = plan_target(root, &assembly_dir)? else {
            if output_path.is_file() {
                orphan_candidates.push(output_path);
            }
            continue;
        };
        targets.push(target);
    }

    let mut owned_orphans = Vec::new();
    for path in orphan_candidates {
        let bytes = fs::read(&path).with_context(|| format!("读取 {} 失败", path.display()))?;
        ensure_owned(&path, &bytes)?;
        owned_orphans.push(path);
    }
    owned_orphans.sort();
    Ok(GenerationPlan {
        targets,
        owned_orphans,
    })
}

fn plan_target(root: &Path, assembly_dir: &Path) -> Result<Option<Target>> {
    let manifest_path = assembly_dir.join(MANIFEST_NAME);
    let output_path = assembly_dir.join(GENERATED_REL);
    reject_symlink(&manifest_path)?;
    ensure_output_path_has_no_symlinks(&output_path)?;
    if !manifest_path.is_file() {
        return Ok(None);
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
    let framework_routes = framework_http_routes(root, &manifest)?;
    let content = render_modules(&manifest, &framework_routes, &source_label)?;
    let actual = read_owned_target(&output_path)?;
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

fn read_owned_target(path: &Path) -> Result<Option<Vec<u8>>> {
    if !path.exists() {
        return Ok(None);
    }
    if !path.is_file() {
        bail!("生成目标不是普通文件：{}", path.display());
    }
    let bytes = fs::read(path).with_context(|| format!("读取 {} 失败", path.display()))?;
    ensure_owned(path, &bytes)?;
    Ok(Some(bytes))
}

fn ensure_owned(path: &Path, bytes: &[u8]) -> Result<()> {
    if !bytes.starts_with(OWNERSHIP_MARKER.as_bytes()) {
        bail!(
            "拒绝覆盖或删除非本生成器文件：{}（缺 ownership marker）",
            path.display()
        );
    }
    Ok(())
}

fn render_modules(
    manifest: &CanonicalAssemblyManifestV1,
    framework_routes: &[String],
    source_label: &str,
) -> Result<String> {
    let manifest_digest = manifest.manifest_digest();
    let mut code = format!(
        "{OWNERSHIP_MARKER}\n// Source: {source_label}\n// Source-Manifest-Digest: {manifest_digest}\n\nuse anyhow::Context as _;\nuse bootstrap::DomainBinding;\n\nuse crate::SharedRuntimeDeps;\n\npub async fn wire_domains(deps: &SharedRuntimeDeps) -> anyhow::Result<Vec<DomainBinding>> {{\n    Ok(vec![\n"
    );
    for domain in manifest.domains() {
        let module = module_name(*domain)?;
        code.push_str(&format!(
            "        crate::domains::{module}::module(deps)\n            .await\n            .context(\"wire domain '{module}'\")?,\n"
        ));
    }
    code.push_str("    ])\n}\n\npub const DOMAIN_LISTENER_BINDINGS: &[bootstrap::DomainListenerBinding] = &[\n");
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

pub const PROVIDER_OUTPUT_BINDINGS: &[bootstrap::ProviderOutputBinding] = &[\n",
    );
    for provider in manifest.diport_providers() {
        code.push_str(&format!(
            "    bootstrap::ProviderOutputBinding {{ port: \"{}\", provider: \"{}\", consumer: \"{}\", channels: &[",
            provider.port.as_str(), provider.provider, provider.consumer
        ));
        for channel in &provider.outputs {
            code.push_str(&format!(
                "bootstrap::LifecycleChannel::{}, ",
                channel_variant(*channel)
            ));
        }
        code.push_str("] },\n");
    }
    code.push_str(
        "];

#[cfg(test)]
pub(crate) async fn wire_test_domains() -> anyhow::Result<Vec<DomainBinding>> {
    Ok(vec![\n",
    );
    for domain in manifest.domains() {
        let module = module_name(*domain)?;
        code.push_str(&format!(
            "        crate::domains::{module}::tests::test_binding()\n            .await\n            .context(\"wire test domain '{module}'\")?,\n"
        ));
    }
    code.push_str("    ])\n}\n\n");
    if manifest.name() == "runtime" || !framework_routes.is_empty() {
        code.push_str("pub const FRAMEWORK_HTTP_ROUTES: &[bootstrap::FrameworkHttpRoute] = &[\n");
        for route in framework_routes {
            code.push_str(&format!(
                "    bootstrap::FrameworkHttpRoute::new({route}),\n"
            ));
        }
        code.push_str("];\n\n");
        code.push_str(
            "pub fn register_framework_routes(registry: &mut bootstrap::Registry) -> Result<(), bootstrap::KernelError> {\n",
        );
        if framework_routes.is_empty() {
            code.push_str("    let _ = registry;\n    Ok(())\n}\n");
        } else {
            code.push_str(
                "    bootstrap::FrameworkRoutes::register(&crate::framework_routes::ROUTES, registry)\n}\n",
            );
        }
    }
    crate::codegen::format_rust(&code)
}

fn framework_http_routes(
    root: &Path,
    manifest: &CanonicalAssemblyManifestV1,
) -> Result<Vec<String>> {
    use crate::contract::manifest::{ContractKind, ContractOwner, Lifecycle};

    let contracts = crate::contract::discover(&root.join("contracts"))?;
    let by_id = contracts
        .iter()
        .map(|contract| (contract.manifest.id.as_str(), contract))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut routes = Vec::new();
    for contract_id in manifest.framework_contracts() {
        let contract = by_id
            .get(contract_id.as_str())
            .with_context(|| format!("unknown framework contract `{contract_id}`"))?;
        if contract.manifest.lifecycle != Lifecycle::Active
            || contract.manifest.owner != ContractOwner::Framework
        {
            bail!("framework contract `{contract_id}` must be active and framework-owned")
        }
        if contract.manifest.kind == ContractKind::Http {
            routes.push(crate::codegen::rendered_http_route_evidence_path(contract)?);
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

    const RATE_PROVIDER: &str = r#"{ port = "diport::RateLimiter", provider = "ratelimit::GovernorLimiter", providerCrate = "ratelimit", requiredFeatures = ["redis", "metrics"], consumer = "httpserve", lifecycle = "active", durability = "ephemeral-memory", purpose = "test", outputs = ["workers", "resources"] }"#;
    const PDP_PROVIDER: &str = r#"{ port = "diport::Pdp", provider = "oidc::OidcProvider", providerCrate = "oidc", consumer = "httpserve", lifecycle = "active", durability = "persistent", purpose = "authorization", outputs = ["probes"] }"#;

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
        assert_eq!(rendered.matches("::module(deps)").count(), 3);
        assert_eq!(rendered.matches(".context(\"wire domain '").count(), 3);
        assert!(rendered.contains("pub(crate) async fn wire_test_domains"));
        assert!(rendered.contains("pub const DOMAIN_LISTENER_BINDINGS"));
        assert!(rendered.contains("bootstrap::ListenerKind::Primary"));
        assert!(rendered.contains("pub const PROVIDER_OUTPUT_BINDINGS"));
        assert!(rendered.contains("bootstrap::LifecycleChannel::Resources"));
        assert_eq!(rendered.matches("::tests::test_binding()").count(), 3);
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
        assert!(rendered.contains("ratelimit::GovernorLimiter"));
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
            )
            .replace("requiredFeatures = [\"redis\", \"metrics\"]", "requiredFeatures = [\"metrics\", \"redis\"]")
            .replace("outputs = [\"workers\", \"resources\"]", "outputs = [\"resources\", \"workers\"]");
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
            "frameworkContracts = [\"framework.status\"]",
        );
        let parsed = AssemblyManifest::from_toml_str(&source)?.canonicalize_v1()?;
        let rendered = render_modules(
            &parsed,
            &["::generated::http::framework_v1::status::ROUTE.evidence()".to_string()],
            "assemblies/runtime/assembly.toml",
        )?;
        assert!(rendered.contains("pub const FRAMEWORK_HTTP_ROUTES"));
        assert!(rendered.contains("bootstrap::FrameworkHttpRoute::new("));
        assert!(rendered.contains("::generated::http::framework_v1::status::ROUTE.evidence()"));
        assert!(rendered.contains(
            "bootstrap::FrameworkRoutes::register(&crate::framework_routes::ROUTES, registry)"
        ));
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
        assert!(settings.contains("domains::settings"));
        assert!(!settings.contains("domains::identity"));
        assert!(!settings.contains("domains::audit"));
        let identity = identity_audit
            .find("domains::identity")
            .ok_or_else(|| anyhow::anyhow!("identityaudit missing identity"))?;
        let audit = identity_audit
            .find("domains::audit")
            .ok_or_else(|| anyhow::anyhow!("identityaudit missing audit"))?;
        assert!(identity < audit);
        assert!(!identity_audit.contains("domains::settings"));

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
}
