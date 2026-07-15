//! Deterministic committed AssemblyLock generation and drift checking.
//!
//! INVARIANT: ASSEMBLY-LOCK-GOLDEN-01 { level = "Hard", exec = "verify", source = "codegen", golden = "assemblies/runtime/assembly.lock.json", synthetic_red = "assembly_lock::tests::changed_inputs_drift_expected_targets", anti_vacuity = "assembly_lock::tests::three_committed_locks_are_clean_and_verified" } — the repository-verified compiler is the sole source of committed lock bytes; raw-byte drift fails the aggregate gate.
//! INVARIANT: ASSEMBLY-LOCK-DIAGNOSTIC-01 { level = "Hard", exec = "native-compile", source = "code", native = "closed command error variants carry only fixed stages, escaped repository-relative paths, counts, and io::ErrorKind; no source error or arbitrary detail field is representable" } — invalid manifest/contract/generated contents cannot enter this command's error value.
//! INVARIANT: ASSEMBLY-LOCK-LF-CHECKOUT-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "generated_file::tests::lf_checkout_rejects_missing_weakened_and_overridden_rules", anti_vacuity = "assembly_lock::tests::three_committed_locks_are_clean_and_verified" } — every lock target has effective `text=set,eol=lf` before byte comparison or generation.
//! INVARIANT: ASSEMBLY-LOCK-VERIFY-GATE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "assembly_lock_check_is_typed_once_and_ordered_in_all_aggregate_plans", anti_vacuity = "assembly_lock::tests::three_committed_locks_are_clean_and_verified" } — the typed no-compile check occurs exactly once in verify, fast, compatibility CI, and ci-meta between modules drift and graph drift.

use assembly_schema::{AssemblyLockErrorStage, RepositoryVerifiedAssemblyLock};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

const LOCK_LF_RULE: &str = "assemblies/*/assembly.lock.json text eol=lf";

/// Closed command surface: v1 intentionally has no single-assembly or compatibility mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssemblyLockAction {
    Generate,
    Check,
}

pub(crate) fn run(action: AssemblyLockAction) -> anyhow::Result<()> {
    run_root(&crate::workspace_root()?, action).map_err(anyhow::Error::new)
}

fn run_root(root: &Path, action: AssemblyLockAction) -> CommandResult<()> {
    let targets = preflight(root)?;
    let plan = plan_locks(root, &targets)?;
    match action {
        AssemblyLockAction::Generate => generate(plan),
        AssemblyLockAction::Check => check(&plan),
    }
}

fn preflight(root: &Path) -> CommandResult<Vec<crate::assembly::AssemblyTarget>> {
    let discovered = crate::assembly::discover_targets(root)
        .map_err(|_| CommandError::Preflight(PreflightFailure::Discovery))?;
    let orphans = orphan_locks(root, &discovered)?;
    if !orphans.is_empty() {
        return Err(CommandError::Orphans(orphans));
    }
    let targets = discovered
        .into_iter()
        .filter(crate::assembly::AssemblyTarget::has_manifest)
        .collect::<Vec<_>>();
    if targets.is_empty() {
        return Err(CommandError::EmptyUniverse);
    }

    let (_, contract_findings) = crate::contract::validate::validate_root(&root.join("contracts"))
        .map_err(|_| CommandError::Preflight(PreflightFailure::ContractHardError))?;
    if !contract_findings.is_empty() {
        return Err(CommandError::Preflight(PreflightFailure::ContractFindings(
            contract_findings.len(),
        )));
    }
    let (_, assembly_findings) = crate::assembly::validate_root(root)
        .map_err(|_| CommandError::Preflight(PreflightFailure::AssemblyHardError))?;
    if !assembly_findings.is_empty() {
        return Err(CommandError::Preflight(PreflightFailure::AssemblyFindings(
            assembly_findings.len(),
        )));
    }
    crate::assembly_codegen::check_root(root)
        .map_err(|_| CommandError::Preflight(PreflightFailure::ModulesAggregate))?;
    let lock_paths = targets
        .iter()
        .map(|target| target.lock_path().to_path_buf())
        .collect::<Vec<_>>();
    crate::generated_file::verify_lf_checkout(root, LOCK_LF_RULE, &lock_paths)
        .map_err(CommandError::CheckoutPolicy)?;
    Ok(targets)
}

fn orphan_locks(
    root: &Path,
    targets: &[crate::assembly::AssemblyTarget],
) -> CommandResult<Vec<SafeRepoPath>> {
    let mut orphans = Vec::new();
    for target in targets.iter().filter(|target| !target.has_manifest()) {
        let path = target.lock_path();
        match fs::symlink_metadata(path) {
            Ok(_) => orphans.push(SafeRepoPath::for_path(root, path)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(CommandError::Io {
                    operation: IoOperation::Inspect,
                    path: SafeRepoPath::for_path(root, path),
                    kind: error.kind(),
                });
            }
        }
    }
    Ok(orphans)
}

struct PlannedLock {
    path: PathBuf,
    label: SafeRepoPath,
    expected: Vec<u8>,
    actual: Option<Vec<u8>>,
}

fn plan_locks(
    root: &Path,
    targets: &[crate::assembly::AssemblyTarget],
) -> CommandResult<Vec<PlannedLock>> {
    let mut plan = Vec::with_capacity(targets.len());
    for target in targets {
        let path = target.lock_path().to_path_buf();
        let label = SafeRepoPath::for_path(root, &path);
        ensure_lock_output(&path, &label)?;
        let lock =
            RepositoryVerifiedAssemblyLock::compile_v1(root, target.dir()).map_err(|error| {
                CommandError::Compile {
                    path: label.clone(),
                    stage: error.stage(),
                }
            })?;
        debug_assert_eq!(lock.identity().name(), target.name());
        let mut expected =
            serde_json::to_vec_pretty(&lock).map_err(|_| CommandError::Serialize(label.clone()))?;
        expected.push(b'\n');
        let actual = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(CommandError::Io {
                    operation: IoOperation::Read,
                    path: label,
                    kind: error.kind(),
                });
            }
        };
        plan.push(PlannedLock {
            path,
            label,
            expected,
            actual,
        });
    }
    Ok(plan)
}

fn ensure_lock_output(path: &Path, label: &SafeRepoPath) -> CommandResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(CommandError::UnsafeOutput(label.clone()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CommandError::Io {
            operation: IoOperation::Inspect,
            path: label.clone(),
            kind: error.kind(),
        }),
    }
}

fn check(plan: &[PlannedLock]) -> CommandResult<()> {
    let drift = plan
        .iter()
        .filter(|target| target.actual.as_deref() != Some(target.expected.as_slice()))
        .map(|target| target.label.clone())
        .collect::<Vec<_>>();
    if !drift.is_empty() {
        return Err(CommandError::Drift(drift));
    }
    eprintln!("assembly lock check: {} 个 lock 无漂移", plan.len());
    Ok(())
}

fn generate(plan: Vec<PlannedLock>) -> CommandResult<()> {
    let mut changed = 0usize;
    for target in plan {
        if target.actual.as_deref() == Some(target.expected.as_slice()) {
            continue;
        }
        crate::generated_file::atomic_replace(&target.path, &target.expected).map_err(|error| {
            CommandError::Io {
                operation: IoOperation::Write,
                path: target.label.clone(),
                kind: error
                    .downcast_ref::<io::Error>()
                    .map_or(io::ErrorKind::Other, io::Error::kind),
            }
        })?;
        eprintln!("generated {}", target.label);
        changed += 1;
    }
    eprintln!("assembly lock generate: {changed} 个 lock 已更新");
    Ok(())
}

type CommandResult<T> = Result<T, CommandError>;

#[derive(Clone, PartialEq, Eq)]
struct SafeRepoPath(Box<str>);

impl SafeRepoPath {
    fn for_path(root: &Path, path: &Path) -> Self {
        let label = path
            .strip_prefix(root)
            .ok()
            .filter(|relative| {
                relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_)))
            })
            .and_then(Path::to_str)
            .map(|relative| {
                relative
                    .chars()
                    .flat_map(char::escape_default)
                    .collect::<String>()
                    .replace('\\', "/")
            })
            .unwrap_or_else(|| "<invalid-repository-path>".to_owned());
        Self(label.into_boxed_str())
    }
}

impl fmt::Debug for SafeRepoPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for SafeRepoPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IoOperation {
    Inspect,
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PreflightFailure {
    Discovery,
    ContractHardError,
    ContractFindings(usize),
    AssemblyHardError,
    AssemblyFindings(usize),
    ModulesAggregate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandError {
    EmptyUniverse,
    Preflight(PreflightFailure),
    CheckoutPolicy(crate::generated_file::LfCheckoutFailure),
    Orphans(Vec<SafeRepoPath>),
    UnsafeOutput(SafeRepoPath),
    Compile {
        path: SafeRepoPath,
        stage: AssemblyLockErrorStage,
    },
    Serialize(SafeRepoPath),
    Drift(Vec<SafeRepoPath>),
    Io {
        operation: IoOperation,
        path: SafeRepoPath,
        kind: io::ErrorKind,
    },
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyUniverse => formatter.write_str(
                "assembly lock: assembly target 集合为空；运行 `cargo xtask assembly validate`",
            ),
            Self::Preflight(PreflightFailure::Discovery) => formatter.write_str(
                "assembly lock: target discovery 失败；运行 `cargo xtask assembly validate`",
            ),
            Self::Preflight(PreflightFailure::ContractHardError) => formatter.write_str(
                "assembly lock: contract 输入不可读或无效；运行 `cargo xtask contract validate`",
            ),
            Self::Preflight(PreflightFailure::ContractFindings(count)) => write!(
                formatter,
                "assembly lock: contract validate 有 {count} 项失败；运行 `cargo xtask contract validate`"
            ),
            Self::Preflight(PreflightFailure::AssemblyHardError) => formatter.write_str(
                "assembly lock: assembly 输入不可读或无效；运行 `cargo xtask assembly validate`",
            ),
            Self::Preflight(PreflightFailure::AssemblyFindings(count)) => write!(
                formatter,
                "assembly lock: assembly validate 有 {count} 项失败；运行 `cargo xtask assembly validate`"
            ),
            Self::Preflight(PreflightFailure::ModulesAggregate) => formatter.write_str(
                "assembly lock: modules aggregate policy 无效；运行 `cargo xtask assembly generate-modules`",
            ),
            Self::CheckoutPolicy(stage) => match stage {
                crate::generated_file::LfCheckoutFailure::AttributesRead => formatter.write_str(
                    "assembly lock: 无法读取 `.gitattributes`；确认文件存在且可读",
                ),
                crate::generated_file::LfCheckoutFailure::DeclarationMismatch => write!(
                    formatter,
                    "assembly lock: `.gitattributes` 必须且只能声明一次 `{LOCK_LF_RULE}`"
                ),
                crate::generated_file::LfCheckoutFailure::GitInvocation => formatter.write_str(
                    "assembly lock: `git check-attr` 执行失败；确认系统 Git 与 checkout 可用",
                ),
                crate::generated_file::LfCheckoutFailure::EffectivePolicyMismatch => write!(
                    formatter,
                    "assembly lock: 最终 Git 属性必须为 text=set,eol=lf；检查 `{LOCK_LF_RULE}` 的后置 override"
                ),
                crate::generated_file::LfCheckoutFailure::Input => formatter.write_str(
                    "assembly lock: LF checkout policy 内部输入无效；检查 generator 实现",
                ),
            },
            Self::Orphans(paths) => write!(
                formatter,
                "assembly lock: {} 个 orphan lock（{}）；人工审查后删除，不自动清理",
                paths.len(),
                DisplayPaths(paths)
            ),
            Self::UnsafeOutput(path) => {
                write!(formatter, "assembly lock: 输出 `{path}` 不是安全普通文件")
            }
            Self::Compile { path, stage } => match stage {
                AssemblyLockErrorStage::Manifest => write!(formatter, "assembly lock: `{path}` manifest 编译失败；检查 assembly.toml"),
                AssemblyLockErrorStage::ContractCatalog => write!(formatter, "assembly lock: `{path}` contract catalog 编译失败；运行 `cargo xtask contract validate`"),
                AssemblyLockErrorStage::GeneratedUniverse => write!(formatter, "assembly lock: `{path}` generated universe 无效；检查 src/generated ownership 与文件类型"),
                AssemblyLockErrorStage::FileSystem => write!(formatter, "assembly lock: `{path}` repository filesystem 无效；检查路径类型与权限"),
                AssemblyLockErrorStage::Serialization | AssemblyLockErrorStage::LockFile => write!(formatter, "assembly lock: `{path}` compiler 内部失败；检查实现"),
            },
            Self::Serialize(path) => write!(
                formatter,
                "assembly lock: 无法渲染 `{path}`；内部生成器失败，请检查实现"
            ),
            Self::Drift(paths) => write!(
                formatter,
                "assembly lock: {} 个目标漂移（{}）；运行 `cargo xtask assembly lock generate`",
                paths.len(),
                DisplayPaths(paths)
            ),
            Self::Io {
                operation,
                path,
                kind,
            } => write!(
                formatter,
                "assembly lock: {operation:?} `{path}` 失败（{kind:?}）"
            ),
        }
    }
}

impl std::error::Error for CommandError {}

struct DisplayPaths<'a>(&'a [SafeRepoPath]);

impl fmt::Display for DisplayPaths<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, path) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str(", ")?;
            }
            write!(formatter, "{path}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use anyhow::Context;
    use assembly_schema::ParsedAssemblyLock;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const SECRET: &str = "ZZ_RSS_ASSEMBLY_LOCK_SECRET_1781";
    const ANSI: &str = "\u{1b}[31m";
    const INJECTED: &str = "INJECTED_DIAGNOSTIC_LINE";
    type FixtureMutation = fn(&Path) -> anyhow::Result<()>;

    #[test]
    fn three_committed_locks_are_clean_and_verified() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        run_root(&root, AssemblyLockAction::Check)?;
        let targets = crate::assembly::discover_targets(&root)?
            .into_iter()
            .filter(crate::assembly::AssemblyTarget::has_manifest)
            .collect::<Vec<_>>();
        assert_eq!(
            targets
                .iter()
                .map(crate::assembly::AssemblyTarget::name)
                .collect::<Vec<_>>(),
            ["identityaudit", "runtime", "settingsonly"]
        );
        for target in targets {
            let bytes = fs::read(target.lock_path())?;
            anyhow::ensure!(!bytes.is_empty(), "committed lock must not be empty");
            ParsedAssemblyLock::from_json_slice(&bytes)?
                .verify_repository_v1(&root, target.dir())?;
        }
        Ok(())
    }

    #[test]
    fn generate_action_is_end_to_end_deterministic_and_check_clean() -> anyhow::Result<()> {
        let fixture = Fixture::new("generate-action")?;
        let (_, findings) = crate::assembly::validate_root(&fixture.root)?;
        anyhow::ensure!(findings.is_empty(), "fixture findings: {findings:?}");
        run_root(&fixture.root, AssemblyLockAction::Generate)?;
        let first = on_disk_locks(&fixture.root)?;
        assert_eq!(first.len(), 3);

        run_root(&fixture.root, AssemblyLockAction::Generate)?;
        assert_eq!(first, on_disk_locks(&fixture.root)?);
        run_root(&fixture.root, AssemblyLockAction::Check)?;
        Ok(())
    }

    #[test]
    fn render_is_byte_deterministic_across_roots_and_secret_opaque() -> anyhow::Result<()> {
        let first = Fixture::new("deterministic-a")?;
        let second = Fixture::new("deterministic-b")?;
        let first_render = rendered(&first.root)?;
        let second_render = rendered(&second.root)?;
        assert_eq!(first_render, second_render);
        for bytes in first_render.values() {
            assert!(bytes.ends_with(b"\n"));
            assert!(!bytes.ends_with(b"\n\n"));
            assert!(!bytes.contains(&b'\r'));
        }

        let generated = first
            .root
            .join("assemblies/runtime/src/generated/modules_gen.rs");
        fs::write(
            &generated,
            format!("{}\n// {SECRET}\n", fs::read_to_string(&generated)?),
        )?;
        let baited = rendered(&first.root)?;
        assert_ne!(first_render["runtime"], baited["runtime"]);
        assert!(
            !baited
                .values()
                .any(|bytes| bytes.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()))
        );
        Ok(())
    }

    #[test]
    fn changed_inputs_drift_expected_targets() -> anyhow::Result<()> {
        let cases = [
            (
                "manifest",
                mutate_manifest as FixtureMutation,
                &["runtime"] as &[&str],
            ),
            (
                "generated",
                mutate_generated as FixtureMutation,
                &["identityaudit"] as &[&str],
            ),
            (
                "contract-semantics",
                mutate_contract_semantics as FixtureMutation,
                &["identityaudit", "runtime"] as &[&str],
            ),
            (
                "contract-schema",
                mutate_contract_schema as FixtureMutation,
                &["runtime", "settingsonly"] as &[&str],
            ),
        ];
        for (name, mutation, expected) in cases {
            let fixture = Fixture::new(name)?;
            let before = rendered(&fixture.root)?;
            mutation(&fixture.root)?;
            let after = rendered(&fixture.root)?;
            assert_eq!(
                changed_names(&before, &after),
                expected.iter().copied().collect()
            );
        }
        Ok(())
    }

    #[test]
    fn equivalent_manifest_layout_is_stable_but_declared_order_is_semantic() -> anyhow::Result<()> {
        let fixture = Fixture::new("manifest-order")?;
        let before = rendered(&fixture.root)?;
        let path = fixture.root.join("assemblies/runtime/assembly.toml");
        let source = fs::read_to_string(&path)?;
        let header = "name = \"runtime\"\nprofile = \"demo\"\ndomains = [\"settings\", \"identity\", \"audit\"]\ntopology = \"durable-shared\"\nframeworkContracts = []";
        let reordered = "frameworkContracts = []\ntopology = \"durable-shared\"\ndomains = [\"settings\", \"identity\", \"audit\"]\nprofile = \"demo\"\nname = \"runtime\"";
        fs::write(&path, source.replacen(header, reordered, 1))?;
        assert_eq!(before, rendered(&fixture.root)?);

        let source = fs::read_to_string(&path)?;
        let provider = concat!(
            "port = \"diport::Publisher\"\n",
            "provider = \"amqp::AmqpPublisher\"\n",
            "providerCrate = \"amqp\"\n",
            "requiredFeatures = [\"backend\"]\n",
            "consumer = \"eventexec\"\n",
            "lifecycle = \"active\"\n",
            "durability = \"persistent\"\n",
            "purpose = \"outbox-relay-amqp-publish\"\n",
            "outputs = [\"probes\", \"resources\", \"workers\"]"
        );
        let equivalent_provider = concat!(
            "outputs = [\"workers\", \"resources\", \"probes\"]\n",
            "purpose = \"outbox-relay-amqp-publish\"\n",
            "durability = \"persistent\"\n",
            "lifecycle = \"active\"\n",
            "consumer = \"eventexec\"\n",
            "requiredFeatures = [\"backend\"]\n",
            "providerCrate = \"amqp\"\n",
            "provider = \"amqp::AmqpPublisher\"\n",
            "port = \"diport::Publisher\""
        );
        anyhow::ensure!(source.contains(provider), "provider fixture source missing");
        fs::write(&path, source.replacen(provider, equivalent_provider, 1))?;
        assert_eq!(before, rendered(&fixture.root)?);

        let source = fs::read_to_string(&path)?;
        fs::write(
            &path,
            source.replacen(
                "domains = [\"settings\", \"identity\", \"audit\"]",
                "domains = [\"identity\", \"settings\", \"audit\"]",
                1,
            ),
        )?;
        let after = rendered(&fixture.root)?;
        assert_eq!(changed_names(&before, &after), BTreeSet::from(["runtime"]));
        Ok(())
    }

    #[test]
    fn check_rejects_missing_tampered_and_crlf_without_writing() -> anyhow::Result<()> {
        for case in ["missing", "tampered", "crlf"] {
            let fixture = Fixture::new(case)?;
            generate_fixture(&fixture.root)?;
            let path = fixture.root.join("assemblies/runtime/assembly.lock.json");
            match case {
                "missing" => fs::remove_file(&path)?,
                "tampered" => fs::write(&path, b"{\"password\":\"SECRET_BAIT\"}\n")?,
                "crlf" => {
                    let bytes = fs::read(&path)?;
                    fs::write(&path, String::from_utf8(bytes)?.replace('\n', "\r\n"))?;
                }
                other => anyhow::bail!("unknown fixture case: {other}"),
            }
            let before = fs::read(&path).ok();
            let error =
                run_root(&fixture.root, AssemblyLockAction::Check).expect_err("drift must fail");
            let CommandError::Drift(paths) = &error else {
                anyhow::bail!("expected drift error, got {error}");
            };
            assert_eq!(paths.len(), 1);
            assert_safe_diagnostic(&format!("{error:?} {error}"));
            assert_eq!(before, fs::read(&path).ok());
        }
        Ok(())
    }

    #[test]
    fn invalid_preflight_inputs_have_closed_secret_safe_diagnostics() -> anyhow::Result<()> {
        let cases = [
            ("manifest", invalidate_manifest as FixtureMutation),
            ("contract", invalidate_contract as FixtureMutation),
            ("generated", invalidate_generated as FixtureMutation),
        ];
        for (name, invalidate) in cases {
            let fixture = Fixture::new(name)?;
            generate_fixture(&fixture.root)?;
            invalidate(&fixture.root)?;
            let error = run_root(&fixture.root, AssemblyLockAction::Check)
                .expect_err("invalid preflight input must fail");
            assert_safe_diagnostic(&format!("{error:?} {error}"));
        }
        Ok(())
    }

    #[test]
    fn invalid_source_and_late_compile_failure_are_secret_safe_and_zero_write() -> anyhow::Result<()>
    {
        let fixture = Fixture::new("secret-error")?;
        generate_fixture(&fixture.root)?;
        let first = fixture
            .root
            .join("assemblies/identityaudit/assembly.lock.json");
        fs::write(&first, b"local drift\n")?;
        let broken = fixture
            .root
            .join("assemblies/settingsonly/src/generated/unowned.rs");
        fs::write(&broken, format!("password = \"{SECRET}\"\n"))?;
        let error = match fixture_plan(&fixture.root) {
            Ok(_) => anyhow::bail!("invalid source must fail planning"),
            Err(error) => error,
        };
        assert!(matches!(
            &error,
            CommandError::Compile {
                stage: AssemblyLockErrorStage::GeneratedUniverse,
                ..
            }
        ));
        let diagnostic = format!("{error:?} {error}");
        assert_safe_diagnostic(&diagnostic);
        assert_eq!(fs::read(&first)?, b"local drift\n");
        Ok(())
    }

    #[test]
    fn orphan_lock_is_rejected_without_deletion() -> anyhow::Result<()> {
        let fixture = Fixture::new("orphan")?;
        let orphan = fixture.root.join("assemblies/removed/assembly.lock.json");
        fs::create_dir_all(orphan.parent().context("orphan parent")?)?;
        fs::write(&orphan, b"reserved\n")?;
        let targets = crate::assembly::discover_targets(&fixture.root)?;
        let found = orphan_locks(&fixture.root, &targets)?;
        assert_eq!(found.len(), 1);
        assert_eq!(fs::read(&orphan)?, b"reserved\n");
        Ok(())
    }

    #[test]
    fn standalone_actions_reject_modules_lf_policy_and_owned_orphan() -> anyhow::Result<()> {
        let fixture = Fixture::new("modules-lf-policy")?;
        fs::write(
            fixture.root.join(".gitattributes"),
            format!("{LOCK_LF_RULE}\n"),
        )?;
        assert_eq!(
            run_root(&fixture.root, AssemblyLockAction::Check),
            Err(CommandError::Preflight(PreflightFailure::ModulesAggregate))
        );
        assert_eq!(
            CommandError::Preflight(PreflightFailure::ModulesAggregate).to_string(),
            "assembly lock: modules aggregate policy 无效；运行 `cargo xtask assembly generate-modules`"
        );

        let fixture = Fixture::new("modules-orphan")?;
        let orphan = fixture
            .root
            .join("assemblies/removed/src/generated/modules_gen.rs");
        fs::create_dir_all(orphan.parent().context("modules orphan parent")?)?;
        fs::write(
            &orphan,
            format!("{}\n", assembly_schema::GENERATED_MODULE_OWNERSHIP_MARKER),
        )?;
        assert_eq!(
            run_root(&fixture.root, AssemblyLockAction::Generate),
            Err(CommandError::Preflight(PreflightFailure::ModulesAggregate))
        );
        assert!(
            orphan.is_file(),
            "lock action must not delete modules orphan"
        );
        Ok(())
    }

    #[test]
    fn empty_target_universe_is_rejected() -> anyhow::Result<()> {
        let fixture = Fixture::new("empty")?;
        let assemblies = fixture.root.join("assemblies");
        fs::remove_dir_all(&assemblies)?;
        fs::create_dir(&assemblies)?;
        assert_eq!(
            run_root(&fixture.root, AssemblyLockAction::Check),
            Err(CommandError::EmptyUniverse)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn output_parent_and_assembly_symlinks_fail_closed() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("output-symlink")?;
        let outside = fixture.root.join("outside-lock");
        fs::write(&outside, b"outside\n")?;
        let lock = fixture.root.join("assemblies/runtime/assembly.lock.json");
        symlink(&outside, &lock)?;
        assert!(fixture_plan(&fixture.root).is_err());
        assert_eq!(fs::read(&outside)?, b"outside\n");

        let fixture = Fixture::new("assembly-symlink")?;
        let runtime = fixture.root.join("assemblies/runtime");
        let outside = fixture.root.join("outside-assembly");
        fs::rename(&runtime, &outside)?;
        symlink(&outside, &runtime)?;
        assert!(crate::assembly::discover_targets(&fixture.root).is_err());

        let fixture = Fixture::new("parent-symlink")?;
        let assemblies = fixture.root.join("assemblies");
        let outside = fixture.root.join("outside-assemblies");
        fs::rename(&assemblies, &outside)?;
        symlink(&outside, &assemblies)?;
        assert!(crate::assembly::discover_targets(&fixture.root).is_err());

        Ok(())
    }

    fn rendered(root: &Path) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
        Ok(fixture_plan(root)?
            .into_iter()
            .map(|target| {
                let name = target
                    .path
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    .unwrap_or("invalid")
                    .to_owned();
                (name, target.expected)
            })
            .collect())
    }

    fn on_disk_locks(root: &Path) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
        let mut locks = BTreeMap::new();
        for target in crate::assembly::discover_targets(root)? {
            if target.has_manifest() {
                locks.insert(target.name().to_owned(), fs::read(target.lock_path())?);
            }
        }
        Ok(locks)
    }

    fn fixture_plan(root: &Path) -> CommandResult<Vec<PlannedLock>> {
        let targets = crate::assembly::discover_targets(root)
            .map_err(|_| CommandError::Preflight(PreflightFailure::Discovery))?
            .into_iter()
            .filter(crate::assembly::AssemblyTarget::has_manifest)
            .collect::<Vec<_>>();
        plan_locks(root, &targets)
    }

    fn generate_fixture(root: &Path) -> anyhow::Result<()> {
        generate(fixture_plan(root)?)?;
        Ok(())
    }

    fn changed_names<'a>(
        before: &'a BTreeMap<String, Vec<u8>>,
        after: &'a BTreeMap<String, Vec<u8>>,
    ) -> BTreeSet<&'a str> {
        before
            .iter()
            .filter_map(|(name, bytes)| (after.get(name) != Some(bytes)).then_some(name.as_str()))
            .collect()
    }

    fn mutate_manifest(root: &Path) -> anyhow::Result<()> {
        replace(
            &root.join("assemblies/runtime/assembly.toml"),
            "profile = \"demo\"",
            "profile = \"test\"",
        )
    }

    fn mutate_generated(root: &Path) -> anyhow::Result<()> {
        let path = root.join("assemblies/identityaudit/src/generated/modules_gen.rs");
        fs::write(
            &path,
            format!("{}\n// changed\n", fs::read_to_string(&path)?),
        )?;
        Ok(())
    }

    fn mutate_contract_semantics(root: &Path) -> anyhow::Result<()> {
        replace(
            &root.join("contracts/event/identity/v1/session-created/contract.toml"),
            "topic = \"identity.session-created\"",
            "topic = \"identity.session-created-v2\"",
        )
    }

    fn mutate_contract_schema(root: &Path) -> anyhow::Result<()> {
        let path = root.join("contracts/event/settings/v1/payload.schema.json");
        fs::write(
            &path,
            format!(
                "{}\n",
                fs::read_to_string(&path)?
                    .replace("ConfigVersionChanged", "ConfigVersionChangedV2")
            ),
        )?;
        Ok(())
    }

    fn invalidate_manifest(root: &Path) -> anyhow::Result<()> {
        fs::write(
            root.join("assemblies/runtime/assembly.toml"),
            format!("password = \"{SECRET}\"\n{ANSI}\n{INJECTED}\n"),
        )?;
        Ok(())
    }

    fn invalidate_contract(root: &Path) -> anyhow::Result<()> {
        fs::write(
            root.join("contracts/event/settings/v1/contract.toml"),
            format!("password = \"{SECRET}\"\n{ANSI}\n{INJECTED}\n"),
        )?;
        Ok(())
    }

    fn invalidate_generated(root: &Path) -> anyhow::Result<()> {
        let path = root.join("assemblies/runtime/src/generated/modules_gen.rs");
        fs::write(
            &path,
            format!(
                "{}\n// {SECRET}{ANSI}{INJECTED}\n",
                fs::read_to_string(&path)?
            ),
        )?;
        Ok(())
    }

    fn assert_safe_diagnostic(diagnostic: &str) {
        for bait in [SECRET, ANSI, INJECTED, "SECRET_BAIT"] {
            assert!(!diagnostic.contains(bait), "diagnostic leaked bait");
        }
    }

    fn replace(path: &Path, from: &str, to: &str) -> anyhow::Result<()> {
        let source = fs::read_to_string(path)?;
        anyhow::ensure!(source.contains(from), "fixture mutation source missing");
        fs::write(path, source.replacen(from, to, 1))?;
        Ok(())
    }

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> anyhow::Result<Self> {
            let root = std::env::temp_dir().join(format!(
                "rss-assembly-lock-{label}-{}-{}",
                std::process::id(),
                FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root)?;
            let source = crate::workspace_root()?;
            copy_tree(&source.join("contracts"), &root.join("contracts"))?;
            for assembly in ["identityaudit", "runtime", "settingsonly"] {
                let source_dir = source.join("assemblies").join(assembly);
                let target_dir = root.join("assemblies").join(assembly);
                fs::create_dir_all(target_dir.join("src/generated"))?;
                fs::copy(
                    source_dir.join("assembly.toml"),
                    target_dir.join("assembly.toml"),
                )?;
                fs::copy(source_dir.join("Cargo.toml"), target_dir.join("Cargo.toml"))?;
                fs::copy(
                    source_dir.join("src/generated/modules_gen.rs"),
                    target_dir.join("src/generated/modules_gen.rs"),
                )?;
                if assembly == "runtime" {
                    fs::write(
                        target_dir.join("src/assembly_lock_fixture.rs"),
                        r#"
pub struct DistributedRuntimeDeps;
pub struct SharedRuntimeDeps;
pub fn wire_distributed(_: &SharedRuntimeDeps) -> DistributedRuntimeDeps {
    DistributedRuntimeDeps
}
pub fn run(deps: &SharedRuntimeDeps) {
    let distributed: DistributedRuntimeDeps = wire_distributed(deps);
    wire_event_transport((), distributed, (), ());
}
fn wire_event_transport(_: (), _: DistributedRuntimeDeps, _: (), _: ()) {}
"#,
                    )?;
                }
            }
            fs::write(
                root.join(".gitattributes"),
                format!("assemblies/*/src/generated/** text eol=lf\n{LOCK_LF_RULE}\n"),
            )?;
            let status = crate::cmd::external_cmd(
                crate::cmd::ExternalProgram::SystemGit,
                &["init", "--quiet"],
                &[],
                Some(&root),
            )
            .status()?;
            anyhow::ensure!(status.success(), "fixture git init failed");
            let status = crate::cmd::external_cmd(
                crate::cmd::ExternalProgram::SystemGit,
                &[
                    "add",
                    "--",
                    ".gitattributes",
                    "assemblies/*/src/generated/**",
                ],
                &[],
                Some(&root),
            )
            .status()?;
            anyhow::ensure!(status.success(), "fixture git add failed");
            Ok(Self { root })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn copy_tree(source: &Path, target: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let destination = target.join(entry.file_name());
            if file_type.is_dir() {
                copy_tree(&entry.path(), &destination)?;
            } else if file_type.is_file() {
                fs::copy(entry.path(), destination)?;
            } else {
                anyhow::bail!("fixture source contains unsupported file type")
            }
        }
        Ok(())
    }
}
