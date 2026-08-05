use anyhow::Result;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::OnceLock;
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

#[cfg(test)]
mod tests {
    use super::{
        CommandWorkspaceFacts, METADATA_STDERR_CHAR_LIMIT, format_metadata_command_failure,
        sanitize_metadata_diagnostic,
    };
    use anyhow::{bail, ensure};
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
