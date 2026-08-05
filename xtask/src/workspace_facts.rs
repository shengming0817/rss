use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use workspacefacts::{WorkspaceFacts, WorkspaceFactsError};

type MetadataLoader = dyn Fn(&Path) -> std::result::Result<Vec<u8>, String>;

#[derive(Clone, Debug)]
enum FactsInitError {
    Load(String),
    Facts(WorkspaceFactsError),
}

impl std::fmt::Display for FactsInitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Load(message) => write!(formatter, "{message}"),
            Self::Facts(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for FactsInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Load(_) => None,
            Self::Facts(error) => Some(error),
        }
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
            let output = crate::cmd::cargo_cmd(
                crate::cmd::CargoSubcommand::Metadata,
                &["--locked", "--all-features", "--format-version", "1"],
                &[],
                Some(root),
            )
            .output()
            .map_err(|error| format!("execute cargo metadata: {error}"))?;
            if !output.status.success() {
                return Err(format!(
                    "cargo metadata failed (status={}): {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Ok(output.stdout)
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
            let bytes = (self.metadata_loader)(&self.root).map_err(FactsInitError::Load)?;
            let json = String::from_utf8(bytes).map_err(|error| {
                FactsInitError::Load(format!("cargo metadata stdout is not UTF-8: {error}"))
            })?;
            WorkspaceFacts::from_metadata_json(&self.root, &json).map_err(FactsInitError::Facts)
        }) {
            Ok(facts) => Ok(facts),
            Err(error) => Err(anyhow::Error::new(error.clone())),
        }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::CommandWorkspaceFacts;
    use std::cell::Cell;
    use std::path::Path;
    use std::rc::Rc;
    use workspacefacts::testing::{
        metadata_json, path_package, path_package_id, resolve_node, target,
    };

    #[test]
    fn command_scope_oncelock_caches_success_and_failure() {
        let success_calls = Rc::new(Cell::new(0));
        let success_counter = Rc::clone(&success_calls);
        let success =
            CommandWorkspaceFacts::with_metadata_loader(Path::new("/workspace"), move |_| {
                success_counter.set(success_counter.get() + 1);
                Ok(single_package_metadata())
            });
        // OnceLock success path: repeated get() shares one loader invocation
        assert!(success.get().is_ok());
        assert!(success.get().is_ok());
        assert!(success.get().is_ok());
        assert_eq!(success_calls.get(), 1);

        let failure_calls = Rc::new(Cell::new(0));
        let failure_counter = Rc::clone(&failure_calls);
        let failure =
            CommandWorkspaceFacts::with_metadata_loader(Path::new("/workspace"), move |_| {
                failure_counter.set(failure_counter.get() + 1);
                Err("synthetic metadata failure".to_owned())
            });
        // OnceLock failure path: repeated get() shares one loader invocation
        assert!(failure.get().is_err());
        assert!(failure.get().is_err());
        assert!(failure.get().is_err());
        assert_eq!(failure_calls.get(), 1);
        let err = failure.get().expect_err("failure path");
        assert!(
            err.source().is_none(),
            "Load init error has no underlying source"
        );
    }

    #[test]
    fn facts_init_error_preserves_workspace_facts_source() {
        let facts = CommandWorkspaceFacts::with_metadata_loader(Path::new("/workspace"), |_| {
            Ok(b"{not-json".to_vec())
        });
        let err = facts.get().expect_err("invalid metadata must fail");
        assert!(
            err.source().is_some(),
            "FactsInitError::Facts must preserve source chain: {err:#}"
        );
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
