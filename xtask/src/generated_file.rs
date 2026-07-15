//! Shared primitives for committed generated files.

use anyhow::{Context, Result, ensure};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LfCheckoutFailure {
    AttributesRead,
    DeclarationMismatch,
    Input,
    GitInvocation,
    EffectivePolicyMismatch,
}

/// Verify one exact `.gitattributes` declaration and its effective LF policy for every target.
pub(crate) fn verify_lf_checkout(
    root: &Path,
    declaration: &str,
    targets: &[PathBuf],
) -> std::result::Result<(), LfCheckoutFailure> {
    let attributes_path = root.join(".gitattributes");
    let attributes =
        fs::read_to_string(&attributes_path).map_err(|_| LfCheckoutFailure::AttributesRead)?;
    let declarations = attributes
        .lines()
        .filter(|line| line.trim() == declaration)
        .count();
    if declarations != 1 {
        return Err(LfCheckoutFailure::DeclarationMismatch);
    }
    if targets.is_empty() {
        return Err(LfCheckoutFailure::Input);
    }

    let labels = targets
        .iter()
        .map(|path| repository_label(root, path))
        .collect::<Result<Vec<_>>>()
        .map_err(|_| LfCheckoutFailure::Input)?;
    let mut args = vec!["check-attr", "-z", "text", "eol", "--"];
    args.extend(labels.iter().map(String::as_str));
    let checked = git_stdout(root, &args).map_err(|_| LfCheckoutFailure::GitInvocation)?;
    let fields = checked
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    if fields.len() != labels.len() * 6 {
        return Err(LfCheckoutFailure::GitInvocation);
    }
    for (label, actual) in labels.iter().zip(fields.chunks_exact(6)) {
        let expected: [&[u8]; 6] = [
            label.as_bytes(),
            b"text",
            b"set",
            label.as_bytes(),
            b"eol",
            b"lf",
        ];
        if actual != expected {
            return Err(LfCheckoutFailure::EffectivePolicyMismatch);
        }
    }
    Ok(())
}

fn repository_label(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("generated path 越过 workspace: {}", path.display()))?;
    ensure!(
        relative
            .components()
            .all(|component| matches!(component, Component::Normal(_))),
        "generated path 不是规范仓库相对路径"
    );
    relative
        .to_str()
        .map(|label| label.replace('\\', "/"))
        .context("generated path 不是 UTF-8")
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

/// Atomically replace one file in-place, sync its contents, and sync the parent directory on Unix.
///
/// The caller owns symlink validation and must keep the checkout stable for the duration of this
/// operation; this primitive never removes a temporary file it did not successfully create.
pub(crate) fn atomic_replace(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} 无父目录", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("创建 {} 失败", parent.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} 无文件名", path.display()))?
        .to_string_lossy();
    let mut opened = None;
    for _ in 0..64 {
        let temp = parent.join(format!(
            ".{file_name}.tmp-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new().create_new(true).write(true).open(&temp) {
            Ok(file) => {
                opened = Some((temp, file));
                break;
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("创建临时文件失败"),
        }
    }
    let (temp, mut file) = opened.context("临时文件名冲突次数超限")?;
    let result = (|| -> Result<()> {
        file.write_all(content)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)
            .with_context(|| format!("rename {} -> {} 失败", temp.display(), path.display()))?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const RULE: &str = "assemblies/*/assembly.lock.json text eol=lf";

    #[test]
    fn lf_checkout_rejects_missing_weakened_and_overridden_rules() -> anyhow::Result<()> {
        let fixture = Fixture::new("lf-policy")?;
        let target = fixture.root.join("assemblies/runtime/assembly.lock.json");
        fs::create_dir_all(target.parent().context("lock parent missing")?)?;
        fs::write(&target, b"{}\n")?;
        let targets = [target];

        fs::write(fixture.root.join(".gitattributes"), format!("{RULE}\n"))?;
        verify_lf_checkout(&fixture.root, RULE, &targets)
            .map_err(|stage| anyhow::anyhow!("{stage:?}"))?;

        for (invalid, expected) in [
            ("", LfCheckoutFailure::DeclarationMismatch),
            (
                "assemblies/*/assembly.lock.json text\n",
                LfCheckoutFailure::DeclarationMismatch,
            ),
            (
                concat!(
                    "assemblies/*/assembly.lock.json text eol=lf\n",
                    "assemblies/runtime/assembly.lock.json -text eol=crlf\n"
                ),
                LfCheckoutFailure::EffectivePolicyMismatch,
            ),
        ] {
            fs::write(fixture.root.join(".gitattributes"), invalid)?;
            assert_eq!(
                verify_lf_checkout(&fixture.root, RULE, &targets),
                Err(expected)
            );
        }
        Ok(())
    }

    #[test]
    fn atomic_replace_is_exact_and_cleans_failed_temp() -> anyhow::Result<()> {
        let fixture = Fixture::new("atomic")?;
        let output = fixture.root.join("generated.json");
        atomic_replace(&output, b"first\n")?;
        atomic_replace(&output, b"second\n")?;
        assert_eq!(fs::read(&output)?, b"second\n");

        let blocked = fixture.root.join("blocked.json");
        fs::create_dir(&blocked)?;
        assert!(atomic_replace(&blocked, b"never written\n").is_err());
        let leftovers = fs::read_dir(&fixture.root)?
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.starts_with(".blocked.json.tmp-"))
            .collect::<Vec<_>>();
        assert!(
            leftovers.is_empty(),
            "temporary files leaked: {leftovers:?}"
        );

        let recovered = fixture.root.join("recovered.json");
        let conflict = fixture.root.join(format!(
            ".recovered.json.tmp-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.load(Ordering::Relaxed)
        ));
        fs::write(&conflict, b"stale but not owned\n")?;
        atomic_replace(&recovered, b"recovered\n")?;
        assert_eq!(fs::read(&recovered)?, b"recovered\n");
        assert_eq!(fs::read(&conflict)?, b"stale but not owned\n");

        let reserved = fixture.root.join("reserved.json");
        let first_sequence = TEMP_SEQUENCE.load(Ordering::Relaxed);
        let occupied = (first_sequence..first_sequence + 64)
            .map(|sequence| {
                fixture.root.join(format!(
                    ".reserved.json.tmp-{}-{sequence}",
                    std::process::id()
                ))
            })
            .collect::<Vec<_>>();
        for path in &occupied {
            fs::write(path, b"not owned by this call\n")?;
        }
        assert!(atomic_replace(&reserved, b"must fail\n").is_err());
        for path in occupied {
            assert_eq!(fs::read(path)?, b"not owned by this call\n");
        }
        Ok(())
    }

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> anyhow::Result<Self> {
            let root = std::env::temp_dir().join(format!(
                "rss-generated-file-{label}-{}-{}",
                std::process::id(),
                FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root)?;
            let status = crate::cmd::external_cmd(
                crate::cmd::ExternalProgram::SystemGit,
                &["init", "--quiet"],
                &[],
                Some(&root),
            )
            .status()?;
            anyhow::ensure!(status.success(), "git init failed");
            Ok(Self { root })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
