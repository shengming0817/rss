//! Shared primitives for committed generated files.

use anyhow::{Context, Result, ensure};
use std::ffi::{OsStr, OsString};
use std::fs;
#[cfg(not(unix))]
use std::fs::OpenOptions;
#[cfg(not(unix))]
use std::io::ErrorKind;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
#[cfg(unix)]
static MODE_PROBE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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

/// An opened parent-directory capability plus its leaf name.
///
/// On Unix every path component is opened relative to the preceding directory with
/// `O_NOFOLLOW|O_DIRECTORY`; callers never publish through a re-resolved parent pathname.
#[cfg(unix)]
pub(crate) struct ParentDirectory {
    fd: rustix::fd::OwnedFd,
    file_name: OsString,
}

#[cfg(unix)]
impl ParentDirectory {
    pub(crate) fn fd(&self) -> &rustix::fd::OwnedFd {
        &self.fd
    }

    pub(crate) fn file_name(&self) -> &OsStr {
        &self.file_name
    }
}

#[cfg(unix)]
pub(crate) fn open_parent_directory(path: &Path) -> Result<ParentDirectory> {
    open_parent_directory_impl(path, false)
}

#[cfg(unix)]
pub(crate) fn open_directory_capability(path: &Path) -> Result<ParentDirectory> {
    open_parent_directory(&path.join(".rss-directory-capability"))
}

#[cfg(unix)]
fn open_or_create_parent_directory(path: &Path) -> Result<ParentDirectory> {
    open_parent_directory_impl(path, true)
}

#[cfg(unix)]
fn open_parent_directory_impl(path: &Path, create_missing: bool) -> Result<ParentDirectory> {
    use rustix::fs::{Mode, OFlags, fstat, open, openat};
    use std::os::unix::fs::MetadataExt as _;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} 无父目录", path.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} 无文件名", path.display()))?
        .to_os_string();
    let observable_parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let before = match fs::symlink_metadata(observable_parent) {
        Ok(metadata) => {
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "{} 不是真实父目录",
                parent.display()
            );
            Some((metadata.dev(), metadata.ino()))
        }
        Err(error) if create_missing && error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("读取 {} metadata 失败", parent.display()));
        }
    };
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = if parent.is_absolute() {
        open("/", flags, Mode::empty()).context("打开根目录 capability 失败")?
    } else {
        open(".", flags, Mode::empty()).context("打开当前目录 capability 失败")?
    };
    let mut normal_index = 0usize;
    for component in parent.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(segment) => {
                #[cfg(target_os = "macos")]
                if parent.is_absolute() && normal_index == 0 && macos_system_alias(segment) {
                    directory = openat(&directory, "private", flags, Mode::empty())
                        .context("安全打开 macOS /private alias root 失败")?;
                    directory =
                        openat(&directory, segment, flags, Mode::empty()).with_context(|| {
                            format!(
                                "安全打开 macOS system alias {} 失败",
                                segment.to_string_lossy()
                            )
                        })?;
                    normal_index += 1;
                    continue;
                }
                directory = open_directory_component(&directory, segment, flags, create_missing)?;
                normal_index += 1;
            }
            Component::ParentDir | Component::Prefix(_) => {
                anyhow::bail!("{} 父目录不是规范路径", path.display());
            }
        }
    }
    let opened = fstat(&directory).context("读取父目录 capability metadata 失败")?;
    if let Some(before) = before {
        ensure!(
            before == (opened.st_dev as u64, opened.st_ino as u64),
            "{} 在打开 capability 前被替换",
            parent.display()
        );
    }
    let after = fs::symlink_metadata(observable_parent)
        .with_context(|| format!("重新读取 {} metadata 失败", parent.display()))?;
    ensure!(
        after.is_dir()
            && !after.file_type().is_symlink()
            && (opened.st_dev as u64, opened.st_ino as u64) == (after.dev(), after.ino()),
        "{} 在打开 capability 期间被替换",
        parent.display()
    );
    Ok(ParentDirectory {
        fd: directory,
        file_name,
    })
}

#[cfg(unix)]
fn open_directory_component(
    directory: &rustix::fd::OwnedFd,
    segment: &OsStr,
    flags: rustix::fs::OFlags,
    create_missing: bool,
) -> Result<rustix::fd::OwnedFd> {
    use rustix::fs::{Mode, fsync, mkdirat, openat};

    match openat(directory, segment, flags, Mode::empty()) {
        Ok(opened) => Ok(opened),
        Err(error) if create_missing && error == rustix::io::Errno::NOENT => {
            match mkdirat(directory, segment, Mode::from_raw_mode(0o777)) {
                Ok(()) => fsync(directory).with_context(|| {
                    format!(
                        "同步新建父目录分量 {} 的 parent capability 失败",
                        segment.to_string_lossy()
                    )
                })?,
                Err(error) if error == rustix::io::Errno::EXIST => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("安全创建父目录分量 {} 失败", segment.to_string_lossy())
                    });
                }
            }
            openat(directory, segment, flags, Mode::empty()).with_context(|| {
                format!("安全打开新建父目录分量 {} 失败", segment.to_string_lossy())
            })
        }
        Err(error) => Err(error)
            .with_context(|| format!("安全打开父目录分量 {} 失败", segment.to_string_lossy())),
    }
}

#[cfg(target_os = "macos")]
fn macos_system_alias(segment: &OsStr) -> bool {
    let expected = match segment.to_str() {
        Some("var") => Some("private/var"),
        Some("tmp") => Some("private/tmp"),
        _ => None,
    };
    expected.is_some_and(|expected| {
        fs::read_link(Path::new("/").join(segment))
            .is_ok_and(|target| target == Path::new(expected))
    })
}

/// Read one bounded UTF-8 ordinary file through a no-follow parent capability.
pub(crate) fn read_stable_utf8_file(path: &Path, max_bytes: u64, label: &str) -> Result<String> {
    read_stable_utf8_file_with_hook(path, max_bytes, label, || {})
}

#[cfg(unix)]
pub(crate) fn read_stable_utf8_file_with_hook(
    path: &Path,
    max_bytes: u64,
    label: &str,
    after_open: impl FnOnce(),
) -> Result<String> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, fstat, openat, statat};
    use std::io::Read as _;

    let parent =
        open_parent_directory(path).with_context(|| format!("{label} parent is unsafe"))?;
    let before = statat(parent.fd(), parent.file_name(), AtFlags::SYMLINK_NOFOLLOW)
        .with_context(|| format!("{label} metadata failed"))?;
    ensure!(
        FileType::from_raw_mode(before.st_mode) != FileType::Symlink,
        "{label} rejects symlink"
    );
    ensure!(
        FileType::from_raw_mode(before.st_mode) == FileType::RegularFile,
        "{label} rejects non-regular file"
    );
    ensure!(
        before.st_size >= 0 && before.st_size as u64 <= max_bytes,
        "{label} exceeds {max_bytes} byte limit"
    );
    let fd = openat(
        parent.fd(),
        parent.file_name(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("{label} open failed"))?;
    let opened = fstat(&fd).with_context(|| format!("{label} fstat failed"))?;
    ensure!(
        (before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino),
        "{label} was replaced before open"
    );

    after_open();
    let mut bytes = Vec::with_capacity((opened.st_size as usize).min(64 * 1024));
    fs::File::from(fd)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("{label} read failed"))?;
    ensure!(
        bytes.len() as u64 <= max_bytes,
        "{label} exceeds {max_bytes} byte limit"
    );
    let after = statat(parent.fd(), parent.file_name(), AtFlags::SYMLINK_NOFOLLOW)
        .with_context(|| format!("{label} post-read metadata failed"))?;
    ensure!(
        FileType::from_raw_mode(after.st_mode) == FileType::RegularFile
            && (opened.st_dev, opened.st_ino) == (after.st_dev, after.st_ino),
        "{label} was replaced during read"
    );
    String::from_utf8(bytes).with_context(|| format!("{label} is not UTF-8"))
}

#[cfg(not(unix))]
pub(crate) fn read_stable_utf8_file_with_hook(
    path: &Path,
    max_bytes: u64,
    label: &str,
    after_open: impl FnOnce(),
) -> Result<String> {
    use std::io::Read as _;

    let before = fs::symlink_metadata(path).with_context(|| format!("{label} metadata failed"))?;
    ensure!(
        !before.file_type().is_symlink() && before.is_file(),
        "{label} rejects symlink/non-regular file"
    );
    ensure!(
        before.len() <= max_bytes,
        "{label} exceeds {max_bytes} byte limit"
    );
    let mut file = fs::File::open(path).with_context(|| format!("{label} open failed"))?;
    after_open();
    let mut bytes = Vec::new();
    file.by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("{label} read failed"))?;
    let after =
        fs::symlink_metadata(path).with_context(|| format!("{label} post-read metadata failed"))?;
    ensure!(
        after.is_file()
            && before.len() == after.len()
            && before.modified().ok() == after.modified().ok(),
        "{label} was replaced during read"
    );
    String::from_utf8(bytes).with_context(|| format!("{label} is not UTF-8"))
}

/// Atomically replace one file in-place, sync its contents, and sync the held parent directory.
///
/// Unix publication is entirely `*at`-relative to an `O_NOFOLLOW` directory capability. The only
/// temporary artifact inode starts and remains `0600` while content is written; immediately before
/// rename its held descriptor receives either the replaced regular file's ordinary permission bits
/// or `0644` limited by the process umask. This primitive never removes a temporary file it did not
/// successfully create.
#[cfg(unix)]
pub(crate) fn atomic_replace(path: &Path, content: &[u8]) -> Result<()> {
    atomic_replace_unix(path, content)
}

#[cfg(not(unix))]
pub(crate) fn atomic_replace(path: &Path, content: &[u8]) -> Result<()> {
    atomic_replace_fallback(path, content)
}

/// Remove one regular file without ever following a symlinked parent or leaf.
///
/// The target identity is checked immediately before the dirfd-relative unlink. A concurrent
/// parent rename therefore cannot redirect deletion to a different directory tree.
#[cfg(all(unix, test))]
fn remove_regular_file(path: &Path) -> Result<()> {
    remove_regular_file_unix_with_hook(path, || {})
}

#[cfg(all(unix, test))]
fn remove_regular_file_unix_with_hook(path: &Path, after_open: impl FnOnce()) -> Result<()> {
    let parent = open_parent_directory(path)?;
    remove_regular_file_in_directory_inner(&parent, parent.file_name(), path, after_open)
}

#[cfg(all(unix, test))]
fn remove_regular_file_in_directory_inner(
    parent: &ParentDirectory,
    file_name: &OsStr,
    display_path: &Path,
    after_open: impl FnOnce(),
) -> Result<()> {
    use rustix::fs::{AtFlags, fsync, unlinkat};

    let target = TargetPublication::inspect_named(parent, file_name)?;
    ensure!(
        matches!(target, TargetPublication::Existing { .. }),
        "删除目标不存在: {}",
        display_path.display()
    );
    after_open();
    target.ensure_unchanged_named(parent, file_name)?;
    unlinkat(parent.fd(), file_name, AtFlags::empty())
        .with_context(|| format!("安全删除 {} 失败", display_path.display()))?;
    fsync(parent.fd())?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn remove_regular_file(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} 无父目录", path.display()))?;
    let canonical_parent = fs::canonicalize(parent).context("解析删除目标父目录失败")?;
    ensure!(canonical_parent.is_dir(), "删除目标父路径不是目录");
    let metadata = fs::symlink_metadata(path).context("读取删除目标 metadata 失败")?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "删除目标不是普通文件"
    );
    fs::remove_file(path)?;
    ensure!(
        fs::canonicalize(parent).context("重新解析删除目标父目录失败")? == canonical_parent,
        "删除期间父目录被替换"
    );
    Ok(())
}

#[cfg(unix)]
fn atomic_replace_unix(path: &Path, content: &[u8]) -> Result<()> {
    atomic_replace_unix_inner(path, content, |_| {})
}

#[cfg(all(unix, test))]
fn atomic_replace_unix_with_hook(
    path: &Path,
    content: &[u8],
    temp_ready: impl FnOnce(&fs::File),
) -> Result<()> {
    atomic_replace_unix_inner(path, content, temp_ready)
}

#[cfg(unix)]
fn atomic_replace_unix_inner(
    path: &Path,
    content: &[u8],
    temp_ready: impl FnOnce(&fs::File),
) -> Result<()> {
    let parent = open_or_create_parent_directory(path)?;
    atomic_replace_in_directory_inner(&parent, parent.file_name(), path, content, temp_ready)
}

#[cfg(unix)]
fn atomic_replace_in_directory_inner(
    parent: &ParentDirectory,
    file_name: &OsStr,
    display_path: &Path,
    content: &[u8],
    temp_ready: impl FnOnce(&fs::File),
) -> Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags, fchmod, fsync, openat, renameat, unlinkat};

    let file_name_str = file_name.to_str().context("generated 文件名不是 UTF-8")?;
    let target = TargetPublication::inspect_named(parent, file_name)?;
    let mut opened = None;
    for _ in 0..64 {
        let temp_name = format!(
            ".{file_name_str}.tmp-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let flags =
            OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::WRONLY | OFlags::CLOEXEC;
        match openat(
            parent.fd(),
            temp_name.as_str(),
            flags,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => {
                opened = Some((temp_name, fd));
                break;
            }
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => return Err(error).context("创建临时文件失败"),
        }
    }
    let (temp_name, fd) = opened.context("临时文件名冲突次数超限")?;
    let mut file = fs::File::from(fd);
    let result = (|| -> Result<()> {
        file.write_all(content)?;
        file.flush()?;
        file.sync_all()?;
        temp_ready(&file);
        target.ensure_unchanged_named(parent, file_name)?;
        fchmod(&file, target.mode()).context("设置 committed generated 文件 mode 失败")?;
        file.sync_all()?;
        renameat(parent.fd(), temp_name.as_str(), parent.fd(), file_name)
            .with_context(|| format!("renameat {temp_name} -> {} 失败", display_path.display()))?;
        drop(file);
        fsync(parent.fd())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = unlinkat(parent.fd(), temp_name.as_str(), AtFlags::empty());
    }
    result
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
enum TargetPublication {
    Missing {
        mode: rustix::fs::Mode,
    },
    Existing {
        device: rustix::fs::Dev,
        inode: u64,
        mode: rustix::fs::Mode,
    },
}

#[cfg(unix)]
impl TargetPublication {
    fn inspect_named(parent: &ParentDirectory, file_name: &OsStr) -> Result<Self> {
        use rustix::fs::{AtFlags, FileType, Mode, statat};

        match statat(parent.fd(), file_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => {
                ensure!(
                    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
                    "committed generated 目标不是普通文件"
                );
                Ok(Self::Existing {
                    device: stat.st_dev,
                    inode: stat.st_ino,
                    mode: Mode::from_raw_mode(stat.st_mode & 0o777),
                })
            }
            Err(error) if error == rustix::io::Errno::NOENT => Ok(Self::Missing {
                mode: probe_umask_limited_committed_mode(parent)?,
            }),
            Err(error) => Err(error).context("读取 committed generated 目标 metadata 失败"),
        }
    }

    fn mode(self) -> rustix::fs::Mode {
        match self {
            Self::Missing { mode } | Self::Existing { mode, .. } => mode,
        }
    }

    fn ensure_unchanged_named(self, parent: &ParentDirectory, file_name: &OsStr) -> Result<()> {
        use rustix::fs::{AtFlags, FileType, statat};

        let current = statat(parent.fd(), file_name, AtFlags::SYMLINK_NOFOLLOW);
        match (self, current) {
            (Self::Missing { .. }, Err(error)) if error == rustix::io::Errno::NOENT => Ok(()),
            (
                Self::Existing {
                    device,
                    inode,
                    mode,
                },
                Ok(stat),
            ) if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                && (stat.st_dev, stat.st_ino) == (device, inode)
                && rustix::fs::Mode::from_raw_mode(stat.st_mode & 0o777) == mode =>
            {
                Ok(())
            }
            (Self::Missing { .. }, Ok(_)) | (Self::Existing { .. }, Ok(_)) => {
                anyhow::bail!("committed generated 目标在发布前被替换")
            }
            (_, Err(error)) => {
                Err(error).context("重新读取 committed generated 目标 metadata 失败")
            }
        }
    }
}

#[cfg(unix)]
fn probe_umask_limited_committed_mode(parent: &ParentDirectory) -> Result<rustix::fs::Mode> {
    use rustix::fs::{AtFlags, Mode, OFlags, fstat, openat, unlinkat};

    for _ in 0..64 {
        let probe_name = format!(
            ".rss-generated-mode-probe-{}-{}",
            std::process::id(),
            MODE_PROBE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let flags =
            OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::WRONLY | OFlags::CLOEXEC;
        match openat(
            parent.fd(),
            probe_name.as_str(),
            flags,
            Mode::from_raw_mode(0o644),
        ) {
            Ok(fd) => {
                let stat = fstat(&fd).context("读取 committed mode probe metadata 失败");
                drop(fd);
                unlinkat(parent.fd(), probe_name.as_str(), AtFlags::empty())
                    .context("清理 committed mode probe 失败")?;
                let stat = stat?;
                return Ok(Mode::from_raw_mode(stat.st_mode & 0o777));
            }
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => return Err(error).context("创建 committed mode probe 失败"),
        }
    }
    anyhow::bail!("committed mode probe 文件名冲突次数超限")
}

#[cfg(not(unix))]
fn atomic_replace_fallback(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} 无父目录", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("创建 {} 失败", parent.display()))?;
    let before = fs::canonicalize(parent).context("解析 generated 父目录失败")?;
    ensure!(before.is_dir(), "generated 父目录不是目录");
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
        let after = fs::canonicalize(parent).context("重新解析 generated 父目录失败")?;
        ensure!(before == after, "generated 父目录在发布期间被替换");
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

    #[cfg(unix)]
    #[test]
    fn atomic_replace_creates_missing_parents_without_following_symlinks() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("atomic-parent")?;
        let nested = fixture.root.join("new/deep/generated.json");
        atomic_replace(&nested, b"nested\n")?;
        assert_eq!(fs::read(&nested)?, b"nested\n");

        let outside = fixture.root.join("outside");
        fs::create_dir(&outside)?;
        symlink(&outside, fixture.root.join("linked"))?;
        let escaped = fixture.root.join("linked/deep/generated.json");
        assert!(atomic_replace(&escaped, b"must not escape\n").is_err());
        assert!(!outside.join("deep/generated.json").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replace_rejects_symlink_target_without_replacing_or_following_it()
    -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("atomic-target-symlink")?;
        let outside = fixture.root.join("outside.json");
        fs::write(&outside, b"outside\n")?;
        let output = fixture.root.join("generated.json");
        symlink(&outside, &output)?;

        assert!(atomic_replace(&output, b"must not publish\n").is_err());
        assert!(fs::symlink_metadata(&output)?.file_type().is_symlink());
        assert_eq!(fs::read(&outside)?, b"outside\n");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn remove_regular_file_never_follows_replaced_parent_or_leaf() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("remove-capability")?;
        let owner = fixture.root.join("owner");
        let moved_owner = fixture.root.join("moved-owner");
        let outside = fixture.root.join("outside");
        fs::create_dir(&owner)?;
        fs::create_dir(&outside)?;
        fs::write(owner.join("stale.txt"), b"owned\n")?;
        fs::write(outside.join("stale.txt"), b"outside\n")?;

        remove_regular_file_unix_with_hook(&owner.join("stale.txt"), || {
            fs::rename(&owner, &moved_owner).expect("move opened owner");
            symlink(&outside, &owner).expect("replace owner with symlink");
        })?;
        assert!(!moved_owner.join("stale.txt").exists());
        assert_eq!(fs::read(outside.join("stale.txt"))?, b"outside\n");

        let outside_leaf = fixture.root.join("outside-leaf.txt");
        fs::write(&outside_leaf, b"outside leaf\n")?;
        let linked_leaf = moved_owner.join("linked.txt");
        symlink(&outside_leaf, &linked_leaf)?;
        assert!(remove_regular_file(&linked_leaf).is_err());
        assert_eq!(fs::read(outside_leaf)?, b"outside leaf\n");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replace_uses_umask_limited_default_and_preserves_existing_mode() -> anyhow::Result<()>
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let fixture = Fixture::new("atomic-mode")?;
        let reference = fixture.root.join("reference-mode");
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .open(&reference)?;
        let expected_new_mode = fs::metadata(&reference)?.permissions().mode() & 0o777;

        let output = fixture.root.join("generated.json");
        atomic_replace_unix_with_hook(&output, b"new\n", |temporary| {
            assert_eq!(
                temporary
                    .metadata()
                    .expect("temporary metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600,
                "named temporary inode must remain private before publication"
            );
        })?;
        assert_eq!(
            fs::metadata(&output)?.permissions().mode() & 0o777,
            expected_new_mode,
            "new committed artifact must use 0644 limited by the process umask"
        );

        fs::set_permissions(&output, fs::Permissions::from_mode(0o640))?;
        atomic_replace(&output, b"replacement\n")?;
        assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o640);
        assert_eq!(fs::read(&output)?, b"replacement\n");
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
