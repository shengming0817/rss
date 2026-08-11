use anyhow::{Context, Result, bail};
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

pub(crate) fn read_stable_ordinary_file(
    path: &Path,
    label: &str,
    size_limit: u64,
) -> Result<Vec<u8>> {
    read_stable_ordinary_file_with_hook(path, label, size_limit, || Ok(()))
}

pub(crate) fn read_stable_ordinary_file_with_hook(
    path: &Path,
    label: &str,
    size_limit: u64,
    after_precheck: impl FnOnce() -> Result<()>,
) -> Result<Vec<u8>> {
    let path_before = ordinary_file_metadata(path, label)?;
    ensure_bounded(path_before.len(), size_limit, label)?;
    after_precheck()?;

    let mut file = File::open(path).with_context(|| format!("open {label}"))?;
    let opened_before = file
        .metadata()
        .with_context(|| format!("inspect opened {label}"))?;
    ensure_same_path_identity(&path_before, &opened_before, label)?;
    let mut contents = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(
            size_limit
                .checked_add(1)
                .context("evidence read limit overflow")?,
        )
        .read_to_end(&mut contents)
        .with_context(|| format!("read {label}"))?;

    let opened_after = file
        .metadata()
        .with_context(|| format!("reinspect opened {label}"))?;
    let path_after = ordinary_file_metadata(path, label)?;
    ensure_same_path_identity(&opened_before, &opened_after, label)?;
    ensure_same_path_identity(&opened_before, &path_after, label)?;
    ensure_bounded(contents.len() as u64, size_limit, label)?;
    if contents.len() as u64 != opened_before.len() || opened_before.len() != opened_after.len() {
        bail!("{label} changed while being read");
    }
    Ok(contents)
}

pub(crate) fn prepare_output_slot(path: &Path, label: &str) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create {label} directory"))?;
    let parent_metadata =
        fs::symlink_metadata(parent).with_context(|| format!("inspect {label} directory"))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!("{label} parent must be an ordinary directory");
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("{label} output must be absent or an ordinary file")
        }
        Ok(_) => fs::remove_file(path).with_context(|| format!("remove stale {label}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(parent.to_path_buf())
}

pub(crate) fn atomic_publish(
    path: &Path,
    contents: &[u8],
    label: &str,
    temporary_stem: &str,
) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let temporary = parent.join(format!(".{temporary_stem}.tmp-{}", std::process::id()));
    match fs::symlink_metadata(&temporary) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("{label} temporary must be absent or an ordinary file")
        }
        Ok(_) => fs::remove_file(&temporary)
            .with_context(|| format!("remove stale {label} temporary"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| format!("create {label} temporary"))?;
    let result: std::io::Result<()> = (|| {
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.with_context(|| format!("publish {label} atomically"))
}

fn ordinary_file_metadata(path: &Path, label: &str) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{label} must be an ordinary file");
    }
    Ok(metadata)
}

fn ensure_bounded(size: u64, limit: u64, label: &str) -> Result<()> {
    if size == 0 || size > limit {
        bail!("{label} size is outside the accepted range");
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_same_path_identity(
    expected: &fs::Metadata,
    observed: &fs::Metadata,
    label: &str,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    if !observed.is_file()
        || expected.dev() != observed.dev()
        || expected.ino() != observed.ino()
        || expected.len() != observed.len()
        || expected.mtime() != observed.mtime()
        || expected.mtime_nsec() != observed.mtime_nsec()
        || expected.ctime() != observed.ctime()
        || expected.ctime_nsec() != observed.ctime_nsec()
    {
        bail!("{label} path identity changed during validation");
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_same_path_identity(
    _expected: &fs::Metadata,
    _observed: &fs::Metadata,
    label: &str,
) -> Result<()> {
    bail!("{label} cannot prove stable file identity on this platform")
}
