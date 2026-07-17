//! Strict, bounded startup-loaded `sha256:<lowercase-hex>` password blocklist.

use std::collections::HashSet;
use std::fs::File;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

const DIGEST_PREFIX: &[u8] = b"sha256:";
const DIGEST_HEX_LEN: usize = 64;
const MAX_LINE_BYTES: usize = 4 * 1024;
const MAX_ENTRIES: usize = 1_000_000;
const MAX_RECORDS: usize = MAX_ENTRIES + MAX_ENTRIES / 10;
const MAX_TOTAL_BYTES: usize = 80 * 1024 * 1024;

#[derive(Clone, Copy)]
struct LoadLimits {
    entries: usize,
    records: usize,
    total_bytes: usize,
}

const PRODUCTION_LIMITS: LoadLimits = LoadLimits {
    entries: MAX_ENTRIES,
    records: MAX_RECORDS,
    total_bytes: MAX_TOTAL_BYTES,
};

/// Blocklist construction failure; messages exclude paths, content and digests.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PasswordBlocklistLoadError {
    #[error("password blocklist read failed")]
    Read(#[source] std::io::Error),
    #[error("password blocklist source is not a regular file")]
    NotRegularFile,
    #[error("password blocklist entry has invalid format")]
    InvalidFormat,
    #[error("password blocklist entry exceeds the line limit")]
    LineTooLong,
    #[error("password blocklist exceeds the entry limit")]
    TooManyEntries,
    #[error("password blocklist exceeds the physical input limit")]
    InputTooLarge,
    #[error("password blocklist contains no entries")]
    Empty,
}

/// Safely open and load a concrete non-empty password blocklist.
pub fn load_password_blocklist(
    path: impl AsRef<Path>,
) -> Result<secure::DigestPasswordBlocklist, PasswordBlocklistLoadError> {
    let file = open_blocklist(path.as_ref()).map_err(PasswordBlocklistLoadError::Read)?;
    if !file
        .metadata()
        .map_err(PasswordBlocklistLoadError::Read)?
        .is_file()
    {
        return Err(PasswordBlocklistLoadError::NotRegularFile);
    }
    load_password_blocklist_from_reader(file)
}

#[cfg(unix)]
fn open_blocklist(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_blocklist(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

/// Validate a hermetic reader and return the same concrete value used in production.
pub fn load_password_blocklist_from_reader(
    reader: impl Read,
) -> Result<secure::DigestPasswordBlocklist, PasswordBlocklistLoadError> {
    load_password_blocklist_from_reader_with_limits(reader, PRODUCTION_LIMITS)
}

fn load_password_blocklist_from_reader_with_limits(
    reader: impl Read,
    limits: LoadLimits,
) -> Result<secure::DigestPasswordBlocklist, PasswordBlocklistLoadError> {
    let mut digests = HashSet::new();
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    let mut entries = 0_usize;
    let mut records = 0_usize;
    let mut total_bytes = 0_usize;

    loop {
        line.clear();
        let bytes = (&mut reader)
            .take(u64::try_from(MAX_LINE_BYTES + 1).unwrap_or(u64::MAX))
            .read_until(b'\n', &mut line)
            .map_err(PasswordBlocklistLoadError::Read)?;
        if bytes == 0 {
            break;
        }
        records = records.saturating_add(1);
        total_bytes = total_bytes.saturating_add(bytes);
        if records > limits.records || total_bytes > limits.total_bytes {
            return Err(PasswordBlocklistLoadError::InputTooLarge);
        }
        if line.len() > MAX_LINE_BYTES {
            return Err(PasswordBlocklistLoadError::LineTooLong);
        }
        trim_line_ending(&mut line);
        std::str::from_utf8(&line).map_err(|_| PasswordBlocklistLoadError::InvalidFormat)?;
        if line.is_empty() || line.first() == Some(&b'#') {
            continue;
        }
        let digest = parse_digest(&line)?;
        entries += 1;
        if entries > limits.entries {
            return Err(PasswordBlocklistLoadError::TooManyEntries);
        }
        digests.insert(digest);
    }

    let Some(first) = digests.iter().next().copied() else {
        return Err(PasswordBlocklistLoadError::Empty);
    };
    digests.remove(&first);
    Ok(secure::DigestPasswordBlocklist::from_nonempty_sha256_digests(first, digests))
}

fn trim_line_ending(line: &mut Vec<u8>) {
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
}

fn parse_digest(line: &[u8]) -> Result<[u8; 32], PasswordBlocklistLoadError> {
    let Some(hex) = line.strip_prefix(DIGEST_PREFIX) else {
        return Err(PasswordBlocklistLoadError::InvalidFormat);
    };
    if hex.len() != DIGEST_HEX_LEN {
        return Err(PasswordBlocklistLoadError::InvalidFormat);
    }

    let mut out = [0_u8; 32];
    for (index, pair) in hex.chunks_exact(2).enumerate() {
        out[index] = (lower_hex(pair[0])? << 4) | lower_hex(pair[1])?;
    }
    Ok(out)
}

fn lower_hex(byte: u8) -> Result<u8, PasswordBlocklistLoadError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(PasswordBlocklistLoadError::InvalidFormat),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::error::Error as _;
    use std::io::{self, Cursor, Read};
    use std::mem::discriminant;
    use std::sync::Arc;

    use sha2::{Digest, Sha256};

    use super::{
        LoadLimits, MAX_LINE_BYTES, PasswordBlocklistLoadError, load_password_blocklist,
        load_password_blocklist_from_reader, load_password_blocklist_from_reader_with_limits,
    };
    use PasswordBlocklistLoadError::{InputTooLarge, TooManyEntries};

    const COMPROMISED: &str = "correct horse battery staple";
    const COMPROMISED_DIGEST: &str =
        "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a";

    fn digest_hex(raw: &str) -> String {
        Sha256::digest(raw.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn load_error(raw: impl AsRef<[u8]>) -> PasswordBlocklistLoadError {
        load_password_blocklist_from_reader(Cursor::new(raw)).expect_err("fixture must be rejected")
    }

    fn limits(entries: usize, records: usize, total_bytes: usize) -> LoadLimits {
        LoadLimits {
            entries,
            records,
            total_bytes,
        }
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "sensitive"))
        }
    }

    #[test]
    fn loads_comments_blank_lines_crlf_and_duplicates_through_the_real_policy_seam() {
        let data = format!(
            "# audited source\r\n\r\nsha256:{COMPROMISED_DIGEST}\r\nsha256:{COMPROMISED_DIGEST}\n"
        );
        let blocklist =
            load_password_blocklist_from_reader(Cursor::new(data)).expect("valid blocklist");
        let policy = secure::PasswordPolicy::new(Arc::new(blocklist));
        assert_eq!(
            policy
                .validate(secure::RawPassword::new(COMPROMISED.to_owned()))
                .err(),
            Some(secure::PasswordPolicyError::Compromised)
        );
        assert!(
            policy
                .validate(secure::RawPassword::new(format!("{COMPROMISED}!")))
                .is_ok()
        );
    }

    #[test]
    fn rejects_empty_and_comment_only_inputs() {
        for raw in ["", "\n", "# source\n"] {
            let error = load_error(raw);
            assert!(matches!(error, PasswordBlocklistLoadError::Empty));
        }
    }

    #[test]
    fn enforces_injectable_entry_record_and_byte_limits() {
        let entry = format!("sha256:{}\n", digest_hex(COMPROMISED));
        let cases = [
            (
                format!("{entry}{entry}"),
                limits(1, 2, usize::MAX),
                TooManyEntries,
            ),
            (
                "# first\n# second\n".to_owned(),
                limits(usize::MAX, 1, usize::MAX),
                InputTooLarge,
            ),
            (entry.clone(), limits(1, 1, entry.len() - 1), InputTooLarge),
        ];

        for (raw, limits, expected) in cases {
            let error = load_password_blocklist_from_reader_with_limits(Cursor::new(raw), limits)
                .expect_err("bounded fixture must be rejected");
            assert_eq!(discriminant(&error), discriminant(&expected));
        }
    }

    #[test]
    fn rejects_bad_prefix_width_hex_case_and_utf8() {
        let valid = digest_hex(COMPROMISED);
        let cases = [
            format!("sha1:{valid}\n").into_bytes(),
            b"sha256:abcd\n".to_vec(),
            format!("sha256:{}\n", valid.to_uppercase()).into_bytes(),
            b"sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n".to_vec(),
            vec![0xff, b'\n'],
            vec![b'#', 0xff, b'\n'],
        ];
        for raw in cases {
            let error = load_error(raw);
            assert!(matches!(error, PasswordBlocklistLoadError::InvalidFormat));
        }
    }

    #[test]
    fn load_accepts_regular_files_and_rejects_non_regular_sources() {
        let fixture = std::env::temp_dir().join(format!("rss-blocklist-{}", std::process::id()));
        std::fs::write(&fixture, format!("sha256:{}\n", digest_hex(COMPROMISED)))
            .expect("write blocklist fixture");
        assert!(load_password_blocklist(&fixture).is_ok());
        std::fs::remove_file(fixture).expect("remove blocklist fixture");

        let error =
            load_password_blocklist(std::env::temp_dir()).expect_err("directory must be rejected");
        assert!(matches!(error, PasswordBlocklistLoadError::NotRegularFile));
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_a_symlink_instead_of_following_it() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "rss-blocklist-symlink-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&root).expect("create fixture directory");
        let target = root.join("target");
        let link = root.join("link");
        std::fs::write(&target, format!("sha256:{}\n", digest_hex(COMPROMISED)))
            .expect("write target");
        symlink(&target, &link).expect("create symlink");

        let error = load_password_blocklist(&link).expect_err("symlink must be rejected");
        assert!(matches!(
            error,
            PasswordBlocklistLoadError::Read(source)
                if source.raw_os_error() == Some(libc::ELOOP)
        ));

        std::fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "subprocess target for the bounded FIFO regression"]
    fn fifo_loader_subprocess() {
        let Some(path) = std::env::var_os("RSS_TEST_PASSWORD_BLOCKLIST_FIFO") else {
            return;
        };
        let error = load_password_blocklist(path).expect_err("FIFO must be rejected");
        assert!(matches!(error, PasswordBlocklistLoadError::NotRegularFile));
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_a_fifo_without_blocking() {
        use std::process::Command;
        use std::time::Duration;

        let root = std::env::temp_dir().join(format!(
            "rss-blocklist-fifo-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&root).expect("create fixture directory");
        let fifo = root.join("blocklist");
        let status = Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run system mkfifo");
        assert!(status.success(), "mkfifo failed: {status}");

        let mut child = Command::new(std::env::current_exe().expect("locate test binary"))
            .args([
                "--ignored",
                "--exact",
                "password_blocklist::tests::fifo_loader_subprocess",
            ])
            .env("RSS_TEST_PASSWORD_BLOCKLIST_FIFO", &fifo)
            .spawn()
            .expect("spawn bounded FIFO loader");
        let mut status = None;
        for _ in 0..300 {
            if let Some(exit) = child.try_wait().expect("poll FIFO loader") {
                status = Some(exit);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if status.is_none() {
            child.kill().expect("kill blocked FIFO loader");
            child.wait().expect("reap blocked FIFO loader");
        }

        std::fs::remove_dir_all(root).expect("remove fixture directory");
        let status = status.expect("FIFO loader exceeded the three-second bound");
        assert!(status.success(), "FIFO loader subprocess failed: {status}");
    }

    #[test]
    fn read_errors_keep_sources_but_display_static_redacted_messages() {
        let raw = format!("{}\n", "x".repeat(MAX_LINE_BYTES + 1));
        let error = load_error(raw);
        assert_eq!(
            error.to_string(),
            "password blocklist entry exceeds the line limit"
        );
        let error = load_password_blocklist("/definitely/missing/rss-password-blocklist")
            .expect_err("missing file must fail");
        assert_eq!(error.to_string(), "password blocklist read failed");
        assert!(error.source().is_some());
        assert!(matches!(
            error,
            PasswordBlocklistLoadError::Read(source)
                if source.kind() == io::ErrorKind::NotFound
        ));

        let error = load_password_blocklist_from_reader(FailingReader)
            .expect_err("read failure must be retained");
        assert_eq!(error.to_string(), "password blocklist read failed");
        assert!(!error.to_string().contains("sensitive"));
        assert!(matches!(
            error,
            PasswordBlocklistLoadError::Read(source)
                if source.kind() == io::ErrorKind::PermissionDenied
        ));
    }
}
