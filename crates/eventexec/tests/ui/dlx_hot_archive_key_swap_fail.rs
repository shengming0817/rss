use eventexec::{DlxArchiveKeyName, DlxHotKeyName};

fn requires_hot_key(_key: DlxHotKeyName) {}

fn main() {
    let Ok(archive_key) = DlxArchiveKeyName::try_new("archive-only") else {
        return;
    };
    requires_hot_key(archive_key);
}
