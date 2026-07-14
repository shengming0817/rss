use eventexec::VerifiedArchiveReceipt;

fn value<T>() -> T {
    panic!("compile-fail fixture")
}

fn main() {
    let _forged = VerifiedArchiveReceipt {
        id: value(),
        tenant: value(),
        object_key: value(),
        checksum: value(),
        archive_version_id: value(),
        archive_key_ref: value(),
        retain_until_epoch_secs: value(),
        verified_at_epoch_secs: value(),
    };
}
