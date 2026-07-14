use diport::DlxArchiveStore;
use eventexec::DlxArchiveObjectKey;

async fn forbidden_delete<S: DlxArchiveStore>(store: &S, key: &DlxArchiveObjectKey) {
    store.delete(key).await;
}

fn main() {}
