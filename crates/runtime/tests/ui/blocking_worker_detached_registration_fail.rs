use std::time::Duration;

use rss_runtime::{DynManagedResource, ManagedBlockingWorker};
use tokio_util::sync::CancellationToken;

fn main() {
    let worker = ManagedBlockingWorker::try_spawn(
        "external",
        CancellationToken::new(),
        Duration::from_secs(1),
        |_| Ok(()),
    )
    .unwrap();
    let _bypass = DynManagedResource::new_box(worker);
}
