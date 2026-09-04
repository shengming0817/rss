use std::time::Duration;

use rss_runtime::{DynManagedResource, ManagedTask};
use tokio_util::sync::CancellationToken;

fn main() {
    let (start, _) = ManagedTask::prepare("external", Duration::from_secs(1));
    let task = start.spawn_detached(CancellationToken::new(), |_| async { Ok(()) });
    let _bypass = DynManagedResource::new_box(task);
}
