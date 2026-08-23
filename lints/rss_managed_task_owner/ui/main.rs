use std::time::Duration;
use std::sync::Arc;

use diport::{ManagedResource, ManagedTask, ShutdownError};
use managed_task_owner_fixture::CrossCrateRawOwner;
use tokio::task::JoinHandle;

struct Direct {
    handle: JoinHandle<()>,
}

impl ManagedResource for Direct {
    fn name(&self) -> &str { "direct" }
    async fn shutdown(&self) -> Result<(), ShutdownError> { Ok(()) }
}

type HandleAlias = JoinHandle<()>;
struct Wrapped(HandleAlias);
struct ThroughNewtype {
    wrapped: Wrapped,
}

impl ManagedResource for ThroughNewtype {
    fn name(&self) -> &str { "wrapped" }
    async fn shutdown(&self) -> Result<(), ShutdownError> { Ok(()) }
}

struct NestedOwner {
    inner: Arc<tokio::sync::Mutex<Vec<JoinHandle<()>>>>,
}

impl ManagedResource for NestedOwner {
    fn name(&self) -> &str { "nested" }
    async fn shutdown(&self) -> Result<(), ShutdownError> { Ok(()) }
}

struct GenericWrap<T>(T);
struct RepeatedGenericOwner {
    canonical_first: GenericWrap<ManagedTask>,
    raw_second: GenericWrap<JoinHandle<()>>,
}

mod impostor {
    pub struct ManagedTask {
        pub raw: tokio::task::JoinHandle<()>,
    }
}

struct SameNameOwner {
    task: impostor::ManagedTask,
}

impl ManagedResource for SameNameOwner {
    fn name(&self) -> &str { "same-name" }
    async fn shutdown(&self) -> Result<(), ShutdownError> { Ok(()) }
}

impl ManagedResource for RepeatedGenericOwner {
    fn name(&self) -> &str { "repeated-generic" }
    async fn shutdown(&self) -> Result<(), ShutdownError> { Ok(()) }
}

struct ThroughCrossCrateNewtype {
    wrapped: CrossCrateRawOwner,
}

impl ManagedResource for ThroughCrossCrateNewtype {
    fn name(&self) -> &str { "cross-crate-newtype" }
    async fn shutdown(&self) -> Result<(), ShutdownError> { Ok(()) }
}

struct Canonical {
    task: ManagedTask,
}

impl ManagedResource for Canonical {
    fn name(&self) -> &str { "canonical" }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        ManagedResource::shutdown(&self.task).await
    }
}

struct NoBackgroundTask;

impl ManagedResource for NoBackgroundTask {
    fn name(&self) -> &str { "none" }
    fn shutdown_timeout(&self) -> Duration { Duration::from_secs(1) }
    async fn shutdown(&self) -> Result<(), ShutdownError> { Ok(()) }
}

fn main() {}
