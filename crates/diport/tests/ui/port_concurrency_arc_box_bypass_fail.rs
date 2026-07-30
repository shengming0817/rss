use std::sync::Arc;

use diport::{AsyncSync, DiPortConcurrency, DynSigner};

type HiddenSendPort = Arc<Box<DynSigner<'static>>>;

fn require_async_sync<T: ?Sized + DiPortConcurrency<Bucket = AsyncSync>>() {}

fn main() {
    require_async_sync::<HiddenSendPort>();
}
