use crate::ctx::AppCtx;
use std::future::Future;

tokio::task_local! {
    static REQUEST_CTX: AppCtx;
}

#[must_use = "scope returns a future that must be awaited"]
pub fn scope<F>(ctx: AppCtx, future: F) -> impl Future<Output = F::Output>
where
    F: Future,
{
    REQUEST_CTX.scope(ctx, future)
}

pub fn try_with<R>(read: impl FnOnce(&AppCtx) -> R) -> Result<R, MissingCtx> {
    REQUEST_CTX.try_with(read).map_err(|_| MissingCtx)
}

pub fn try_current() -> Result<AppCtx, MissingCtx> {
    try_with(Clone::clone)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("request context missing")]
pub struct MissingCtx;
