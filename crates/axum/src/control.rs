//! Request-future lifetime only; response streaming is owned by the product.
use crate::HttpError;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use rss_contract::{SafeError, SafeErrorCode};
use rss_request_context::{
    Cancellation, CancellationFuture, CancellationObserver, Deadline, RequestContextView,
    RequestId, TenantId,
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Explicit nonzero maximum time for downstream processing until a Response is returned.
#[derive(Debug, Clone, Copy)]
pub struct RequestBudget(Duration);

/// Invalid local configuration; never stores the rejected value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RequestBudgetError {
    /// A request must have some processing time.
    #[error("request budget must be nonzero")]
    Zero,
    /// The platform monotonic clock cannot represent the deadline.
    #[error("request deadline is not representable")]
    Overflow,
}

#[allow(
    clippy::disallowed_methods,
    reason = "HTTP transport owns the monotonic request deadline source"
)]
impl RequestBudget {
    /// Validate a caller-selected budget against the transport's monotonic clock.
    pub fn new(duration: Duration) -> Result<Self, RequestBudgetError> {
        if duration.is_zero() {
            return Err(RequestBudgetError::Zero);
        }
        tokio::time::Instant::now()
            .checked_add(duration)
            .ok_or(RequestBudgetError::Overflow)?;
        Ok(Self(duration))
    }
}

/// Cloneable read-only observation of one request lifetime. The cancellation trigger is private.
#[derive(Debug, Clone)]
pub struct RequestControl {
    deadline: Deadline,
    cancellation: CancellationToken,
}

impl RequestControl {
    #[allow(
        clippy::disallowed_methods,
        reason = "HTTP transport owns the monotonic request deadline source"
    )]
    fn start(budget: RequestBudget, parent: Option<&Self>) -> Result<Self, RequestBudgetError> {
        let instant = tokio::time::Instant::now()
            .checked_add(budget.0)
            .ok_or(RequestBudgetError::Overflow)?
            .into_std();
        let (deadline, cancellation) = match parent {
            Some(parent) => (
                parent.deadline.shortened_to(instant),
                parent.cancellation.child_token(),
            ),
            None => (Deadline::at(instant), CancellationToken::new()),
        };
        Ok(Self {
            deadline,
            cancellation,
        })
    }

    /// Observe the original or shortened absolute deadline.
    pub fn deadline(&self) -> Deadline {
        self.deadline
    }

    /// Project caller-supplied identity values, without authenticating or authorizing them.
    pub fn context<'a>(
        &'a self,
        tenant: Option<&'a TenantId>,
        request_id: &'a RequestId,
    ) -> RequestContextView<'a> {
        RequestContextView::new(
            tenant,
            request_id,
            self.deadline,
            Cancellation::observe(self),
        )
    }
}

impl CancellationObserver for RequestControl {
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn cancelled(&self) -> CancellationFuture<'_> {
        Box::pin(self.cancellation.cancelled())
    }
}

struct EndRequest(RequestControl);
impl Drop for EndRequest {
    fn drop(&mut self) {
        self.0.cancellation.cancel();
    }
}

/// Use with `axum::middleware::from_fn_with_state(budget, request_control)`.
///
/// Place outside every middleware whose processing must share this budget. Nested installation
/// only shortens the inherited deadline. Completion, timeout and future drop end observation;
/// timeout stops waiting and does not prove rollback. Response-body transmission is not timed.
#[allow(
    clippy::disallowed_methods,
    reason = "HTTP transport enforces its own monotonic request deadline"
)]
pub async fn request_control(
    State(budget): State<RequestBudget>,
    mut request: Request,
    next: Next,
) -> Response {
    let control = match RequestControl::start(budget, request.extensions().get()) {
        Ok(control) => control,
        Err(_) => return HttpError::from(SafeError::new(SafeErrorCode::Internal)).into_response(),
    };
    // Do not admit new downstream work when an inherited control has already ended.
    if control.is_cancelled()
        || control
            .deadline
            .is_expired(tokio::time::Instant::now().into_std())
    {
        return HttpError::from(SafeError::new(SafeErrorCode::Unavailable)).into_response();
    }
    request.extensions_mut().insert(control.clone());
    let _end = EndRequest(control.clone());
    tokio::select! {
        biased;
        // Preserve a completed result when termination becomes ready in the same poll.
        response = next.run(request) => response,
        () = control.cancelled() => HttpError::from(SafeError::new(SafeErrorCode::Unavailable)).into_response(),
        // Deadline polling must not inherit a budget exhausted by downstream work.
        () = tokio::task::unconstrained(tokio::time::sleep_until(control.deadline.instant().into())) => HttpError::from(SafeError::new(SafeErrorCode::Unavailable)).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    #[allow(
        clippy::unwrap_used,
        clippy::disallowed_methods,
        reason = "test controls the transport clock"
    )]
    async fn deadline_is_not_a_cancellation_signal() {
        use std::task::Poll;
        let control =
            RequestControl::start(RequestBudget::new(Duration::from_secs(1)).unwrap(), None)
                .unwrap();
        let mut cancelled = control.cancelled();
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            control
                .deadline
                .is_expired(tokio::time::Instant::now().into_std())
        );
        assert!(!control.is_cancelled());
        std::future::poll_fn(|cx| {
            assert!(cancelled.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        control.cancellation.cancel();
        cancelled.await;
        assert!(control.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    #[allow(
        clippy::unwrap_used,
        reason = "test uses validated fixed budgets and an infallible router"
    )]
    async fn ended_parent_never_admits_downstream() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use tower::ServiceExt as _;
        for expired in [false, true] {
            let parent =
                RequestControl::start(RequestBudget::new(Duration::from_secs(1)).unwrap(), None)
                    .unwrap();
            if expired {
                tokio::time::advance(Duration::from_secs(1)).await;
            } else {
                parent.cancellation.cancel();
            }
            let called = Arc::new(AtomicBool::new(false));
            let observed = called.clone();
            let router = axum::Router::new()
                .route(
                    "/",
                    axum::routing::get(move || async move {
                        observed.store(true, Ordering::SeqCst);
                        "unexpected"
                    }),
                )
                .layer(axum::middleware::from_fn_with_state(
                    RequestBudget::new(Duration::from_secs(60)).unwrap(),
                    request_control,
                ));
            let mut request = Request::new(axum::body::Body::empty());
            request.extensions_mut().insert(parent);
            assert_eq!(router.oneshot(request).await.unwrap().status(), 503);
            assert!(!called.load(Ordering::SeqCst));
        }
    }
}
