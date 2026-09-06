//! Request-future lifetime only; response streaming is owned by the product.
use crate::HttpError;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use rss_contract::{SafeError, SafeErrorCode};
use rss_request_context::{
    Cancellation, CancellationFuture, CancellationObserver, CancellationReason, Deadline,
    RequestContextView, RequestId, TenantId,
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
    #[allow(
        clippy::disallowed_methods,
        reason = "observe the transport-owned deadline using the same monotonic clock"
    )]
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
            || self
                .deadline
                .is_expired(tokio::time::Instant::now().into_std())
    }

    fn cancelled(&self, deadline: Deadline) -> CancellationFuture<'_> {
        let instant = self.deadline.instant().min(deadline.instant());
        Box::pin(async move {
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(instant.into()) => CancellationReason::DeadlineExceeded,
                () = self.cancellation.cancelled() => CancellationReason::Cancelled,
            }
        })
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
    if control.is_cancelled() {
        return HttpError::from(SafeError::new(SafeErrorCode::Unavailable)).into_response();
    }
    request.extensions_mut().insert(control.clone());
    let _end = EndRequest(control.clone());
    tokio::select! {
        biased;
        // Preserve a completed result when termination becomes ready in the same poll.
        response = next.run(request) => response,
        _ = control.cancelled(control.deadline) => HttpError::from(SafeError::new(SafeErrorCode::Unavailable)).into_response(),
    }
}
