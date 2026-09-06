use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    Router, body::Body, extract::Request, middleware, response::IntoResponse, routing::get,
};
use http_body_util::BodyExt as _;
use rss_axum::{HttpError, RequestBudget, RequestControl, request_control};
use rss_contract::{SafeError, SafeErrorCode};
use rss_request_context::{
    CancellationObserver as _, CancellationReason, Deadline, RequestId, TenantId,
};
use tower::ServiceExt as _;

#[tokio::test]
async fn closed_errors_have_only_safe_code_and_message() {
    let cases = [
        (SafeErrorCode::InvalidInput, 400),
        (SafeErrorCode::Unauthenticated, 401),
        (SafeErrorCode::Forbidden, 403),
        (SafeErrorCode::NotFound, 404),
        (SafeErrorCode::Conflict, 409),
        (SafeErrorCode::RateLimited, 429),
        (SafeErrorCode::Unavailable, 503),
        (SafeErrorCode::Internal, 500),
    ];
    for (code, status) in cases {
        let response = HttpError::from(SafeError::new(code)).into_response();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["content-type"], "application/json");
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|e| unreachable!("{e}"))
            .to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).ok(),
            Some(serde_json::json!({"error":{"code":code.as_str(),"message":code.message()}}))
        );
    }
}

#[test]
fn zero_and_overflow_budgets_are_rejected() {
    assert!(RequestBudget::new(Duration::ZERO).is_err());
    assert!(RequestBudget::new(Duration::MAX).is_err());
    assert!(RequestBudget::new(Duration::from_secs(1)).is_ok());
}

#[tokio::test(start_paused = true)]
#[allow(clippy::unwrap_used, clippy::disallowed_methods)]
async fn timeout_drops_handler_and_preserves_earliest_budget() {
    struct Dropped(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = Arc::new(Mutex::new(None::<RequestControl>));
    let route = {
        let dropped = dropped.clone();
        let observed = observed.clone();
        get(move |request: Request| async move {
            *observed.lock().unwrap() = request.extensions().get::<RequestControl>().cloned();
            let _guard = Dropped(dropped);
            std::future::pending::<&'static str>().await
        })
    };
    let app = Router::new()
        .route("/", route)
        .layer(middleware::from_fn_with_state(
            RequestBudget::new(Duration::from_secs(60)).unwrap(),
            request_control,
        ))
        .layer(middleware::from_fn_with_state(
            RequestBudget::new(Duration::from_secs(1)).unwrap(),
            request_control,
        ));
    let start = tokio::time::Instant::now();
    let response = app.oneshot(Request::new(Body::empty())).await.unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(start.elapsed(), Duration::from_secs(1));
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    let control = observed.lock().unwrap().clone().unwrap();
    assert!(control.is_cancelled());
    assert_eq!(
        control
            .cancelled(Deadline::at(
                control.deadline().instant() + Duration::from_secs(60)
            ))
            .await,
        CancellationReason::DeadlineExceeded
    );
}

#[tokio::test(start_paused = true)]
#[allow(clippy::unwrap_used, clippy::disallowed_methods)]
async fn context_is_explicit_and_streaming_outlives_request_control() {
    let observed = Arc::new(Mutex::new(None::<RequestControl>));
    let saved = observed.clone();
    let app = Router::new()
        .route(
            "/",
            get(move |request: Request| async move {
                let control = request
                    .extensions()
                    .get::<RequestControl>()
                    .unwrap()
                    .clone();
                let id = RequestId::parse("request-7").unwrap();
                let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
                let view = control.context(Some(&tenant), &id);
                assert_eq!(view.tenant(), Some(&tenant));
                assert_eq!(view.request_id(), &id);
                assert_eq!(view.deadline(), control.deadline());
                *saved.lock().unwrap() = Some(control);
                // Delayed body production is owned by the product, after the Response is returned.
                let stream = http_body_util::StreamBody::new(DelayedFrame {
                    sleep: Box::pin(tokio::time::sleep(Duration::from_secs(5))),
                    sent: false,
                });
                Body::new(stream)
            }),
        )
        .layer(middleware::from_fn_with_state(
            RequestBudget::new(Duration::from_secs(1)).unwrap(),
            request_control,
        ));
    let response = app.oneshot(Request::new(Body::empty())).await.unwrap();
    assert!(observed.lock().unwrap().as_ref().unwrap().is_cancelled());
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "done"
    );
}

struct DelayedFrame {
    sleep: std::pin::Pin<Box<tokio::time::Sleep>>,
    sent: bool,
}
impl futures::Stream for DelayedFrame {
    type Item = Result<http_body::Frame<axum::body::Bytes>, std::convert::Infallible>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::future::Future as _;
        if self.sent {
            return std::task::Poll::Ready(None);
        }
        std::task::ready!(self.sleep.as_mut().poll(cx));
        self.sent = true;
        std::task::Poll::Ready(Some(Ok(http_body::Frame::data(
            axum::body::Bytes::from_static(b"done"),
        ))))
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn dropping_request_future_cancels_observers_and_drops_downstream() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let observed = Arc::new(Mutex::new(None::<RequestControl>));
    let app = {
        let entered = entered.clone();
        let observed = observed.clone();
        Router::new()
            .route(
                "/",
                get(move |request: Request| async move {
                    *observed.lock().unwrap() =
                        request.extensions().get::<RequestControl>().cloned();
                    entered.notify_one();
                    std::future::pending::<&'static str>().await
                }),
            )
            .layer(middleware::from_fn_with_state(
                RequestBudget::new(Duration::from_secs(60)).unwrap(),
                request_control,
            ))
    };
    let task = tokio::spawn(app.oneshot(Request::new(Body::empty())));
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    let control = observed.lock().unwrap().clone().unwrap();
    assert!(!control.is_cancelled());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        control.cancelled(control.deadline()).await,
        CancellationReason::Cancelled
    );
}

#[tokio::test(start_paused = true)]
#[allow(clippy::unwrap_used)]
async fn completed_handler_wins_when_deadline_is_ready_in_the_same_poll() {
    let app = Router::new()
        .route(
            "/",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                "committed"
            }),
        )
        .layer(middleware::from_fn_with_state(
            RequestBudget::new(Duration::from_secs(1)).unwrap(),
            request_control,
        ));
    let response = app.oneshot(Request::new(Body::empty())).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "committed"
    );
}
