mod support;
use axum::{Router, body::Body, extract::Request};
use http_body_util::BodyExt as _;
use rss_axum::Endpoint;
use rss_contract::Contract;
use support::{App, Echo, echo};
use tower::ServiceExt as _;

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn endpoint_binds_method_path_state_and_safe_decode() {
    let endpoint = Endpoint::<Echo, App>::new(echo);
    assert_eq!(endpoint.descriptor(), Echo::DESCRIPTOR);
    let app = endpoint.mount(Router::new()).with_state(App(7));
    let request = |method, path, body: &'static str| {
        Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    };
    let response = app
        .clone()
        .oneshot(request("POST", "/echo", "5"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "12"
    );
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/echo", ""))
            .await
            .unwrap()
            .status(),
        405
    );
    assert_eq!(
        app.clone()
            .oneshot(request("POST", "/other", "5"))
            .await
            .unwrap()
            .status(),
        404
    );
    let response = app
        .oneshot(request("POST", "/echo", "private-invalid-payload"))
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(!String::from_utf8_lossy(&body).contains("private"));
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn product_layer_finalizes_both_decode_and_handler_authentication_errors() {
    use axum::{
        extract::State,
        http::{HeaderValue, StatusCode, header::WWW_AUTHENTICATE},
        middleware,
        response::Response,
        routing::MethodFilter,
    };
    use rss_axum::{ContractMarker, HttpContract};
    use rss_contract::{ContractDescriptor, SafeError, SafeErrorCode};
    struct DecodeFailure;
    impl Contract for DecodeFailure {
        type Request = u32;
        type Response = u32;
        const DESCRIPTOR: ContractDescriptor = Echo::DESCRIPTOR;
    }
    impl HttpContract<App> for DecodeFailure {
        const METHOD: MethodFilter = MethodFilter::POST;
        const PATH: &'static str = "/echo";
        async fn decode(_: Request, _: &App) -> Result<u32, SafeError> {
            // Fixture represents a product authenticator failure, not actual authentication.
            Err(SafeError::new(SafeErrorCode::Unauthenticated))
        }
        fn encode(value: u32) -> Response {
            Echo::encode(value)
        }
    }
    async fn challenge(mut response: Response) -> Response {
        if response.status() == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
    let decoder = Endpoint::<DecodeFailure, App>::new(
        |_: ContractMarker<DecodeFailure>, _: State<App>, value: u32| async move { Ok(value) },
    )
    .mount(Router::new());
    let handler =
        Endpoint::<Echo, App>::new(|_: ContractMarker<Echo>, _: State<App>, _: u32| async {
            Err(SafeError::new(SafeErrorCode::Unauthenticated))
        })
        .mount(Router::new());
    for router in [decoder, handler] {
        let app = router
            .with_state(App(0))
            .layer(middleware::map_response(challenge));
        let request = Request::builder()
            .method("POST")
            .uri("/echo")
            .header("content-type", "application/json")
            .body(Body::from("0"))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), 401);
        assert_eq!(response.headers()[WWW_AUTHENTICATE], "Bearer");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"error":{"code":"unauthenticated","message":"authentication required"}})
        );
    }
}
