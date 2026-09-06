# rss-axum

Optional Axum integration for RSS public contracts: exact handler binding, request-future
control, safe HTTP errors, and opt-in managed serving. Version 0.1.0 is experimental.
Default features are empty; `managed-server` adds `rss-runtime` and an owned Hyper HTTP/2 transport for the Axum Router.
Neither mode depends on the retired HTTP/DI packages or requires `rss-platform::Application`.

## Typed product routing

`rss_contract::Contract` is the sole protocol-neutral request/response identity owner.
`HttpContract<S>` adds HTTP method/path and product codecs. The codecs delegate to Axum; DTOs
need no HTTP traits. The endpoint constructor checks the exact marker, state, request, successful
response and SafeError before erasing the handler into an HTTP service. There is no registry or
codegen. The authored schema digest is not proof that Rust types match the schema, nor do these
types authenticate requests or prove handler effects. Router nesting and outer middleware remain
product transformations; the binding does not enforce final deployment paths or policy.

```rust
use axum::{Json, Router, extract::{FromRequest, Request, State},
    middleware, response::{IntoResponse, Response}, routing::MethodFilter};
use rss_axum::{ContractMarker, Endpoint, HttpContract, RequestBudget, request_control};
use rss_contract::{Contract, ContractDescriptor, SafeError, SafeErrorCode};
use std::time::Duration;

#[derive(Clone)]
struct App { increment: u32 }
struct Add;
impl Contract for Add {
    type Request = u32;
    type Response = u32;
    const DESCRIPTOR: ContractDescriptor = ContractDescriptor::from_static(
        "example.add", 1,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}
impl HttpContract<App> for Add {
    const METHOD: MethodFilter = MethodFilter::POST;
    const PATH: &'static str = "/add";
    async fn decode(request: Request, state: &App) -> Result<u32, SafeError> {
        Json::<u32>::from_request(request, state).await
            .map(|Json(value)| value)
            .map_err(|_| SafeError::new(SafeErrorCode::InvalidInput))
    }
    fn encode(value: u32) -> Response { Json(value).into_response() }
}
async fn add(_: ContractMarker<Add>, State(app): State<App>, value: u32)
    -> Result<u32, SafeError>
{
    value.checked_add(app.increment).ok_or(SafeError::new(SafeErrorCode::InvalidInput))
}
let budget = RequestBudget::new(Duration::from_secs(5))?;
let router = Endpoint::<Add, App>::new(add).mount(Router::new())
    .with_state::<()>(App { increment: 1 })
    .layer(middleware::from_fn_with_state(budget, request_control));
# Ok::<(), rss_axum::RequestBudgetError>(())
```

Products put authentication/authorization inside the budget layer when that work must share its
deadline. Decoders can read `RequestControl` from request extensions and carry a clone in their
own request DTO. Supply previously confirmed identity values explicitly:

```rust
use rss_axum::RequestControl;
use rss_request_context::{RequestContextView, RequestId, TenantId};
fn view<'a>(control: &'a RequestControl, tenant: Option<&'a TenantId>, id: &'a RequestId)
    -> RequestContextView<'a>
{
    control.context(tenant, id)
}
```

No header is promoted to tenant authority. Request IDs, authentication, devices, authorization,
proxy trust, CORS, body limits, health, telemetry and configuration belong to the product.
Axum extractor defaults are unchanged. Errors outside this RSS projection, including product
middleware/extractor responses, follow their respective owners' policies.

## Request lifetime and errors

`RequestBudget::new` rejects zero and unrepresentable deadlines. Nested request-control middleware
can only shorten an existing deadline. Controls expose cancellation observation, not a trigger.
Completion, timeout or dropping the request future ends observation. A completed downstream
result wins when completion and termination become ready in the same poll; an already ended
inherited control does not admit new work. The budget covers downstream
processing (including decoding) until Response is returned, not subsequent body transmission.
A disconnected client is not guaranteed to cause immediate handler cancellation. Requests/tasks
spawned outside the request future are not automatically owned by this middleware.

Timeout stops waiting and returns Unavailable; it proves neither rollback nor absence of external
effects. Handle the complete transaction outcome (including CommitUnknown) before projecting a
failure into SafeError. An HTTP success must not conflate command admission, message publication,
device receipt and actual application. This package owns no retry or recovery algorithm.

`HttpError::from(SafeError)` implements IntoResponse. The envelope is exactly
`{"error":{"code":"internal","message":"internal error"}}` for Internal. Codes/messages come
from SafeError; category maps to 400/401/403/404/409/429/503/500. No sources, diagnostic details,
requestId or retryable are added. This is a new wire surface, not compatibility with the retired
httpserve envelope. Product-owned successful responses and codecs remain trusted implementations.

A 401 is not a complete authentication response until the product adds its applicable
`WWW-Authenticate` challenge (RFC 9110 §15.5.2). The existing outer Router middleware seam covers
both decoder and handler failures; no RSS authentication scheme or extra policy API is needed.
For example, a product using Bearer authentication can finalize responses as follows:

```rust
use axum::{Router, http::{StatusCode, HeaderValue, header::WWW_AUTHENTICATE},
    middleware, response::Response};
async fn bearer_challenge(mut response: Response) -> Response {
    if response.status() == StatusCode::UNAUTHORIZED
        && !response.headers().contains_key(WWW_AUTHENTICATE)
    {
        response.headers_mut().insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}
fn authenticated_product(router: Router) -> Router {
    router.layer(middleware::map_response(bearer_challenge))
}
```

The product selects the applicable scheme/realm and preserves challenges emitted by its actual
authenticator. The status/body mapper alone does not provide a complete authentication protocol.

## Optional serving

```rust,no_run
# #[cfg(feature = "managed-server")]
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use std::time::Duration;
use rss_runtime::{ShutdownStack, TotalDrainBudget};
let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
let registration = rss_axum::serve_registration(
    listener, axum::Router::new(), "http", Duration::from_secs(5));
let status = registration.status();
let mut owner = ShutdownStack::try_new(TotalDrainBudget::new(Duration::from_secs(10))?)?;
let mut startup = owner.startup()?;
startup.stage_task_with_token(registration);
startup.commit().finish();
// The product drives its application and decides when to shut down.
let receipt = owner.shutdown().await?;
assert!(receipt.is_clean());
let _exit = status.wait_stopped().await;
# Ok(()) }
```

Only adoption starts the task. Dropping an unadopted registration closes its socket. The
managed task directly owns a FuturesUnordered set of Hyper HTTP/2 connection futures; it does
not spawn independent connection tasks. Hyper's executor submits stream futures to a private
connection-owned queue and future set, so HTTP/2 stream work shares the same cancellation owner. Cancellation first stops accept, then requests graceful
shutdown of all existing connections. The runtime's drain timeout cancels the same owning task
and its remaining request/response-body futures, so they cannot resume when later dependencies
shut down. A timeout is still a failed drain, not successful completion of those requests.

This minimal transport supports HTTP/2 prior knowledge without HTTP/1 fallback. HTTP/1, WebSocket and CONNECT tunnels
are outside this managed transport. TLS/ALPN termination is owned by the product edge. Hyper owns protocol parsing, keep-alive and graceful close;
RSS only supplies ownership and uses Hyper's Tokio I/O/service adapters. A per-connection panic
or protocol failure terminates that connection without taking unrelated clients down.

Cancellation remains cooperative: handlers must yield and the original Tokio runtime must
continue being driven. Blocking code, product-spawned tasks and remote effects are not made
cancellable by this adapter. The parent task polls connection futures cooperatively rather than
spawning one Tokio task per connection. Task Running is not readiness. No signals, TLS policy,
restart loop or process runtime is installed here.

## Extraction and verification

Source: `baseline/pre-community-core-20260902` at
`5b63e10a1b396b0ff70b7d1e6e55db296cd7a891`, compared with lifecycle extraction at `3e660e2f5`.
Historical sources are not test evidence. #2299 owns retirement of the old packages; this package
never forwards to them. Tests cover compile-time binding, budgets, safe errors and real sockets.
`hack/axum-package-proof.py` verifies actual artifact consumers for base, managed serving and the
shared contract/platform composition. There are no persisted schemas or production T3 fixtures.

ref: tokio-rs/axum axum/src/handler/mod.rs@axum-v0.8.9
ref: tokio-rs/axum axum/src/serve/mod.rs@axum-v0.8.9
ref: tokio-rs/axum axum/src/middleware/from_fn.rs@axum-v0.8.9

ref: hyperium/hyper src/server/conn/http2.rs@v1.10.1
ref: rust-lang/futures-rs futures-util/src/stream/futures_unordered/mod.rs@0.3.32
