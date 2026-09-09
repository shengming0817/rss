# rss-axum

Optional Axum integration for RSS public contracts: exact handler binding, request-future
control, safe HTTP errors, and opt-in managed serving. Version 0.1.0 is experimental.
Default features are empty. Opt-in `http1`, `http2`, and `auto-protocol` add owned Hyper transports
for the Axum Router; `managed-server` supplies their lifecycle dependencies without selecting a protocol.
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

`RequestControl` observes cancellation only through `is_cancelled()` and `cancelled()`.
Its absolute `deadline()` is separate: middleware enforces both limits independently, refusing
already-ended requests before downstream work. The old deadline-taking observer wait is removed.
Completion, timeout or dropping the request future cancels observers; an elapsed deadline alone
is not a cancellation signal. Request-future termination does not cover response-body streaming.

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
# #[cfg(feature = "http2")]
# async fn example(timer: std::sync::Arc<impl rss_request_context::ExecutionTimer + 'static>) -> Result<(), Box<dyn std::error::Error>> {
use std::time::Duration;
use rss_runtime::{ShutdownStack, TotalDrainBudget};
let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
let registration = rss_axum::serve_http2_registration(
    listener, axum::Router::new(), "http", Duration::from_secs(5));
let status = registration.status();
let mut owner = ShutdownStack::try_new(TotalDrainBudget::new(Duration::from_secs(10))?, timer)?;
let mut startup = owner.startup()?;
startup.stage_task_with_token(registration);
startup.commit().finish();
// The product drives its application and decides when to shut down.
let receipt = owner.shutdown().join().await?;
assert!(receipt.is_clean());
let _exit = status.wait_stopped().await;
# Ok(()) }
```

Only adoption starts the task. Dropping an unadopted registration closes its socket. The
managed task directly owns a FuturesUnordered set of Hyper connection futures; it does
not spawn independent connection tasks. Hyper's executor submits stream futures to a private
connection-owned queue and future set, so HTTP/2 stream work shares the same cancellation owner. Cancellation first stops accept, then requests graceful
shutdown of all existing connections. The runtime's drain timeout cancels the same owning task
and its remaining request/response-body futures, so they cannot resume when later dependencies
shut down. A timeout is still a failed drain, not successful completion of those requests.

Cargo features make protocol implementations available; the constructor fixes each listener's
policy even when another dependency enables additional features.

| Feature | Public constructor | Listener policy |
| --- | --- | --- |
| `managed-server` | none | Lifecycle dependencies only |
| `http1` | `serve_http1_registration` | HTTP/1 only |
| `http2` | `serve_http2_registration` | HTTP/2 prior knowledge only |
| `auto-protocol` | `serve_auto_registration` (plus both dedicated constructors) | HTTP/1 and HTTP/2 prior knowledge on the same socket |

`http1` and `http2` each imply `managed-server`; `auto-protocol` implies both. Enabling both
protocol features alone does not expose the Auto constructor. Hyper owns parsing, keep-alive
and graceful close; hyper-util owns Auto detection. H1 drain disables keep-alive while allowing
an active request/response body to finish; Auto drain also cancels unfinished protocol detection.
H1 request headers have an explicit 30-second read timeout, including later requests on a
keep-alive connection. Auto additionally allows 30 seconds from connection driving until the
first decoded request reaches the service, bounding idle/partial protocol detection and initial
headers without duplicating Hyper's parser. This establishment deadline is disabled before the
handler runs: it does not bound admitted handlers, request bodies, response bodies or subsequent
H2 streams. These transport deadlines are independent of the product's RequestBudget.
A connection panic or protocol failure terminates that connection without taking unrelated
clients down. H2 stream panics are additionally isolated within the connection-owned executor.
Managed serving emits DEBUG tracing events under `rss_axum::server` with closed `outcome`
(`peer_error`, `panic`, `establishment_timeout`) and `scope` (`connection`, `stream`) fields.
RSS does not record error text, peer input or panic payloads in those events, and installs no
subscriber; the product owns filtering/export and the process panic hook.

A product can select different policies in the same binary:

```rust,no_run
# #[cfg(feature = "auto-protocol")]
# async fn listeners() -> Result<(), Box<dyn std::error::Error>> {
use std::time::Duration;
let device = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
let admin = tokio::net::TcpListener::bind("127.0.0.1:8081").await?;
let device = rss_axum::serve_auto_registration(
    device, axum::Router::new(), "device", Duration::from_secs(5));
let admin = rss_axum::serve_http2_registration(
    admin, axum::Router::new(), "admin", Duration::from_secs(5));
// Stage both registrations in the product's ShutdownStack to start them.
# drop((device, admin));
# Ok(()) }
```

Direct deployment can select `auto-protocol`; deployment behind an edge proxy can select only
`http2` and configure the proxy's upstream accordingly. Proxy downstream negotiation is
independent of this choice. These are plain TCP transports: TLS/ALPN and the TLS integration
needed for direct HTTPS remain product responsibilities. Auto does not itself implement HTTPS,
h2c Upgrade, WebSocket or CONNECT tunnels, or hand upgraded IO to another owner.

### Migration from the initial experimental API

Replace dependency feature `managed-server` with `http2` and calls to the removed
`serve_registration` with `serve_http2_registration` to retain the initial H2-only behavior.
Select `http1` or `auto-protocol` and their explicit constructors when those policies are needed.
There is no compatibility alias or implicit protocol fallback. The current Release Surface
records an uncommitted Rust API (#2315); this replacement retains the 0.1.0 package version.

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
`hack/axum-package-proof.py` checks isolated artifact consumers for base, lifecycle-only,
H1-only, H2-only, H1+H2, Auto and all features, plus the shared contract/platform composition.
It verifies actual protocol feature resolution and missing API boundaries, and runs real requests
and shutdown for H1, H2 and Auto. Candidate mode binds revision, version and archive digest.
The managed example is shared with those artifact consumers; component tests own the fault matrix.
Run it with `--features http1`, `--features http2` or `--features auto-protocol`. Lifecycle-only
`--features managed-server` deliberately exits with an instruction to select a protocol, which
the artifact proof also checks. There are no persisted schemas or production T3 fixtures.

ref: tokio-rs/axum axum/src/handler/mod.rs@axum-v0.8.9
ref: tokio-rs/axum axum/src/serve/mod.rs@axum-v0.8.9
ref: tokio-rs/axum axum/src/middleware/from_fn.rs@axum-v0.8.9

ref: hyperium/hyper src/server/conn/http1.rs@v1.10.1
ref: hyperium/hyper src/server/conn/http2.rs@v1.10.1
ref: hyperium/hyper-util src/server/conn/auto/mod.rs@v0.1.20
ref: rust-lang/futures-rs futures-util/src/stream/futures_unordered/mod.rs@0.3.32

Managed listeners inject the accepted TCP peer as standard Axum `ConnectInfo<SocketAddr>`
on every request, for HTTP/1, HTTP/2 and Auto. They never interpret proxy headers;
products own trusted proxy normalization and client attribution.

### Listener recovery

A recognized transient accept failure pauses new acceptance for one second while existing
connections continue progressing. Retries retain only one deadline, create no tasks or connection
queue, and have no cumulative expiry. A successful accept ends recovery; shutdown interrupts the
wait and uses the existing graceful drain and runtime budget. Unknown and terminal errors return a
redacted failure instead of retrying forever. Recognized resource pressure includes Unix
EMFILE/ENFILE/ENOBUFS/ENOMEM and Windows WSAEMFILE/WSAENOBUFS. The first failure and subsequent
recovery emit closed `accept_retry` / `accept_recovered` events with the stable operator-controlled
`listener` registration name through `rss_redact::safe`. Names are public operator labels: use
1–64 ASCII letters, digits, hyphens or underscores, and never include credentials or tenant/device
data. Other names render as `<redacted>`; wire projection always redacts the name. Repeated failures
do not grow logs. Raw error text and peer data are not included in these recovery events.

This bounds retry overhead, not total server capacity: the current connection set has no explicit
connection-count limit. Product hosts own readiness, alerting, traffic removal, exit/restart and
capacity values. A future local connection limit must be enforced by this connection owner; HTTP
handler concurrency alone cannot bound TCP connections. No automatic restart or fixed listener
failure window is installed by this adapter.
