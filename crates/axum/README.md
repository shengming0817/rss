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
    listener, axum::Router::new(), rss_axum::PlainTransport, "http",
    rss_axum::ServePolicy::new(128, Duration::from_secs(8), Duration::from_secs(30), Duration::from_secs(5))?);
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
managed task directly owns one FuturesUnordered set of preparation-to-HTTP connection futures; it does
not spawn independent connection tasks. Hyper's executor submits stream futures to a private
connection-owned queue and future set, so HTTP/2 stream work shares the same cancellation owner. Cancellation first stops accept and cancels incomplete preparation, then requests graceful
shutdown of established connections. The runtime's drain timeout cancels the same owning task
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
H1 request headers use the explicit Http1ServePolicy timeout, including later requests on a
keep-alive connection. All three protocols additionally use ServePolicy establishment_timeout
from prepared connection driving until the first decoded request reaches the service. This
bounds silent H2 peers and partial protocol detection/headers without duplicating Hyper's parser. This establishment deadline is disabled before the
handler runs: it does not bound admitted handlers, request bodies, response bodies or subsequent
H2 streams. These transport deadlines are independent of the product's RequestBudget.
A connection panic or protocol failure terminates that connection without taking unrelated
clients down. H2 stream panics are additionally isolated within the connection-owned executor.
Managed serving emits DEBUG tracing events under `rss_axum::server` with closed `outcome`
(`peer_error`, `panic`, `preparation_error`, `preparation_timeout`, `establishment_timeout`),
`scope` (`connection`, `stream`) and safely rendered `listener` fields.
RSS does not record error text, peer input or panic payloads in those events, and installs no
subscriber; the product owns filtering/export and the process panic hook.

A product can select different policies in the same binary:

```rust,no_run
# #[cfg(feature = "auto-protocol")]
# async fn listeners() -> Result<(), Box<dyn std::error::Error>> {
use std::time::Duration;
let device = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
let admin = tokio::net::TcpListener::bind("127.0.0.1:8081").await?;
let policy = rss_axum::ServePolicy::new(128, Duration::from_secs(8), Duration::from_secs(30), Duration::from_secs(5))?;
let h1 = rss_axum::Http1ServePolicy::new(policy, Duration::from_secs(10), 64, 32768)?;
let device = rss_axum::serve_auto_registration(
    device, axum::Router::new(), rss_axum::PlainTransport, "device", h1);
let admin = rss_axum::serve_http2_registration(
    admin, axum::Router::new(), rss_axum::PlainTransport, "admin", policy);
// Stage both registrations in the product's ShutdownStack to start them.
# drop((device, admin));
# Ok(()) }
```

Direct deployment can select `auto-protocol`; deployment behind an edge proxy can select only
`http2` and configure the proxy's upstream accordingly. Proxy downstream negotiation is
independent of this choice. These are plain TCP transports: TLS/ALPN and the TLS integration
needed for direct HTTPS remain product responsibilities. Auto does not itself implement HTTPS,
h2c Upgrade, WebSocket or CONNECT tunnels, or hand upgraded IO to another owner.

### Transport preparation and migration (#2418)

All three constructors now require an explicit `ConnectionTransport` and validated policy.
There are no old-signature wrappers or parallel TLS constructors. Existing plain consumers pass
`PlainTransport`, `ServePolicy` (H2) or `Http1ServePolicy` (H1/Auto). Policy capacity counts all
accepted connections, including preparation, and has no unlimited mode. ServePolicy::new takes
capacity, preparation_timeout, establishment_timeout, shutdown_timeout in that order. All phase
budgets must be positive and at most 24 hours: the supported range is independent of when policy
is constructed or used; H1 header capacity is positive and its buffer is at least 8192 bytes. `ServePolicyError`
retains a closed `ServePolicyField` identity (also available through `field()`), so products can
identify the rejected configuration field without parsing text or retaining the rejected value.

A product implements `ConnectionTransport::prepare` over the TCP stream and socket peer supplied
by RSS. It performs admission, TLS/ALPN and client verification, then returns
`EstablishedTransport::new(io, metadata, guard)`. RSS polls this entire preparation future in the
same connection future that subsequently drives HTTP. Metadata is Clone + Send + Sync; the guard
only needs Send and remains owned through HTTP completion or cancellation. Keep connection
permits in the guard, not in metadata cloned into requests. Generic metadata is not proof that a
product verifier is correct; authentication and tenant/device authority stay with the product.

The preparation budget covers the entire product future, including failure handling. For a
product doing five seconds of TLS followed by up to two seconds of failure audit, select an
explicit larger total budget (the example uses eight seconds, then a separate 30-second first
request budget and ten-second shutdown budget). No separate audit hook or
background task is needed. A preparation error, factory/poll panic or preparation timeout closes
only that connection. Cancellation wins over preparation and prevents a ready transport from
being promoted to HTTP; already-established HTTP connections retain graceful drain.

Requests receive only `Extension<AcceptedConnectionInfo<M>>`, with `socket_peer()` and
`metadata()`. RSS privately binds these after preparation succeeds; a transport cannot override
the original TCP peer. Forwarding headers are never interpreted. Trusted in-process middleware
and the semantics of product metadata remain outside this construction guarantee.

This is a breaking replacement of the experimental Rust API (uncommitted under #2315), retaining
version 0.1.0. Update all listener calls and replace `ConnectInfo<SocketAddr>` extraction with
`Extension<AcceptedConnectionInfo<M>>` (M = () for PlainTransport). Consumers mounting third-party
routers that require standard ConnectInfo must explicitly map the RSS context at their product
integration boundary. There is no standard ConnectInfo duplicate projection inside RSS.

`cargo run -p rss-axum --example tls --features http1` runs the real rustls public consumer with
verified client certificate metadata, actual TCP peer and permit release. Its source is reused
by `axum-integration` and `hack/axum-package-proof.py` for isolated source/artifact consumption.
Rustls/rcgen are example and test dependencies only. These assertions do not promise TLS
close_notify, production certificate configuration, MDM migration or Windows T3.

MDM #998 must later upgrade its fixed RSS revision, migrate both Windows TLS listeners and the
browser registration, and remove its duplicate Hyper/futures lifecycle. Its F4 remains blocked
until that product migration and real PG/TLS acceptance complete; #2418 library proof alone does
not close the product finding.

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
H1-only, H2-only, H1+H2, Auto, all features and a real TLS consumer, plus the shared contract/platform composition.
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

Managed listeners expose the accepted TCP peer and preparation metadata through
`Extension<AcceptedConnectionInfo<M>>` for HTTP/1, HTTP/2 and Auto. Products own trusted proxy
normalization and client attribution; network headers cannot construct this RSS context.

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

Retry overhead is bounded independently of ServePolicy capacity. The connection owner enforces
the caller-selected limit over preparation and established connections; HTTP handler concurrency
alone cannot bound TCP connections. Product hosts own capacity values, readiness, alerting,
traffic removal and exit/restart. No automatic restart or fixed listener failure window is installed.

Capacity emits DEBUG `capacity_saturated` / `capacity_recovered` transitions with safe `listener`
and caller-selected `limit`. Repeated polls while full do not repeat saturation; shutdown while
full does not report recovery because acceptance will not resume. These events describe local
capacity, not product readiness or a guarantee that later network requests can succeed.
