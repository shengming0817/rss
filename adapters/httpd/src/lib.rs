//! Provider-neutral HTTP server transport.
//!
//! This adapter owns socket binding, graceful shutdown, remote-address injection, trace-parent
//! restoration, and bounded HTTP server observations. Authentication and device-domain clients
//! are deliberately outside this transport.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::serve::{IncomingStream, Listener};
use rss_runtime::ShutdownError;
use tokio::net::TcpListener;
use tower::Service;

pub use listenerlifecycle::ListenerTaskRegistration;

mod server_observation;
#[cfg(test)]
mod server_observation_tests;

/// Stateless HTTP listener factory.
pub enum HttpServer {}

/// Failure while binding a neutral HTTP listener.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpServeError {
    #[error("failed to bind HTTP listener")]
    Bind(#[source] std::io::Error),
    #[error("failed to inspect HTTP listener address")]
    LocalAddr(#[source] std::io::Error),
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransportPolicy {
    Plaintext,
    #[cfg(test)]
    Tls,
}

impl TransportPolicy {
    fn scheme(self) -> server_observation::TransportScheme {
        match self {
            Self::Plaintext => server_observation::TransportScheme::Http,
            #[cfg(test)]
            Self::Tls => server_observation::TransportScheme::Https,
        }
    }

    fn finalize_response(self, mut response: axum::response::Response) -> axum::response::Response {
        if self == Self::Plaintext {
            response.headers_mut().remove("strict-transport-security");
        }
        response
    }
}

#[derive(Clone)]
struct TransportMakeService {
    inner: httpserve::ServerService,
    policy: TransportPolicy,
}

impl TransportMakeService {
    fn plaintext(inner: httpserve::ServerService) -> Self {
        Self {
            inner,
            policy: TransportPolicy::Plaintext,
        }
    }
}

impl<'a, L> Service<IncomingStream<'a, L>> for TransportMakeService
where
    L: Listener<Addr = SocketAddr>,
{
    type Response = TransportService;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: IncomingStream<'a, L>) -> Self::Future {
        std::future::ready(Ok(TransportService {
            inner: self.inner.clone(),
            policy: self.policy,
            remote_addr: *target.remote_addr(),
        }))
    }
}

#[derive(Clone)]
struct TransportService {
    inner: httpserve::ServerService,
    policy: TransportPolicy,
    remote_addr: SocketAddr,
}

impl Service<axum::extract::Request> for TransportService {
    type Response = axum::response::Response;
    type Error = Infallible;
    type Future = TransportResponseFuture<
        <httpserve::ServerService as Service<axum::extract::Request>>::Future,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: axum::extract::Request) -> Self::Future {
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(self.remote_addr));
        let observation = match self.inner.observation_policy() {
            httpserve::ServerObservationPolicy::Enabled(listener) => {
                let inbound =
                    server_observation::InboundTraceContext::from_headers(request.headers());
                let observation = server_observation::RequestObservation::new(
                    request.method(),
                    request.version(),
                    self.policy.scheme(),
                    listener,
                );
                if let Some(inbound) = inbound {
                    inbound.apply_to(&observation.span());
                }
                Some(observation)
            }
            httpserve::ServerObservationPolicy::Disabled => None,
        };
        TransportResponseFuture {
            inner: self.inner.call(request),
            observation,
            policy: self.policy,
        }
    }
}

struct TransportResponseFuture<F> {
    inner: F,
    observation: Option<server_observation::RequestObservation>,
    policy: TransportPolicy,
}

impl<F> Future for TransportResponseFuture<F>
where
    F: Future<Output = Result<httpserve::ServerResponse, Infallible>> + Unpin,
{
    type Output = Result<axum::response::Response, Infallible>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let span = self.observation.as_ref().map_or_else(
            tracing::Span::none,
            server_observation::RequestObservation::span,
        );
        match span.in_scope(|| Pin::new(&mut self.inner).poll(cx)) {
            Poll::Ready(Ok(response)) => {
                let response = match self.observation.take() {
                    Some(observation) => observation.observe_response(response),
                    None => response.into_response(),
                };
                Poll::Ready(Ok(self.policy.finalize_response(response)))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Bound, not-yet-served HTTP listener.
#[derive(Debug)]
#[must_use = "a bound listener must be served"]
pub struct BoundHttpServer {
    name: &'static str,
    listener: listenerlifecycle::BoundTcpListener,
    local_addr: SocketAddr,
}

impl BoundHttpServer {
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn serve(self, service: httpserve::ServerService) -> ListenerTaskRegistration {
        let listener = self.listener;
        let registration = listener.into_registration(
            rss_runtime::DEFAULT_SHUTDOWN_TIMEOUT,
            move |listener, serve_token| async move {
                axum::serve(listener, TransportMakeService::plaintext(service))
                    .with_graceful_shutdown(async move { serve_token.cancelled().await })
                    .await
                    .map_err(ShutdownError::new)
            },
        );
        tracing::info!(name = self.name, addr = %self.local_addr, "http server started");
        registration
    }
}

impl HttpServer {
    pub async fn bind(
        name: &'static str,
        addr: SocketAddr,
    ) -> Result<BoundHttpServer, HttpServeError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(HttpServeError::Bind)?;
        let listener = listenerlifecycle::BoundTcpListener::new(name, listener)
            .map_err(HttpServeError::LocalAddr)?;
        let local_addr = listener.local_addr();
        Ok(BoundHttpServer {
            name,
            listener,
            local_addr,
        })
    }
}
