//! Closed metadata passed from the sealed HTTP core to its transport-owned observation seam.
//!
//! These types carry no emitter, timer, span, scheme, raw URI, headers, body, or free-form error.
//! Constructors that could mint route/cause evidence remain crate-private; `httpd` can only read
//! metadata produced by the sealed router.

/// Listener label selected by auth finalization and carried by [`crate::ServerService`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerObservationListener {
    Primary,
    Internal,
    Admin,
    Other,
}

impl ServerObservationListener {
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Internal => "internal",
            Self::Admin => "admin",
            Self::Other => "other",
        }
    }
}

/// Non-optional observation policy sealed into the transport core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerObservationPolicy {
    Enabled(ServerObservationListener),
    Disabled,
}

/// Axum-matched route template produced inside the sealed router.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerObservationRoute(String);

impl ServerObservationRoute {
    pub(crate) fn from_matched_path(path: &axum::extract::MatchedPath) -> Self {
        Self(path.as_str().to_owned())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Closed response cause readable by the transport owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerResponseCauseKind {
    Timeout,
    Panic,
}

/// Opaque response extension; only sealed middleware can mint it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ServerResponseCause(ServerResponseCauseKind);

impl ServerResponseCause {
    pub(crate) const fn timeout() -> Self {
        Self(ServerResponseCauseKind::Timeout)
    }

    pub(crate) const fn panic() -> Self {
        Self(ServerResponseCauseKind::Panic)
    }

    pub(crate) const fn kind(self) -> ServerResponseCauseKind {
        self.0
    }
}

/// Sealed result of the per-request core.
///
/// External wrappers may call the core, but cannot construct or mutate this value's observation
/// metadata. The transport adapter reads the closed fields and consumes it into an Axum response.
pub struct ServerResponse {
    response: axum::response::Response,
    route: Option<String>,
    cause: Option<ServerResponseCauseKind>,
}

impl ServerResponse {
    pub(crate) fn from_response(mut response: axum::response::Response) -> Self {
        let route = response
            .extensions_mut()
            .remove::<ServerObservationRoute>()
            .map(|route| route.as_str().to_owned());
        let cause = response
            .extensions_mut()
            .remove::<ServerResponseCause>()
            .map(ServerResponseCause::kind);
        Self {
            response,
            route,
            cause,
        }
    }

    #[must_use]
    pub fn route(&self) -> Option<&str> {
        self.route.as_deref()
    }

    #[must_use]
    pub const fn cause(&self) -> Option<ServerResponseCauseKind> {
        self.cause
    }

    #[must_use]
    pub const fn response(&self) -> &axum::response::Response {
        &self.response
    }

    #[must_use]
    pub fn into_response(self) -> axum::response::Response {
        self.response
    }
}
