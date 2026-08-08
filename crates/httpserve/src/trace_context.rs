//! Narrow HTTP server tracing boundary.
//!
//! The observation type deliberately cannot retain a request, URI, headers, body, authority, or
//! free-form error text. Only closed protocol/method values and axum's matched route template can
//! reach the SERVER span.

use axum::extract::MatchedPath;
use axum::http::{HeaderMap, Method, Version, header::HeaderName};

const TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");
const TRACESTATE: HeaderName = HeaderName::from_static("tracestate");
const MAX_TRACE_HEADER_BYTES: usize = 512;

pub(super) struct InboundTraceContext {
    traceparent: String,
    tracestate: Option<String>,
}

impl InboundTraceContext {
    pub(super) fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let mut parents = headers.get_all(&TRACEPARENT).iter();
        let traceparent = parents.next()?.to_str().ok()?;
        if parents.next().is_some() || !valid_traceparent(traceparent) {
            return None;
        }

        let mut tracestate = String::new();
        for value in headers.get_all(&TRACESTATE) {
            let Ok(value) = value.to_str() else {
                return Some(Self {
                    traceparent: traceparent.to_owned(),
                    tracestate: None,
                });
            };
            let next_len = tracestate
                .len()
                .saturating_add(usize::from(!tracestate.is_empty()))
                .saturating_add(value.len());
            if next_len > MAX_TRACE_HEADER_BYTES {
                return Some(Self {
                    traceparent: traceparent.to_owned(),
                    tracestate: None,
                });
            }
            if !tracestate.is_empty() {
                tracestate.push(',');
            }
            tracestate.push_str(value);
        }

        Some(Self {
            traceparent: traceparent.to_owned(),
            tracestate: (!tracestate.is_empty()).then_some(tracestate),
        })
    }

    pub(super) fn apply_to(&self, span: &tracing::Span) {
        tracewire::restore_remote_parent(span, &self.traceparent, self.tracestate.as_deref());
    }
}

fn valid_traceparent(value: &str) -> bool {
    if value.len() > MAX_TRACE_HEADER_BYTES {
        return false;
    }
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() < 4
        || parts[0].len() != 2
        || parts[1].len() != 32
        || parts[2].len() != 16
        || parts[3].len() != 2
        || !parts[0].bytes().all(is_lower_hex)
        || !parts[1].bytes().all(is_lower_hex)
        || !parts[2].bytes().all(is_lower_hex)
        || !parts[3].bytes().all(is_lower_hex)
        || parts[1].bytes().all(|byte| byte == b'0')
        || parts[2].bytes().all(|byte| byte == b'0')
    {
        return false;
    }
    let Ok(version) = u8::from_str_radix(parts[0], 16) else {
        return false;
    };
    version != u8::MAX && (version != 0 || parts.len() == 4)
}

const fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (byte >= b'a' && byte <= b'f')
}

#[derive(Clone, Copy)]
enum ObservedHttpMethod {
    Connect,
    Delete,
    Get,
    Head,
    Options,
    Patch,
    Post,
    Put,
    Trace,
    Other,
}

impl ObservedHttpMethod {
    fn from_method(method: &Method) -> Self {
        match *method {
            Method::CONNECT => Self::Connect,
            Method::DELETE => Self::Delete,
            Method::GET => Self::Get,
            Method::HEAD => Self::Head,
            Method::OPTIONS => Self::Options,
            Method::PATCH => Self::Patch,
            Method::POST => Self::Post,
            Method::PUT => Self::Put,
            Method::TRACE => Self::Trace,
            _ => Self::Other,
        }
    }

    const fn attribute(self) -> &'static str {
        match self {
            Self::Connect => "CONNECT",
            Self::Delete => "DELETE",
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Patch => "PATCH",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Trace => "TRACE",
            Self::Other => "_OTHER",
        }
    }

    const fn name_token(self) -> &'static str {
        match self {
            Self::Other => "HTTP",
            known => known.attribute(),
        }
    }
}

pub(super) struct HttpServerObservation {
    method: ObservedHttpMethod,
    route: Option<String>,
    protocol: &'static str,
    request_id: String,
    correlation: String,
}

impl HttpServerObservation {
    pub(super) fn new(
        method: &Method,
        route: Option<&MatchedPath>,
        version: Version,
        request_id: &str,
        correlation: &str,
    ) -> Self {
        Self {
            method: ObservedHttpMethod::from_method(method),
            route: route.map(|matched| matched.as_str().to_owned()),
            protocol: match version {
                Version::HTTP_09 => "0.9",
                Version::HTTP_10 => "1.0",
                Version::HTTP_11 => "1.1",
                Version::HTTP_2 => "2",
                Version::HTTP_3 => "3",
                _ => "_OTHER",
            },
            request_id: request_id.to_owned(),
            correlation: correlation.to_owned(),
        }
    }

    pub(super) fn span(&self) -> tracing::Span {
        let name = match (self.method, self.route.as_ref()) {
            (ObservedHttpMethod::Other, _) => self.method.name_token().to_owned(),
            (_, Some(route)) => format!("{} {route}", self.method.name_token()),
            (_, None) => self.method.name_token().to_owned(),
        };
        let span = tracing::info_span!(
            parent: None,
            "http.server.request",
            otel.kind = "server",
            otel.name = %name,
            "http.request.method" = self.method.attribute(),
            "http.route" = tracing::field::Empty,
            "network.protocol.version" = self.protocol,
            "http.response.status_code" = tracing::field::Empty,
            "error.type" = tracing::field::Empty,
            otel.status_code = tracing::field::Empty,
            request_id = %self.request_id,
            correlation = %self.correlation,
        );
        if let Some(route) = &self.route {
            span.record("http.route", route.as_str());
        }
        span
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const VALID_PARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn http_server_inbound_traceparent_rejects_invalid_corpus() {
        for value in [
            "",
            "not-w3c",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0g",
            &"a".repeat(MAX_TRACE_HEADER_BYTES + 1),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(&TRACEPARENT, HeaderValue::from_str(value).unwrap());
            assert!(
                InboundTraceContext::from_headers(&headers).is_none(),
                "{value}"
            );
        }
    }

    #[test]
    fn http_server_inbound_traceparent_rejects_non_utf8_and_accepts_512_byte_future_version() {
        let mut non_utf8 = HeaderMap::new();
        non_utf8.insert(&TRACEPARENT, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(InboundTraceContext::from_headers(&non_utf8).is_none());

        let prefix = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extension=";
        let future = format!(
            "{prefix}{}",
            "a".repeat(MAX_TRACE_HEADER_BYTES - prefix.len())
        );
        assert_eq!(future.len(), MAX_TRACE_HEADER_BYTES);
        let mut boundary = HeaderMap::new();
        boundary.insert(&TRACEPARENT, HeaderValue::from_str(&future).unwrap());
        assert!(InboundTraceContext::from_headers(&boundary).is_some());
    }

    #[test]
    fn http_server_inbound_context_requires_exactly_one_parent_and_joins_state_in_wire_order() {
        let mut headers = HeaderMap::new();
        assert!(InboundTraceContext::from_headers(&headers).is_none());
        headers.append(&TRACEPARENT, HeaderValue::from_static(VALID_PARENT));
        headers.append(&TRACESTATE, HeaderValue::from_static("one=1"));
        headers.append(&TRACESTATE, HeaderValue::from_static("two=2"));
        let context = InboundTraceContext::from_headers(&headers).unwrap();
        assert_eq!(context.tracestate.as_deref(), Some("one=1,two=2"));
        headers.append(&TRACEPARENT, HeaderValue::from_static(VALID_PARENT));
        assert!(InboundTraceContext::from_headers(&headers).is_none());
    }

    #[test]
    fn http_server_inbound_context_drops_bad_state_but_keeps_valid_parent() {
        let mut non_utf8 = HeaderMap::new();
        non_utf8.insert(&TRACEPARENT, HeaderValue::from_static(VALID_PARENT));
        non_utf8.insert(&TRACESTATE, HeaderValue::from_bytes(&[0xff]).unwrap());
        let context = InboundTraceContext::from_headers(&non_utf8).unwrap();
        assert_eq!(context.tracestate, None);

        let mut oversized = HeaderMap::new();
        oversized.insert(&TRACEPARENT, HeaderValue::from_static(VALID_PARENT));
        oversized.insert(
            &TRACESTATE,
            HeaderValue::from_str(&"a".repeat(MAX_TRACE_HEADER_BYTES + 1)).unwrap(),
        );
        let context = InboundTraceContext::from_headers(&oversized).unwrap();
        assert_eq!(context.tracestate, None);
    }
}
