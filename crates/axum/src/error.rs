//! Closed RSS errors projected to HTTP; recovery decisions remain with the caller.
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rss_contract::{SafeError, SafeErrorCategory};
use serde::Serialize;

/// Status/body projection of an already classified safe error. No provider/source storage exists.
///
/// Authentication protocol headers are product-owned. Before serving an Unauthenticated (401)
/// response, the product must add its appropriate WWW-Authenticate challenge, normally via outer
/// Router middleware. This projection cannot choose an authentication scheme for the product.
#[derive(Debug, Clone, Copy)]
pub struct HttpError(SafeError);

impl From<SafeError> for HttpError {
    fn from(error: SafeError) -> Self {
        Self(error)
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let status = match self.0.category() {
            SafeErrorCategory::InvalidInput => StatusCode::BAD_REQUEST,
            SafeErrorCategory::Authentication => StatusCode::UNAUTHORIZED,
            SafeErrorCategory::Authorization => StatusCode::FORBIDDEN,
            SafeErrorCategory::NotFound => StatusCode::NOT_FOUND,
            SafeErrorCategory::Conflict => StatusCode::CONFLICT,
            SafeErrorCategory::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            SafeErrorCategory::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            SafeErrorCategory::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(Envelope {
                error: ErrorBody {
                    code: self.0.code().as_str(),
                    message: self.0.message(),
                },
            }),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct Envelope {
    error: ErrorBody,
}
#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}
