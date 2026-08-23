use std::error::Error;
use std::fmt;

/// Closed diagnostic categories for redact-safe public errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SafeErrorCategory {
    /// Caller input is invalid.
    InvalidInput,
    /// Authentication is absent or invalid.
    Authentication,
    /// The authenticated caller lacks authority.
    Authorization,
    /// The requested resource is absent.
    NotFound,
    /// The request conflicts with current state.
    Conflict,
    /// A rate limit rejected the request.
    RateLimited,
    /// The operation is temporarily unavailable.
    Unavailable,
    /// An internal failure occurred.
    Internal,
}

impl SafeErrorCategory {
    /// Return the stable lower-kebab label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid-input",
            Self::Authentication => "authentication",
            Self::Authorization => "authorization",
            Self::NotFound => "not-found",
            Self::Conflict => "conflict",
            Self::RateLimited => "rate-limited",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for SafeErrorCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Closed public error codes with fixed categories and safe messages.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SafeErrorCode {
    /// Caller input is invalid.
    InvalidInput,
    /// Authentication is required.
    Unauthenticated,
    /// Access is forbidden.
    Forbidden,
    /// The requested resource is absent.
    NotFound,
    /// The request conflicts with current state.
    Conflict,
    /// A rate limit rejected the request.
    RateLimited,
    /// The operation is temporarily unavailable.
    Unavailable,
    /// An internal failure occurred.
    Internal,
}

impl SafeErrorCode {
    /// Return the stable lower-kebab code label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid-input",
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not-found",
            Self::Conflict => "conflict",
            Self::RateLimited => "rate-limited",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        }
    }

    /// Return the fixed category for this code.
    #[must_use]
    pub const fn category(self) -> SafeErrorCategory {
        match self {
            Self::InvalidInput => SafeErrorCategory::InvalidInput,
            Self::Unauthenticated => SafeErrorCategory::Authentication,
            Self::Forbidden => SafeErrorCategory::Authorization,
            Self::NotFound => SafeErrorCategory::NotFound,
            Self::Conflict => SafeErrorCategory::Conflict,
            Self::RateLimited => SafeErrorCategory::RateLimited,
            Self::Unavailable => SafeErrorCategory::Unavailable,
            Self::Internal => SafeErrorCategory::Internal,
        }
    }

    /// Return the fixed redact-safe message for this code.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid input",
            Self::Unauthenticated => "authentication required",
            Self::Forbidden => "access denied",
            Self::NotFound => "not found",
            Self::Conflict => "conflict",
            Self::RateLimited => "rate limited",
            Self::Unavailable => "service unavailable",
            Self::Internal => "internal error",
        }
    }
}

impl fmt::Display for SafeErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A redact-safe public error containing only a closed [`SafeErrorCode`].
///
/// Arbitrary messages, provider errors, payloads, and sources cannot be stored.
/// Callers must project internal failures explicitly to a closed code.
///
/// ```compile_fail
/// use rss_contract::SafeError;
/// let _ = SafeError::new("provider said password=hunter2");
/// ```
///
/// ```compile_fail
/// use rss_contract::{SafeError, SafeErrorCode};
/// let _ = SafeError(SafeErrorCode::Internal);
/// ```
///
/// ```compile_fail
/// use rss_contract::SafeError;
/// #[derive(Debug)]
/// struct ProviderError;
/// impl std::fmt::Display for ProviderError {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         f.write_str("provider failure")
///     }
/// }
/// impl std::error::Error for ProviderError {}
/// let _: SafeError = ProviderError.into();
/// ```
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SafeError(SafeErrorCode);

impl SafeError {
    /// Construct an error from a closed safe code.
    #[must_use]
    pub const fn new(code: SafeErrorCode) -> Self {
        Self(code)
    }

    /// Return the closed safe code.
    #[must_use]
    pub const fn code(self) -> SafeErrorCode {
        self.0
    }

    /// Return the fixed category for this error.
    #[must_use]
    pub const fn category(self) -> SafeErrorCategory {
        self.0.category()
    }

    /// Return the fixed redact-safe message for this error.
    #[must_use]
    pub const fn message(self) -> &'static str {
        self.0.message()
    }
}

impl fmt::Debug for SafeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafeError")
            .field("code", &self.code())
            .field("category", &self.category())
            .finish()
    }
}

impl fmt::Display for SafeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for SafeError {}
