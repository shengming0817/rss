#![doc = include_str!("../README.md")]

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ContextValueError {
    Empty,
    TooLong,
    InvalidFormat,
}

impl fmt::Display for ContextValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("request context value is invalid")
    }
}
impl Error for ContextValueError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TenantIdError {
    Empty,
    Nil,
    InvalidFormat,
}

impl fmt::Display for TenantIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("tenant identifier is invalid")
    }
}
impl Error for TenantIdError {}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct TenantId(uuid::Uuid);

impl TenantId {
    pub fn parse(value: &str) -> Result<Self, TenantIdError> {
        if value.is_empty() {
            return Err(TenantIdError::Empty);
        }
        let parsed = uuid::Uuid::try_parse(value).map_err(|_| TenantIdError::InvalidFormat)?;
        if parsed.hyphenated().to_string() != value {
            return Err(TenantIdError::InvalidFormat);
        }
        if parsed.is_nil() {
            return Err(TenantIdError::Nil);
        }
        Ok(Self(parsed))
    }

    #[must_use]
    pub const fn octets(self) -> [u8; 16] {
        *self.0.as_bytes()
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(formatter)
    }
}
impl fmt::Debug for TenantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantId")
            .field(&self.to_string())
            .finish()
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RequestId(Box<str>);

impl RequestId {
    pub fn parse(value: &str) -> Result<Self, ContextValueError> {
        if value.is_empty() {
            return Err(ContextValueError::Empty);
        }
        if value.len() > 128 {
            return Err(ContextValueError::TooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(ContextValueError::InvalidFormat);
        }
        Ok(Self(value.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
impl fmt::Debug for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RequestId")
            .field(&self.as_str())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Deadline(Instant);

impl Deadline {
    #[must_use]
    pub const fn at(instant: Instant) -> Self {
        Self(instant)
    }
    #[must_use]
    pub const fn instant(self) -> Instant {
        self.0
    }
    #[must_use]
    pub fn is_expired(self, now: Instant) -> bool {
        now >= self.0
    }
    #[must_use]
    pub fn remaining(self, now: Instant) -> Option<Duration> {
        self.0.checked_duration_since(now)
    }
    #[must_use]
    pub fn shortened_to(self, earlier: Instant) -> Self {
        Self(self.0.min(earlier))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationReason {
    Cancelled,
    DeadlineExceeded,
}

pub type CancellationFuture<'a> = Pin<Box<dyn Future<Output = CancellationReason> + Send + 'a>>;

pub trait CancellationObserver: Send + Sync {
    fn is_cancelled(&self) -> bool;
    fn cancelled(&self, deadline: Deadline) -> CancellationFuture<'_>;
}

#[derive(Clone, Copy)]
pub struct Cancellation<'a>(&'a dyn CancellationObserver);

impl<'a> Cancellation<'a> {
    #[must_use]
    pub const fn observe(observer: &'a dyn CancellationObserver) -> Self {
        Self(observer)
    }
    #[must_use]
    pub fn is_cancelled(self) -> bool {
        self.0.is_cancelled()
    }
    #[must_use]
    pub fn cancelled(self, deadline: Deadline) -> CancellationFuture<'a> {
        self.0.cancelled(deadline)
    }
}

impl fmt::Debug for Cancellation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cancellation")
            .finish_non_exhaustive()
    }
}

/// Read-only, provider-neutral request execution context.
#[derive(Clone, Copy, Debug)]
pub struct RequestContextView<'a> {
    tenant: Option<&'a TenantId>,
    request_id: &'a RequestId,
    deadline: Deadline,
    cancellation: Cancellation<'a>,
}

impl<'a> RequestContextView<'a> {
    #[must_use]
    pub const fn new(
        tenant: Option<&'a TenantId>,
        request_id: &'a RequestId,
        deadline: Deadline,
        cancellation: Cancellation<'a>,
    ) -> Self {
        Self {
            tenant,
            request_id,
            deadline,
            cancellation,
        }
    }

    #[must_use]
    pub const fn tenant(self) -> Option<&'a TenantId> {
        self.tenant
    }
    #[must_use]
    pub const fn request_id(self) -> &'a RequestId {
        self.request_id
    }
    #[must_use]
    pub const fn deadline(self) -> Deadline {
        self.deadline
    }
    #[must_use]
    pub const fn cancellation(self) -> Cancellation<'a> {
        self.cancellation
    }
}
