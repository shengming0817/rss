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

/// Monotonic time source shared by in-process execution components.
/// Observations and deadlines must use the same time domain and never move backwards.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

/// Supplies deadline wakeups; each execution component owns its arbitration policy.
/// An elapsed cutoff must be immediately ready, even after executor cooperative budget exhaustion.
/// Otherwise the wait must wake its task at or after the cutoff. Creating, polling and dropping
/// the wait must not block. The sleep and Clock observations must use the same monotonic domain.
pub trait ExecutionTimer: Clock {
    fn sleep_until(&self, deadline: Deadline) -> impl Future<Output = ()> + Send;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("deadline exceeds the monotonic time range")]
pub struct DeadlineOverflow;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A cutoff in the injected clock's in-process monotonic domain.
pub struct Deadline(Instant);

impl Deadline {
    /// Freeze a relative timeout with one clock observation; zero is already elapsed.
    pub fn from_timeout(
        clock: &(impl Clock + ?Sized),
        timeout: Duration,
    ) -> Result<Self, DeadlineOverflow> {
        clock
            .now()
            .checked_add(timeout)
            .map(Self)
            .ok_or(DeadlineOverflow)
    }
    /// Shorten this cutoff to at most `cap` from the current observation, never extending it.
    #[must_use]
    pub fn capped(self, clock: &(impl Clock + ?Sized), cap: Duration) -> Self {
        clock
            .now()
            .checked_add(cap)
            .map_or(self, |instant| self.shortened_to(instant))
    }

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

/// A wait for cancellation only; deadlines are driven by the execution owner.
pub type CancellationFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Read-only cancellation observation, independent of the request deadline.
///
/// Cancellation is sticky. A wait must complete immediately if already cancelled and wake all
/// registered waiters when cancellation occurs, without losing a concurrent cancellation.
/// Creating, polling and dropping the wait must not block. Never-cancelled sources may stay pending.
pub trait CancellationObserver: Send + Sync {
    fn is_cancelled(&self) -> bool;
    fn cancelled(&self) -> CancellationFuture<'_>;
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
    pub fn cancelled(self) -> CancellationFuture<'a> {
        self.0.cancelled()
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
