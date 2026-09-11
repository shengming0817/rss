//! Explicit, validated transport and protocol budgets.
use std::time::Duration;

/// Invalid listener policy. Diagnostics never retain the rejected input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ServePolicyError {
    /// Connections and headers require a positive capacity.
    #[error("capacity must be nonzero")]
    ZeroCapacity,
    /// Each phase must have a positive time budget.
    #[error("timeout must be nonzero")]
    ZeroTimeout,
    /// The monotonic clock cannot represent this deadline.
    #[error("timeout is not representable")]
    TimeoutOverflow,
    /// Hyper requires at least 8192 bytes for its HTTP/1 buffer.
    #[error("HTTP/1 buffer must be at least 8192 bytes")]
    BufferTooSmall,
}

#[allow(
    clippy::disallowed_methods,
    reason = "transport owns the monotonic deadline domain"
)]
fn validate_timeout(timeout: Duration) -> Result<(), ServePolicyError> {
    if timeout.is_zero() {
        return Err(ServePolicyError::ZeroTimeout);
    }
    tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or(ServePolicyError::TimeoutOverflow)?;
    Ok(())
}

/// Required connection capacity, complete preparation budget and runtime drain budget.
///
/// Capacity counts both preparing and established connections. Preparation includes any
/// product failure handling; choose a budget that covers all work before HTTP starts.
#[derive(Debug, Clone, Copy)]
pub struct ServePolicy {
    pub(super) connection_limit: usize,
    pub(super) preparation_timeout: Duration,
    pub(super) shutdown_timeout: Duration,
}

impl ServePolicy {
    /// Validate all budgets without starting work or requiring an active Tokio runtime.
    pub fn new(
        connection_limit: usize,
        preparation_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> Result<Self, ServePolicyError> {
        if connection_limit == 0 {
            return Err(ServePolicyError::ZeroCapacity);
        }
        validate_timeout(preparation_timeout)?;
        validate_timeout(shutdown_timeout)?;
        Ok(Self {
            connection_limit,
            preparation_timeout,
            shutdown_timeout,
        })
    }
}

/// HTTP/1 limits, also used by the HTTP/1 branch of an Auto listener.
#[cfg(feature = "http1")]
#[derive(Debug, Clone, Copy)]
pub struct Http1ServePolicy {
    pub(super) serve: ServePolicy,
    pub(super) header_read_timeout: Duration,
    pub(super) max_headers: usize,
    pub(super) max_buffer_size: usize,
}

#[cfg(feature = "http1")]
impl Http1ServePolicy {
    /// Validate limits before handing them to Hyper; no implicit or unlimited defaults.
    /// ref: hyperium/hyper src/server/conn/http1.rs@v1.10.1
    pub fn new(
        serve: ServePolicy,
        header_read_timeout: Duration,
        max_headers: usize,
        max_buffer_size: usize,
    ) -> Result<Self, ServePolicyError> {
        validate_timeout(header_read_timeout)?;
        if max_headers == 0 {
            return Err(ServePolicyError::ZeroCapacity);
        }
        if max_buffer_size < 8192 {
            return Err(ServePolicyError::BufferTooSmall);
        }
        Ok(Self {
            serve,
            header_read_timeout,
            max_headers,
            max_buffer_size,
        })
    }
}
