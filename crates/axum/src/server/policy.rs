//! Explicit, validated transport and protocol budgets.
use std::time::Duration;

/// Closed field identity for policy diagnostics; never stores rejected configuration values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServePolicyField {
    /// Maximum simultaneous preparing and established connections.
    ConnectionLimit,
    /// Product preparation's total duration.
    PreparationTimeout,
    /// Duration before the first request reaches the service.
    EstablishmentTimeout,
    /// Managed runtime drain duration.
    ShutdownTimeout,
    /// HTTP/1 request header read duration.
    HeaderReadTimeout,
    /// HTTP/1 header count bound.
    MaxHeaders,
    /// HTTP/1 buffer bound.
    MaxBufferSize,
}

impl std::fmt::Display for ServePolicyField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ConnectionLimit => "connection_limit",
            Self::PreparationTimeout => "preparation_timeout",
            Self::EstablishmentTimeout => "establishment_timeout",
            Self::ShutdownTimeout => "shutdown_timeout",
            Self::HeaderReadTimeout => "header_read_timeout",
            Self::MaxHeaders => "max_headers",
            Self::MaxBufferSize => "max_buffer_size",
        })
    }
}

/// Invalid listener policy. Diagnostics never retain the rejected input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ServePolicyError {
    /// Connections and headers require a positive capacity.
    #[error("{0} must be nonzero")]
    ZeroCapacity(ServePolicyField),
    /// Each phase must have a positive time budget.
    #[error("{0} must be nonzero")]
    ZeroTimeout(ServePolicyField),
    /// Listener phase budgets support at most 24 hours.
    #[error("{0} must not exceed 24 hours")]
    TimeoutTooLarge(ServePolicyField),
    /// Hyper requires at least 8192 bytes for its HTTP/1 buffer.
    #[error("max_buffer_size must be at least 8192 bytes")]
    BufferTooSmall,
}

impl ServePolicyError {
    /// Identify the rejected field without parsing Display text.
    pub fn field(&self) -> ServePolicyField {
        match self {
            Self::ZeroCapacity(field) | Self::ZeroTimeout(field) | Self::TimeoutTooLarge(field) => {
                *field
            }
            Self::BufferTooSmall => ServePolicyField::MaxBufferSize,
        }
    }
}

// A stable supported horizon, not a check against the instant at construction time.
// HTTP listener phases are finite operational budgets, not calendar-scale scheduling.
const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

fn validate_timeout(timeout: Duration, field: ServePolicyField) -> Result<(), ServePolicyError> {
    if timeout.is_zero() {
        return Err(ServePolicyError::ZeroTimeout(field));
    }
    if timeout > MAX_TIMEOUT {
        return Err(ServePolicyError::TimeoutTooLarge(field));
    }
    Ok(())
}

/// Required capacity and budgets for preparation, first request and runtime drain.
///
/// Capacity counts both preparing and established connections. Preparation includes any
/// product failure handling; choose a budget that covers all work before HTTP starts.
/// Establishment ends at the first service call and never limits admitted handlers/bodies.
/// Each duration must be in (0, 24 hours]; this stable range remains valid after storage.
#[derive(Debug, Clone, Copy)]
pub struct ServePolicy {
    pub(super) connection_limit: usize,
    pub(super) preparation_timeout: Duration,
    pub(super) establishment_timeout: Duration,
    pub(super) shutdown_timeout: Duration,
}

impl ServePolicy {
    /// Validate all budgets without starting work or requiring an active Tokio runtime.
    pub fn new(
        connection_limit: usize,
        preparation_timeout: Duration,
        establishment_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> Result<Self, ServePolicyError> {
        if connection_limit == 0 {
            return Err(ServePolicyError::ZeroCapacity(
                ServePolicyField::ConnectionLimit,
            ));
        }
        validate_timeout(preparation_timeout, ServePolicyField::PreparationTimeout)?;
        validate_timeout(
            establishment_timeout,
            ServePolicyField::EstablishmentTimeout,
        )?;
        validate_timeout(shutdown_timeout, ServePolicyField::ShutdownTimeout)?;
        Ok(Self {
            connection_limit,
            preparation_timeout,
            establishment_timeout,
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
        validate_timeout(header_read_timeout, ServePolicyField::HeaderReadTimeout)?;
        if max_headers == 0 {
            return Err(ServePolicyError::ZeroCapacity(ServePolicyField::MaxHeaders));
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
