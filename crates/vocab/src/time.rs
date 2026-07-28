//! Fallible Unix-epoch time vocabulary shared by event producers and consumers.

use std::time::{Duration, SystemTime};

/// A non-negative Unix timestamp that is representable by the wire `int64` contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixEpochSeconds(i64);

/// Unix timestamp conversion failed at a protocol boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UnixEpochSecondsError {
    #[error("time precedes the Unix epoch")]
    BeforeEpoch,
    #[error("time exceeds the Unix int64 range")]
    Overflow,
}

impl UnixEpochSeconds {
    /// Convert an elapsed duration since the epoch without saturating.
    pub fn try_from_duration(duration: Duration) -> Result<Self, UnixEpochSecondsError> {
        i64::try_from(duration.as_secs())
            .map(Self)
            .map_err(|_| UnixEpochSecondsError::Overflow)
    }

    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }

    /// Rebuild `SystemTime`; platforms with a narrower range fail closed.
    pub fn to_system_time(self) -> Result<SystemTime, UnixEpochSecondsError> {
        let seconds = u64::try_from(self.0).map_err(|_| UnixEpochSecondsError::BeforeEpoch)?;
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .ok_or(UnixEpochSecondsError::Overflow)
    }
}

impl TryFrom<SystemTime> for UnixEpochSeconds {
    type Error = UnixEpochSecondsError;

    fn try_from(value: SystemTime) -> Result<Self, Self::Error> {
        value
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| UnixEpochSecondsError::BeforeEpoch)
            .and_then(Self::try_from_duration)
    }
}

impl TryFrom<i64> for UnixEpochSeconds {
    type Error = UnixEpochSecondsError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        if value < 0 {
            Err(UnixEpochSecondsError::BeforeEpoch)
        } else {
            Ok(Self(value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_rejects_pre_epoch_and_int64_overflow() {
        assert_eq!(
            UnixEpochSeconds::try_from(SystemTime::UNIX_EPOCH - Duration::from_secs(1)),
            Err(UnixEpochSecondsError::BeforeEpoch)
        );
        assert_eq!(
            UnixEpochSeconds::try_from_duration(Duration::from_secs(i64::MAX as u64 + 1)),
            Err(UnixEpochSecondsError::Overflow)
        );
        assert_eq!(
            UnixEpochSeconds::try_from(-1),
            Err(UnixEpochSecondsError::BeforeEpoch)
        );
    }

    #[test]
    fn conversion_round_trips_representable_values() {
        let value = UnixEpochSeconds::try_from(42).expect("valid epoch seconds");
        assert_eq!(value.get(), 42);
        assert_eq!(
            value.to_system_time().expect("representable system time"),
            SystemTime::UNIX_EPOCH + Duration::from_secs(42)
        );
    }
}
