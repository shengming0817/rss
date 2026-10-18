use crate::Error;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// Exact opaque identity: 1..=256 UTF-8 bytes, no control characters.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Id(String);
impl Id {
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(Error::InvalidInput);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for Id {
    type Error = Error;
    fn try_from(v: String) -> Result<Self, Error> {
        Self::new(v)
    }
}
impl From<Id> for String {
    fn from(v: Id) -> Self {
        v.0
    }
}
impl std::fmt::Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Id([redacted])")
    }
}

/// Nonnegative Unix microseconds, bounded by signed 64-bit storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct Timestamp(i64);
impl Timestamp {
    pub fn new(micros: i64) -> Result<Self, Error> {
        if micros < 0 {
            return Err(Error::NumericRange);
        }
        Ok(Self(micros))
    }
    pub const fn micros(self) -> i64 {
        self.0
    }
    pub fn from_system_time(value: SystemTime) -> Result<Self, Error> {
        let d = value
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| Error::NumericRange)?;
        if !d.subsec_nanos().is_multiple_of(1000) {
            return Err(Error::NumericRange);
        }
        Self::new(i64::try_from(d.as_micros()).map_err(|_| Error::NumericRange)?)
    }
    pub fn to_system_time(self) -> Result<SystemTime, Error> {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_micros(self.0 as u64))
            .ok_or(Error::NumericRange)
    }
}
impl TryFrom<i64> for Timestamp {
    type Error = Error;
    fn try_from(v: i64) -> Result<Self, Error> {
        Self::new(v)
    }
}
impl From<Timestamp> for i64 {
    fn from(v: Timestamp) -> Self {
        v.0
    }
}

/// Finite IEEE value; negative zero canonicalizes to positive zero.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "f64", into = "f64")]
pub struct FiniteF64(f64);
impl FiniteF64 {
    pub fn new(v: f64) -> Result<Self, Error> {
        if !v.is_finite() {
            return Err(Error::NumericRange);
        }
        Ok(Self(if v == 0.0 { 0.0 } else { v }))
    }
    pub const fn get(self) -> f64 {
        self.0
    }
}
impl TryFrom<f64> for FiniteF64 {
    type Error = Error;
    fn try_from(v: f64) -> Result<Self, Error> {
        Self::new(v)
    }
}
impl From<FiniteF64> for f64 {
    fn from(v: FiniteF64) -> Self {
        v.0
    }
}
impl std::fmt::Debug for FiniteF64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FiniteF64([redacted])")
    }
}

/// Tagged numeric types do not coerce integers through a float.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum Number {
    I64(i64),
    U64(u64),
    F64(FiniteF64),
}
impl Number {
    pub const fn kind(self) -> NumberKind {
        match self {
            Self::I64(_) => NumberKind::I64,
            Self::U64(_) => NumberKind::U64,
            Self::F64(_) => NumberKind::F64,
        }
    }
    pub fn is_negative(self) -> bool {
        match self {
            Self::I64(v) => v < 0,
            Self::U64(_) => false,
            Self::F64(v) => v.get() < 0.0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NumberKind {
    I64,
    U64,
    F64,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum Value {
    Number(Number),
    Bool(bool),
    State(Id),
}

/// Absence never supplies a zero or a false value.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "quality",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum Reading {
    Valid(Value),
    Missing,
    Failed,
}

/// Ordered interval. A zero-width cumulative interval is a reset observation;
/// delta samples and query windows additionally require positive width.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "IntervalDto")]
pub struct Interval {
    start: Timestamp,
    end: Timestamp,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IntervalDto {
    start: Timestamp,
    end: Timestamp,
}
impl TryFrom<IntervalDto> for Interval {
    type Error = Error;
    fn try_from(v: IntervalDto) -> Result<Self, Error> {
        Self::new(v.start, v.end)
    }
}
impl Interval {
    pub fn new(start: Timestamp, end: Timestamp) -> Result<Self, Error> {
        if start > end {
            return Err(Error::InvalidInput);
        }
        Ok(Self { start, end })
    }
    pub const fn start(self) -> Timestamp {
        self.start
    }
    pub const fn end(self) -> Timestamp {
        self.end
    }
    pub fn width_micros(self) -> u64 {
        (self.end.0 - self.start.0) as u64
    }
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => { $(impl std::fmt::Debug for $ty {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(concat!(stringify!($ty), "([redacted])")) }
    })+ };
}
redacted_debug!(Number, Value, Reading);
