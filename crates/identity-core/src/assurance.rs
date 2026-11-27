//! Normalized authentication facts, not authorization or a transferable proof.
//! ref: openidconnect-rs src/verification/mod.rs@b639b5d39eac6903238867aeb2b29326502e6b26.
use crate::federation::FederationError;
use serde::{Deserialize, Serialize};

/// Closed normalized authentication strength. ref: serde enum representations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Acr {
    Unspecified,
    Mfa,
}
impl Acr {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Mfa => "mfa",
        }
    }
}
impl std::str::FromStr for Acr {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unspecified" => Ok(Self::Unspecified),
            "mfa" => Ok(Self::Mfa),
            _ => Err("unknown acr"),
        }
    }
}
/// Verified authentication methods, ordered by canonical wire spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Amr {
    Mfa,
    Otp,
    Pwd,
}
impl Amr {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mfa => "mfa",
            Self::Otp => "otp",
            Self::Pwd => "pwd",
        }
    }
}
impl std::str::FromStr for Amr {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mfa" => Ok(Self::Mfa),
            "otp" => Ok(Self::Otp),
            "pwd" => Ok(Self::Pwd),
            _ => Err("unknown amr"),
        }
    }
}
/// The closed enum bounds cardinality; ordering also rejects duplicate methods.
pub fn canonical_methods(methods: &[Amr]) -> bool {
    methods.windows(2).all(|w| w[0] < w[1])
}

/// Exact request intent; reauthentication alone never asks for or proves MFA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i16)]
pub enum AuthenticationMode {
    Login = 0,
    Reauthenticate = 1,
    StepUp = 2,
}
impl AuthenticationMode {
    pub fn from_storage(value: i16) -> Result<Self, FederationError> {
        match value {
            0 => Ok(Self::Login),
            1 => Ok(Self::Reauthenticate),
            2 => Ok(Self::StepUp),
            _ => Err(FederationError::Claims),
        }
    }
}

/// A validated snapshot. Only the upstream adapter interprets signed provider claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Input")]
pub struct Assurance {
    auth_time: Option<i64>,
    acr: Acr,
    amr: Vec<Amr>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    auth_time: Option<i64>,
    acr: Acr,
    amr: Vec<Amr>,
}
impl TryFrom<Input> for Assurance {
    type Error = FederationError;
    fn try_from(v: Input) -> Result<Self, Self::Error> {
        if v.auth_time.is_some_and(|t| t <= 0)
            || (v.acr == Acr::Mfa && v.auth_time.is_none())
            || !canonical_methods(&v.amr)
        {
            return Err(FederationError::Claims);
        }
        Ok(Self {
            auth_time: v.auth_time,
            acr: v.acr,
            amr: v.amr,
        })
    }
}
impl Assurance {
    /// Construct normalized facts; provider interpretation belongs to the upstream adapter.
    pub fn new(auth_time: Option<i64>, acr: Acr, amr: Vec<Amr>) -> Result<Self, FederationError> {
        Input {
            auth_time,
            acr,
            amr,
        }
        .try_into()
    }
    pub fn password(auth_time: i64) -> Result<Self, FederationError> {
        Input {
            auth_time: Some(auth_time),
            acr: Acr::Unspecified,
            amr: vec![Amr::Pwd],
        }
        .try_into()
    }
    /// PG supplies the attempt creation time and a fresh post-lock clock.
    pub fn check(
        &self,
        mode: AuthenticationMode,
        started: i64,
        now: i64,
        future_skew_seconds: u32,
    ) -> Result<(), FederationError> {
        if started <= 0
            || now < started
            || self
                .auth_time
                .is_some_and(|t| t > now.saturating_add(i64::from(future_skew_seconds)))
            || (mode != AuthenticationMode::Login
                && self
                    .auth_time
                    .is_none_or(|t| t < started.saturating_sub(i64::from(future_skew_seconds))))
            || (mode == AuthenticationMode::StepUp && self.acr != Acr::Mfa)
        {
            return Err(FederationError::Claims);
        }
        Ok(())
    }
    pub fn auth_time(&self) -> Option<i64> {
        self.auth_time
    }
    pub fn acr(&self) -> Acr {
        self.acr
    }
    pub fn amr(&self) -> &[Amr] {
        &self.amr
    }
}
