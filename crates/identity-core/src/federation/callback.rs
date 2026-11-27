//! A provider callback carries one outcome. Upstream error text is never a return target.
use super::FederationError;
use zeroize::Zeroizing;

pub enum CallbackOutcome {
    Code(Zeroizing<String>),
    Denied { cancelled: bool },
}
impl CallbackOutcome {
    pub fn from_parts(
        code: Option<String>,
        error: Option<String>,
    ) -> Result<Self, FederationError> {
        match (code, error) {
            (Some(code), None) => Ok(Self::Code(Zeroizing::new(code))),
            (None, Some(error)) => Ok(Self::Denied {
                cancelled: error == "access_denied",
            }),
            _ => Err(FederationError::Configuration),
        }
    }
}
