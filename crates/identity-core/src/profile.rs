//! Bounded, non-authorizing login profile values. No value here is an authentication proof.
//! ref: openidconnect-rs src/claims.rs@b639b5d39eac6903238867aeb2b29326502e6b26.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const MAX_BYTES: usize = 65_536;
pub const MAX_MEMBERS: usize = 1024;
pub const MAX_DEPTH: usize = 8;
pub const MAX_ARRAY: usize = 1024;
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid profile value or budget")]
pub struct ProfileError;

/// Deployment may tighten structural budgets and choose a finite positive profile lifetime.
#[derive(Debug, Clone, Copy)]
pub struct ProfileLimits {
    bytes: usize,
    members: usize,
    depth: usize,
    array: usize,
    max_age: u32,
}
impl Default for ProfileLimits {
    fn default() -> Self {
        Self {
            bytes: MAX_BYTES,
            members: MAX_MEMBERS,
            depth: MAX_DEPTH,
            array: MAX_ARRAY,
            max_age: 86400,
        }
    }
}
impl ProfileLimits {
    pub fn new(
        bytes: usize,
        members: usize,
        depth: usize,
        array: usize,
        max_age: u32,
    ) -> Result<Self, ProfileError> {
        if bytes == 0
            || bytes > MAX_BYTES
            || members == 0
            || members > MAX_MEMBERS
            || depth == 0
            || depth > MAX_DEPTH
            || array == 0
            || array > MAX_ARRAY
            || max_age == 0
        {
            return Err(ProfileError);
        }
        Ok(Self {
            bytes,
            members,
            depth,
            array,
            max_age,
        })
    }
    pub fn max_age_seconds(self) -> u32 {
        self.max_age
    }
}
/// Unknown business keys are preserved; this object grants no authentication or authorization.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "Value")]
pub struct Extensions(Map<String, Value>);
impl std::fmt::Debug for Extensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Extensions(<redacted>)")
    }
}
impl TryFrom<Value> for Extensions {
    type Error = ProfileError;
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let Value::Object(object) = value else {
            return Err(ProfileError);
        };
        let mut members = 0;
        check_object(&object, 1, &mut members, ProfileLimits::default())?;
        if serde_json::to_vec(&object).map_err(|_| ProfileError)?.len() > MAX_BYTES {
            return Err(ProfileError);
        }
        Ok(Self(object))
    }
}
impl Extensions {
    pub fn object(&self) -> &Map<String, Value> {
        &self.0
    }
    pub fn into_value(self) -> Value {
        Value::Object(self.0)
    }
}
fn check_object(
    object: &Map<String, Value>,
    depth: usize,
    members: &mut usize,
    limits: ProfileLimits,
) -> Result<(), ProfileError> {
    if depth > limits.depth {
        return Err(ProfileError);
    }
    *members = members.checked_add(object.len()).ok_or(ProfileError)?;
    if *members > limits.members {
        return Err(ProfileError);
    }
    for (key, value) in object {
        if key.chars().any(char::is_control)
            || matches!(
                key.to_ascii_lowercase().replace('-', "_").as_str(),
                "password"
                    | "access_token"
                    | "refresh_token"
                    | "id_token"
                    | "client_secret"
                    | "totp_seed"
                    | "private_key"
                    | "recovery_codes"
            )
        {
            return Err(ProfileError);
        }
        check_value(value, depth, members, limits)?;
    }
    Ok(())
}
fn check_value(
    value: &Value,
    depth: usize,
    members: &mut usize,
    limits: ProfileLimits,
) -> Result<(), ProfileError> {
    match value {
        Value::Object(object) => check_object(object, depth + 1, members, limits)?,
        Value::Array(values) => {
            if depth >= limits.depth || values.len() > limits.array {
                return Err(ProfileError);
            }
            for value in values {
                check_value(value, depth + 1, members, limits)?;
            }
        }
        Value::String(value) if value.contains('\0') => return Err(ProfileError),
        Value::Number(number) => {
            let number = number.as_f64().ok_or(ProfileError)?;
            if !number.is_finite() || (number.fract() == 0.0 && number.abs() > MAX_SAFE_INTEGER) {
                return Err(ProfileError);
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Attribute<T> {
    NotConfigured,
    Missing,
    Invalid,
    Available { value: T },
}
impl<T> Attribute<T> {
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Available { value } => Some(value),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Profile {
    pub display_name: Attribute<String>,
    pub username: Attribute<String>,
    pub email: Attribute<String>,
    pub email_verified: Attribute<bool>,
    pub extensions: Attribute<Extensions>,
}
impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Profile(<redacted>)")
    }
}
impl Profile {
    /// Invalid extension data is withheld, never truncated or substituted with an older value.
    pub fn apply_limits(&mut self, limits: ProfileLimits) {
        if let Attribute::Available { value } = &self.extensions {
            let mut members = 0;
            if check_object(value.object(), 1, &mut members, limits).is_err()
                || serde_json::to_vec(value.object()).map_or(true, |v| v.len() > limits.bytes)
            {
                self.extensions = Attribute::Invalid;
            }
        }
    }
    /// Called only on already verified ID-token claims by the installed OIDC adapter.
    /// Malformed ordinary profile values do not invalidate the subject/signature proof.
    pub fn from_claims(claims: &Map<String, Value>, settings: &ProfileSettings) -> Self {
        Self {
            display_name: text(claims.get("name"), 512),
            username: text(claims.get("preferred_username"), 256),
            email: text(claims.get("email"), 320),
            email_verified: match claims.get("email_verified") {
                None | Some(Value::Null) => Attribute::Missing,
                Some(Value::Bool(value)) => Attribute::Available { value: *value },
                _ => Attribute::Invalid,
            },
            extensions: match &settings.extensions_claim {
                None => Attribute::NotConfigured,
                Some(root) => match claims.get(root) {
                    None | Some(Value::Null) => Attribute::Missing,
                    Some(value) => match Extensions::try_from(value.clone()) {
                        Ok(value) => Attribute::Available { value },
                        Err(_) => Attribute::Invalid,
                    },
                },
            },
        }
    }
    pub fn missing() -> Self {
        Self {
            display_name: Attribute::Missing,
            username: Attribute::Missing,
            email: Attribute::Missing,
            email_verified: Attribute::Missing,
            extensions: Attribute::Missing,
        }
    }
    pub fn validate(&self) -> Result<(), ProfileError> {
        for (value, max) in [
            (&self.display_name, 512),
            (&self.username, 256),
            (&self.email, 320),
        ] {
            if value
                .value()
                .is_some_and(|v| v.len() > max || v.chars().any(char::is_control))
            {
                return Err(ProfileError);
            }
        }
        Ok(())
    }
}
fn text(value: Option<&Value>, max: usize) -> Attribute<String> {
    match value {
        None | Some(Value::Null) => Attribute::Missing,
        Some(Value::String(value))
            if value.len() <= max && !value.chars().any(char::is_control) =>
        {
            Attribute::Available {
                value: value.clone(),
            }
        }
        _ => Attribute::Invalid,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileSettings {
    pub extensions_claim: Option<String>,
    pub max_age_seconds: u32,
}
impl Default for ProfileSettings {
    fn default() -> Self {
        Self {
            extensions_claim: None,
            max_age_seconds: 14_400,
        }
    }
}
impl ProfileSettings {
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.max_age_seconds == 0 {
            return Err(ProfileError);
        }
        if self.extensions_claim.as_ref().is_some_and(|root| {
            root.is_empty()
                || root.len() > 255
                || root.chars().any(char::is_control)
                || matches!(
                    root.as_str(),
                    "sub"
                        | "iss"
                        | "aud"
                        | "exp"
                        | "iat"
                        | "nonce"
                        | "auth_time"
                        | "acr"
                        | "amr"
                        | "name"
                        | "preferred_username"
                        | "email"
                        | "email_verified"
                )
        }) {
            return Err(ProfileError);
        }
        Ok(())
    }
}

/// Explicit local source, not an override for an external provider observation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalProfile {
    pub display_name: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub extensions: Extensions,
    pub max_age_seconds: u32,
}
impl std::fmt::Debug for LocalProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalProfile(<redacted>)")
    }
}
impl LocalProfile {
    pub fn observation(&self) -> Result<Profile, ProfileError> {
        ProfileSettings {
            extensions_claim: None,
            max_age_seconds: self.max_age_seconds,
        }
        .validate()?;
        let attr = |value: &Option<String>| {
            value
                .clone()
                .map_or(Attribute::Missing, |value| Attribute::Available { value })
        };
        let profile = Profile {
            display_name: attr(&self.display_name),
            username: attr(&self.username),
            email: attr(&self.email),
            email_verified: Attribute::Missing,
            extensions: Attribute::Available {
                value: self.extensions.clone(),
            },
        };
        profile.validate()?;
        Ok(profile)
    }
}
