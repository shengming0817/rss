//! Strict ID-token security claims with separately interpreted ordinary profile values.
//! ref: jsonwebtoken src/validation.rs@11f83ab50d796f7e3a51d8fbd203ab3d050fed1b.
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rss_identity_core::federation::FederationError;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: Audiences,
    pub iat: i64,
    pub exp: i64,
    #[serde(
        default,
        deserialize_with = "numeric_date",
        skip_serializing_if = "Option::is_none"
    )]
    pub nbf: Option<u64>,
    pub nonce: String,
    pub azp: Option<String>,
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
    #[serde(flatten)]
    pub ordinary: serde_json::Map<String, serde_json::Value>,
}
impl Claims {
    /// Move the verified ordinary claims into the exchange's mapping input. Project only
    /// explicitly selected standard fields, preserving NumericDate normalization and absence.
    pub fn mapping_fields(
        &mut self,
        mapping: &rss_identity_core::federation::ClaimMapping,
    ) -> Result<serde_json::Value, FederationError> {
        let mut fields = std::mem::take(&mut self.ordinary);
        for name in [
            mapping.groups.as_deref(),
            mapping.profile.extensions_claim.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let value = match name {
                "iat" => self.iat.into(),
                "exp" => self.exp.into(),
                "nbf" => match self.nbf {
                    Some(date) => date.into(),
                    None => continue,
                },
                "auth_time" => self.auth_time.into(),
                "acr" => serde_json::to_value(&self.acr).map_err(|_| FederationError::Claims)?,
                "amr" => serde_json::to_value(&self.amr).map_err(|_| FederationError::Claims)?,
                _ => continue,
            };
            fields.insert(name.to_owned(), value);
        }
        Ok(serde_json::Value::Object(fields))
    }
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum Audiences {
    One(String),
    Many(Vec<String>),
}

pub(super) fn approved_header(
    raw: &str,
    metadata: &super::Metadata,
) -> Result<jsonwebtoken::Header, FederationError> {
    if raw.is_empty() {
        return Err(FederationError::Claims);
    }
    let header = decode_header(raw).map_err(|_| FederationError::Claims)?;
    if header.crit.is_some()
        || header.cty.is_some()
        || header.typ.as_ref().is_some_and(|v| {
            !v.eq_ignore_ascii_case("jwt") && !v.eq_ignore_ascii_case("application/jwt")
        })
    {
        return Err(FederationError::Claims);
    }
    if !metadata
        .id_token_signing_alg_values_supported
        .iter()
        .any(|value| value.parse::<Algorithm>() == Ok(header.alg))
    {
        return Err(FederationError::Claims);
    }
    Ok(header)
}
pub(super) fn symmetric(alg: Algorithm) -> bool {
    matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)
}
pub(super) fn signing_key<'a>(
    header: &jsonwebtoken::Header,
    keys: Option<&'a super::discovery::Jwks>,
    client_secret: &str,
) -> Result<std::borrow::Cow<'a, DecodingKey>, FederationError> {
    if symmetric(header.alg) {
        return Ok(std::borrow::Cow::Owned(DecodingKey::from_secret(
            client_secret.as_bytes(),
        )));
    }
    keys.ok_or(FederationError::Claims)?
        .select(header)
        .map(std::borrow::Cow::Borrowed)
}
#[allow(
    clippy::too_many_arguments,
    reason = "bind the approved algorithm, key, claims and host clock together"
)]
pub(super) fn verify(
    raw: &str,
    alg: Algorithm,
    key: &DecodingKey,
    metadata: &super::Metadata,
    nonce: &str,
    client: &str,
    future_skew_seconds: u32,
    observed: SystemTime,
) -> Result<Claims, FederationError> {
    let mut validation = Validation::new(alg);

    validation.set_required_spec_claims(&["iss", "sub", "aud", "exp"]);
    validation.set_audience(&[client]);
    validation.set_issuer(&[metadata.issuer.as_str()]);
    validation.validate_exp = false; // The host clock checks both temporal claims below.
    let claims = decode::<Claims>(raw, key, &validation)
        .map_err(|_| FederationError::Claims)?
        .claims;
    let now = unix_seconds(observed)?;
    if claims.sub.is_empty()
        || claims.sub.len() > 256
        || claims.iat <= 0
        || claims.iat > now.saturating_add(i64::from(future_skew_seconds))
        || claims.exp <= claims.iat
        || claims.exp <= now
        || claims.nbf.is_some_and(|nbf| nbf > now as u64)
        || claims.azp.as_ref().is_some_and(|v| v != client)
        || matches!(&claims.aud, Audiences::Many(values) if values.as_slice() != [client])
        || rss_identity_core::federation::digest(nonce)
            != rss_identity_core::federation::digest(&claims.nonce)
    {
        return Err(FederationError::Claims);
    }
    Ok(claims)
}

// jsonwebtoken 11.1 rounds representable nonnegative fractional NumericDates to seconds.
// Serde's field default handles absence. A present value must be a JSON number.
fn numeric_date<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    let number = serde_json::Number::deserialize(d)?;
    let value = number.as_u64().or_else(|| {
        number
            .as_f64()
            .filter(|n| *n >= 0.0 && *n < u64::MAX as f64)
            .map(|n| n.round() as u64)
    });
    value
        .map(Some)
        .ok_or_else(|| serde::de::Error::custom("invalid NumericDate"))
}

pub(super) fn unix_seconds(observed: SystemTime) -> Result<i64, FederationError> {
    i64::try_from(
        observed
            .duration_since(UNIX_EPOCH)
            .map_err(|_| FederationError::Unavailable)?
            .as_secs(),
    )
    .map_err(|_| FederationError::Unavailable)
}
