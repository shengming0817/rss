//! Strict ID-token security claims with separately interpreted ordinary profile values.
//! ref: jsonwebtoken src/validation.rs@11f83ab50d796f7e3a51d8fbd203ab3d050fed1b.
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::Jwk};
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
    pub nonce: String,
    pub azp: Option<String>,
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
    #[serde(flatten)]
    pub ordinary: serde_json::Map<String, serde_json::Value>,
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
    let algorithm = serde_json::to_value(header.alg).map_err(|_| FederationError::Claims)?;
    let approved = serde_json::to_value(&metadata.id_token_signing_alg_values_supported)
        .map_err(|_| FederationError::Claims)?;
    if !approved
        .as_array()
        .is_some_and(|values| values.contains(&algorithm))
    {
        return Err(FederationError::Claims);
    }
    Ok(header)
}
pub(super) fn symmetric(alg: Algorithm) -> bool {
    matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)
}
pub(super) fn signing_key(
    header: &jsonwebtoken::Header,
    keys: Option<&super::discovery::Jwks>,
    client_secret: &str,
) -> Result<DecodingKey, FederationError> {
    let algorithm = serde_json::to_value(header.alg).map_err(|_| FederationError::Claims)?;
    let key = if symmetric(header.alg) {
        DecodingKey::from_secret(client_secret.as_bytes())
    } else {
        let keys = &keys.ok_or(FederationError::Claims)?.keys;
        let key_type = match header.alg {
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => "RSA",
            Algorithm::ES256 | Algorithm::ES384 => "EC",
            Algorithm::EdDSA => "OKP",
            _ => return Err(FederationError::Claims),
        };
        let candidates: Vec<_> = keys
            .iter()
            .filter(|v| {
                header
                    .kid
                    .as_ref()
                    .is_none_or(|kid| v.get("kid").and_then(|v| v.as_str()) == Some(kid))
                    && v.get("kty").and_then(|v| v.as_str()) == Some(key_type)
                    && v.get("use").is_none_or(|v| v.as_str() == Some("sig"))
                    && v.get("alg").is_none_or(|v| v == &algorithm)
                    && v.get("key_ops").is_none_or(|v| {
                        v.as_array()
                            .is_some_and(|ops| ops.iter().any(|v| v.as_str() == Some("verify")))
                    })
            })
            .collect();
        if candidates.len() != 1 {
            return Err(FederationError::Claims);
        }
        let jwk: Jwk =
            serde_json::from_value(candidates[0].clone()).map_err(|_| FederationError::Claims)?;
        DecodingKey::from_jwk(&jwk).map_err(|_| FederationError::Claims)?
    };
    Ok(key)
}
pub(super) fn verify(
    raw: &str,
    alg: Algorithm,
    key: &DecodingKey,
    metadata: &super::Metadata,
    nonce: &str,
    client: &str,
    future_skew_seconds: u32,
) -> Result<Claims, FederationError> {
    let mut validation = Validation::new(alg);

    validation.set_required_spec_claims(&["iss", "sub", "aud", "exp"]);
    validation.set_audience(&[client]);
    validation.set_issuer(&[metadata.issuer.as_str()]);
    validation.leeway = 0;
    validation.validate_nbf = true;
    let claims = decode::<Claims>(raw, key, &validation)
        .map_err(|_| FederationError::Claims)?
        .claims;
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| FederationError::Unavailable)?
            .as_secs(),
    )
    .map_err(|_| FederationError::Unavailable)?;
    if claims.sub.is_empty()
        || claims.sub.len() > 256
        || claims.iat <= 0
        || claims.iat > now.saturating_add(i64::from(future_skew_seconds))
        || claims.exp <= claims.iat
        || claims.exp <= now
        || claims.azp.as_ref().is_some_and(|v| v != client)
        || matches!(&claims.aud,Audiences::Many(values) if values.len()>1 && claims.azp.as_deref()!=Some(client))
        || rss_identity_core::federation::digest(nonce)
            != rss_identity_core::federation::digest(&claims.nonce)
    {
        return Err(FederationError::Claims);
    }
    Ok(claims)
}
