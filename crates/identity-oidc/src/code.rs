//! Exchange the OIDC authorization code through the provider's vetted transport.
//! ref: oauth2-rs v5.0.0 src/endpoint.rs (RFC 6749 client authentication and exchange).
use super::{Transport, failure};
use base64::{Engine, engine::general_purpose::STANDARD};
use http::{HeaderValue, StatusCode, header};
use rss_identity_core::federation::{
    FederationError, ProtocolMaterial, ProviderCredentials, ProviderReason, ProviderSettings,
    ProviderStage,
};
use serde::Deserialize;
use url::{Url, form_urlencoded};
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
    #[serde(rename = "access_token")]
    _access_token: String,
    #[serde(rename = "token_type")]
    _token_type: String,
    #[serde(rename = "expires_in")]
    _expires_in: Option<u64>,
    #[serde(rename = "refresh_token")]
    _refresh_token: Option<String>,
    #[serde(rename = "scope")]
    _scope: Option<String>,
}

#[derive(Deserialize)]
struct TokenError {
    #[serde(rename = "error")]
    _error: String,
    #[serde(rename = "error_description")]
    _description: Option<String>,
    #[serde(rename = "error_uri")]
    _uri: Option<String>,
}

pub(super) fn valid_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

pub(super) async fn exchange(
    transport: &Transport,
    endpoint: &Url,
    settings: &ProviderSettings,
    credentials: &ProviderCredentials,
    material: &ProtocolMaterial,
    code: &str,
) -> Result<Zeroizing<String>, FederationError> {
    let client_id: String =
        form_urlencoded::byte_serialize(settings.client_id().as_str().as_bytes()).collect();
    let secret = Zeroizing::new(
        form_urlencoded::byte_serialize(credentials.client_secret().as_bytes()).collect::<String>(),
    );
    let basic = Zeroizing::new(format!("{client_id}:{}", secret.as_str()));
    let mut authorization =
        HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(basic.as_bytes())))
            .map_err(|_| invalid_response())?;
    authorization.set_sensitive(true);
    let body = form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", settings.redirect_uri()),
            ("code_verifier", material.verifier.as_str()),
        ])
        .finish();
    let request = http::Request::post(endpoint.as_str())
        .header(header::ACCEPT, "application/json")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, authorization)
        .body(body.into_bytes())
        .map_err(|_| invalid_response())?;
    parse_token(transport.call(ProviderStage::Exchange, request).await?)
}

fn invalid_response() -> FederationError {
    failure(ProviderStage::Exchange, ProviderReason::InvalidResponse)
}

fn parse_token(response: http::Response<Vec<u8>>) -> Result<Zeroizing<String>, FederationError> {
    let body = response.body();
    // Both the successful response and OAuth errors are JSON objects.
    if body.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return Err(invalid_response());
    }
    if response.status() != StatusCode::OK {
        return Err(match serde_json::from_slice::<TokenError>(body) {
            Ok(_) => failure(ProviderStage::Exchange, ProviderReason::CodeRejected),
            Err(_) => invalid_response(),
        });
    }
    if response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| {
            !v.to_str().is_ok_and(|v| {
                v.split(';')
                    .next()
                    .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
            })
        })
    {
        return Err(invalid_response());
    }
    let token: TokenResponse = serde_json::from_slice(body).map_err(|_| invalid_response())?;
    Ok(Zeroizing::new(token.id_token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_response_requires_a_complete_json_object() {
        let response = |status: StatusCode, media: &str, body: &str| {
            http::Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, media)
                .body(body.as_bytes().to_vec())
                .unwrap()
        };
        let success =
            r#"{"id_token":"fixture-id","access_token":"fixture-access","token_type":"bearer"}"#;
        assert_eq!(
            parse_token(response(
                StatusCode::OK,
                "Application/JSON; charset=UTF-8",
                success
            ))
            .unwrap()
            .as_str(),
            "fixture-id"
        );
        for (media, body) in [
            (
                "application/json",
                r#"["fixture-id","fixture-access","bearer",null,null,null]"#.to_owned(),
            ),
            ("application/json", format!("{success} []")),
            ("application/json+other", success.to_owned()),
        ] {
            assert_eq!(
                parse_token(response(StatusCode::OK, media, &body)).err(),
                Some(invalid_response())
            );
        }
        assert_eq!(
            parse_token(response(
                StatusCode::BAD_REQUEST,
                "application/json",
                r#"{"error":"invalid_grant"}"#
            ))
            .err(),
            Some(failure(
                ProviderStage::Exchange,
                ProviderReason::CodeRejected
            ))
        );
    }
}
