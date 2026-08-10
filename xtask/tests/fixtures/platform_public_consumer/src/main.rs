use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use rss_platform::contracts::{
    RuntimeDomain, RuntimeInventory, RuntimeInventoryData, RuntimeInventoryRequest,
    RuntimeInventoryResponse, Sha256Fingerprint,
};
use rss_platform::{
    AccessToken, ApplicationBuilder, ApplicationModule, ApplicationName, ConditionCode,
    DiagnosticCode, Handler, HandlerError, ModuleName, RequestContext, RequestId, TrustedIssuer,
};

const TENANT: &str = "8b117a90-752f-4f2a-85f1-00c7c4e1f41c";

struct InventoryHandler;
impl Handler<RuntimeInventory> for InventoryHandler {
    fn handle(
        &self,
        _: RuntimeInventoryRequest,
        context: RequestContext<'_>,
    ) -> Result<RuntimeInventoryResponse, HandlerError> {
        assert_eq!(context.request_id().as_str(), "consumer-request");
        assert!(context.principal().matches_subject("consumer-user"));
        assert!(context.tenant().is_some_and(|tenant| tenant.id().as_str() == TENANT));
        assert!(context.allows_permission("runtime:inventory:read"));
        let assembly = fingerprint('a')?;
        let plan = fingerprint('b')?;
        let data = RuntimeInventoryData::new(assembly, plan, vec![RuntimeDomain::Identity])
            .map_err(|_| HandlerError::new())?;
        Ok(RuntimeInventoryResponse::new(data))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signing = SigningKey::from_bytes((&[9_u8; 32]).into())
        .map_err(|_| std::io::Error::other("invalid test signing key"))?;
    let point = signing.verifying_key().to_encoded_point(false);
    let jwks = serde_json::json!({"keys":[{
        "kty":"EC", "crv":"P-256", "alg":"ES256", "use":"sig", "kid":"consumer-key",
        "x":URL_SAFE_NO_PAD.encode(point.x().ok_or_else(|| std::io::Error::other("missing x"))?),
        "y":URL_SAFE_NO_PAD.encode(point.y().ok_or_else(|| std::io::Error::other("missing y"))?)
    }]}).to_string();
    let issuer = TrustedIssuer::from_jwks_json("https://consumer.example", "rss-platform", &jwks)?;
    let handle = ApplicationBuilder::new(ApplicationName::parse("external_consumer")?)
        .trusted_issuer(issuer)
        .module(ApplicationModule::new(ModuleName::parse("runtime")?).handler::<RuntimeInventory, _>(InventoryHandler))
        .build()?.start();
    let dispatcher = handle.dispatcher();
    let invalid = AccessToken::parse("header.payload.signature")?;
    assert!(
        dispatcher
            .verify(&invalid, SystemTime::now())
            .is_err()
    );
    let token = signed_token(&signing)?;
    let access = dispatcher.verify(&token, SystemTime::now())?;
    let response = dispatcher.dispatch::<RuntimeInventory>(
        &access,
        RequestId::parse("consumer-request")?,
        RuntimeInventoryRequest,
    )?;
    assert_eq!(response.data().schema_version(), 1);
    let conditions_read = dispatcher
        .conditions()
        .iter()
        .any(|item| item.code() == ConditionCode::AcceptingDispatch);
    assert!(conditions_read);
    let diagnostics_read = handle
        .diagnostics()
        .iter()
        .any(|item| item.code() == DiagnosticCode::InvalidCredential);
    assert!(diagnostics_read);
    let report = handle.shutdown(Duration::from_secs(1))?;
    let shutdown = report
        .diagnostics()
        .iter()
        .any(|item| item.code() == DiagnosticCode::ShutdownComplete);
    assert!(shutdown);
    let stopped_fail_closed = dispatcher
        .dispatch::<RuntimeInventory>(
            &access,
            RequestId::parse("consumer-request")?,
            RuntimeInventoryRequest,
        )
        .is_err();
    assert!(stopped_fail_closed);
    println!(
        "{}",
        serde_json::json!({
            "contract": "runtime.inventory",
            "subjectMatched": true,
            "tenantMatched": true,
            "permissionMatched": true,
            "requestIdMatched": true,
            "dispatch": response.data().schema_version() == 1,
            "conditionsRead": conditions_read,
            "diagnosticsRead": diagnostics_read,
            "shutdown": shutdown,
            "stoppedFailClosed": stopped_fail_closed
        })
    );
    Ok(())
}

fn fingerprint(byte: char) -> Result<Sha256Fingerprint, HandlerError> {
    Sha256Fingerprint::parse(&format!("sha256:{}", byte.to_string().repeat(64)))
        .map_err(|_| HandlerError::new())
}

fn signed_token(signing: &SigningKey) -> Result<AccessToken, Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"alg":"ES256","typ":"at+jwt","kid":"consumer-key"}))?);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({
        "sub":"consumer-user", "iat":now-10, "exp":now+100, "token_use":"access",
        "iss":"https://consumer.example", "aud":"rss-platform", "kind":"user",
        "tenant_id":TENANT, "permissions":["runtime:inventory:read"]
    }))?);
    let input = format!("{header}.{payload}");
    let signature: Signature = signing.sign(input.as_bytes());
    Ok(AccessToken::parse(&format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())))?)
}
