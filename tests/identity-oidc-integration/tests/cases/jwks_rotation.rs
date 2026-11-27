//! One live HTTP JWKS endpoint changes keys under a single installed provider revision.
use crate::support::*;
use axum::{Json,Router,routing::{get,post}};
use jsonwebtoken::{Algorithm,EncodingKey,Header};
use rss_identity_core::federation::*;
use rss_identity_oidc::{HttpOidc,test_support::{fixture_provider,reuse_policy}};
use serde_json::{json,Value};
use std::sync::{Arc,atomic::{AtomicBool,AtomicUsize,Ordering::SeqCst}};
use std::time::{Duration,SystemTime,UNIX_EPOCH};
use tokio::sync::RwLock;

const JWK_A:&str=include_str!("../../../../crates/identity-oidc/tests/fixtures/entra-a.json");
const JWK_B:&str=include_str!("../../../../crates/identity-oidc/tests/fixtures/entra-b.json");
const KEY_A:&[u8]=include_bytes!("../../../../crates/identity-oidc/tests/fixtures/entra-a.der");
const KEY_B:&[u8]=include_bytes!("../../../../crates/identity-oidc/tests/fixtures/entra-b.der");

#[allow(clippy::disallowed_methods, reason="Test issuer mints live signed timestamps")]
async fn exchange(adapter:&HttpOidc,bound:&BoundProvider,issuer:&str,token:&RwLock<String>,kid:&str,key:&[u8])->anyhow::Result<UpstreamClaims>{
    let material=ProtocolMaterial::new(random_secret()?.to_string())?;
    let now=SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut header=Header::new(Algorithm::RS256);
    header.kid=Some(kid.into());
    *token.write().await=jsonwebtoken::encode(&header,&json!({"iss":issuer,"sub":"alice","aud":"identity-test","iat":now,"exp":now+120,"nonce":material.nonce.as_str()}),&EncodingKey::from_rsa_der(key))?;
    Ok(adapter.exchange(bound.clone(),material,random_secret()?,deadline()).await?)
}
#[tokio::test]
async fn jwks_refreshes_on_new_signing_key() -> anyhow::Result<()> {
    let socket=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let issuer=format!("http://{}/realm",socket.local_addr()?);
    let meta=json!({"issuer":issuer,"authorization_endpoint":format!("{issuer}/auth"),"token_endpoint":format!("{issuer}/token"),"jwks_uri":format!("{issuer}/keys"),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"authorization_response_iss_parameter_supported":true});
    let rotated=Arc::new(AtomicBool::new(false));
    let reads=Arc::new(AtomicUsize::new(0));
    let token=Arc::new(RwLock::new(String::new()));
    let cache=[("cache-control","max-age=120")];
    let keys={
        let rotated=rotated.clone();
        let reads=reads.clone();
        move || async move {
            reads.fetch_add(1,SeqCst);
            let key:Value=serde_json::from_str(if rotated.load(SeqCst){JWK_B}else{JWK_A}).expect("versioned JWK fixture");
            (cache,Json(json!({"keys":[key]})))
        }
    };
    let tokens={
        let token=token.clone();
        move || async move {Json(json!({"token_type":"Bearer","access_token":"fixture","id_token":token.read().await.clone()}))}
    };
    let routes=Router::new().route("/realm/.well-known/openid-configuration",get(move ||async move{(cache,Json(meta))})).route("/realm/keys",get(keys)).route("/realm/token",post(tokens));
    let server=tokio::spawn(axum::serve(socket,routes).into_future());
    let mut reuse=reuse_policy();
    reuse.refresh_cooldown=Duration::from_secs(60);
    let adapter=HttpOidc::for_loopback_test(vec![],policy()?,reuse)?;
    let bound=fixture_provider(&adapter,tenant()?,&settings(&issuer)?,&ProviderCredentials::new("fixture-secret".into(),None)?);
    exchange(&adapter,&bound,&issuer,&token,"entra-a",KEY_A).await?;
    let before=reads.load(SeqCst);
    assert_eq!(before,1);
    rotated.store(true,SeqCst);
    exchange(&adapter,&bound,&issuer,&token,"entra-b",KEY_B).await?;
    assert_eq!(reads.load(SeqCst),before+1);
    assert!(exchange(&adapter,&bound,&issuer,&token,"entra-b",KEY_A).await.is_err());
    server.abort();
    Ok(())
}
