//! Vault resolver production-closeout journey.
//!
//! The journey enters through the runtime integration seam so the same typed allowlist parser and
//! production HTTPS resolver constructor used by serving are exercised. The active Settings
//! capability derives its readiness target from that same allowlist: invalid configuration is a
//! startup failure, request authorization errors remain local, and an allowed canary reaches the
//! provider and retains provider-down classification.

use std::sync::Arc;
use std::time::Duration;

use diport::{SecretCoordinate, SecretResolver, SecretResolverError};
use runtime::test_support::build_vault_runtime_from_values;
use tokio::net::TcpListener;
use vocab::TenantId;

const TENANT_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const TENANT_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const STORE_A: &str = "primary";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn allowlist_json() -> String {
    serde_json::json!({
        "bindings": [{
            "tenantId": TENANT_A,
            "storeId": STORE_A,
            "mount": "secret",
            "kvPathPrefix": "tenants/a"
        }]
    })
    .to_string()
}

fn build_runtime(endpoint: String, allowlist: String) -> TestResult<vault::VaultRuntimeDeps> {
    let (runtime, _signer, _settings_key) = build_vault_runtime_from_values(
        endpoint,
        "journey-vault-token".to_owned(),
        "transit".to_owned(),
        "rss-jwt-es256".to_owned(),
        "settings-config".to_owned(),
        allowlist,
    )?;
    Ok(runtime)
}

#[test]
fn security_provider_closeout_rejects_invalid_or_empty_allowlist_at_startup() -> TestResult {
    for allowlist in [
        String::new(),
        "not-json".to_owned(),
        r#"{"bindings":[]}"#.to_owned(),
    ] {
        let result = build_runtime("https://127.0.0.1:1".to_owned(), allowlist);
        let Err(error) = result else {
            return Err(std::io::Error::other(
                "invalid or empty allowlist must fail before runtime construction",
            )
            .into());
        };
        assert!(
            format!("{error:#}").contains("vault tenant store allowlist"),
            "startup error must retain the static allowlist classification: {error:#}"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn security_provider_closeout_separates_forbidden_requests_from_provider_down() -> TestResult
{
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await?);
    let endpoint = format!("https://{}", listener.local_addr()?);
    let runtime = build_runtime(endpoint, allowlist_json())?;
    let settings = runtime.for_domain::<vault::caps::Settings>();
    let readiness_targets = settings.secret_resolver_readiness_targets();
    assert_eq!(readiness_targets.len(), 1);
    assert_eq!(readiness_targets[0].tenant(), TenantId::parse(TENANT_A)?);
    assert_eq!(readiness_targets[0].coordinate().store_id(), STORE_A);
    assert_eq!(
        readiness_targets[0].coordinate().key(),
        vault::SECRET_RESOLVER_READINESS_KEY
    );
    let resolver = settings.secret_resolver();
    let tenant_a = TenantId::parse(TENANT_A)?;
    let tenant_b = TenantId::parse(TENANT_B)?;

    let allowed_coordinate = readiness_targets[0].coordinate().clone();
    let wrong_tenant = resolver.resolve(tenant_b, &allowed_coordinate).await;
    assert!(
        matches!(wrong_tenant, Err(SecretResolverError::Forbidden)),
        "cross-tenant request must be locally forbidden: {wrong_tenant:?}"
    );

    let unknown_store_coordinate = SecretCoordinate::new("unknown", "database/password", None);
    let unknown_store = resolver.resolve(tenant_a, &unknown_store_coordinate).await;
    assert!(
        matches!(unknown_store, Err(SecretResolverError::Forbidden)),
        "unknown store must be locally forbidden: {unknown_store:?}"
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "allowlist misses must not open a provider connection"
    );

    let observer = Arc::clone(&listener);
    let provider_connection = tokio::spawn(async move {
        let (socket, _) = tokio::time::timeout(Duration::from_secs(1), observer.accept())
            .await
            .map_err(|_| std::io::Error::other("allowed request did not reach provider"))??;
        drop(socket);
        Ok::<_, std::io::Error>(())
    });
    let provider_down = resolver.resolve(tenant_a, &allowed_coordinate).await;
    provider_connection.await??;

    assert!(
        matches!(
            provider_down,
            Err(SecretResolverError::StoreUnreachable { .. } | SecretResolverError::Timeout)
        ),
        "allowlisted request to a down provider must not be classified as Forbidden: {provider_down:?}"
    );
    assert!(
        !matches!(provider_down, Err(SecretResolverError::Forbidden)),
        "provider reachability and request authorization failures must remain distinct"
    );

    Ok(())
}
