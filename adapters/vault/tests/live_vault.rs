//! Hermetic TLS HashiCorp Vault Transit + PKI T2 conformance.
//!
//! Run with Docker: `./hack/cargo.sh test -p vault --features integration --test live_vault`.

#![allow(clippy::expect_used)]

#[path = "live_vault_support.rs"]
mod live_vault_support;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use deviceloop::{
    CertificateKeyUsage, CertificatePolicy, CertificatePolicyDurations,
    CertificateRenewBeforeSeconds, CertificateSan, CertificateValiditySeconds,
};
use diport::{
    CertScope, Clock, KeyId, KeyName, KeyProvider, PkiArtifactErrorKind, PkiArtifactRequest,
    PkiAuthorizationReceipt, PkiCommonName, PkiExtendedKeyUsage, PkiPolicyDigest,
    PkiRequestGeneration, PkiSan, PkiSpkiDigest, RedactedBytes, SignRequest, Signer,
    SigningPurpose,
};
use identity_composition::{
    CertificateArtifactAcquisition, DeviceCertificateScope, DevicePolicyAuthorizationReceiptId,
    ExpectedGeneration, PolicyHash, classify_external_pki_artifact_error,
    mint_external_pki_production_artifact, validate_external_pki_artifact_request,
};
use ids::DeviceId;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, PublicKeyData, SanType,
};
use reqwest::{Client, StatusCode};
use rss_request_context::TenantId;
use secure::{Plaintext, ProtectionContext};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use vault::{
    VaultExternalPkiProviderClosure, VaultKeyProvider, VaultPkiHttpClient, VaultPkiMount,
    VaultPkiRole, VaultPkiTransport, VaultPkiTransportConfig, VaultSigner,
};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer, X509Certificate};

use live_vault_support::WarmOutageProxy;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSIT_MOUNT: &str = "transit";
const SIGNING_KEY: &str = "rss-ecdsa";
const ENCRYPTION_KEY: &str = "rss-aes";
const PKI_MOUNT: &str = "pki-device";
const PKI_ROLE: &str = "rss-device";
const DEVICE_COMMON_NAME: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

struct LiveClock;
impl Clock for LiveClock {
    #[allow(clippy::disallowed_methods)]
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

struct ProvisionedVault {
    _fixture: testkit::VaultTlsFixture,
    _network: testkit::BridgeNetwork,
    client: Client,
    endpoint: String,
    runtime_token: String,
    pki_root_pem: String,
    vault_tls_ca_pem: String,
}

async fn provision() -> Result<ProvisionedVault, Box<dyn std::error::Error>> {
    let network = testkit::bridge_network("rss-vault-tls").await?;
    let dns_name = format!("{}-node", network.name());
    let fixture = testkit::vault_tls(testkit::NetworkAttachment {
        network: network.name(),
        dns_name: &dns_name,
    })
    .await?;
    let endpoint = fixture.endpoint_url().to_owned();
    let vault_tls_ca_pem = fixture.ca_pem().to_owned();
    let ca = reqwest::Certificate::from_pem(vault_tls_ca_pem.as_bytes())?;
    let client = Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .pool_max_idle_per_host(0)
        .timeout(REQUEST_TIMEOUT)
        .build()?;
    let root_token = fixture.root_token().to_owned();

    vault_post(
        &client,
        &endpoint,
        &root_token,
        "sys/mounts/transit",
        json!({"type":"transit"}),
    )
    .await?;
    vault_post(
        &client,
        &endpoint,
        &root_token,
        "transit/keys/rss-ecdsa",
        json!({"type":"ecdsa-p256"}),
    )
    .await?;
    vault_post(
        &client,
        &endpoint,
        &root_token,
        "transit/keys/rss-aes",
        json!({"type":"aes256-gcm96","derived":true}),
    )
    .await?;
    vault_post(
        &client,
        &endpoint,
        &root_token,
        "sys/mounts/pki-root",
        json!({"type":"pki"}),
    )
    .await?;
    let root = vault_post(
        &client,
        &endpoint,
        &root_token,
        "pki-root/root/generate/internal",
        json!({"common_name":"RSS T2 Root","ttl":"720h","key_type":"ec","key_bits":256}),
    )
    .await?;
    let pki_root_pem = required_str(&root, "/data/certificate")?.to_owned();

    vault_post(
        &client,
        &endpoint,
        &root_token,
        "sys/mounts/pki-device",
        json!({"type":"pki"}),
    )
    .await?;
    let intermediate = vault_post(
        &client,
        &endpoint,
        &root_token,
        "pki-device/intermediate/generate/internal",
        json!({"common_name":"RSS T2 Device Intermediate","key_type":"ec","key_bits":256}),
    )
    .await?;
    let intermediate_csr = required_str(&intermediate, "/data/csr")?;
    let signed = vault_post(&client, &endpoint, &root_token, "pki-root/root/sign-intermediate", json!({"csr":intermediate_csr,"common_name":"RSS T2 Device Intermediate","ttl":"168h","format":"pem"})).await?;
    let intermediate_pem = required_str(&signed, "/data/certificate")?;
    vault_post(
        &client,
        &endpoint,
        &root_token,
        "pki-device/intermediate/set-signed",
        json!({"certificate":intermediate_pem}),
    )
    .await?;
    vault_post(
        &client,
        &endpoint,
        &root_token,
        "pki-device/roles/rss-device",
        json!({
            "allowed_domains":["device.example", DEVICE_COMMON_NAME], "allow_bare_domains":true,
            "allowed_uri_sans":["spiffe://tenant/device"], "allow_ip_sans":false,
            "client_flag":true, "server_flag":false, "code_signing_flag":false,
            "email_protection_flag":false, "key_usage":["DigitalSignature"],
            "basic_constraints_valid_for_non_ca":true,
            "ext_key_usage":["ClientAuth"], "require_cn":true,
            "key_type":"ec", "key_bits":256,
            "use_csr_common_name":true, "use_csr_sans":true, "ttl":"1h", "max_ttl":"1h"
        }),
    )
    .await?;

    let policy = format!(
        r#"
path "transit/sign/{SIGNING_KEY}" {{ capabilities = ["update"] }}
path "transit/encrypt/{ENCRYPTION_KEY}" {{ capabilities = ["update"] }}
path "transit/decrypt/{ENCRYPTION_KEY}" {{ capabilities = ["update"] }}
path "transit/rewrap/{ENCRYPTION_KEY}" {{ capabilities = ["update"] }}
path "{PKI_MOUNT}/sign/{PKI_ROLE}" {{ capabilities = ["update"] }}
"#
    );
    vault_post(
        &client,
        &endpoint,
        &root_token,
        "sys/policies/acl/rss-live",
        json!({"policy":policy}),
    )
    .await?;
    let token = vault_post(
        &client,
        &endpoint,
        &root_token,
        "auth/token/create",
        json!({"policies":["rss-live"],"ttl":"1h","no_default_policy":true}),
    )
    .await?;
    let runtime_token = required_str(&token, "/auth/client_token")?.to_owned();
    Ok(ProvisionedVault {
        _fixture: fixture,
        _network: network,
        client,
        endpoint,
        runtime_token,
        pki_root_pem,
        vault_tls_ca_pem,
    })
}

async fn vault_post(
    client: &Client,
    endpoint: &str,
    token: &str,
    path: &str,
    body: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let response = client
        .post(format!("{endpoint}/v1/{path}"))
        .header("X-Vault-Token", token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&body)?)
        .send()
        .await?;
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > 1024 * 1024)
    {
        return Err("Vault provisioning response exceeds limit".into());
    }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > 1024 * 1024 {
            return Err("Vault provisioning response exceeds limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        return Err(format!("Vault provisioning request failed with status {status}").into());
    }
    if bytes.is_empty() {
        Ok(Value::Null)
    } else {
        Ok(serde_json::from_slice(&bytes)?)
    }
}

fn required_str<'a>(
    value: &'a Value,
    pointer: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Vault response missing {pointer}").into())
}

fn pki_request() -> Result<PkiArtifactRequest, Box<dyn std::error::Error>> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec!["device.example".to_owned()])?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, DEVICE_COMMON_NAME);
    params.distinguished_name = name;
    params
        .subject_alt_names
        .push(SanType::URI("spiffe://tenant/device".try_into()?));
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let csr = params.serialize_request(&key)?;
    let csr_pem = csr.pem()?;
    let spki_digest: [u8; 32] = Sha256::digest(key.subject_public_key_info()).into();
    Ok(PkiArtifactRequest::try_new(
        CertScope::new(
            TenantId::parse("11111111-2222-4333-8444-555555555555")?,
            DeviceId::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")?,
        ),
        PkiRequestGeneration::try_new(7)?,
        PkiPolicyDigest::new([0x5a; 32]),
        PkiAuthorizationReceipt::try_new([7; 16])?,
        RedactedBytes::new(csr_pem.into_bytes()),
        PkiSpkiDigest::new(spki_digest),
        PkiCommonName::try_new(DEVICE_COMMON_NAME)?,
        vec![
            PkiSan::dns("device.example")?,
            PkiSan::uri("spiffe://tenant/device")?,
        ],
        vec![PkiExtendedKeyUsage::ClientAuth],
        Duration::from_secs(3600),
        Duration::from_secs(300),
    )?)
}

fn pki_transport_config(
    addr: impl Into<String>,
    token: impl Into<String>,
    mount: &str,
    role: &str,
    trust_roots_pem: Vec<RedactedBytes>,
    timeout: Duration,
) -> Result<VaultPkiTransportConfig, Box<dyn std::error::Error>> {
    Ok(VaultPkiTransportConfig::new(
        addr,
        token,
        VaultPkiMount::try_new(mount)?,
        VaultPkiRole::try_new(role)?,
        trust_roots_pem,
        timeout,
    ))
}

fn production_acquisition() -> Result<CertificateArtifactAcquisition, Box<dyn std::error::Error>> {
    let scope = DeviceCertificateScope::for_test(
        TenantId::parse("11111111-2222-4333-8444-555555555555")?,
        DeviceId::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")?,
    );
    let policy = CertificatePolicy::new(
        CertificatePolicyDurations::new(
            CertificateValiditySeconds::try_new(3600)?,
            CertificateRenewBeforeSeconds::try_new(300)?,
        )?,
        vec![CertificateKeyUsage::ClientAuth],
        vec![
            CertificateSan::parse("device.example")?,
            CertificateSan::parse("spiffe://tenant/device")?,
        ],
    )?;
    Ok(CertificateArtifactAcquisition::for_test(
        scope,
        ExpectedGeneration::try_new(7)?,
        PolicyHash::restore(&[0x5a; 32])?,
        DevicePolicyAuthorizationReceiptId::restore(uuid::Uuid::from_bytes([7; 16]))?,
        policy,
    ))
}

fn pki_http_client(
    vault: &ProvisionedVault,
) -> Result<VaultPkiHttpClient, Box<dyn std::error::Error>> {
    Ok(VaultPkiHttpClient::with_root_certificates([vault
        .vault_tls_ca_pem
        .as_bytes()])?)
}

fn field_aad() -> secure::DerivedAad {
    let tenant = TenantId::parse("11111111-2222-4333-8444-555555555555").expect("tenant");
    ProtectionContext::authenticated_request(tenant, "settings/db", "value", 1)
        .expect("context")
        .derive()
}

#[tokio::test(flavor = "multi_thread")]
async fn integration_vault_transit_and_pki_conformance() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let vault = provision().await?;
    let signer = VaultSigner::new_rss_access(
        vault.client.clone(),
        vault.endpoint.clone(),
        vault.runtime_token.clone(),
        TRANSIT_MOUNT,
        REQUEST_TIMEOUT,
        diport::JwtSigningBinding::rss_access(KeyId::new(SIGNING_KEY)),
    )?;
    let signature = signer
        .sign(SignRequest {
            key: KeyId::new(SIGNING_KEY),
            purpose: SigningPurpose::new("auth.rss-access"),
            message: b"hello-rss".to_vec().into(),
        })
        .await?;
    assert!(!signature.as_bytes().is_empty());

    let key_provider = VaultKeyProvider::new(
        vault.client.clone(),
        vault.endpoint.clone(),
        vault.runtime_token.clone(),
        TRANSIT_MOUNT,
        REQUEST_TIMEOUT,
    )?;
    let aad = field_aad();
    let encrypted = key_provider
        .encrypt(
            KeyName::try_new(ENCRYPTION_KEY)?,
            Plaintext::new(b"vault-field-secret".to_vec()),
            aad.clone(),
        )
        .await?;
    let decrypted = key_provider
        .decrypt(
            encrypted.ciphertext().to_vec().into(),
            encrypted.key().clone(),
            aad,
        )
        .await?;
    assert_eq!(decrypted.expose(), b"vault-field-secret");

    let transport = VaultPkiTransport::new(
        Arc::new(LiveClock),
        pki_http_client(&vault)?,
        pki_transport_config(
            vault.endpoint.clone(),
            vault.runtime_token.clone(),
            PKI_MOUNT,
            PKI_ROLE,
            vec![RedactedBytes::new(vault.pki_root_pem.as_bytes().to_vec())],
            REQUEST_TIMEOUT,
        )?,
    )?;
    let production_provider = VaultExternalPkiProviderClosure::new(
        Arc::new(LiveClock),
        pki_http_client(&vault)?,
        pki_transport_config(
            vault.endpoint.clone(),
            vault.runtime_token.clone(),
            PKI_MOUNT,
            PKI_ROLE,
            vec![RedactedBytes::new(vault.pki_root_pem.as_bytes().to_vec())],
            REQUEST_TIMEOUT,
        )?,
    )?;
    let production_acquisition = production_acquisition()?;
    let production_request = pki_request()?;
    validate_external_pki_artifact_request(&production_acquisition, &production_request)?;
    let production_evidence = production_provider
        .sign_csr(production_request)
        .await
        .map_err(|error| classify_external_pki_artifact_error(&error))?;
    let production_artifact = mint_external_pki_production_artifact(
        production_provider.provider_closure(),
        production_acquisition,
        production_evidence.into_verified(),
    )?
    .into_append_authorization()
    .into_snapshot();
    assert_eq!(
        production_artifact.authorization_receipt_id().as_uuid(),
        uuid::Uuid::from_bytes([7; 16])
    );
    assert!(
        production_artifact
            .artifact_id()
            .as_str()
            .starts_with("vault-pki-sha256:")
    );
    let evidence = transport.sign_csr(pki_request()?).await?;
    assert_eq!(
        evidence.request().scope().tenant().to_string(),
        "11111111-2222-4333-8444-555555555555"
    );
    assert_eq!(
        evidence.request().scope().device().as_uuid().to_string(),
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    );
    assert_eq!(evidence.request().generation().get(), 7);
    assert_eq!(evidence.request().policy_digest().as_bytes(), &[0x5a; 32]);
    assert_eq!(evidence.issuer_chain_der().len(), 2);
    let (_, leaf) = X509Certificate::from_der(evidence.leaf_der().as_bytes())?;
    let leaf_spki: [u8; 32] = Sha256::digest(leaf.public_key().raw).into();
    assert_eq!(evidence.request().spki_digest().as_bytes(), &leaf_spki);
    assert_eq!(evidence.serial().as_bytes(), leaf.raw_serial());
    assert_eq!(
        evidence.not_after().unix_seconds(),
        leaf.validity().not_after.timestamp()
    );
    let sans = leaf.subject_alternative_name()?.expect("leaf SAN");
    assert!(
        sans.value
            .general_names
            .iter()
            .any(|name| matches!(name, GeneralName::DNSName("device.example")))
    );
    assert!(
        sans.value
            .general_names
            .iter()
            .any(|name| matches!(name, GeneralName::URI("spiffe://tenant/device")))
    );
    assert!(leaf.extensions().iter().any(|extension| matches!(extension.parsed_extension(), ParsedExtension::ExtendedKeyUsage(eku) if eku.client_auth && !eku.server_auth)));
    let mut digest = Sha256::new();
    for cert in std::iter::once(evidence.leaf_der()).chain(evidence.issuer_chain_der()) {
        digest.update((cert.len() as u64).to_be_bytes());
        digest.update(cert.as_bytes());
    }
    assert_eq!(
        evidence.chain_digest().as_bytes(),
        &<[u8; 32]>::from(digest.finalize())
    );

    for path in [
        format!("{PKI_MOUNT}/issue/{PKI_ROLE}"),
        format!("{PKI_MOUNT}/roles/adjacent"),
        format!("{PKI_MOUNT}/issuers/generate/root/internal"),
        format!("{PKI_MOUNT}/keys/generate/internal"),
        format!("{PKI_MOUNT}/revoke"),
    ] {
        let response = vault
            .client
            .post(format!("{}/v1/{path}", vault.endpoint))
            .header("X-Vault-Token", &vault.runtime_token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body("{}")
            .send()
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "runtime token must not access {path}"
        );
    }

    let denied_role = VaultPkiTransport::new(
        Arc::new(LiveClock),
        pki_http_client(&vault)?,
        pki_transport_config(
            vault.endpoint.clone(),
            vault.runtime_token.clone(),
            PKI_MOUNT,
            "adjacent",
            vec![RedactedBytes::new(vault.pki_root_pem.as_bytes().to_vec())],
            REQUEST_TIMEOUT,
        )?,
    )?;
    assert_eq!(
        denied_role
            .sign_csr(pki_request()?)
            .await
            .expect_err("runtime token must not select another role")
            .kind(),
        PkiArtifactErrorKind::Forbidden
    );

    let mut wrong_root_params = CertificateParams::default();
    wrong_root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    wrong_root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let wrong_root_key = KeyPair::generate()?;
    let wrong_pki_root = wrong_root_params.self_signed(&wrong_root_key)?.pem();
    let wrong_ca_transport = VaultPkiTransport::new(
        Arc::new(LiveClock),
        pki_http_client(&vault)?,
        pki_transport_config(
            vault.endpoint.clone(),
            vault.runtime_token.clone(),
            PKI_MOUNT,
            PKI_ROLE,
            vec![RedactedBytes::new(wrong_pki_root.into_bytes())],
            Duration::from_secs(5),
        )?,
    )?;
    assert_eq!(
        wrong_ca_transport
            .sign_csr(pki_request()?)
            .await
            .expect_err("wrong PKI trust root must fail")
            .kind(),
        PkiArtifactErrorKind::InvalidResponse
    );

    let proxy = WarmOutageProxy::start(&vault.endpoint).await?;
    let outage_client = pki_http_client(&vault)?;
    let outage_transport = VaultPkiTransport::new(
        Arc::new(LiveClock),
        outage_client.clone(),
        pki_transport_config(
            proxy.endpoint(),
            vault.runtime_token.clone(),
            PKI_MOUNT,
            PKI_ROLE,
            vec![RedactedBytes::new(vault.pki_root_pem.as_bytes().to_vec())],
            Duration::from_secs(5),
        )?,
    )?;
    outage_transport.sign_csr(pki_request()?).await?;
    proxy.cut().await?;
    let error = outage_transport
        .sign_csr(pki_request()?)
        .await
        .expect_err("warm outage must fail closed");
    assert!(matches!(
        error.kind(),
        PkiArtifactErrorKind::Unavailable | PkiArtifactErrorKind::OutcomeUnknown
    ));
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains(&vault.runtime_token));
    assert!(!diagnostic.contains(&vault.endpoint));
    assert!(diagnostic.contains("<redacted>"));
    let recovered_proxy = WarmOutageProxy::start(&vault.endpoint).await?;
    let recovered_transport = VaultPkiTransport::new(
        Arc::new(LiveClock),
        outage_client,
        pki_transport_config(
            recovered_proxy.endpoint(),
            vault.runtime_token.clone(),
            PKI_MOUNT,
            PKI_ROLE,
            vec![RedactedBytes::new(vault.pki_root_pem.as_bytes().to_vec())],
            Duration::from_secs(5),
        )?,
    )?;
    recovered_transport.sign_csr(pki_request()?).await?;
    Ok(())
}
