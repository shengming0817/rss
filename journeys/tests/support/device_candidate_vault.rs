use std::sync::Arc;
use std::time::{Duration, SystemTime};

use diport::{Clock, ExternalCsrError, ExternalCsrEvidence, ExternalCsrRequest};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
};
use reqwest::Client;
use serde_json::{Value, json};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const PKI_MOUNT: &str = "pki-device";
const PKI_ROLE: &str = "rss-device";

pub struct LiveClock;

impl Clock for LiveClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

pub struct ProvisionedDevicePki {
    _fixture: testkit::VaultTlsFixture,
    _network: testkit::BridgeNetwork,
    endpoint: String,
    runtime_token: String,
    pki_root_pem: String,
    vault_tls_ca_pem: String,
}

impl ProvisionedDevicePki {
    pub fn provider(&self) -> anyhow::Result<Arc<vault::VaultExternalPkiProviderClosure>> {
        let client =
            vault::VaultPkiHttpClient::with_root_certificates([self.vault_tls_ca_pem.as_bytes()])?;
        let config = vault::VaultPkiTransportConfig::new(
            self.endpoint.clone(),
            self.runtime_token.clone(),
            vault::VaultPkiMount::try_new(PKI_MOUNT)?,
            vault::VaultPkiRole::try_new(PKI_ROLE)?,
            vec![diport::RedactedBytes::new(
                self.pki_root_pem.as_bytes().to_vec(),
            )],
            REQUEST_TIMEOUT,
        );
        Ok(Arc::new(vault::VaultExternalPkiProviderClosure::new(
            Arc::new(LiveClock),
            client,
            config,
        )?))
    }
}

pub async fn provision() -> anyhow::Result<ProvisionedDevicePki> {
    let network = testkit::bridge_network("rss-device-candidate-vault").await?;
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
        "sys/mounts/pki-root",
        json!({"type":"pki"}),
    )
    .await?;
    let root = vault_post(
        &client,
        &endpoint,
        &root_token,
        "pki-root/root/generate/internal",
        json!({"common_name":"RSS Candidate T2 Root","ttl":"720h","key_type":"ec","key_bits":256}),
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
        json!({"common_name":"RSS Candidate Device Intermediate","key_type":"ec","key_bits":256}),
    )
    .await?;
    let signed = vault_post(
        &client,
        &endpoint,
        &root_token,
        "pki-root/root/sign-intermediate",
        json!({"csr":required_str(&intermediate, "/data/csr")?,"common_name":"RSS Candidate Device Intermediate","ttl":"168h","format":"pem"}),
    )
    .await?;
    vault_post(
        &client,
        &endpoint,
        &root_token,
        "pki-device/intermediate/set-signed",
        json!({"certificate":required_str(&signed, "/data/certificate")?}),
    )
    .await?;
    vault_post(
        &client,
        &endpoint,
        &root_token,
        "pki-device/roles/rss-device",
        json!({
            "allowed_domains":[super::DEVICE,"device-convergence-two.example"],
            "allow_bare_domains":true,"allow_ip_sans":false,
            "client_flag":true,"server_flag":false,"code_signing_flag":false,
            "email_protection_flag":false,"key_usage":["DigitalSignature"],
            "basic_constraints_valid_for_non_ca":true,"ext_key_usage":["ClientAuth"],
            "require_cn":true,"key_type":"ec","key_bits":256,
            "use_csr_common_name":true,"use_csr_sans":true,"ttl":"1h","max_ttl":"1h"
        }),
    )
    .await?;
    vault_post(
        &client,
        &endpoint,
        &root_token,
        "sys/policies/acl/rss-device-candidate",
        json!({"policy":format!("path \"{PKI_MOUNT}/sign/{PKI_ROLE}\" {{ capabilities = [\"update\"] }}")}),
    )
    .await?;
    let token = vault_post(
        &client,
        &endpoint,
        &root_token,
        "auth/token/create",
        json!({"policies":["rss-device-candidate"],"ttl":"1h","no_default_policy":true}),
    )
    .await?;
    Ok(ProvisionedDevicePki {
        _fixture: fixture,
        _network: network,
        endpoint,
        runtime_token: required_str(&token, "/auth/client_token")?.to_owned(),
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
) -> anyhow::Result<Value> {
    let response = client
        .post(format!("{endpoint}/v1/{path}"))
        .header("X-Vault-Token", token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&body)?)
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "Vault provisioning request failed"
    );
    let bytes = response.bytes().await?;
    anyhow::ensure!(
        bytes.len() <= 1024 * 1024,
        "Vault provisioning response exceeds limit"
    );
    if bytes.is_empty() {
        Ok(Value::Null)
    } else {
        Ok(serde_json::from_slice(&bytes)?)
    }
}

fn required_str<'a>(value: &'a Value, pointer: &str) -> anyhow::Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Vault response omitted required field"))
}

pub struct ExistingCsrResolver {
    csr_pem: Vec<u8>,
}

impl ExistingCsrResolver {
    pub fn new(device: &str, san: &str) -> anyhow::Result<Self> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![san.to_owned()])?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, device);
        params.distinguished_name = name;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let csr_pem = params.serialize_request(&key)?.pem()?.into_bytes();
        Ok(Self { csr_pem })
    }
}

impl diport::ExternalCsrResolver for ExistingCsrResolver {
    async fn resolve(
        &self,
        request: ExternalCsrRequest,
    ) -> Result<ExternalCsrEvidence, ExternalCsrError> {
        tracing::info!(
            generation = request.generation().get(),
            "candidate CSR evidence resolved"
        );
        ExternalCsrEvidence::new(request, self.csr_pem.clone())
    }
}
