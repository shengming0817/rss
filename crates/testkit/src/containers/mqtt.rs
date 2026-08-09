use std::time::Duration;

use testcontainers::core::{IntoContainerPort as _, WaitFor};
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt as _};

use super::{ContainerService, MQTTS_PORT, Result, runtime};

// ── mqtt（Mosquitto mTLS + assertion plugin）─────────────────────────────────

pub(super) const MQTT_TENANT: &str = "11111111-1111-4111-8111-111111111111";
pub(super) const MQTT_CROSS_TENANT: &str = "33333333-3333-4333-8333-333333333333";
pub(super) const MQTT_DEVICE: &str = "22222222-2222-4222-8222-222222222222";
pub(super) const MQTT_CURRENT_GENERATION: u64 = 2;
pub(super) const MQTT_STALE_GENERATION: u64 = 1;
pub(super) const MQTT_RSS_CLIENT_ID: &str = "rss-mqtt-adapter";
pub(super) const MQTT_UPLINK_CONTRACTS: &[&str] = &[
    "identity.device-command-acked",
    "identity.device-certificate-reported",
];
pub(super) const MQTT_DOWNLINK_CONTRACTS: &[&str] = &[
    "identity.commands.apply-device-certificate",
    "identity.device-ingress-receipted",
];
pub(super) const MQTT_DEVICE_CURRENT_SERIAL: u64 = 2002;
pub(super) const MQTT_DEVICE_STALE_SERIAL: u64 = 2001;
pub(super) const MQTT_DEVICE_CROSS_SERIAL: u64 = 3002;
pub(super) const MQTT_RSS_A_SERIAL: u64 = 1001;
pub(super) const MQTT_RSS_B_SERIAL: u64 = 1002;
pub(super) const MOSQUITTO_READY_STDOUT: &str = "mosquitto version 2.0.22 running";

/// Closed broker assertion fault set for hermetic MQTT boundary tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MqttAssertionFault {
    CorruptFirstSignature,
}

/// Client-side MQTT trust and identity material. PEM fields are intentionally absent from Debug.
#[derive(Clone)]
pub struct MqttFixtureTlsPem {
    pub(super) ca_pem: String,
    pub(super) certificate_pem: Option<String>,
    pub(super) private_key_pem: Option<String>,
}

impl MqttFixtureTlsPem {
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn certificate_pem(&self) -> Option<&str> {
        self.certificate_pem.as_deref()
    }

    pub fn private_key_pem(&self) -> Option<&str> {
        self.private_key_pem.as_deref()
    }
}

impl std::fmt::Debug for MqttFixtureTlsPem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MqttFixtureTlsPem")
            .field("ca", &"<redacted>")
            .field(
                "certificate",
                &self.certificate_pem.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "private_key",
                &self.private_key_pem.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// One closed credential case minted by [`mosquitto_mtls`].
#[derive(Clone)]
pub struct MqttCredential {
    pub(super) revision: u64,
    pub(super) stable_client_id: String,
    pub(super) tls: MqttFixtureTlsPem,
}

impl MqttCredential {
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn stable_client_id(&self) -> &str {
        &self.stable_client_id
    }

    pub fn tls(&self) -> &MqttFixtureTlsPem {
        &self.tls
    }
}

impl std::fmt::Debug for MqttCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MqttCredential")
            .field("revision", &self.revision)
            .field("stable_client_id", &self.stable_client_id)
            .field("tls", &self.tls)
            .finish()
    }
}

pub(super) struct MqttGeneratedMaterial {
    pub(super) ca_pem: String,
    pub(super) server_certificate_pem: String,
    pub(super) server_private_key_pem: String,
    pub(super) assertion_signing_key_pem: String,
    pub(super) assertion_public_key: [u8; 32],
    pub(super) empty_crl_pem: String,
    pub(super) revoked_device_current_crl_pem: String,
    pub(super) acl: String,
    pub(super) rss_a: MqttCredential,
    pub(super) rss_b: MqttCredential,
    pub(super) device_current: MqttCredential,
    pub(super) device_stale: MqttCredential,
    pub(super) device_cross_tenant: MqttCredential,
    pub(super) device_wrong_ca: MqttCredential,
    pub(super) device_no_certificate: MqttCredential,
}

/// Hermetic Mosquitto mTLS fixture. It owns the broker and exposes only client material plus the
/// Ed25519 verification key; the signing key is copied into the broker and then discarded.
pub struct MqttMtlsFixture {
    pub(super) container: Box<ContainerAsync<GenericImage>>,
    pub(super) url: String,
    pub(super) assertion_public_key: [u8; 32],
    pub(super) empty_crl_pem: String,
    pub(super) revoked_device_current_crl_pem: String,
    pub(super) broker_bundle: MqttBrokerBundle,
    pub(super) rss_a: MqttCredential,
    pub(super) rss_b: MqttCredential,
    pub(super) device_current: MqttCredential,
    pub(super) device_stale: MqttCredential,
    pub(super) device_cross_tenant: MqttCredential,
    pub(super) device_wrong_ca: MqttCredential,
    pub(super) device_no_certificate: MqttCredential,
}

#[derive(Clone)]
pub(super) struct MqttBrokerBundle {
    pub(super) ca_pem: String,
    pub(super) server_certificate_pem: String,
    pub(super) server_private_key_pem: String,
    pub(super) assertion_signing_key_pem: String,
    pub(super) acl: String,
    pub(super) assertion_fault: Option<MqttAssertionFault>,
}

impl MqttMtlsFixture {
    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn broker_assertion_public_key(&self) -> &[u8; 32] {
        &self.assertion_public_key
    }

    pub fn rss_a(&self) -> &MqttCredential {
        &self.rss_a
    }

    pub fn rss_b(&self) -> &MqttCredential {
        &self.rss_b
    }

    pub fn device_current(&self) -> &MqttCredential {
        &self.device_current
    }

    pub fn device_stale(&self) -> &MqttCredential {
        &self.device_stale
    }

    pub fn device_cross_tenant(&self) -> &MqttCredential {
        &self.device_cross_tenant
    }

    pub fn device_wrong_ca(&self) -> &MqttCredential {
        &self.device_wrong_ca
    }

    pub fn device_no_certificate(&self) -> &MqttCredential {
        &self.device_no_certificate
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.container.stop_with_timeout(Some(10)).await?;
        Ok(())
    }

    pub async fn start(&mut self) -> Result<()> {
        let prior_stdout_len = self
            .container
            .stdout_to_vec()
            .await
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        self.container.start().await?;
        let host = self.container.get_host().await?;
        let port = self.container.get_host_port_ipv4(MQTTS_PORT).await?;
        self.url = format!("mqtts://{host}:{port}");
        self.wait_broker_ready(BrokerReadyMode::FreshStart { prior_stdout_len })
            .await
    }

    /// Freeze the broker process without changing published ports. Used to prove session
    /// readiness recovery across transport loss on a stable endpoint.
    pub async fn pause(&mut self) -> Result<()> {
        self.container.pause().await?;
        Ok(())
    }

    pub async fn unpause(&mut self) -> Result<()> {
        self.container.unpause().await?;
        // Process continues; readiness marker was logged at initial bring-up and is not re-emitted.
        self.wait_broker_ready(BrokerReadyMode::Resume).await
    }

    pub(super) fn broker_socket(&self) -> Result<String> {
        let endpoint = url::Url::parse(&self.url)
            .map_err(|error| anyhow::anyhow!("fixture URL must stay mqtts: {error}"))?;
        let host = endpoint
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("fixture URL missing host"))?;
        let port = endpoint
            .port()
            .ok_or_else(|| anyhow::anyhow!("fixture URL missing port"))?;
        Ok(format!("{host}:{port}"))
    }

    /// Wait until the broker accepts TCP *and* has logged the same readiness marker used at
    /// initial `WaitFor` start. TCP alone is insufficient after restart because the listener can
    /// race ahead of mosquitto finishing plugin/TLS bring-up.
    ///
    /// attempts + 固定间隔 backoff：TCP/stdout 探活 I/O **不计入** attempt 预算。
    pub(super) async fn wait_broker_ready(&self, mode: BrokerReadyMode) -> Result<()> {
        const ATTEMPTS: u32 = 40;
        const INTERVAL: Duration = Duration::from_millis(250);
        let socket = self.broker_socket()?;
        for _ in 0..ATTEMPTS {
            crate::await_delay(INTERVAL).await;
            if tokio::net::TcpStream::connect(&socket).await.is_err() {
                continue;
            }
            let stdout = self.container.stdout_to_vec().await.unwrap_or_default();
            let haystack = match mode {
                BrokerReadyMode::FreshStart { prior_stdout_len } => {
                    stdout.get(prior_stdout_len..).unwrap_or(stdout.as_slice())
                }
                BrokerReadyMode::Resume => stdout.as_slice(),
            };
            if String::from_utf8_lossy(haystack).contains(MOSQUITTO_READY_STDOUT) {
                return Ok(());
            }
        }
        Err(anyhow::anyhow!(
            "mosquitto container did not become ready after {ATTEMPTS} attempts (TCP + `{MOSQUITTO_READY_STDOUT}`)"
        ))
    }

    pub async fn restart(&mut self) -> Result<()> {
        self.stop().await?;
        self.start().await
    }

    /// Rebind the broker with a CRL that revokes `device_current` while leaving RSS B valid.
    pub async fn revoke_device_current_and_rebind(mut self) -> Result<Self> {
        self.stop().await?;
        drop(self.container);
        let started = start_mosquitto_mtls_container(
            &self.broker_bundle,
            &self.revoked_device_current_crl_pem,
        )
        .await?;
        Ok(Self {
            container: started.container,
            url: started.url,
            assertion_public_key: self.assertion_public_key,
            empty_crl_pem: self.empty_crl_pem,
            revoked_device_current_crl_pem: self.revoked_device_current_crl_pem,
            broker_bundle: self.broker_bundle,
            rss_a: self.rss_a,
            rss_b: self.rss_b,
            device_current: self.device_current,
            device_stale: self.device_stale,
            device_cross_tenant: self.device_cross_tenant,
            device_wrong_ca: self.device_wrong_ca,
            device_no_certificate: self.device_no_certificate,
        })
    }
}

pub(super) fn mqtt_base64url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[(first >> 2) as usize]));
        output.push(char::from(
            ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize],
        ));
        if chunk.len() >= 2 {
            output.push(char::from(
                ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize],
            ));
        }
        if chunk.len() == 3 {
            output.push(char::from(ALPHABET[(third & 0x3f) as usize]));
        }
    }
    output
}

pub(super) fn mqtt_device_client_id(tenant_byte: u8) -> String {
    let mut identity = [0_u8; 32];
    identity[..16].fill(tenant_byte);
    identity[16..].fill(0x22);
    mqtt_base64url(&identity)
}

pub(super) fn mqtt_principal(tenant: &str, generation: u64) -> String {
    format!("urn:rss:mqtt-device:v1:{tenant}:{MQTT_DEVICE}:{generation}")
}

pub(super) fn mqtt_client_material(
    issuer: &rcgen::CertifiedIssuer<'_, rcgen::KeyPair>,
    ca_pem: &str,
    stable_client_id: &str,
    principal: Option<&str>,
    serial: u64,
) -> Result<MqttFixtureTlsPem> {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType, SerialNumber};

    let key = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::ExplicitNoCa;
    params.serial_number = Some(SerialNumber::from(serial));
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, stable_client_id);
    if let Some(principal) = principal {
        params.subject_alt_names = vec![SanType::URI(principal.try_into()?)];
    }
    let certificate = params.signed_by(&key, issuer)?;
    Ok(MqttFixtureTlsPem {
        ca_pem: ca_pem.to_owned(),
        certificate_pem: Some(certificate.pem()),
        private_key_pem: Some(key.serialize_pem()),
    })
}

pub(super) fn mqtt_sign_crl(
    issuer: &rcgen::CertifiedIssuer<'_, rcgen::KeyPair>,
    revoked_serials: &[u64],
    crl_number: u64,
) -> Result<String> {
    use rcgen::{
        CertificateRevocationListParams, KeyIdMethod, RevocationReason, RevokedCertParams,
        SerialNumber, date_time_ymd,
    };

    let revoked_certs = revoked_serials
        .iter()
        .map(|serial| RevokedCertParams {
            serial_number: SerialNumber::from(*serial),
            revocation_time: date_time_ymd(2026, 1, 1),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        })
        .collect();
    let crl = CertificateRevocationListParams {
        this_update: date_time_ymd(2026, 1, 1),
        next_update: date_time_ymd(2030, 1, 1),
        crl_number: SerialNumber::from(crl_number),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(issuer)?;
    Ok(crl.pem()?)
}

pub(super) fn mqtt_generated_material() -> Result<MqttGeneratedMaterial> {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose, PKCS_ED25519, SanType, SerialNumber,
    };

    let issuer = |label: &str| -> Result<CertifiedIssuer<'static, KeyPair>> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, label);
        Ok(CertifiedIssuer::self_signed(params, KeyPair::generate()?)?)
    };
    let ca = issuer("rss-mqtt-test-ca")?;
    let wrong_ca = issuer("rss-mqtt-test-wrong-ca")?;
    let ca_pem = ca.pem();

    let server_key = KeyPair::generate()?;
    let mut server = CertificateParams::default();
    server.is_ca = IsCa::ExplicitNoCa;
    server.serial_number = Some(SerialNumber::from(1u64));
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::IpAddress("127.0.0.1".parse()?),
        SanType::IpAddress("::1".parse()?),
    ];
    let server_certificate = server.signed_by(&server_key, &ca)?;

    let primary_client_id = mqtt_device_client_id(0x11);
    let cross_client_id = mqtt_device_client_id(0x33);
    let current_principal = mqtt_principal(MQTT_TENANT, MQTT_CURRENT_GENERATION);
    let stale_principal = mqtt_principal(MQTT_TENANT, MQTT_STALE_GENERATION);
    let cross_principal = mqtt_principal(MQTT_CROSS_TENANT, MQTT_CURRENT_GENERATION);

    let credential = |revision, stable_client_id: &str, tls| MqttCredential {
        revision,
        stable_client_id: stable_client_id.to_owned(),
        tls,
    };
    let rss_a = credential(
        1,
        MQTT_RSS_CLIENT_ID,
        mqtt_client_material(&ca, &ca_pem, MQTT_RSS_CLIENT_ID, None, MQTT_RSS_A_SERIAL)?,
    );
    let rss_b = credential(
        2,
        MQTT_RSS_CLIENT_ID,
        mqtt_client_material(&ca, &ca_pem, MQTT_RSS_CLIENT_ID, None, MQTT_RSS_B_SERIAL)?,
    );
    let device_current = credential(
        MQTT_CURRENT_GENERATION,
        &primary_client_id,
        mqtt_client_material(
            &ca,
            &ca_pem,
            &primary_client_id,
            Some(&current_principal),
            MQTT_DEVICE_CURRENT_SERIAL,
        )?,
    );
    let device_stale = credential(
        MQTT_STALE_GENERATION,
        &primary_client_id,
        mqtt_client_material(
            &ca,
            &ca_pem,
            &primary_client_id,
            Some(&stale_principal),
            MQTT_DEVICE_STALE_SERIAL,
        )?,
    );
    let device_cross_tenant = credential(
        MQTT_CURRENT_GENERATION,
        &cross_client_id,
        mqtt_client_material(
            &ca,
            &ca_pem,
            &cross_client_id,
            Some(&cross_principal),
            MQTT_DEVICE_CROSS_SERIAL,
        )?,
    );
    let device_wrong_ca = credential(
        MQTT_CURRENT_GENERATION,
        &primary_client_id,
        mqtt_client_material(
            &wrong_ca,
            &ca_pem,
            &primary_client_id,
            Some(&current_principal),
            MQTT_DEVICE_CURRENT_SERIAL,
        )?,
    );
    let device_no_certificate = credential(
        MQTT_CURRENT_GENERATION,
        &primary_client_id,
        MqttFixtureTlsPem {
            ca_pem: ca_pem.clone(),
            certificate_pem: None,
            private_key_pem: None,
        },
    );

    let assertion_key = KeyPair::generate_for(&PKCS_ED25519)?;
    let assertion_public_key = assertion_key
        .public_key_raw()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 public key must be exactly 32 bytes"))?;
    let empty_crl_pem = mqtt_sign_crl(&ca, &[], 1)?;
    let revoked_device_current_crl_pem = mqtt_sign_crl(&ca, &[MQTT_DEVICE_CURRENT_SERIAL], 2)?;
    let acl = mqtt_exact_acl(&primary_client_id, &cross_client_id);
    Ok(MqttGeneratedMaterial {
        ca_pem,
        server_certificate_pem: server_certificate.pem(),
        server_private_key_pem: server_key.serialize_pem(),
        assertion_signing_key_pem: assertion_key.serialize_pem(),
        assertion_public_key,
        empty_crl_pem,
        revoked_device_current_crl_pem,
        acl,
        rss_a,
        rss_b,
        device_current,
        device_stale,
        device_cross_tenant,
        device_wrong_ca,
        device_no_certificate,
    })
}

pub(super) fn mqtt_exact_acl(primary_client_id: &str, cross_client_id: &str) -> String {
    let mut acl = format!("user {MQTT_RSS_CLIENT_ID}\n");
    for generation in [MQTT_STALE_GENERATION, MQTT_CURRENT_GENERATION] {
        for contract in MQTT_DOWNLINK_CONTRACTS {
            acl.push_str(&format!(
                "topic write rss/v1/{MQTT_TENANT}/{MQTT_DEVICE}/{generation}/downlink/{contract}\n"
            ));
        }
        for contract in MQTT_UPLINK_CONTRACTS {
            acl.push_str(&format!(
                "topic read rss/v1/{MQTT_TENANT}/{MQTT_DEVICE}/{generation}/uplink/{contract}\n"
            ));
        }
    }
    acl.push_str(&format!("\nuser {primary_client_id}\n"));
    for generation in [MQTT_STALE_GENERATION, MQTT_CURRENT_GENERATION] {
        for contract in MQTT_DOWNLINK_CONTRACTS {
            acl.push_str(&format!(
                "topic read rss/v1/{MQTT_TENANT}/{MQTT_DEVICE}/{generation}/downlink/{contract}\n"
            ));
        }
        for contract in MQTT_UPLINK_CONTRACTS {
            acl.push_str(&format!(
                "topic write rss/v1/{MQTT_TENANT}/{MQTT_DEVICE}/{generation}/uplink/{contract}\n"
            ));
        }
    }
    acl.push_str(&format!("\nuser {cross_client_id}\n"));
    for contract in MQTT_DOWNLINK_CONTRACTS {
        acl.push_str(&format!(
            "topic read rss/v1/{MQTT_CROSS_TENANT}/{MQTT_DEVICE}/{MQTT_CURRENT_GENERATION}/downlink/{contract}\n"
        ));
    }
    for contract in MQTT_UPLINK_CONTRACTS {
        acl.push_str(&format!(
            "topic write rss/v1/{MQTT_CROSS_TENANT}/{MQTT_DEVICE}/{MQTT_CURRENT_GENERATION}/uplink/{contract}\n"
        ));
    }
    acl
}

pub(super) fn mqtt_broker_config(fault: Option<MqttAssertionFault>) -> String {
    let mut config = "per_listener_settings false\
\nlistener 8883\
\nprotocol mqtt\
\nallow_anonymous false\
\ncafile /mosquitto/config/ca.pem\
\ncertfile /mosquitto/config/server.pem\
\nkeyfile /mosquitto/config/server-key.pem\
\ncrlfile /mosquitto/config/ca.crl\
\nrequire_certificate true\
\nuse_identity_as_username true\
\nuse_username_as_clientid true\
\ntls_version tlsv1.3\
\nacl_file /mosquitto/config/acl\
\npersistence true\
\npersistence_location /mosquitto/data/\
\nautosave_interval 1\
\nautosave_on_changes true\
\nplugin /usr/lib/rss_mqtt_authn.so\
\nplugin_opt_signing_key /mosquitto/config/assertion-key.pem\
"
    .to_owned();
    if matches!(fault, Some(MqttAssertionFault::CorruptFirstSignature)) {
        config.push_str("\nplugin_opt_assertion_fault corrupt_first_signature");
    }
    config.push_str(
        "\
\nlog_dest stdout\
\nlog_type all\
\nconnection_messages true\n",
    );
    config
}

pub(super) struct StartedMosquittoMtls {
    pub(super) container: Box<ContainerAsync<GenericImage>>,
    pub(super) url: String,
}

#[derive(Clone, Copy)]
pub(super) enum BrokerReadyMode {
    /// After stop/start: only accept a readiness marker emitted in the new log suffix.
    FreshStart { prior_stdout_len: usize },
    /// After unpause: process continues; historical readiness marker + TCP is sufficient.
    Resume,
}

pub(super) async fn start_mosquitto_mtls_container(
    bundle: &MqttBrokerBundle,
    crl_pem: &str,
) -> Result<StartedMosquittoMtls> {
    let image = runtime::build_mosquitto_mtls_image()
        .await?
        .with_exposed_port(MQTTS_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout(MOSQUITTO_READY_STDOUT));
    let request = image
        .with_copy_to(
            "/mosquitto/config/mosquitto.conf",
            mqtt_broker_config(bundle.assertion_fault).into_bytes(),
        )
        .with_copy_to("/mosquitto/config/acl", bundle.acl.as_bytes().to_vec())
        .with_copy_to(
            "/mosquitto/config/ca.pem",
            bundle.ca_pem.as_bytes().to_vec(),
        )
        .with_copy_to("/mosquitto/config/ca.crl", crl_pem.as_bytes().to_vec())
        .with_copy_to(
            "/mosquitto/config/server.pem",
            bundle.server_certificate_pem.as_bytes().to_vec(),
        )
        .with_copy_to(
            CopyTargetOptions::new("/mosquitto/config/server-key.pem").with_mode(0o600),
            bundle.server_private_key_pem.as_bytes().to_vec(),
        )
        .with_copy_to(
            CopyTargetOptions::new("/mosquitto/config/assertion-key.pem").with_mode(0o600),
            bundle.assertion_signing_key_pem.as_bytes().to_vec(),
        )
        .with_cmd(["mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]);
    let container = runtime::start(request, ContainerService::Mosquitto).await?;
    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(MQTTS_PORT).await?;
    Ok(StartedMosquittoMtls {
        container: Box::new(container),
        url: format!("mqtts://{host}:{port}"),
    })
}

/// Starts the one production-shaped MQTT test broker. There is deliberately no environment URL
/// fallback and no plaintext listener: T2 always exercises the same mTLS/plugin/ACL boundary.
pub async fn mosquitto_mtls() -> Result<MqttMtlsFixture> {
    mosquitto_mtls_with_optional_assertion_fault(None).await
}

/// Starts the production-shaped fixture with one closed, one-shot assertion fault.
pub async fn mosquitto_mtls_with_assertion_fault(
    fault: MqttAssertionFault,
) -> Result<MqttMtlsFixture> {
    mosquitto_mtls_with_optional_assertion_fault(Some(fault)).await
}

async fn mosquitto_mtls_with_optional_assertion_fault(
    assertion_fault: Option<MqttAssertionFault>,
) -> Result<MqttMtlsFixture> {
    let material = mqtt_generated_material()?;
    let broker_bundle = MqttBrokerBundle {
        ca_pem: material.ca_pem,
        server_certificate_pem: material.server_certificate_pem,
        server_private_key_pem: material.server_private_key_pem,
        assertion_signing_key_pem: material.assertion_signing_key_pem,
        acl: material.acl,
        assertion_fault,
    };
    let started = start_mosquitto_mtls_container(&broker_bundle, &material.empty_crl_pem).await?;

    Ok(MqttMtlsFixture {
        container: started.container,
        url: started.url,
        assertion_public_key: material.assertion_public_key,
        empty_crl_pem: material.empty_crl_pem,
        revoked_device_current_crl_pem: material.revoked_device_current_crl_pem,
        broker_bundle,
        rss_a: material.rss_a,
        rss_b: material.rss_b,
        device_current: material.device_current,
        device_stale: material.device_stale,
        device_cross_tenant: material.device_cross_tenant,
        device_wrong_ca: material.device_wrong_ca,
        device_no_certificate: material.device_no_certificate,
    })
}
