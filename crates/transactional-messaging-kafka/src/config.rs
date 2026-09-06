//! Closed reliable-producer configuration; no provider configuration escapes this boundary.
use crate::KafkaError;
use rdkafka::ClientConfig;
use rss_transactional_messaging::message::{MessageRoute, MessagingDomain};
use std::{collections::HashMap, time::Duration};

/// Caller-owned, stable, non-secret identity used for Kafka quotas and diagnostic correlation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KafkaClientId(Box<str>);
impl KafkaClientId {
    /// Accept 1..=128 ASCII letters, digits, dots, underscores or hyphens; never supply a secret.
    pub fn parse(value: &str) -> Result<Self, KafkaError> {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(KafkaError::InvalidClientId);
        }
        Ok(Self(value.into()))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl rss_redact::Redact for KafkaClientId {
    fn redact_scoped(&self, _: rss_redact::RedactScope) -> String {
        // This type explicitly represents public operational identity, never authentication material.
        self.0.to_string()
    }
}

/// Validated limits for queued commands, native in-flight records, and authored record bytes.
#[derive(Clone, Copy, Debug)]
pub struct KafkaLimits {
    pub(crate) queued: usize,
    pub(crate) in_flight: usize,
    pub(crate) record_bytes: usize,
    pub(crate) timeout_ms: u32,
}
impl KafkaLimits {
    /// Bound both queues independently. Timeout must be integral milliseconds in 10ms..=24h.
    /// Record bytes include key, headers and payload; native bookkeeping is additional.
    pub fn new(
        queued: usize,
        in_flight: usize,
        record_bytes: usize,
        timeout: Duration,
    ) -> Result<Self, KafkaError> {
        let millis = timeout.as_millis();
        if queued == 0
            || queued > 100_000
            || in_flight == 0
            || in_flight > 100_000
            || record_bytes == 0
            || record_bytes > 100_000_000
            || !(10..=86_400_000).contains(&millis)
            || !timeout.subsec_nanos().is_multiple_of(1_000_000)
            || in_flight
                .checked_mul(record_bytes)
                .is_none_or(|bytes| bytes > 2_000_000_000)
            || queued
                .checked_mul(record_bytes)
                .is_none_or(|bytes| bytes > 2_000_000_000)
        {
            return Err(KafkaError::InvalidLimits);
        }
        Ok(Self {
            queued,
            in_flight,
            record_bytes,
            timeout_ms: millis as u32,
        })
    }
}

/// Authentication material. Debug deliberately hides every field.
pub struct KafkaCredentials(Auth);
enum Auth {
    MutualTls {
        certificate: String,
        key: zeroize::Zeroizing<String>,
    },
    Scram {
        username: String,
        password: zeroize::Zeroizing<String>,
    },
}
impl std::fmt::Debug for KafkaCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KafkaCredentials(<redacted>)")
    }
}
impl KafkaCredentials {
    /// Supply a PEM client certificate chain and unencrypted PEM private key.
    pub fn mutual_tls(certificate: String, key: String) -> Result<Self, KafkaError> {
        validate_text(&certificate)?;
        validate_text(&key)?;
        Ok(Self(Auth::MutualTls {
            certificate,
            key: zeroize::Zeroizing::new(key),
        }))
    }
    /// Authenticate with SCRAM-SHA-512 over verified TLS.
    pub fn scram_sha512(username: String, password: String) -> Result<Self, KafkaError> {
        validate_text(&username)?;
        validate_text(&password)?;
        Ok(Self(Auth::Scram {
            username,
            password: zeroize::Zeroizing::new(password),
        }))
    }
}

/// Immutable routing and transport configuration. Credentials and endpoints are never Debugged.
pub(crate) struct PublishPlan {
    pub(crate) client_id: KafkaClientId,
    pub(crate) domain: MessagingDomain,
    pub(crate) routes: HashMap<MessageRoute, String>,
    pub(crate) limits: KafkaLimits,
}

/// Immutable transport configuration; consumed at creation so publish handles cannot retain secrets.
pub struct KafkaConfig {
    pub(crate) plan: PublishPlan,
    brokers: String,
    ca: String,
    credentials: KafkaCredentials,
}
impl std::fmt::Debug for KafkaConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KafkaConfig(<redacted>)")
    }
}
impl KafkaConfig {
    /// Bind explicit bootstrap servers, private CA, authentication and a domain's topic mapping.
    /// Native initialization validates PEM material; creation is not broker readiness evidence.
    pub fn new(
        client_id: KafkaClientId,
        brokers: String,
        ca: String,
        credentials: KafkaCredentials,
        domain: MessagingDomain,
        routes: impl IntoIterator<Item = (MessageRoute, String)>,
        limits: KafkaLimits,
    ) -> Result<Self, KafkaError> {
        validate_text(&brokers)?;
        validate_text(&ca)?;
        let mut topics = HashMap::new();
        for (route, topic) in routes {
            if !valid_topic(&topic) || topics.insert(route, topic).is_some() {
                return Err(KafkaError::InvalidRoute);
            }
        }
        if topics.is_empty() {
            return Err(KafkaError::InvalidRoute);
        }
        Ok(Self {
            plan: PublishPlan {
                client_id,
                domain,
                routes: topics,
                limits,
            },
            brokers,
            ca,
            credentials,
        })
    }
    pub(crate) fn into_parts(self) -> (PublishPlan, ClientConfig) {
        let native = self.client();
        (self.plan, native)
    }
    pub(crate) fn client(&self) -> ClientConfig {
        let mut c = ClientConfig::new();
        c.set("bootstrap.servers", &self.brokers)
            .set("client.id", self.plan.client_id.as_str())
            .set("ssl.ca.pem", &self.ca)
            .set("enable.ssl.certificate.verification", "true")
            .set("ssl.endpoint.identification.algorithm", "https")
            .set("enable.idempotence", "true")
            .set("acks", "all")
            .set("max.in.flight.requests.per.connection", "5")
            .set("retries", "2147483647")
            .set(
                "message.timeout.ms",
                self.plan.limits.timeout_ms.to_string(),
            )
            .set(
                "socket.timeout.ms",
                self.plan.limits.timeout_ms.min(10_000).to_string(),
            )
            .set(
                "request.timeout.ms",
                self.plan.limits.timeout_ms.min(10_000).to_string(),
            )
            .set("linger.ms", "0")
            .set(
                "queue.buffering.max.messages",
                self.plan.limits.in_flight.to_string(),
            )
            .set(
                "queue.buffering.max.kbytes",
                (self.plan.limits.in_flight * self.plan.limits.record_bytes)
                    .div_ceil(1024)
                    .to_string(),
            )
            .set(
                "message.max.bytes",
                (self.plan.limits.record_bytes + 1024).max(1000).to_string(),
            )
            .set("allow.auto.create.topics", "false");
        match &self.credentials.0 {
            Auth::MutualTls { certificate, key } => {
                c.set("security.protocol", "ssl")
                    .set("ssl.certificate.pem", certificate)
                    .set("ssl.key.pem", key.as_str());
            }
            Auth::Scram { username, password } => {
                c.set("security.protocol", "sasl_ssl")
                    .set("sasl.mechanism", "SCRAM-SHA-512")
                    .set("sasl.username", username)
                    .set("sasl.password", password.as_str());
            }
        }
        c
    }
}
fn validate_text(value: &str) -> Result<(), KafkaError> {
    if value.trim().is_empty() || value.contains('\0') {
        Err(KafkaError::InvalidConfiguration)
    } else {
        Ok(())
    }
}
fn valid_topic(topic: &str) -> bool {
    !topic.is_empty()
        && topic.len() <= 249
        && topic != "."
        && topic != ".."
        && topic
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
