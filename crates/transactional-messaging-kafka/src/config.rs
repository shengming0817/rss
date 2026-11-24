//! Closed reliable-producer configuration; no provider configuration escapes this boundary.
use crate::KafkaError;
use rdkafka::ClientConfig;
use rss_transactional_messaging::message::{MessageRoute, MessagingDomain};
use std::{collections::HashMap, time::Duration};

/// Caller-owned, stable, non-secret identity used for Kafka quotas and diagnostic correlation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KafkaClientId(Box<str>);
impl KafkaClientId {
    /// Accept 1..=255 ASCII letters, digits, dots, underscores or hyphens; never supply a secret.
    pub fn parse(value: &str) -> Result<Self, KafkaError> {
        if value.is_empty()
            || value.len() > 255
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

/// Independent native timeouts. Delivery is finite and includes native retries.
///
/// Socket, request and delivery use integral milliseconds; linger uses integral microseconds.
/// No Java-producer request-plus-linger relation is imposed by librdkafka 2.12.1.
#[derive(Clone, Copy, Debug)]
pub struct KafkaTimeouts {
    socket_ms: u32,
    request_ms: u32,
    linger_ms: f64,
    delivery_ms: u32,
}
impl KafkaTimeouts {
    /// Configure socket (10ms..=300s), request (1ms..=900s), linger (0..=900s),
    /// and delivery (1ms..=i32::MAX milliseconds). Delivery must exceed linger.
    pub fn new(
        socket: Duration,
        request: Duration,
        linger: Duration,
        delivery: Duration,
    ) -> Result<Self, KafkaError> {
        let socket_ms = milliseconds(socket, 10, 300_000)?;
        let request_ms = milliseconds(request, 1, 900_000)?;
        let delivery_ms = milliseconds(delivery, 1, i32::MAX as u32)?;
        if !linger.subsec_nanos().is_multiple_of(1_000)
            || linger.as_micros() > 900_000_000
            || linger >= delivery
        {
            return Err(KafkaError::InvalidTimeouts);
        }
        // Native truncates double milliseconds to integer microseconds. Avoid losing one
        // microsecond to binary floating-point rounding (for example 1001us / 1000).
        let micros = linger.as_micros() as f64;
        let mut linger_ms = micros / 1000.0;
        if linger_ms * 1000.0 < micros {
            linger_ms = linger_ms.next_up();
        }
        Ok(Self {
            socket_ms,
            request_ms,
            linger_ms,
            delivery_ms,
        })
    }
    /// Use 10-second socket/request timeouts and zero linger; delivery remains caller-selected.
    /// Native Produce requests still consume only the remaining message delivery time.
    pub fn low_latency(delivery: Duration) -> Result<Self, KafkaError> {
        Self::new(
            Duration::from_secs(10),
            Duration::from_secs(10),
            Duration::ZERO,
            delivery,
        )
    }
}
fn milliseconds(value: Duration, min: u32, max: u32) -> Result<u32, KafkaError> {
    if !value.subsec_nanos().is_multiple_of(1_000_000)
        || !(u128::from(min)..=u128::from(max)).contains(&value.as_millis())
    {
        return Err(KafkaError::InvalidTimeouts);
    }
    Ok(value.as_millis() as u32)
}

// ref: librdkafka e1db7eaa517f0a6438bc846a9c49ede73b9ea211
// src/rdkafka_proto.h:526-534 and src/rdkafka_msg.h:189-199.
// 36 is the maximum per-record v2 framing, excluding batch/ProduceRequest framing.
const RECORD_FRAMING_BYTES: usize = 36;

/// Finite queue counts and a static aggregate record-accounting budget.
///
/// This budget is an admission model, not an exact process RSS limit. See the crate documentation
/// for queue, transient-copy and structural charges and the additional native/allocator memory.
#[derive(Clone, Copy, Debug)]
pub struct KafkaLimits {
    pub(crate) queued: usize,
    pub(crate) in_flight: usize,
    pub(crate) record_bytes: usize,
    timeouts: KafkaTimeouts,
    native_queue_kbytes: i32,
    native_message_bytes: i32,
}
impl KafkaLimits {
    /// Choose positive counts/record bytes and an explicit total accounting budget in bytes.
    ///
    /// Construction checks the aggregate worst case, checked arithmetic and native representation;
    /// it does not allocate queue slots or record bodies. Native pending count must fit i32.
    pub fn new(
        queued: usize,
        in_flight: usize,
        record_bytes: usize,
        total_budget_bytes: usize,
        timeouts: KafkaTimeouts,
    ) -> Result<Self, KafkaError> {
        let invalid = KafkaError::InvalidLimits;
        if queued == 0
            || queued > tokio::sync::Semaphore::MAX_PERMITS
            || in_flight == 0
            || record_bytes == 0
            || total_budget_bytes == 0
        {
            return Err(invalid);
        }
        i32::try_from(in_flight).map_err(|_| invalid)?;
        let native_message_bytes = record_bytes
            .checked_add(RECORD_FRAMING_BYTES)
            .ok_or(invalid)?;
        if native_message_bytes > 1_000_000_000 {
            return Err(invalid);
        }
        let native_bytes = in_flight.checked_mul(record_bytes).ok_or(invalid)?;
        let native_queue_kbytes = native_bytes.div_ceil(1024);
        let rounded_native_bytes = native_queue_kbytes.checked_mul(1024).ok_or(invalid)?;
        let native_queue_kbytes = i32::try_from(native_queue_kbytes).map_err(|_| invalid)?;
        let required = Self::required_budget(queued, in_flight, record_bytes, rounded_native_bytes)
            .ok_or(invalid)?;
        if required > total_budget_bytes {
            return Err(invalid);
        }
        Ok(Self {
            queued,
            in_flight,
            record_bytes,
            timeouts,
            native_queue_kbytes,
            native_message_bytes: native_message_bytes.max(1000) as i32,
        })
    }
    fn required_budget(
        queued: usize,
        in_flight: usize,
        record: usize,
        native: usize,
    ) -> Option<usize> {
        // Every slot can be encoding simultaneously. The single worker owns its dequeued record.
        let records = queued
            .checked_mul(2)?
            .checked_add(1)?
            .checked_mul(record)?
            .checked_add(native)?;
        // Channel backing slots coexist with candidates on publishing threads.
        let slots = queued.checked_mul(std::mem::size_of::<crate::engine::QueuedCommand>())?;
        let commands = slots
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<crate::engine::Command>())?;
        let pending = in_flight.checked_mul(crate::engine::pending_entry_bytes())?;
        // Rust channel allocation must also be representable independently of its record charge.
        if slots > isize::MAX as usize {
            return None;
        }
        records.checked_add(commands)?.checked_add(pending)
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
                self.plan.limits.timeouts.delivery_ms.to_string(),
            )
            .set(
                "socket.timeout.ms",
                self.plan.limits.timeouts.socket_ms.to_string(),
            )
            .set(
                "request.timeout.ms",
                self.plan.limits.timeouts.request_ms.to_string(),
            )
            .set("linger.ms", self.plan.limits.timeouts.linger_ms.to_string())
            .set(
                "queue.buffering.max.messages",
                self.plan.limits.in_flight.to_string(),
            )
            .set(
                "queue.buffering.max.kbytes",
                self.plan.limits.native_queue_kbytes.to_string(),
            )
            .set(
                "message.max.bytes",
                self.plan.limits.native_message_bytes.to_string(),
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
