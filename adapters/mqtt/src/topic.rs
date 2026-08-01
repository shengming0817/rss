use std::num::NonZeroU64;

use ids::DeviceId;
use vocab::TenantId;

const TOPIC_PREFIX: &str = "rss/v1";
const UPLINK: &str = "uplink";
const DOWNLINK: &str = "downlink";
const COMMAND_CONTRACT: &str = "identity.commands.apply-device-certificate";
const COMMAND_ACKED_CONTRACT: &str = "identity.device-command-acked";
const CERTIFICATE_REPORTED_CONTRACT: &str = "identity.device-certificate-reported";
const MAX_DEVICE_SCOPES: usize = 512;

/// Monotonic device credential generation. Zero is not a real credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialGeneration(NonZeroU64);

impl CredentialGeneration {
    pub fn new(value: u64) -> Result<Self, TopicPolicyError> {
        NonZeroU64::new(value).map(Self).ok_or(TopicPolicyError)
    }

    pub fn get(self) -> u64 {
        self.0.get()
    }
}

/// Exact tenant/device credential scope accepted by a session.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceScope {
    tenant: TenantId,
    device: DeviceId,
    generation: CredentialGeneration,
}

impl DeviceScope {
    pub fn new(tenant: TenantId, device: DeviceId, generation: CredentialGeneration) -> Self {
        Self {
            tenant,
            device,
            generation,
        }
    }

    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub fn device(&self) -> DeviceId {
        self.device
    }

    pub fn generation(&self) -> CredentialGeneration {
        self.generation
    }

    /// Canonical device URI SAN / assertion principal for this scope.
    pub fn principal_urn(&self) -> String {
        format!(
            "urn:rss:mqtt-device:v1:{}:{}:{}",
            self.tenant,
            self.device.as_uuid().hyphenated(),
            self.generation.get()
        )
    }
}

/// A topic minted by [`MqttTopicPolicy`]. There is deliberately no public string constructor.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExactMqttTopic(String);

impl ExactMqttTopic {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ExactMqttTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Closed set of authenticated device uplinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MqttUplinkContract {
    CommandAcked,
    CertificateReported,
}

impl MqttUplinkContract {
    pub(crate) const fn as_label(self) -> &'static str {
        match self {
            Self::CommandAcked => "ack",
            Self::CertificateReported => "report",
        }
    }
}

/// Non-empty exact topic allow-set shared by subscription, ACL generation and assertion checks.
#[derive(Clone)]
pub struct MqttTopicPolicy {
    scopes: Vec<DeviceScope>,
}

impl std::fmt::Debug for MqttTopicPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MqttTopicPolicy")
            .field("scope_count", &self.scopes.len())
            .finish()
    }
}

impl MqttTopicPolicy {
    pub fn new(mut scopes: Vec<DeviceScope>) -> Result<Self, TopicPolicyError> {
        if scopes.is_empty() || scopes.len() > MAX_DEVICE_SCOPES {
            return Err(TopicPolicyError);
        }
        scopes.sort_by_key(scope_sort_key);
        if scopes
            .windows(2)
            .any(|pair| same_device(&pair[0], &pair[1]))
        {
            return Err(TopicPolicyError);
        }
        Ok(Self { scopes })
    }

    pub fn command_topic(&self, scope: &DeviceScope) -> Option<ExactMqttTopic> {
        self.configured(scope)
            .then(|| topic(scope, DOWNLINK, COMMAND_CONTRACT))
    }

    pub fn command_acked_topic(&self, scope: &DeviceScope) -> Option<ExactMqttTopic> {
        self.configured(scope)
            .then(|| topic(scope, UPLINK, COMMAND_ACKED_CONTRACT))
    }

    pub fn certificate_reported_topic(&self, scope: &DeviceScope) -> Option<ExactMqttTopic> {
        self.configured(scope)
            .then(|| topic(scope, UPLINK, CERTIFICATE_REPORTED_CONTRACT))
    }

    pub fn scope(&self, tenant: TenantId, device: DeviceId) -> Option<&DeviceScope> {
        self.scopes
            .iter()
            .find(|scope| scope.tenant == tenant && scope.device == device)
    }

    pub fn scopes(&self) -> &[DeviceScope] {
        &self.scopes
    }

    pub(crate) fn uplink_topics(&self) -> Vec<ExactMqttTopic> {
        self.scopes
            .iter()
            .flat_map(|scope| {
                [
                    topic(scope, UPLINK, COMMAND_ACKED_CONTRACT),
                    topic(scope, UPLINK, CERTIFICATE_REPORTED_CONTRACT),
                ]
            })
            .collect()
    }

    pub(crate) fn exact_verified_topic(&self, raw: &str) -> Option<ExactMqttTopic> {
        self.resolve_uplink(raw)
            .map(|_| ExactMqttTopic(raw.to_owned()))
    }

    pub(crate) fn resolve_uplink(&self, raw: &str) -> Option<(&DeviceScope, MqttUplinkContract)> {
        let mut parts = raw.split('/');
        if parts.next()? != "rss" || parts.next()? != "v1" {
            return None;
        }
        let tenant_raw = parts.next()?;
        let device_raw = parts.next()?;
        let generation_raw = parts.next()?;
        if parts.next()? != UPLINK {
            return None;
        }
        let contract = match parts.next()? {
            COMMAND_ACKED_CONTRACT => MqttUplinkContract::CommandAcked,
            CERTIFICATE_REPORTED_CONTRACT => MqttUplinkContract::CertificateReported,
            _ => return None,
        };
        if parts.next().is_some() {
            return None;
        }
        let tenant = TenantId::parse(tenant_raw).ok()?;
        let device = DeviceId::parse(device_raw).ok()?;
        if device.as_uuid().hyphenated().to_string() != device_raw {
            return None;
        }
        let generation = CredentialGeneration::new(parse_generation(generation_raw)?).ok()?;
        let scope = self.scope(tenant, device)?;
        if scope.generation != generation {
            return None;
        }
        Some((scope, contract))
    }

    fn configured(&self, wanted: &DeviceScope) -> bool {
        self.scopes.iter().any(|scope| scope == wanted)
    }
}

fn same_device(left: &DeviceScope, right: &DeviceScope) -> bool {
    left.tenant == right.tenant && left.device == right.device
}

fn scope_sort_key(scope: &DeviceScope) -> (String, String) {
    (
        scope.tenant.to_string(),
        scope.device.as_uuid().hyphenated().to_string(),
    )
}

fn topic(scope: &DeviceScope, direction: &str, contract: &str) -> ExactMqttTopic {
    ExactMqttTopic(format!(
        "{TOPIC_PREFIX}/{}/{}/{}/{direction}/{contract}",
        scope.tenant,
        scope.device.as_uuid().hyphenated(),
        scope.generation.get(),
    ))
}

/// Decimal generation without leading zeros (aligns with diport principal URN rules).
pub(crate) fn parse_generation(raw: &str) -> Option<u64> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) || bytes[0] == b'0' {
        return None;
    }
    raw.parse().ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid mqtt topic policy")]
pub struct TopicPolicyError;
