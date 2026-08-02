//! #1902 MQTTS 配置与设备主题策略的 T1 契约测试。
//!
//! 这些测试先于实现落地，用编译失败冻结新公开 API。主题只能从 typed [`DeviceScope`]
//! 经 [`MqttTopicPolicy`] 取得；本边界不接受 raw topic 字符串，因此 `+` / `#` 无法进入构造路径。

#![allow(clippy::expect_used)] // reason: deterministic typed fixtures fail loudly in tests.

use ids::DeviceId;
use mqtt::{CredentialGeneration, DeviceScope, MqttTopicPolicy, MqttsEndpoint};
use vocab::TenantId;

const TENANT: &str = "018f3f42-a7c1-7d31-8ed9-6a93261b71f0";
const DEVICE: &str = "018f3f42-b8d2-7c42-9fea-7ba4372c82a1";

fn scope(generation: u64) -> DeviceScope {
    let tenant = TenantId::parse(TENANT).expect("fixture tenant is canonical");
    let device = DeviceId::parse(DEVICE).expect("fixture device is a UUID");
    let generation = CredentialGeneration::new(generation).expect("fixture generation is positive");
    DeviceScope::new(tenant, device, generation)
}

#[test]
fn mqtts_endpoint_accepts_only_authority_without_ambient_components() {
    for endpoint in [
        "mqtts://broker.example.com",
        "mqtts://broker.example.com:8883",
    ] {
        assert!(
            MqttsEndpoint::parse(endpoint).is_ok(),
            "valid MQTTS endpoint rejected: {endpoint}"
        );
    }

    for endpoint in [
        "mqtt://broker.example.com:1883",
        "mqtts://user:secret@broker.example.com:8883",
        "mqtts://broker.example.com/mqtt",
        "mqtts://broker.example.com?tenant=shadow",
        "mqtts://broker.example.com#fragment",
        "mqtts://broker.example.com:0",
        "mqtts://",
    ] {
        assert!(
            MqttsEndpoint::parse(endpoint).is_err(),
            "unsafe or ambiguous endpoint accepted: {endpoint}"
        );
    }
}

#[test]
fn credential_generation_is_strictly_positive() {
    assert!(CredentialGeneration::new(1).is_ok());
    assert!(CredentialGeneration::new(u64::MAX).is_ok());
    assert!(CredentialGeneration::new(0).is_err());
}

#[test]
fn topic_policy_requires_a_nonempty_unique_scope_set() {
    let configured = scope(7);

    assert!(MqttTopicPolicy::new(vec![configured.clone()]).is_ok());
    assert!(MqttTopicPolicy::new(Vec::<DeviceScope>::new()).is_err());
    assert!(
        MqttTopicPolicy::new(vec![configured.clone(), configured]).is_err(),
        "duplicate device scope must fail closed"
    );
}

#[test]
fn topic_policy_scope_count_is_bounded() {
    let tenant = TenantId::parse(TENANT).expect("fixture tenant is canonical");
    let generation = CredentialGeneration::new(7).expect("positive generation");
    let scopes = (1_u64..=513)
        .map(|suffix| {
            let raw = format!("018f3f42-b8d2-7c42-9fea-{suffix:012x}");
            let device = DeviceId::parse(&raw).expect("generated device UUID");
            DeviceScope::new(tenant, device, generation)
        })
        .collect();
    assert!(MqttTopicPolicy::new(scopes).is_err());
}

#[test]
fn topic_policy_mints_only_the_four_canonical_exact_topics() {
    let configured = scope(7);
    let policy = MqttTopicPolicy::new(vec![configured.clone()]).expect("one scope is valid");

    let command = policy
        .command_topic(&configured)
        .expect("configured scope has a command topic");
    assert_eq!(
        command.as_str().split('/').collect::<Vec<_>>(),
        [
            "rss",
            "v1",
            TENANT,
            DEVICE,
            "7",
            "downlink",
            "identity.commands.apply-device-certificate"
        ]
    );

    let command_acked = policy
        .command_acked_topic(&configured)
        .expect("configured scope has an acknowledgement topic");
    assert_eq!(
        command_acked.as_str().split('/').collect::<Vec<_>>(),
        [
            "rss",
            "v1",
            TENANT,
            DEVICE,
            "7",
            "uplink",
            "identity.device-command-acked"
        ]
    );

    let certificate_reported = policy
        .certificate_reported_topic(&configured)
        .expect("configured scope has a certificate report topic");
    assert_eq!(
        certificate_reported.as_str().split('/').collect::<Vec<_>>(),
        [
            "rss",
            "v1",
            TENANT,
            DEVICE,
            "7",
            "uplink",
            "identity.device-certificate-reported"
        ]
    );

    let application_receipt = policy
        .application_receipt_topic(&configured)
        .expect("configured scope has an application receipt topic");
    assert_eq!(
        application_receipt.as_str().split('/').collect::<Vec<_>>(),
        [
            "rss",
            "v1",
            TENANT,
            DEVICE,
            "7",
            "downlink",
            "identity.device-ingress-receipted"
        ]
    );

    let unconfigured = scope(8);
    assert!(policy.command_topic(&unconfigured).is_none());
    assert!(policy.command_acked_topic(&unconfigured).is_none());
    assert!(policy.certificate_reported_topic(&unconfigured).is_none());
    assert!(policy.application_receipt_topic(&unconfigured).is_none());

    for topic in [
        command,
        command_acked,
        certificate_reported,
        application_receipt,
    ] {
        assert!(!topic.as_str().contains('+'));
        assert!(!topic.as_str().contains('#'));
    }
}
