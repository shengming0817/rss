use rss_transactional_messaging::transport::Publisher;
use rss_transactional_messaging_kafka::{
    KafkaLimits, KafkaPublishReceipt, KafkaPublisher, KafkaPublisherResource,
};
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::time::Duration;
assert_impl_all!(KafkaPublisher: Clone, Send, Sync, Publisher<Vec<u8>>);
assert_impl_all!(KafkaPublishReceipt: Send, Sync);
assert_not_impl_any!(KafkaPublisherResource: Clone, Publisher<Vec<u8>>);

#[test]
fn limits_reject_unbounded_or_unrepresentable_values() {
    assert!(KafkaLimits::new(0, 1, 1024, Duration::from_secs(1)).is_err());
    assert!(KafkaLimits::new(1, 0, 1024, Duration::from_secs(1)).is_err());
    assert!(KafkaLimits::new(1, 1, 0, Duration::from_secs(1)).is_err());
    assert!(KafkaLimits::new(1, 1, 1024, Duration::ZERO).is_err());
    assert!(KafkaLimits::new(1, 1, 1024, Duration::MAX).is_err());
    assert!(KafkaLimits::new(1, 1, 1024, Duration::from_secs(1)).is_ok());
}

#[test]
fn client_identity_is_explicit_bounded_and_log_safe() -> anyhow::Result<()> {
    use rss_transactional_messaging_kafka::KafkaClientId;
    for invalid in ["", "a\0b", "a\nb", "user@host", "a b"] {
        assert!(KafkaClientId::parse(invalid).is_err());
    }
    assert!(KafkaClientId::parse(&"a".repeat(129)).is_err());
    assert_eq!(
        KafkaClientId::parse("inventory-relay-01")?.as_str(),
        "inventory-relay-01"
    );
    Ok(())
}
