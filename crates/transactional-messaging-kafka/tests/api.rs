use rss_transactional_messaging::transport::Publisher;
use rss_transactional_messaging_kafka::{
    KafkaPublishReceipt, KafkaPublisher, KafkaPublisherResource,
};
use static_assertions::{assert_impl_all, assert_not_impl_any};
assert_impl_all!(KafkaPublisher: Clone, Send, Sync, Publisher<Vec<u8>>);
assert_impl_all!(KafkaPublishReceipt: Send, Sync);
assert_not_impl_any!(KafkaPublisherResource: Clone, Publisher<Vec<u8>>);

#[test]
fn client_identity_is_explicit_bounded_and_log_safe() -> anyhow::Result<()> {
    use rss_transactional_messaging_kafka::KafkaClientId;
    for invalid in ["", "a\0b", "a\nb", "user@host", "a b"] {
        assert!(KafkaClientId::parse(invalid).is_err());
    }
    assert!(KafkaClientId::parse(&"a".repeat(255)).is_ok());
    assert!(KafkaClientId::parse(&"a".repeat(256)).is_err());
    assert!(KafkaClientId::parse("设备").is_err());
    assert_eq!(
        KafkaClientId::parse("inventory-relay-01")?.as_str(),
        "inventory-relay-01"
    );
    Ok(())
}
