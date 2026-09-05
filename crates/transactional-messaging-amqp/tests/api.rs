//! Public capability separation must hold without constructing a broker connection.
use rss_runtime::ManagedResource;
use rss_transactional_messaging::transport::{DeliverySource, Publisher};
use rss_transactional_messaging_amqp::{
    AmqpPublisher, AmqpPublisherEndpoint, AmqpPublisherResource, AmqpSubscriber,
    AmqpSubscriberEndpoint, AmqpSubscriberResource,
};
use static_assertions::{assert_impl_all, assert_not_impl_any};

assert_impl_all!(AmqpPublisher: Clone, Publisher<Vec<u8>>, Send, Sync);
assert_impl_all!(AmqpSubscriber: Clone, DeliverySource<Vec<u8>>, Send, Sync);
assert_impl_all!(AmqpPublisherResource: ManagedResource, Send, Sync);
assert_impl_all!(AmqpSubscriberResource: ManagedResource, Send, Sync);
assert_not_impl_any!(AmqpPublisher: ManagedResource);
assert_not_impl_any!(AmqpSubscriber: ManagedResource);
assert_not_impl_any!(AmqpPublisherResource: Clone, Publisher<Vec<u8>>);
assert_not_impl_any!(AmqpSubscriberResource: Clone, DeliverySource<Vec<u8>>);

#[test]
fn production_endpoints_require_tls_and_explicit_vhost() {
    for raw in [
        "amqp://localhost/vhost",
        "amqps://broker",
        "amqps://broker/",
    ] {
        assert!(AmqpPublisherEndpoint::parse(raw).is_err());
        assert!(AmqpSubscriberEndpoint::parse(raw).is_err());
    }
    assert!(AmqpPublisherEndpoint::parse("amqps://user:pass@broker/%2f").is_ok());
    assert!(AmqpSubscriberEndpoint::parse("amqps://user:pass@broker/vhost").is_ok());
}

#[cfg(feature = "test-support")]
#[tokio::test]
async fn invalid_recovery_timeout_is_publicly_classified_before_connect()
-> Result<(), rss_transactional_messaging_amqp::AmqpEndpointError> {
    use rss_transactional_messaging_amqp::AmqpConnectError;
    let endpoint = AmqpPublisherEndpoint::for_test("amqp://127.0.0.1:1/%2f")?;
    let result =
        AmqpPublisher::connect_for_test(&endpoint, "invalid-timeout", std::time::Duration::ZERO)
            .await;
    assert!(matches!(
        result,
        Err(AmqpConnectError::InvalidRecoveryTimeout)
    ));
    let endpoint = AmqpSubscriberEndpoint::for_test("amqp://127.0.0.1:1/%2f")?;
    let result = AmqpSubscriber::connect_for_test(
        &endpoint,
        "invalid-subscriber-timeout",
        std::time::Duration::ZERO,
    )
    .await;
    assert!(matches!(
        result,
        Err(AmqpConnectError::InvalidRecoveryTimeout)
    ));
    Ok(())
}

#[test]
fn production_endpoints_reject_implicit_identity_and_sasl_overrides() {
    for raw in [
        "amqps://broker/vhost",
        "amqps://user@broker/vhost",
        "amqps://user:@broker/vhost",
        "amqps://:pass@broker/vhost",
        "amqps://user:pass@broker/vhost?auth_mechanism=ANONYMOUS",
        "amqps://user:pass@broker/vhost?auth_mechanism=EXTERNAL",
        "amqps://user:pass@broker/vhost#identity",
    ] {
        assert!(
            AmqpPublisherEndpoint::parse(raw).is_err(),
            "implicit/SASL identity must be rejected"
        );
        assert!(
            AmqpSubscriberEndpoint::parse(raw).is_err(),
            "implicit/SASL identity must be rejected"
        );
    }
    assert!(AmqpPublisherEndpoint::parse("amqps://publisher:secret@broker/%2f").is_ok());
}
