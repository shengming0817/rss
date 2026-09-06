use rss_mqtt::{Limits, MqttError, PublishRequest};

#[test]
fn invalid_limits_are_rejected() {
    assert!(matches!(
        Limits::new(0, 32, 32, 1024),
        Err(MqttError::InvalidConfig)
    ));
    assert!(Limits::new(32, 32, 32, 1024).is_ok());
}

#[test]
fn invalid_topic_cannot_be_published() {
    assert!(PublishRequest::new("bad/+", b"secret".to_vec()).is_err());
    assert!(PublishRequest::new("", Vec::new()).is_err());
    assert!(PublishRequest::new("events/test", Vec::new()).is_ok());
}

#[test]
fn debug_does_not_disclose_wire_data() -> anyhow::Result<()> {
    let request = PublishRequest::new("secret-topic", b"secret-body".to_vec())?
        .correlation_data(b"secret-correlation".to_vec());
    let diagnostic = format!("{request:?}");
    assert!(!diagnostic.contains("secret"));
    Ok(())
}

static_assertions::assert_not_impl_any!(rss_mqtt::Settlement: Clone, Copy);
static_assertions::assert_not_impl_any!(rss_mqtt::MqttResource: Clone, Copy);
static_assertions::assert_not_impl_any!(rss_mqtt::MqttReceiver: Clone, Copy);

#[test]
fn invalid_credentials_fail_before_a_runtime_or_driver_is_needed() -> anyhow::Result<()> {
    use std::sync::Arc;
    let tls = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth(),
    );
    for (username, password) in [
        ("bad\0user".to_owned(), Vec::new()),
        ("u".repeat(65536), Vec::new()),
        ("valid".to_owned(), vec![0; 65536]),
    ] {
        let config = rss_mqtt::MqttConfig::new(
            "localhost",
            8883,
            "test",
            "scope",
            tls.clone(),
            Limits::new(2, 2, 2, 1024)?,
        )?;
        assert!(matches!(
            config.credentials(username, password),
            Err(MqttError::InvalidConfig)
        ));
    }
    Ok(())
}

#[test]
fn reconnect_policy_rejects_unbounded_or_inverted_budgets() {
    use rss_mqtt::ReconnectPolicy;
    use std::time::Duration;
    assert!(ReconnectPolicy::new(Duration::ZERO, Duration::from_secs(1)).is_err());
    assert!(ReconnectPolicy::new(Duration::from_secs(2), Duration::from_secs(1)).is_err());
    assert!(ReconnectPolicy::new(Duration::from_millis(100), Duration::from_secs(30)).is_ok());
}

#[test]
fn outbox_plan_rejects_duplicate_routes_and_invalid_topics() -> anyhow::Result<()> {
    use rss_mqtt::{MqttOutboxPlan, MqttOutboxTopic};
    use rss_transactional_messaging::message::{MessageRoute, MessagingDomain};
    assert!(MqttOutboxTopic::new("bad/+").is_err());
    let domain = MessagingDomain::parse("test")?;
    let route = MessageRoute::parse("created")?;
    assert!(MqttOutboxPlan::new(domain.clone(), []).is_err());
    assert!(
        MqttOutboxPlan::new(
            domain,
            [
                (route.clone(), MqttOutboxTopic::new("events/a")?),
                (route, MqttOutboxTopic::new("events/b")?),
            ]
        )
        .is_err()
    );
    Ok(())
}
