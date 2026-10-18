use super::*;
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::{
    message::*,
    policy::OperationDeadline,
    transport::{PublishOutcome, Publisher},
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

fn metadata(attributes: BTreeMap<String, String>) -> anyhow::Result<MessageMetadata> {
    Ok(MessageMetadata::new(
        AuthoredMessageMetadata::new(
            TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
            Timepoint::try_from(1_i64)?,
            MessagingDomain::parse("webhook")?,
            MessageRoute::parse("events")?,
            ContractIdentity::new(
                ContractId::parse("example.event")?,
                ContractVersion::from_major(1)?,
                SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?,
            ),
        ),
        MessageMetadataExtensions::new(
            None,
            Some(PartitionKey::parse("ordered")?),
            None,
            attributes,
        ),
    ))
}
fn target() -> anyhow::Result<Target> {
    Ok(Target::new(
        TargetId::parse("endpoint")?,
        TargetVersion::new(1)?,
    ))
}

#[test]
fn binding_is_authored_and_reserved_fields_fail_closed() -> anyhow::Result<()> {
    let body = b"\0{\"x\": 1}\xff".to_vec();
    let one = pending_message(
        MessageId::parse("delivery-1")?,
        metadata(BTreeMap::new())?,
        target()?,
        body.clone(),
    )?;
    assert_eq!(one.envelope().payload(), &body);
    assert_eq!(
        one.envelope()
            .metadata()
            .partition()
            .map(|p| p.key().as_str()),
        Some("ordered")
    );
    let two = pending_message(
        MessageId::parse("delivery-1")?,
        metadata(BTreeMap::new())?,
        Target::new(TargetId::parse("endpoint")?, TargetVersion::new(2)?),
        body,
    )?;
    assert_ne!(
        MessageFingerprint::of(one.envelope()),
        MessageFingerprint::of(two.envelope())
    );
    for key in ["webhookTargetId", "webhookTargetVersion"] {
        assert!(
            pending_message(
                MessageId::parse("id")?,
                metadata(BTreeMap::from([(key.into(), "injected".into())]))?,
                target()?,
                vec![]
            )
            .is_err()
        );
    }
    assert!(
        pending_message(
            MessageId::parse("id.with.dot")?,
            metadata(BTreeMap::new())?,
            target()?,
            vec![]
        )
        .is_err()
    );
    let bare = MessageEnvelope::new(
        MessageId::parse("bare")?,
        metadata(BTreeMap::new())?,
        vec![],
    );
    assert!(Publication::parse(&bare).is_err());
    assert!(TargetVersion::new(0).is_err());
    Ok(())
}
#[test]
fn signature_exact_bytes_rotation_and_safe_errors() -> anyhow::Result<()> {
    let keys = SigningKeys::new(
        SigningKey::new(vec![0x0b; 32])?,
        Some(SigningKey::new(vec![0x0c; 32])?),
    );
    let (time, signature) = keys.sign("msg_123", 1700000000, b"{ \"hello\":\"world\" }\n")?;
    assert_eq!(time, "1700000000");
    // Independent Python hmac/hashlib fixture; includes the trailing LF and JSON whitespace.
    assert_eq!(
        signature,
        "v1,cKYpBuvHZDFpwJCwY0hAxuHJ3jIc+RK4bm9TE31uwWk= v1,F44l3pkLwq/efYo4lAigXKIOje9G2jwCq3co0loMhWw="
    );
    assert_ne!(
        signature,
        keys.sign("msg_123", 1700000001, b"{ \"hello\":\"world\" }\n")?
            .1
    );
    assert_ne!(
        signature,
        keys.sign("msg_123", 1700000000, b"{\"hello\":\"world\"}")?
            .1
    );
    assert!(keys.sign("id", -1, b"").is_err());
    assert!(SigningKey::new(vec![1; 23]).is_err());
    assert!(SigningKey::new(vec![1; 65]).is_err());
    assert!(SigningKey::from_encoded("secret-do-not-print").is_err());
    assert!(!format!("{keys:?}").contains("0b"));
    assert_eq!(Error::Signing.to_string(), "invalid webhook signing input");
    Ok(())
}
#[test]
fn network_limits_and_mapped_addresses() -> anyhow::Result<()> {
    assert!(NetworkAccess::new(vec![], vec![]).is_err());
    assert!(
        NetworkAccess::new(vec!["127.0.0.1:443".parse()?], vec!["10.0.0.0/8".parse()?]).is_err()
    );
    let network = NetworkAccess::new(
        vec!["[::ffff:127.0.0.1]:443".parse()?],
        vec!["127.0.0.0/8".parse()?],
    )?;
    assert_eq!(
        network.addresses,
        vec!["127.0.0.1:443".parse::<std::net::SocketAddr>()?]
    );
    for limits in [
        (0, 1, 1, 1, 8192),
        (1, 0, 1, 1, 8192),
        (1, 1, 0, 1, 8192),
        (1, 1, 1, 0, 8192),
        (1, 1, 1, 1, 8191),
    ] {
        assert!(Limits::new(limits.0, limits.1, limits.2, limits.3, limits.4).is_err());
    }
    assert!(TrustRoots::from_der([]).is_err());
    assert!(TrustRoots::from_der([vec![1, 2, 3]]).is_err());
    Ok(())
}
struct Timer;
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)] // reason: injected host/test monotonic clock implementation.
    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, d: Deadline) {
        tokio::time::sleep_until(d.instant().into()).await;
    }
}
impl WallClock for Timer {
    fn unix_seconds(&self) -> i64 {
        1700000000
    }
}
struct Denied;
impl TargetAuthorizer for Denied {
    async fn authorize(
        &self,
        _: &Publication<'_>,
        _: OperationDeadline,
    ) -> Result<AuthorizedTarget, AuthorizationFailure> {
        Err(AuthorizationFailure::Denied)
    }
}
#[tokio::test]
async fn preflight_and_auth_denial_are_definite() -> anyhow::Result<()> {
    let publisher = WebhookPublisher::new(Denied, Timer, Timer, Limits::new(1, 16, 1, 16, 8192)?);
    let message = pending_message(
        MessageId::parse("id")?,
        metadata(BTreeMap::new())?,
        target()?,
        vec![1],
    )?;
    let outcome = publisher
        .publish(
            message.envelope(),
            OperationDeadline::from_remaining(Duration::from_secs(1)),
        )
        .await;
    assert!(
        matches!(outcome, PublishOutcome::DefinitelyNotPublished(f) if f.kind().is_permanent())
    );
    let outcome = publisher
        .publish(
            message.envelope(),
            OperationDeadline::from_remaining(Duration::ZERO),
        )
        .await;
    assert!(
        matches!(outcome, PublishOutcome::DefinitelyNotPublished(f) if f.kind().is_retryable())
    );
    Ok(())
}
