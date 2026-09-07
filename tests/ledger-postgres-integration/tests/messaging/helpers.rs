use super::*;
pub(super) struct Validator;
impl rss_transactional_messaging::transaction::IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        challenge: rss_transactional_messaging::transaction::IngressChallenge<'_, Vec<u8>>,
    ) -> Result<
        rss_transactional_messaging::transaction::VerifiedIngress,
        rss_transactional_messaging::transaction::EnvelopeValidationFailure,
    > {
        Ok(challenge.verified())
    }
}
#[allow(clippy::expect_used, clippy::panic)]
// reason: fixed integration identities and budgets.
pub(super) fn message(id: &str) -> rss_transactional_messaging::message::MessageEnvelope<Vec<u8>> {
    use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
    use rss_transactional_messaging::message::*;
    MessageEnvelope::new(
        MessageId::parse(id).expect("id"),
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                    .expect("tenant"),
                Timepoint::try_from(1_i64).expect("time"),
                MessagingDomain::parse("integration").expect("domain"),
                MessageRoute::parse("created").expect("route"),
                ContractIdentity::new(
                    ContractId::parse("integration.created").expect("contract"),
                    ContractVersion::from_major(1).expect("version"),
                    SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64))).expect("digest"),
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        vec![1, 2, 3],
    )
}
#[allow(clippy::expect_used, clippy::panic)]
// reason: fixed integration identities and budgets.
pub(super) fn binding(
    message: &rss_transactional_messaging::message::MessageEnvelope<Vec<u8>>,
) -> rss_transactional_messaging::transaction::VerifiedConsumerBinding {
    use rss_transactional_messaging::{
        inbox::ConsumerGroup, message::SubscriptionIdentity, transaction::verify_ingress,
    };
    let metadata = message.metadata();
    verify_ingress(
        &Validator,
        ConsumerGroup::parse("suite").expect("group"),
        &SubscriptionIdentity::new(
            metadata.domain().clone(),
            metadata.route().clone(),
            metadata.contract().clone(),
        ),
        message,
    )
    .unwrap_or_else(|_| panic!("valid test ingress"))
}
#[allow(clippy::expect_used, clippy::panic)]
// reason: fixed integration identities and budgets.
pub(super) fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    let clock = crate::Clock::new();
    AbsoluteDeadline::from_timeout(&clock, Duration::from_secs(5))
        .expect("deadline")
        .operation(&clock)
}
