use super::*;
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::PgInboxClaim;
pub(super) struct Validator;
impl rss_transactional_messaging::transaction::IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        challenge: rss_transactional_messaging::transaction::IngressChallenge<'_, Vec<u8>>,
    ) -> Result<
        rss_transactional_messaging::transaction::VerifiedIngress,
        rss_transactional_messaging::transaction::EnvelopeValidationFailure,
    > {
        let tenant = rss_request_context::TenantId::parse(crate::TENANT).map_err(|_| {
            rss_transactional_messaging::transaction::EnvelopeValidationFailure::MalformedIdentity
        })?;
        Ok(challenge.verified(crate::binding(tenant)))
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
    OperationDeadline::from_cutoff(
        Deadline::from_timeout(&clock, Duration::from_secs(5)).expect("deadline"),
        &clock,
    )
}

pub(super) async fn claim(
    inbox: &PgInboxStore,
    binding: &rss_transactional_messaging::transaction::VerifiedConsumerBinding,
) -> anyhow::Result<IdempotencyDisposition<PgInboxClaim>> {
    let permit = inbox
        .reserve_claim(binding.execution(), binding.identity(), deadline())?
        .acquire()
        .await?;
    Ok(inbox.claim(permit).await?)
}

pub(super) async fn assert_terminal(
    inbox: &PgInboxStore,
    binding: &rss_transactional_messaging::transaction::VerifiedConsumerBinding,
    expected: TerminalDisposition,
) -> anyhow::Result<()> {
    let IdempotencyDisposition::Terminal(receipt) = claim(inbox, binding).await? else {
        anyhow::bail!("expected durable terminal receipt on redelivery");
    };
    let settlement = binding
        .validate_terminal(receipt)
        .map_err(|_| anyhow::anyhow!("terminal receipt does not match the verified message"))?;
    assert_eq!(settlement.disposition(), expected);
    Ok(())
}
