use rss_request_context::TenantId;
use rss_transactional_messaging::message::MessageId;
use rss_transactional_messaging_recovery::{Action, Mutation, OperationId, Target, Version};

#[test]
#[allow(clippy::expect_used)] // reason: fixed request fixtures.
fn replay_requires_dead_letter_target_and_new_identity() {
    let tenant = TenantId::parse("11111111-1111-1111-1111-111111111111").expect("tenant");
    let id = MessageId::parse("message").expect("id");
    assert!(
        Mutation::new(
            tenant,
            OperationId::new(),
            Target::Outbox(id.clone()),
            Version::new(1).expect("version"),
            Action::Replay(id)
        )
        .is_err()
    );
    assert!(Version::new(0).is_err());
}
