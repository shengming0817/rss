fn wrong_action(
    authorization: diport::DlqOperatorAuthorization<diport::dlq_operator_action::List>,
    id: eventexec::DeadLetterId,
    replay_id: rss_transactional_messaging::message::MessageId,
) {
    let _ = eventexec::DlqReplayRequest::new(authorization, id, replay_id);
}

fn main() {}
