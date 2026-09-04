fn separate_tenant(
    authorization: diport::DlqOperatorAuthorization<diport::dlq_operator_action::RedriveOutbox>,
    tenant: rss_request_context::TenantId,
    message_id: rss_transactional_messaging::message::MessageId,
) {
    let _ = eventexec::DlqRedriveRequest::new(tenant, message_id, authorization);
}

fn main() {}
