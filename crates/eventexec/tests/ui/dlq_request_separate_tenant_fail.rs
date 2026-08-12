fn separate_tenant(
    authorization: diport::DlqOperatorAuthorization<diport::dlq_operator_action::RedriveOutbox>,
    tenant: rss_request_context::TenantId,
    event_id: consistency::IdemKey,
) {
    let _ = eventexec::DlqRedriveRequest::new(tenant, event_id, authorization);
}

fn main() {}
