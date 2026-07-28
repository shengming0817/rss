use identity::CredentialSecurityService;
use identity::ports::PasswordChangeProducerReceipt;

async fn string_cannot_cross_as_the_new_password(
    service: &CredentialSecurityService,
    receipt: PasswordChangeProducerReceipt,
    tenant: vocab::TenantId,
    user_id: ids::UserId,
    current_password: secure::RawPassword,
    new_password: String,
) {
    let _result = service
        .change_password(receipt, tenant, user_id, current_password, new_password)
        .await;
}

async fn raw_password_cannot_cross_as_the_new_password(
    service: &CredentialSecurityService,
    receipt: PasswordChangeProducerReceipt,
    tenant: vocab::TenantId,
    user_id: ids::UserId,
    current_password: secure::RawPassword,
    new_password: secure::RawPassword,
) {
    let _result = service
        .change_password(receipt, tenant, user_id, current_password, new_password)
        .await;
}

fn main() {}
