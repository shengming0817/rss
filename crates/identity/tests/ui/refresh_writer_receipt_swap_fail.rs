//! INVARIANT: REFRESH-PRODUCER-RECEIPT-02 { level = "Medium", exec = "test", source = "trybuild" }

use identity::ports::{
    IdentitySecurityLifecycle, PasswordChangeProducerReceipt, RefreshExecutionCommand,
    TenantRepoScope,
};

fn value<T>() -> T {
    panic!("compile-fail fixture")
}

async fn attempt<L: IdentitySecurityLifecycle>(
    lifecycle: &L,
    password_receipt: PasswordChangeProducerReceipt,
) {
    let _: _ = lifecycle
        .execute_refresh(
            password_receipt,
            value::<TenantRepoScope>(),
            value::<RefreshExecutionCommand>(),
        )
        .await;
}

fn main() {}
