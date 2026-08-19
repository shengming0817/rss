//! INVARIANT: IDENTITY-SECURITY-ROUTE-COMMAND-01 { level = "Medium", exec = "test", source = "trybuild" }

use identity::ports::{
    IdentitySecurityLifecycle, LogoutAllCommand, LogoutCurrentProducerReceipt, TenantRepoScope,
};

async fn swap_route_command<L: IdentitySecurityLifecycle>(
    lifecycle: &L,
    receipt: LogoutCurrentProducerReceipt,
    scope: TenantRepoScope,
    command: LogoutAllCommand,
) {
    let _ = lifecycle
        .execute_logout_current(receipt, scope, command)
        .await;
}

fn main() {}
