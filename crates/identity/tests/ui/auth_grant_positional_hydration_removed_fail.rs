//! INVARIANT: AUTH-GRANT-NAMED-SNAPSHOT-01 { level = "Hard", exec = "verify", source = "trybuild" }

use std::time::SystemTime;

use identity::ports::{
    AuthGrant, AuthGrantCloseReason, AuthGrantStatus, AuthnEpoch, RefreshStatus,
    RefreshTokenRecord,
};

fn positional_hydration_is_not_available(
    tenant: vocab::TenantId,
    user_id: ids::UserId,
    epoch: AuthnEpoch,
) {
    let _grant = AuthGrant::hydrate(
        "grant",
        tenant,
        user_id,
        SystemTime::UNIX_EPOCH,
        epoch,
        AuthGrantStatus::Revoked,
        SystemTime::UNIX_EPOCH,
        SystemTime::UNIX_EPOCH,
        Some(SystemTime::UNIX_EPOCH),
        Some(AuthGrantCloseReason::LogoutCurrent),
    );
    let _refresh = RefreshTokenRecord::hydrate(
        "refresh",
        tenant,
        "grant",
        user_id,
        epoch,
        AuthGrantStatus::Active,
        [0_u8; 32],
        None,
        "refresh",
        RefreshStatus::Active,
        SystemTime::UNIX_EPOCH,
        SystemTime::UNIX_EPOCH,
    );
}

fn main() {}
