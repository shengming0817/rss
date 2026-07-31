use primitives::{AuthPlan, AuthScheme, ListenerKind};

mod listeners {
    use super::*;

    pub fn primary_auth_plan() -> Result<AuthPlan, primitives::AuthPlanError> {
        AuthPlan::new(
            ListenerKind::Primary,
            AuthScheme::FederatedAccessToken,
        )
    }

    pub fn health_auth_plan() -> Result<AuthPlan, primitives::AuthPlanError> {
        AuthPlan::none(ListenerKind::Health)
    }

    pub fn admin_auth_plan() -> Result<AuthPlan, primitives::AuthPlanError> {
        AuthPlan::new(
            ListenerKind::Admin,
            AuthScheme::FederatedAccessToken,
        )
    }

    pub fn wrong_wrapper() -> Result<AuthPlan, primitives::AuthPlanError> {
        AuthPlan::none(ListenerKind::Primary)
    }
}

fn main() {}
