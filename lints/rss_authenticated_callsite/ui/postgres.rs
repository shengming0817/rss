// Exact green fixture for the sole persistence hydration impl method; the same target also carries
// the postgres-owned capability red fixture without a same-named adapter dev-dependency.
#![allow(unused)]

struct ConfigValueMaintenanceCapability;

impl ConfigValueMaintenanceCapability {
    fn from_verified_service_caller(_: vocab::ServiceCallerDomain) -> Self {
        Self
    }
}

fn forbidden_capability_mint() {
    let _ = ConfigValueMaintenanceCapability::from_verified_service_caller(
        vocab::ServiceCallerDomain::MaintenanceOperator,
    );
    let mint = ConfigValueMaintenanceCapability::from_verified_service_caller;
    let _mint_fn: fn(vocab::ServiceCallerDomain) -> ConfigValueMaintenanceCapability =
        ConfigValueMaintenanceCapability::from_verified_service_caller;
    let _ = mint;
}

mod auth_grant_lifecycle {
    pub(super) struct PgAuthGrantLifecycle;

    impl PgAuthGrantLifecycle {
        pub(super) fn find_active() {
            let _ = authn::AuthGrant::hydrate;
        }
    }
}

mod fake {
    struct PgAuthGrantLifecycle;

    impl PgAuthGrantLifecycle {
        fn find_active() {
            let _ = authn::AuthGrant::hydrate;
        }
    }
}

fn main() {}
