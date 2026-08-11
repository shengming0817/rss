//! Request-time durable validation for verified RSS User access grants.

use std::sync::Arc;

use authn::AccessGrantValidationInput;

use crate::ports::{AuthGrantValidator, DynAuthGrantValidator, IdentityError};

/// Opaque request-scoped evidence for the exact durable grant accepted by the validator.
#[derive(Clone, PartialEq, Eq)]
pub struct CurrentAuthGrant {
    grant_id: ids::CanonicalUuidV4,
    user_id: ids::UserId,
    tenant_id: vocab::TenantId,
    authn_epoch: u64,
}

impl std::fmt::Debug for CurrentAuthGrant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CurrentAuthGrant(<redacted>)")
    }
}

impl CurrentAuthGrant {
    pub(crate) fn grant_id(&self) -> ids::CanonicalUuidV4 {
        self.grant_id
    }
    pub(crate) fn user_id(&self) -> ids::UserId {
        self.user_id
    }
    pub(crate) fn tenant_id(&self) -> vocab::TenantId {
        self.tenant_id
    }
    pub(crate) fn authn_epoch(&self) -> u64 {
        self.authn_epoch
    }

    /// Compare against the verified HTTP principal without exposing correlation fields.
    pub fn binds_principal(&self, tenant: vocab::TenantId, subject: &str) -> bool {
        self.tenant_id == tenant && self.user_id.as_uuid().hyphenated().to_string() == subject
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(
        grant_id: ids::CanonicalUuidV4,
        user_id: ids::UserId,
        tenant_id: vocab::TenantId,
        authn_epoch: u64,
    ) -> Self {
        Self {
            grant_id,
            user_id,
            tenant_id,
            authn_epoch,
        }
    }
}

/// Opaque move-only proof that the durable grant and account epoch matched one verified token.
///
/// The value has no public constructor or field access. It can only be returned after the
/// injected provider accepts the complete source-bound validation input.
pub struct ValidatedAuthGrant {
    _input: AccessGrantValidationInput,
}

impl std::fmt::Debug for ValidatedAuthGrant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ValidatedAuthGrant(<redacted>)")
    }
}

impl ValidatedAuthGrant {
    /// Consume the proof into identity-owned evidence. Callers cannot substitute individual fields.
    pub fn into_current_auth_grant(self) -> CurrentAuthGrant {
        let input = self._input;
        CurrentAuthGrant {
            grant_id: input.grant_id().as_verified(),
            user_id: input.user_id(),
            tenant_id: input.tenant(),
            authn_epoch: input.authn_epoch().get(),
        }
    }
}

/// Closed failure channel for request-time grant validation.
#[derive(thiserror::Error)]
pub enum AccessGrantValidationError {
    /// The durable grant/account state is missing, terminal, expired or does not match the token.
    #[error("access grant is not current")]
    Invalid,
    /// The durable provider could not make a security decision.
    #[error("access grant validation provider unavailable")]
    Provider(#[source] IdentityError),
}

impl std::fmt::Debug for AccessGrantValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => formatter.write_str("AccessGrantValidationError::Invalid"),
            Self::Provider(_) => {
                formatter.write_str("AccessGrantValidationError::Provider(<redacted>)")
            }
        }
    }
}

/// Mandatory request-time service that turns verified JWT facts into current durable evidence.
pub struct AuthGrantValidationService {
    validator: Arc<DynAuthGrantValidator<'static>>,
    clock: Box<dyn diport::Clock>,
}

impl AuthGrantValidationService {
    /// Build the service from a read-only validator and the runtime's injected clock.
    #[must_use]
    pub fn new(
        validator: Arc<DynAuthGrantValidator<'static>>,
        clock: Box<dyn diport::Clock>,
    ) -> Self {
        Self { validator, clock }
    }

    /// Validate one complete, source-bound token receipt against current durable state.
    pub async fn validate(
        &self,
        input: AccessGrantValidationInput,
    ) -> Result<ValidatedAuthGrant, AccessGrantValidationError> {
        let observed_at = self.clock.now();
        let scope = crate::ports::TenantRepoScope::from_authenticated_tenant(input.tenant());
        match self.validator.is_current(scope, &input, observed_at).await {
            Ok(true) => Ok(ValidatedAuthGrant { _input: input }),
            Ok(false) => Err(AccessGrantValidationError::Invalid),
            Err(error) => Err(AccessGrantValidationError::Provider(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AccessGrantValidationError;

    #[test]
    fn provider_error_debug_and_display_do_not_expose_source() {
        let error = AccessGrantValidationError::Provider(crate::ports::IdentityError::Storage(
            Box::new(std::io::Error::other("grant-validator-secret-canary")),
        ));
        let debug = format!("{error:?}");
        let display = error.to_string();
        assert_eq!(debug, "AccessGrantValidationError::Provider(<redacted>)");
        assert_eq!(display, "access grant validation provider unavailable");
        assert!(!debug.contains("grant-validator-secret-canary"));
        assert!(!display.contains("grant-validator-secret-canary"));
    }
}
