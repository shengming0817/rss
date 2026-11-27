//! Programmatic presentation of the same account/session authority.
//! ref: kanidm server/lib/src/idm/account.rs@f76b7ee9fdd28f123bb57d26351afef1515857d6
use crate::{
    AttemptSource, AuthenticatedSession, Authority, AuthorityError, SessionIdentity, SessionView,
    types::Budget,
};
use rss_identity_core::{
    account::{LoginKey, Password},
    session::{BearerSecret, CredentialKind},
};
use rss_transactional_messaging::fence::ExecutionBinding;
use rss_transactional_messaging::policy::OperationDeadline;

/// A committed issuance. Only the explicit HTTP response may expose its secret.
#[derive(Debug)]
pub struct IssuedBearer {
    secret: BearerSecret,
    identity: SessionIdentity,
    view: SessionView,
}
impl IssuedBearer {
    pub fn secret(&self) -> &BearerSecret {
        &self.secret
    }
    pub fn identity(&self) -> &SessionIdentity {
        &self.identity
    }
    pub fn view(&self) -> &SessionView {
        &self.view
    }
}
impl Authority {
    /// Uses the same password checks, attempt limits and atomic issuance as browser login.
    /// Does not replace a browser session or claim MFA assurance.
    pub async fn login_local_bearer(
        &self,
        binding: ExecutionBinding,
        login: LoginKey,
        password: Password,
        source: AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<IssuedBearer, AuthorityError> {
        let budget = Budget::new(deadline)?;
        let candidate = self
            .verify_password(binding, login, password, source, budget.remaining())
            .await?;
        let issued = self
            .create_session_for(candidate, None, CredentialKind::Bearer, budget.remaining())
            .await?;
        Ok(IssuedBearer {
            secret: BearerSecret::parse(issued.secret().expose().into())
                .map_err(|_| AuthorityError::Unavailable)?,
            identity: issued.identity().clone(),
            view: issued.view().clone(),
        })
    }
    /// Check a retained credential without extending its idle deadline.
    pub async fn inspect_bearer(
        &self,
        binding: ExecutionBinding,
        secret: BearerSecret,
        deadline: OperationDeadline,
    ) -> Result<AuthenticatedSession, AuthorityError> {
        self.session_proof(
            binding,
            secret.digest(),
            CredentialKind::Bearer,
            deadline,
            false,
        )
        .await
    }
    /// Authenticate programmatic activity, including reads, within the original absolute limit.
    /// Host ingress must have admitted the transport/source before calling this method.
    pub async fn authenticate_bearer(
        &self,
        binding: ExecutionBinding,
        secret: BearerSecret,
        deadline: OperationDeadline,
    ) -> Result<AuthenticatedSession, AuthorityError> {
        self.session_proof(
            binding,
            secret.digest(),
            CredentialKind::Bearer,
            deadline,
            true,
        )
        .await
    }
}
