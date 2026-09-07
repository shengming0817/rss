use crate::{Error, Mutation, Query};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::{
    AbsoluteDeadline, ExecutionTimer, OperationDeadline, within,
};

/// Borrowed, library-issued authorization challenge. Products authenticate and authorize its exact inputs.
/// Closed request presented to the trusted product authorizer.
#[derive(Clone, Copy)]
pub enum AuthorizationSubject<'a> {
    /// A dead-letter mutation or its exact receipt readback.
    Mutation(&'a Mutation),
    /// A bounded dead-letter query.
    Query(&'a Query),
    /// A DR plan or its exact receipt/progress readback.
    Dr(&'a crate::dr::Plan),
}
/// Library-issued authorization challenge.
pub struct Challenge<'a> {
    subject: AuthorizationSubject<'a>,
    digest: [u8; 32],
    tenant: TenantId,
}
impl Challenge<'_> {
    /// Exact subject, including external restore evidence for DR.
    pub const fn subject(&self) -> AuthorizationSubject<'_> {
        self.subject
    }
    /// Tenant requested by the caller; the product must authenticate it.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Bind this challenge after product authorization. This records a trusted decision; it does not perform authentication.
    pub fn authorized(self) -> Authorization {
        Authorization {
            digest: self.digest,
            tenant: self.tenant,
        }
    }
}
/// Move-only product authorization, bound by the library to a single challenge.
pub struct Authorization {
    digest: [u8; 32],
    tenant: TenantId,
}
/// Trusted product seam, analogous to messaging's ingress validator. No identity service is implemented here.
pub trait Authorizer: Send + Sync {
    /// Check the complete request against authenticated product policy under the supplied budget.
    fn authorize(
        &self,
        challenge: Challenge<'_>,
        deadline: OperationDeadline,
    ) -> impl Future<Output = Result<Authorization, Error>> + Send;
}
/// Exact authorized mutation passed to a trusted store; no public constructor or mutation access.
pub struct AuthorizedMutation(Mutation);
impl AuthorizedMutation {
    /// Immutable authorized inputs.
    pub const fn request(&self) -> &Mutation {
        &self.0
    }
}
/// Exact authorized query passed to a trusted store.
pub struct AuthorizedQuery(Query);
impl AuthorizedQuery {
    /// Immutable authorized query.
    pub const fn request(&self) -> &Query {
        &self.0
    }
}
/// Authorize a mutation without allowing a stale/different proof to authorize it.
pub async fn authorize_mutation<A: Authorizer, C: ExecutionTimer>(
    authorizer: &A,
    request: Mutation,
    clock: &C,
    cutoff: AbsoluteDeadline,
) -> Result<AuthorizedMutation, Error> {
    let digest = request.digest();
    let tenant = request.tenant();
    let challenge = Challenge {
        subject: AuthorizationSubject::Mutation(&request),
        digest,
        tenant,
    };
    let proof = within(clock, cutoff, |deadline| {
        authorizer.authorize(challenge, deadline)
    })
    .await
    .map_err(|_| Error::Deadline)??;
    if proof.digest != digest || proof.tenant != tenant {
        return Err(Error::Unauthorized);
    }
    Ok(AuthorizedMutation(request))
}
/// Authorize exact query filters, scope and cursor before any storage access.
pub async fn authorize_query<A: Authorizer, C: ExecutionTimer>(
    authorizer: &A,
    request: Query,
    clock: &C,
    cutoff: AbsoluteDeadline,
) -> Result<AuthorizedQuery, Error> {
    let digest = request.digest();
    let tenant = request.tenant();
    let challenge = Challenge {
        subject: AuthorizationSubject::Query(&request),
        digest,
        tenant,
    };
    let proof = within(clock, cutoff, |deadline| {
        authorizer.authorize(challenge, deadline)
    })
    .await
    .map_err(|_| Error::Deadline)??;
    if proof.digest != digest || proof.tenant != tenant {
        return Err(Error::Unauthorized);
    }
    Ok(AuthorizedQuery(request))
}

/// Bind product authorization to the exact DR recovery or termination action and execution facts.
pub async fn authorize_dr<A: Authorizer, C: ExecutionTimer>(
    authorizer: &A,
    request: crate::dr::Plan,
    clock: &C,
    cutoff: AbsoluteDeadline,
) -> Result<crate::dr::AuthorizedPlan, Error> {
    let digest = request.digest();
    let tenant = request.tenant();
    let challenge = Challenge {
        subject: AuthorizationSubject::Dr(&request),
        digest,
        tenant,
    };
    let proof = within(clock, cutoff, |deadline| {
        authorizer.authorize(challenge, deadline)
    })
    .await
    .map_err(|_| Error::Deadline)??;
    if proof.digest != digest || proof.tenant != tenant {
        return Err(Error::Unauthorized);
    }
    Ok(crate::dr::AuthorizedPlan(request))
}
