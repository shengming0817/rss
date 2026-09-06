use crate::{Error, Mutation, Query, Target};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::{
    AbsoluteDeadline, ExecutionTimer, OperationDeadline, within,
};

/// Borrowed, library-issued authorization challenge. Products authenticate and authorize its exact inputs.
pub struct Challenge<'a> {
    mutation: Option<&'a Mutation>,
    query: Option<&'a Query>,
    digest: [u8; 32],
    tenant: TenantId,
}
impl Challenge<'_> {
    /// Exact mutation, when requesting mutation or operation-receipt readback.
    pub const fn mutation(&self) -> Option<&Mutation> {
        self.mutation
    }
    /// Exact read query, when listing/inspecting.
    pub const fn query(&self) -> Option<&Query> {
        self.query
    }
    /// Tenant requested by the caller; the product must authenticate it.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Exact target, or none for a tenant-scoped list.
    pub fn target(&self) -> Option<&Target> {
        self.mutation
            .map(Mutation::target)
            .or_else(|| self.query.and_then(Query::target))
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
        mutation: Some(&request),
        query: None,
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
        mutation: None,
        query: Some(&request),
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
