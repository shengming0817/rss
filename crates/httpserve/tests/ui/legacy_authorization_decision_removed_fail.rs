use httpserve::RouteAuthorizationDecision;

fn main() {
    let _: RouteAuthorizationDecision = RouteAuthorizationDecision::Allow;
    let _ = RouteAuthorizationDecision::AllowWithProjection;
    let _ = RouteAuthorizationDecision::allow_with_unmasked_fields;
}
