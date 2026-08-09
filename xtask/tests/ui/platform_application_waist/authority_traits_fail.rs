use std::fmt::Display;

use platform_application_waist_contract::{
    RequestContext, VerifiedPrincipal, VerifiedTenant,
};
use serde::{Serialize, de::DeserializeOwned};

fn demand_display<T: Display>() {}
fn demand_serialize<T: Serialize>() {}
fn demand_deserialize<T: DeserializeOwned>() {}

fn clone_views(
    context: RequestContext<'_>,
    principal: VerifiedPrincipal<'_>,
    tenant: VerifiedTenant<'_>,
) {
    let _ = context.clone();
    let _ = principal.clone();
    let _ = tenant.clone();
}

fn main() {
    demand_display::<VerifiedPrincipal<'static>>();
    demand_serialize::<VerifiedPrincipal<'static>>();
    demand_serialize::<VerifiedTenant<'static>>();
    demand_serialize::<RequestContext<'static>>();
    demand_deserialize::<VerifiedPrincipal<'static>>();
    demand_deserialize::<VerifiedTenant<'static>>();
    demand_deserialize::<RequestContext<'static>>();
    let _ = clone_views;
}
