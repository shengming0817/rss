#![allow(unused, unknown_lints)]

use diport::{RawCredential, ServiceTokenTenantBinding, TokenProfile};

fn main() {
    let _rss = RawCredential::rss_access("rss.token");
    let federated_constructor = RawCredential::federated_access;
    let _federated = federated_constructor("federated.token");
    let service_constructor: fn(String, ServiceTokenTenantBinding) -> RawCredential =
        RawCredential::service_token;

    // Anti-vacuity/specificity: discovery is based on the inherent impl self type plus the
    // RawCredential return type. Non-constructing associated functions on the same type stay legal.
    let _profile_getter: fn(&RawCredential) -> TokenProfile = RawCredential::profile;
    let _token_getter: for<'a> fn(&'a RawCredential) -> &'a str = RawCredential::token;

    // Common associated constructors on unrelated types are not targets.
    let _bytes: Vec<u8> = Vec::new();

    allowed_by_attr();
}

#[allow(rss_raw_credential_callsite)] // reason: UI fixture verifies the explicit escape hatch
fn allowed_by_attr() {
    let _rss = RawCredential::rss_access("fixture.token");
}
