#![allow(unused)]

use diport::{RawCredential, ServiceTokenTenantBinding};

fn main() {
    let _rss = RawCredential::rss_access("rss.token");
    let _federated = RawCredential::federated_access("federated.token");
    let _service_constructor: fn(String, ServiceTokenTenantBinding) -> RawCredential =
        RawCredential::service_token;
}
