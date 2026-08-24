# rss-device-security-contracts

Transport-neutral DTOs, standalone resolved schema bytes, compatibility descriptors, and
authority-free HTTP operation metadata for the six RSS device-security Draft candidates. This
package is not an authorization SDK, runtime client, or production-eligibility claim.

`AuthorizationReceiptId` is an opaque correlation identity. It never proves that a caller or
device is authorized; RSS restores and verifies durable authorization lineage server-side.

```rust
use rss_device_security_contracts::{
    apply_device_certificate, policy_put, status_get, AuthorizationReceiptId, HttpMethod,
};

let receipt: AuthorizationReceiptId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".parse()
    .expect("non-nil receipt identity");
assert_eq!(receipt.as_uuid().to_string(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
assert_eq!(format!("{receipt:?}"), "AuthorizationReceiptId(<redacted>)");
assert_eq!(apply_device_certificate::LIFECYCLE, "draft");
assert!(!apply_device_certificate::SCHEMAS[0].json().is_empty());
assert_eq!(policy_put::OPERATION.contract(), policy_put::DESCRIPTOR);
assert_eq!(policy_put::OPERATION.method(), HttpMethod::Put);
assert_eq!(policy_put::OPERATION.method().as_str(), "PUT");
assert_eq!(
    policy_put::OPERATION.path_template(),
    "/api/v2/identity/devices/{deviceId}/certificate-policy"
);
assert_eq!(status_get::OPERATION.contract(), status_get::DESCRIPTOR);
assert_eq!(status_get::OPERATION.method(), HttpMethod::Get);
assert_eq!(
    status_get::OPERATION.path_template(),
    "/api/v2/identity/devices/{deviceId}/certificate-status"
);
```

HTTP paths are unbound, origin-relative templates. Consumers remain responsible for binding the
origin and substituting path parameters with segment-safe URL construction. Operation metadata
does not grant tenant or authorization capability, register a route, activate a Draft contract, or
assert that a service is available.
