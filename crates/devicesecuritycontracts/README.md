# rss-device-security-contracts

Transport-neutral DTOs, standalone resolved schema bytes, and compatibility descriptors for the six RSS
device-security Draft candidates. This package is not an authorization SDK, runtime client, or
production-eligibility claim.

`AuthorizationReceiptId` is an opaque correlation identity. It never proves that a caller or
device is authorized; RSS restores and verifies durable authorization lineage server-side.

```rust
use rss_device_security_contracts::{apply_device_certificate, AuthorizationReceiptId};

let receipt: AuthorizationReceiptId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".parse()
    .expect("non-nil receipt identity");
assert_eq!(receipt.as_uuid().to_string(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
assert_eq!(format!("{receipt:?}"), "AuthorizationReceiptId(<redacted>)");
assert_eq!(apply_device_certificate::LIFECYCLE, "draft");
assert!(!apply_device_certificate::SCHEMAS[0].json().is_empty());
```
