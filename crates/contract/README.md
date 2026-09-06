# rss-contract

`rss-contract` provides canonical, authority-free values used by RSS public APIs: contract
identities, absolute timepoints, opaque pagination cursors, data classification, and redact-safe
errors, and the protocol-neutral `Contract` trait.

`Contract` binds associated Request/Response types to one ContractDescriptor. It is the sole
owner previously located in rss-platform; consumers import it directly from rss-contract.
The trait does not prove schema/DTO equivalence or authorize execution. No old export remains.

Values can be parsed at runtime or authored as validated constants. The package deliberately does
not contain a registry, generated catalog, runtime binding, or admission authority.
Parsing errors distinguish empty, overlong, malformed, and zero-version identities without
echoing rejected input.

`Timepoint` is a non-negative Unix `int64` seconds value with total ordering and fallible
conversions. It does not provide a clock, `now`, deadlines, or scheduling authority.

`PageCursor` stores at most 4096 bytes of canonical unpadded base64url. Its contents stay opaque to
Foundation: consumers classify a well-formed token as `Stale` when it no longer matches their
tenant, query, version, or provider state. Cursor diagnostics never echo the token.

`DataClass` is the sole closed vocabulary for public, internal, PII, and secret data. It does not
contain redaction engines or policy. `SafeError` stores only a closed `SafeErrorCode`; its category
and message are fixed by that code, and it cannot carry provider sources, arbitrary messages,
payloads, or details.

```rust
use rss_contract::{
    ContractDescriptor, ContractId, ContractVersion, DataClass, PageCursor, SafeError,
    SafeErrorCode, Timepoint,
};

let id = ContractId::parse("runtime.inventory")?;
let version = ContractVersion::parse("v1")?;
assert_eq!(id.as_str(), "runtime.inventory");
assert_eq!(version.major(), 1);
assert_eq!(Timepoint::try_from(42)?.unix_seconds(), 42);
assert_eq!(PageCursor::parse("AQ")?.as_str(), "AQ");
assert_eq!(DataClass::Pii.as_str(), "pii");
assert_eq!(
    SafeError::new(SafeErrorCode::Unavailable).to_string(),
    "service unavailable"
);

const INVENTORY: ContractDescriptor = ContractDescriptor::from_static(
    "runtime.inventory",
    1,
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
);
assert_eq!(INVENTORY.id(), "runtime.inventory");
# Ok::<(), Box<dyn std::error::Error>>(())
```

Licensed under the Apache License, Version 2.0.
