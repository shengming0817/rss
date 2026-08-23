# rss-contract

`rss-contract` provides canonical, authority-free values used by RSS public APIs: contract
identities, absolute timepoints, and opaque pagination cursors.

Values can be parsed at runtime or authored as validated constants. The package deliberately does
not contain a registry, generated catalog, runtime binding, or admission authority.
Parsing errors distinguish empty, overlong, malformed, and zero-version identities without
echoing rejected input.

`Timepoint` is a non-negative Unix `int64` seconds value with total ordering and fallible
conversions. It does not provide a clock, `now`, deadlines, or scheduling authority.

`PageCursor` stores at most 4096 bytes of canonical unpadded base64url. Its contents stay opaque to
Foundation: consumers classify a well-formed token as `Stale` when it no longer matches their
tenant, query, version, or provider state. Cursor diagnostics never echo the token.

```rust
use rss_contract::{ContractDescriptor, ContractId, ContractVersion, PageCursor, Timepoint};

let id = ContractId::parse("runtime.inventory")?;
let version = ContractVersion::parse("v1")?;
assert_eq!(id.as_str(), "runtime.inventory");
assert_eq!(version.major(), 1);
assert_eq!(Timepoint::try_from(42)?.unix_seconds(), 42);
assert_eq!(PageCursor::parse("AQ")?.as_str(), "AQ");

const INVENTORY: ContractDescriptor = ContractDescriptor::from_static(
    "runtime.inventory",
    1,
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
);
assert_eq!(INVENTORY.id(), "runtime.inventory");
# Ok::<(), Box<dyn std::error::Error>>(())
```

Licensed under the Apache License, Version 2.0.
