# rss-contract

`rss-contract` provides the canonical, authority-free contract identity values used by RSS public
APIs: dotted contract IDs, `vN` versions, SHA-256 schema digests, and immutable descriptors.

Values can be parsed at runtime or authored as validated constants. The package deliberately does
not contain a registry, generated catalog, runtime binding, or admission authority.
Parsing errors distinguish empty, overlong, malformed, and zero-version identities without
echoing rejected input.

```rust
use rss_contract::{ContractDescriptor, ContractId, ContractVersion};

let id = ContractId::parse("runtime.inventory")?;
let version = ContractVersion::parse("v1")?;
assert_eq!(id.as_str(), "runtime.inventory");
assert_eq!(version.major(), 1);

const INVENTORY: ContractDescriptor = ContractDescriptor::from_static(
    "runtime.inventory",
    1,
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
);
assert_eq!(INVENTORY.id(), "runtime.inventory");
# Ok::<(), rss_contract::IdentityError>(())
```

Licensed under the Apache License, Version 2.0.
