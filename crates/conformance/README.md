# rss-conformance

`rss-conformance` supplies provider-neutral assertions for LocalTx behavior. Version 0.1 exposes
the closed `ConformanceErrorCategory` taxonomy and cases for commit, rollback, validation or
authorization rejection without writes, commit-unknown without replay, and rollback-failed
without replay.

The caller owns the provider, fixture, state probes, and error values. Provider errors remain
opaque and are never formatted, preventing tenant identifiers, keys, credentials, payloads, or
provider messages from entering assertion diagnostics.

```rust
use std::cell::Cell;
use rss_conformance::{
    ConformanceErrorCategory,
    localtx::{ClassifiedError, CommitCase, assert_commit},
};

# async fn example() -> Result<(), rss_conformance::localtx::LocalTxConformanceError> {
struct ProviderError;
let writes = Cell::new(0_u32);
let _classified = ClassifiedError::new(ConformanceErrorCategory::Storage, ProviderError);
assert_commit(CommitCase::new(
    || async { writes.set(writes.get() + 1); Ok::<_, ClassifiedError<ProviderError>>(()) },
    || async { Ok::<_, ClassifiedError<ProviderError>>(writes.get()) },
    1,
    || writes.get() as usize,
)).await?;
# Ok(())
# }
```

The supported surface does not include adapters, provider drivers, containers, fixtures,
schedulers, artifact or CI selectors, internal T3 metadata, or any provider/product maturity
claim. The package has no default features and supports Rust 1.96.

This experimental 0.x package follows per-package SemVer while it remains in the positive Release
Surface. Explicit removal from that surface ends future Axis A commitments; no compatibility shim
is retained. Publication eligibility and candidate proof do not upload or release the crate.

Licensed under the Apache License, Version 2.0.
