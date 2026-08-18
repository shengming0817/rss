# Runtime Assembly Residual

`runtime-assembly-residual` owns only cross-file risks that Rust ownership and visibility cannot
make unrepresentable. Run it through the canonical verify selector:

```bash
cargo xtask verify --only runtime-assembly-residual
```

It remains a FullOnly gate. There is no standalone update/verify command and no committed runtime
inventory. `assemblies/runtime/Cargo.toml` is the dependency source of truth; dependency changes do
not require synchronizing a generated copy.

## Native proof owners

- `DomainModuleResult` privately stores one `DomainLifecycleOutput` collection. Its closed
  `Probe | Resource | Worker` enum and the runtime sink's exhaustive match force new lifecycle
  output kinds to update the consumer at compile time.
- `SharedRuntimeDeps` remains constrained by `runtime-deps-guard`.
- Runtime config, provider receipts, lifecycle ownership and execution-plan closure stay beside
  their typed and behavioral owners in runtime/runtimeexec.
- Server request budgeting is enforced by the opaque `ServerService` type and required
  `ServerRequestBudget` finalization argument, with httpserve compile-fail coverage.

## Cross-file residuals

The gate retains the risk-centric checks for ambient config and secret escapes, provider and
lifecycle bypasses, handwritten plan binding, service-token replay, PostgreSQL setup transaction
closure, audit security side channels, and projection-target enrollment. These checks scan
production reachability and carry synthetic-red plus real-workspace anti-vacuity tests.

The residual gate intentionally does not snapshot Cargo dependencies, struct fields, merge
statements, source positions or current statement counts. Those facts are either canonical inputs,
native type relationships, or implementation details.
