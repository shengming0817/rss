# rss-redact-derive

This is the procedural-macro implementation used by `rss-redact`.

Application and library code should depend on `rss-redact` and explicitly enable its `derive`
feature to use the re-exported `#[derive(Redact)]`:

```toml
[dependencies]
rss-redact = { version = "0.1", features = ["derive"] }
```

Without this feature, `rss-redact` provides its redaction traits, policies, and built-in safety
types without this procedural-macro dependency. Enabling it adds the derive macro without changing
the built-in types' safety guarantees.

Keeping the macro in a dedicated `proc-macro` package is required by Rust, while the re-export keeps
one user-facing redaction dependency. Consumers should not depend directly on this implementation
package.

Generic derives add bounds only to the generated `Redact` and `Debug` impls. Public/show fields require
`FieldType: Debug`; partial masks require `FieldType: RedactField`. Fixed/drop fields are not read and
require neither trait. Bounds apply to complete field types, including wrappers and associated types,
and preserve the input where clause. A public declaration remains the type author's responsibility;
the derive checks policy grammar, not whether a value is actually public.

Concrete fields are checked in the generated impl body. The macro traverses type syntax to detect
generic uses; it does not resolve aliases or guess recursion from type names. For generic recursion,
use a struct-level override such as `#[redact(bound = "T: std::fmt::Debug")]`, or `bound = ""`
when no extra bound is needed. This replaces all inferred bounds on both generated impls while
preserving the struct's existing where clause. Field policy checks and rendering expressions still
compile normally, so an insufficient override is rejected by Rust. Bounds describe the actual
visible/masked fields; hidden generic parameters need no bound.

ref: serde-rs/serde serde_derive/src/bound.rs@v1.0.228
ref: https://serde.rs/attr-bound.html

`secret`/`internal` fields allow only default/fixed and drop. Explicit last4, email_mask and show
are compile errors, including through struct-level bound overrides. PII partial masks remain valid;
PII show remains invalid. Unsafe historical declarations have no compatibility mode.
