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
