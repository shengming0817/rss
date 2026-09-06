# rss-redact

`rss-redact` is the public owner of RSS diagnostic-output redaction. It provides typed redaction
policies, safe wrappers for text, bytes and error sources, and keyed hashing. These APIs and the
`Redact` trait are available by default without the `rss-redact-derive` dependency.

```rust
use rss_redact::{Redact, RedactScope, SecretText};
let secret = SecretText::from_string("do-not-log".into());
assert_eq!(format!("{secret:?}"), "SecretText(<redacted>)");
assert_eq!(secret.redact_scoped(RedactScope::Wire), "SecretText(<redacted>)");
```

To generate `Redact` and safe `Debug` implementations for your own types, explicitly enable `derive`:

```toml
[dependencies]
rss-redact = { version = "0.1", features = ["derive"] }
```

Consumers use this package's re-export; the implementation crate is not a separate entry point.
The feature adds the macro without changing the safety guarantees of any built-in type.

```rust
# #[cfg(feature = "derive")]
# {
use rss_redact::{Redact, RedactScope};

#[derive(Redact)]
struct Login {
    #[redact(sensitivity = pii_email)]
    email: String,
    #[redact(sensitivity = secret)]
    token: String,
}

let login = Login { email: "a@example.com".into(), token: "secret".into() };
let safe = login.redact_scoped(RedactScope::ServerLog);
assert!(!safe.contains("secret"));
# }
```

This package does not own storage encryption, key-provider integrations, logging backends, or
authorization policy.
