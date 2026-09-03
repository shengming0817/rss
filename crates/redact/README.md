# rss-redact

`rss-redact` is the public owner of RSS diagnostic-output redaction. It provides typed redaction
policies, safe wrappers for text, bytes and error sources, keyed hashing, and the `Redact` derive.

Consumers depend only on this package; the derive implementation package is re-exported and is not
a separate user-facing API.

```rust
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
```

This package does not own storage encryption, key-provider integrations, logging backends, or
authorization policy.
