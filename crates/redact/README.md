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

## Output trust boundaries

`ErrorSummary` is a closed, payload-free diagnostic vocabulary. Components retain their own error
classification and explicitly project it at the output boundary; summaries do not determine retry,
authorization or HTTP behavior. `LastError::from_summary` stores the enum itself and can only render
its fixed label. There is no raw-error or open-renderer constructor.

```rust
use rss_redact::{ErrorSummary, LastError};
assert_eq!(LastError::from_summary(ErrorSummary::Io).as_str(), "io");
```

`Redact` and `safe` render the type author's policy, including public/show fields. A handwritten
implementation can return arbitrary text. `Redacted` records a particular helper's result, not a
universal secrecy guarantee: key filtering leaves unmatched values intact and URL credential
scrubbing only removes userinfo. None of these results can construct `LastError`.

### API replacement (#2326)

`redact_error`, `LastError::from_error` and `LastError::from_redactable` have been removed. Classify
errors at their component owner and explicitly select `ErrorSummary`; never infer a category from
provider text. Built-in secret wrappers remain available with or without the optional derive feature.

`secret` and `internal` derive fields accept only default/fixed or drop; partial masks and show
are rejected at compile time. PII retains its declared masking policy. Email masking requires
one `@`, nonempty local/domain parts, and no Unicode whitespace or control characters; malformed
input is rendered as `<redacted>`. This is a diagnostic safety check, not RFC mailbox validation.
`RedactionHashKey` takes zeroizing ownership before length validation, including rejected inputs.
