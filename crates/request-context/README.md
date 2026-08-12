# rss-request-context

`rss-request-context` provides canonical request values and borrowed, read-only views for async
handlers. It includes tenant and request IDs, redacted principal references, deadlines,
cancellation observation, and closed obligation projections.

These values are not authentication or authorization evidence. The package exposes no trusted
context mint, cancellation trigger, deadline extension, cross-tenant capability, or obligation
elevation API.

```rust
use rss_request_context::{PrincipalKind, PrincipalRef, RequestId, TenantId};

let tenant = TenantId::parse("8b117a90-752f-4f2a-85f1-00c7c4e1f41c")?;
let request = RequestId::parse("request-42")?;
let principal = PrincipalRef::new(PrincipalKind::User, "private-subject")?;
assert_eq!(tenant.to_string(), "8b117a90-752f-4f2a-85f1-00c7c4e1f41c");
assert_eq!(request.as_str(), "request-42");
assert!(principal.matches_subject("private-subject"));
assert!(!format!("{principal:?}").contains("private-subject"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

Licensed under the Apache License, Version 2.0.
