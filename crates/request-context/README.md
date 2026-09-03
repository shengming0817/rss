# rss-request-context

`rss-request-context` provides canonical request values and borrowed, read-only views for async
handlers. It includes tenant and request IDs, deadlines, and cancellation observation.

These values are not authentication or authorization evidence. The package exposes no principal,
policy obligation, trusted context mint, cancellation trigger, deadline extension, or cross-tenant
capability API.

Parsing errors are stable, non-sensitive categories: empty, too long, invalid format, and nil
tenant identifiers. Error messages never echo the rejected input.

```rust
use rss_request_context::{RequestId, TenantId};

let tenant = TenantId::parse("8b117a90-752f-4f2a-85f1-00c7c4e1f41c")?;
let request = RequestId::parse("request-42")?;
assert_eq!(tenant.to_string(), "8b117a90-752f-4f2a-85f1-00c7c4e1f41c");
assert_eq!(request.as_str(), "request-42");
# Ok::<(), Box<dyn std::error::Error>>(())
```

Licensed under the Apache License, Version 2.0.
