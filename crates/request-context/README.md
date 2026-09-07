# rss-request-context

`rss-request-context` provides canonical request values and borrowed, read-only views for async
handlers. It includes tenant and request IDs, deadlines, and cancellation observation.

Cancellation is independent of deadline: `CancellationObserver::is_cancelled()` reports only
sticky cancellation, and `cancelled()` waits for that event without accepting a deadline.
Execution owners must drive their own timer; cancellation observers are not deadline providers.
The old combined `CancellationReason` and deadline-taking wait are removed without compatibility
wrappers. A wait must not lose concurrent cancellation and must wake all registered observers.

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

`Clock`, `ExecutionTimer` and `Deadline` are the shared in-process monotonic time boundary.
Consumers implement one timer for Platform and transactional messaging; each execution core
owns its own arbitration. Timers must wake independently of the workload and report elapsed
deadlines even when the executor cooperative budget is exhausted. `Deadline::from_timeout`
rejects representational overflow. Deadlines are not wall-clock or persistent timestamps.
