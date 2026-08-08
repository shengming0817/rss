# Traceability

| Requirement | Code carrier | Test carrier |
|---|---|---|
| remote parent/state | `tracewire::restore_remote_parent` | tracewire in-memory exporter |
| safe SERVER fields | private `HttpServerObservation` | matched/unmatched/privacy corpus |
| mandatory policy | private non-optional `TracePolicy` field | Health/enabled listener tests |
| layer order | `seal_server_router` | bridge, handler, 413, 503, panic tests |
| breaking replacement | public API baseline | engine public-api check |

Tracker linkage is exactly `#2034 -> #2035 -> {#2037, #2038, #2036}`.
