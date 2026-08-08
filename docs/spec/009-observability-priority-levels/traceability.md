# Traceability

| Requirement | Code carrier | Test carrier |
|---|---|---|
| remote parent/state | `tracewire::restore_remote_parent` | tracewire in-memory exporter |
| safe SERVER fields | private `HttpServerObservation` | matched/unmatched/privacy corpus |
| mandatory policy | private non-optional `TracePolicy` field | Health/enabled listener tests |
| layer order | `seal_server_router` | bridge, handler, 413, 503, panic tests |
| breaking replacement | public API baseline | engine public-api check |
| outbound context authority | headerless request + sealed `W3cTraceContext` | API/residue checks |
| single HTTP attempt funnel | private `ObservedHttpClient` | redirect/retry loopback tests |
| CLIENT→SERVER continuity | current-span capture order | dual-ended in-memory exporter T2 |
| closed settlement/privacy | private terminal enum and safe observation | outcome/privacy corpus |

Tracker linkage is exactly `#2034 -> #2035 -> {#2037, #2038, #2036}`.
