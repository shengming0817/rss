# Traceability

| Requirement | Code carrier | Test carrier |
|---|---|---|
| remote parent/state | `tracewire::restore_remote_parent` | tracewire in-memory exporter |
| safe SERVER/RED fields | adapter-private `RequestObservation` owner and closed metadata | matched/unmatched/privacy corpus |
| mandatory policy | sealed non-optional `ServerObservationPolicy` field | Health/enabled listener tests |
| trusted scheme | `httpd`-private emitter created by real bind branches; core emits none | forged-wrapper negative proof + HTTP/HTTPS transport metric tests |
| exactly-once body lifecycle | `RequestObservation -> ResponseObservation -> ObservedBody` | EOS/error/cancel/drop/concurrency tests |
| layer order | `TransportService` + `seal_server_router` metadata seam | bridge, handler, body-poll, 413, 503, panic tests |
| breaking replacement | public API baseline | engine public-api check |
| outbound context authority | headerless request + sealed `W3cTraceContext` | API/residue checks |
| single HTTP attempt funnel | private `ObservedHttpClient` | redirect/retry loopback tests |
| CLIENT→SERVER continuity | current-span capture order | dual-ended in-memory exporter T2 |
| closed settlement/privacy | private terminal enum and safe observation | outcome/privacy corpus |

Tracker linkage is exactly `#2034 -> #2035 -> {#2037, #2038, #2036}`.
