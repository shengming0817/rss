# Spec 009 — Observability scope

## Purpose

Define the minimum request-observation contracts delivered by Epic #2034 without prescribing an
operations platform. The tracker is authoritative for delivery state; this directory records the
four-PBI dependency graph and stable wire/privacy contracts.

## Delivery graph

| PBI | Scope | Dependency |
|---|---|---|
| #2035 | Inbound W3C context and HTTP SERVER span | Root |
| #2037 | HTTP response-body RED settlement | blocked by #2035 |
| #2038 | JSON resource observation | blocked by #2035 |
| #2036 | Outbound HTTP CLIENT span | blocked by #2035 |

Only these four PBIs belong to Epic #2034. The three child PBIs may proceed independently after
#2035 establishes the shared inbound span.

## #2035 acceptance

- Restore a single valid `traceparent` and ordered `tracestate` fields before authentication.
- Emit one SERVER span for every enabled listener request, including synthetic 413/503/500 paths.
- Use a closed method value and matched route template; never observe raw URI, query, authority,
  credentials, body, tenant, principal, or free-form error text.
- Health listeners emit no request span.
- Malformed diagnostic headers fail open and never affect authentication or tenancy.

Response-body completion is intentionally owned by #2037.
