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

## #2037 acceptance

- The adapter-private observation owner mints trusted `http`/`https` inside the actual plaintext/mTLS
  bind branch. The exported per-request core emits no transport evidence, so an external wrapper
  cannot forge RSS's official scheme; assembly, request URI, extensions, and forwarding headers
  cannot select it.
- One move-only owner holds the SERVER span, monotonic timer, and active-request handle until response
  body EOS, final-frame end, body error, timeout, panic, or cancellation.
- Each request records exactly one duration sample and one matching active decrement. Headers do not
  settle a streaming body, and post-settlement Drop cannot emit twice.
- Duration labels use only closed values and an optional `MatchedPath`; active labels reuse the exact
  begin-time method, scheme, and listener set. Health emits neither span nor RED metrics.
- Timeout and recovered panic are typed response causes; ordinary 5xx responses retain ordinary
  status-derived error semantics. Raw request surfaces and free-form errors never enter attributes.

## #2036 acceptance

- A private outbound funnel owns the raw client, disables redirect/retry, and emits exactly one
  CLIENT span for each real network attempt. In-process dispatch emits no CLIENT span.
- The CLIENT span becomes current before the adapter captures and injects W3C context, so the peer
  SERVER span is its exact child and `tracestate` remains continuous. Valid unsampled context propagates.
- `HttpContractRequest` has no header slot. W3C context and canonical correlation are ambient-only;
  request id, credentials, tenant and arbitrary caller headers cannot be expressed.
- URL, endpoint/address, path/query, header/body values, identity data and raw errors are forbidden
  from the observation surface.
- Response-too-large, timeout, invalid-response and dispatch failures use distinct closed outcomes;
  complete 4xx/5xx responses remain transport results while setting OTel error status.
