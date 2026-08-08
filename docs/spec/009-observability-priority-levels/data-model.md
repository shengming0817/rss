# Data model

## Inbound context

`traceparent` is accepted only when exactly one ASCII field is present and it is valid W3C data no
longer than 512 bytes. Version 00 uses exactly four fields; future non-`ff` versions follow W3C's
forward-compatible extension rule. Repeated `tracestate` fields are joined in wire order. Invalid
or oversized state is discarded without discarding a valid parent.

## HTTP server observation

The observation boundary contains only:

- closed HTTP method (`QUERY` is well-known; `_OTHER` for an extension method);
- optional axum matched route template;
- closed protocol version;
- trusted transport scheme minted only by the actual adapter-private plaintext/mTLS observation owner;
- closed listener, terminal outcome, status class, and error type;
- response status code.

It cannot contain the request, URI, header map, body, authority, authentication evidence, tenant,
principal, or arbitrary error text.

`RequestObservation -> ResponseObservation -> ObservedBody` lives only in private `httpd` code and
is a non-cloneable ownership chain. `httpserve` returns only opaque matched-route and response-cause
metadata with crate-private constructors. Single settlement consumes the monotonic timer and active
handle, so EOS, error, timeout, panic, and Drop cannot double-record; the handle's method, scheme,
and listener labels are reused unchanged for decrement.

## HTTP client observation

The private observation value contains only a closed HTTP method and one typed `ContractBinding`.
It derives the method-only span name, domain and contract id; status and closed settlement values are
recorded after the attempt. It has no field capable of holding an endpoint, URL/path/query, headers,
body, address/port, credential, tenant, principal, or raw error.

`W3cTraceContext` has private fields and one production mint function, `capture_current`. The contract
request has no header field, leaving the current CLIENT span as the only W3C header authority.
