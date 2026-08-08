# Data model

## Inbound context

`traceparent` is accepted only when exactly one ASCII field is present and it is valid W3C data no
longer than 512 bytes. Version 00 uses exactly four fields; future non-`ff` versions follow W3C's
forward-compatible extension rule. Repeated `tracestate` fields are joined in wire order. Invalid
or oversized state is discarded without discarding a valid parent.

## HTTP server observation

The observation boundary contains only:

- closed HTTP method (`_OTHER` for an extension method);
- optional axum matched route template;
- closed protocol version;
- request and correlation identifiers;
- response status code.

It cannot contain the request, URI, header map, body, authority, authentication evidence, tenant,
principal, or arbitrary error text.
