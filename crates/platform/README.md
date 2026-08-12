# rss-platform

`rss-platform` is the provider-free asynchronous application waist for RSS. Applications author
typed `Contract` markers and async `Handler` implementations; the host supplies a read-only
`HostView`, while authenticated request values arrive as `rss-request-context` views.

The crate deliberately contains no JWT/JWKS verification, provider catalog, process lifecycle,
runtime plan, cancellation authority, or inventory publisher. Those remain owned by official
integrations, RuntimeExec, and the composition root.
