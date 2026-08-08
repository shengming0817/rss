# Verification quickstart

```bash
./hack/cargo.sh test -p tracewire
./hack/cargo.sh test -p httpserve --lib
./hack/cargo.sh test -p eventexec --lib build_consume_span_
./hack/cargo.sh xtask public-api --layer engine --check
```

Inspect an enabled listener request for one `http.server.request` span. A matched request uses
`METHOD route-template`; an unmatched request uses only the closed method token. Health requests
must not emit that span.
