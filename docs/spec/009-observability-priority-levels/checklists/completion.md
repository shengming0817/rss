# Completion checklist

- [x] Sixteen Spec 009 files are present.
- [x] Contract JSON and YAML parse.
- [x] Breaking tracewire API baseline is regenerated.
- [x] eventexec uses the replacement API directly.
- [x] HTTP SERVER semantics and continuity tests pass.
- [x] Synthetic 413, 503, and panic 500 settle the SERVER span.
- [x] HTTP/HTTPS labels are minted by the actual adapter-private transport make-service rather than assembly or request data.
- [x] Empty, single/multi-frame, last-frame, error, request/body Drop, timeout, and panic paths settle RED exactly once.
- [x] Concurrent active requests return through `0 -> 1 -> 2 -> 1 -> 0` with identical begin/end labels.
- [x] Health, unmatched routes, malicious paths, and free-form body errors satisfy the zero-leak contract.
- [x] Governance text names httpserve as a tracewire consumer.
- [x] Old Spec 008 priority-level path has no current references.
- [x] Outbound CLIENT span is the exact parent of the peer SERVER span.
- [x] Caller-authored transport headers and the legacy trace capture API are removed.
- [x] Redirect/retry are disabled and settlement/privacy conformance tests pass.
