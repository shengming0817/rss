# Plan

Epic #2034 is split at observable lifecycle boundaries:

1. #2035 establishes W3C ingress continuity and the safe HTTP SERVER span funnel.
2. After #2035, #2037, #2038, and #2036 are independently unblocked.

Each PBI owns its implementation, tests, and contract updates. Cross-PBI runtime configuration or
durable metadata is out of scope unless its tracker item explicitly adds it.
