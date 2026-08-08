# Requirements checklist

- [x] Epic #2034 has exactly four PBIs in this spec.
- [x] #2035 is the sole dependency root.
- [x] W3C parent/state handling is fail open.
- [x] SERVER span starts outside budget, body-limit, authentication, recovery, and handler work.
- [x] Health policy remains disabled.
- [x] Span naming is low-cardinality and route-template based.
- [x] The observation type cannot retain sensitive request surfaces.
- [x] Body lifecycle remains owned by #2037.
