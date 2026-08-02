# LocalTx Adoption Checklist

This override is a planning entry point. Correctness adoption is always applicable; GA maturity
work is conditional. The manifest/codegen/typed route carriers are Hard, while cross-file backend
and journey carriers are Medium. Completing a box does not replace those enforcement carriers.

## Correctness adoption

- [ ] [LOCALTX-CONTRACT] Declare `consistencyLevel = "LocalTx"` and the complete typed `[capabilities.localTx]` block in the canonical contract manifest.
- [ ] [LOCALTX-CODEGEN] Run `cargo xtask codegen --check` and confirm the contract is derived into `generated::http::LOCAL_TX_SPECS`.
- [ ] [LOCALTX-ROUTE-TEST] Bind a production handler whose first extractor is `ContractMarker<RouteMarker>` and place exactly one absolute `::vocab::HttpRouteBinding<::generated::http::<route>::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::<route>::ROUTE` in a real owner test.
- [ ] [LOCALTX-BACKEND] Enroll one canonical `LOCALTX_BACKEND_PROFILE_` per provider + fixture and close every txModel-required probe without cross-fixture aggregation.
- [ ] [LOCALTX-JOURNEY] Add the exact active entry to `journeys/status-board.toml`; its runner Cargo target keeps `required-features = ["integration"]`.
- [ ] [LOCALTX-DIAGNOSIS] Close minimum T1/T2 transaction accounting and typed diagnostic metrics/probes; if a correctness change touches an existing operations consumer, make only the compatibility sync needed to preserve its semantics.
- [ ] [LOCALTX-STATIC-REPORT] Generate static evidence with `cargo xtask localtx report --format json` and `cargo xtask localtx report --format markdown`.

## GA maturity work (conditional)

- Authorization: `<exact accepted GA-hardening trigger or bounded pre-GA exception; otherwise N/A（未授权）>`
- `[LOCALTX-OPERATIONS]`: `<authorized minimum SLI/fixed-environment capacity scope; any new dashboard, alert, or docs/ops/*.rules.yaml carrier requires a bounded exception that authorizes it individually; otherwise N/A（未授权）>`
- `[LOCALTX-RUNBOOK]`: `<necessary runbook explicitly authorized by the trigger/exception, including any approved link to docs/runbooks/202607130312-1705-localtx-unsafe-settlement.md; otherwise N/A（未授权）>`

When authorization is `N/A（未授权）`, keep both maturity rows as `N/A（未授权）` and do not generate
an issue, task, implementation step, or acceptance requirement from them. Metric presence, an existing
operations carrier, or this checklist is not authorization.
