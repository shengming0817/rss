# LocalTx Adoption Checklist

This override is a planning entry point. Correctness adoption is always applicable; GA maturity
work is conditional. The manifest/codegen/typed route carriers are Hard, while cross-file backend
carriers are Medium. Completing a box does not replace those enforcement carriers.

## Correctness adoption

- [ ] [LOCALTX-CONTRACT] Declare `consistencyLevel = "LocalTx"` and the complete typed `[capabilities.localTx]` block in the canonical contract manifest.
- [ ] [LOCALTX-CODEGEN] Run the current owner crate's generated-output tests and confirm the contract is derived into `generated::http::LOCAL_TX_SPECS`.
- [ ] [LOCALTX-ROUTE-TEST] Bind a production handler whose first extractor is `ContractMarker<RouteMarker>` and place exactly one absolute `::vocab::HttpRouteBinding<::generated::http::<route>::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::<route>::ROUTE` in a real owner test.
- [ ] [LOCALTX-BACKEND] Enroll one canonical `LOCALTX_BACKEND_PROFILE_` per provider + fixture and close every txModel-required probe without cross-fixture aggregation.
- [ ] [LOCALTX-DIAGNOSIS] Close minimum T1/T2 transaction accounting and typed diagnostic metrics/probes.

## GA maturity work (conditional)

- Authorization: `<exact accepted GA-hardening trigger or bounded pre-GA exception; otherwise N/A（未授权）>`
- `[LOCALTX-OPERATIONS]`: `<authorized minimum SLI/fixed-environment capacity scope backed by production code, manifests, SQL, and typed gates; otherwise N/A（未授权）>`
- `[LOCALTX-RUNBOOK]`: `<necessary operator behavior explicitly authorized by the trigger/exception and enforced by production or typed-gate evidence; otherwise N/A（未授权）>`

When authorization is `N/A（未授权）`, keep both maturity rows as `N/A（未授权）` and do not generate
an issue, task, implementation step, or acceptance requirement from them. Metric presence, an existing
operations carrier, or this checklist is not authorization.
