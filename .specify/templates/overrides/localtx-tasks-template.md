# LocalTx Adoption Checklist

This override is a planning entry point. The manifest/codegen/typed route carriers are Hard;
cross-file backend, journey, and operations carriers are Medium. Completing a box does not
replace those enforcement carriers.

- [ ] [LOCALTX-CONTRACT] Declare `consistencyLevel = "LocalTx"` and the complete typed `[capabilities.localTx]` block in the canonical contract manifest.
- [ ] [LOCALTX-CODEGEN] Run `cargo xtask codegen --check` and confirm the contract is derived into `generated::http::LOCAL_TX_SPECS`.
- [ ] [LOCALTX-ROUTE-TEST] Bind a production handler whose first extractor is `ContractMarker<RouteMarker>` and place exactly one absolute `::vocab::HttpRouteBinding<::generated::http::<route>::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::<route>::ROUTE` in a real owner test.
- [ ] [LOCALTX-BACKEND] Enroll one canonical `LOCALTX_BACKEND_PROFILE_` per provider + fixture and close every txModel-required probe without cross-fixture aggregation.
- [ ] [LOCALTX-JOURNEY] Add the exact active entry to `journeys/status-board.toml`; its runner Cargo target keeps `required-features = ["integration"]`.
- [ ] [LOCALTX-OPERATIONS] Consume `localtx_retry_attempts_total`, `localtx_final_total`, `localtx_attempts`, and diagnostic-only `localtx_deadline_exceeded_total`; keep actionable settlement alerts in `docs/ops/localtx-alerts.rules.yaml`.
- [ ] [LOCALTX-RUNBOOK] Generate static evidence with `cargo xtask localtx report --format json` and `cargo xtask localtx report --format markdown`; link `docs/runbooks/202607130312-1705-localtx-unsafe-settlement.md` for unsafe settlement response.
