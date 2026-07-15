# LocalTx Proof Report

Static inventory status: **failed** · Active LocalTx contracts: **1** · Findings: **1**

Evidence scope: `staticInventory`. This artifact does not claim real-backend execution or promtool validation.

## Operations

- Validation: `referenceOnly`; included in report status: `false`
- Metrics: `localtx_retry_attempts_total`, `localtx_final_total`, `localtx_attempts`
- Actionable alerts: `LocalTxCommitUnknown`, `LocalTxRollbackFailed`
- Retry pressure: `diagnosticOnly` via `localtx_retry_attempts_total`
- Rules: `docs/ops/localtx-alerts.rules.yaml`
- Runbook: `docs/runbooks/202607130312-1705-localtx-unsafe-settlement.md`

## Contracts

| Contract | Owner | Capability | Manifest | Generated | Route | Test | Backend profiles | Journey |
|---|---|---|---|---|---|---|---|---|
| <code>demo.write</code> | <code>demo</code> | <code>boundary=single-domain; txModel=tenant-scoped-uow; retry=bounded-transient; commitUnknown=not-retryable</code> | <code>complete: contracts/http/demo/v1/write/contract.toml</code> | <code>complete: generated/src/http/demo&#95;v1.rs</code> | <code>missing</code> | <code>complete: crates/demo/src/lib.rs</code> | <code>demo-pg / postgres: providerStatus=valid; status=complete; sources=&#91;adapters/demo-pg/tests/localtx.rs&#93;; required=&#91;commit&#93;, observed=&#91;commit=1&#93;, missing=&#91;&#93;</code> | <code>spec=journeys/demo-localtx-journey.toml; fixture=fixtures/demo-localtx.toml; runner=journeys/tests/demo&#95;journey.rs; scenarios=&#91;happy&#93;</code> |

## Findings

| Rule | Subject | Detail |
|---|---|---|
| <code>MissingRouteBinding</code> | <code>contracts/http/demo/v1/write/contract.toml</code> | <code>route &#124; missing<br>synthetic</code> |
