# Tasks: Runtime Deployment Executable Plan

**Status**: Planned | **Graph**: 31 nodes, 52 edges, acyclic, depth 20

## 当前事实

All #1779–#1809 PBIs are open. The tracker bodies own scope, acceptance, budget, and focused validation; the latest `pm:epic-wave` comment on #1778 owns dynamic scheduling. This matrix freezes dependencies and carrier intent without claiming implementation.

## 目标能力

| Task | Owner | Blocked by | Budget | Focused V&V | Planned carrier |
|---|---:|---|---:|---|---|
| RTD-001 | #1779 | — | No cap | `cargo xtask runtime-deployment-spec --selftest --against origin/develop && cargo xtask verify --fast` | Medium — typed fast-aggregate artifact validator |
| RTD-002 | #1780 | #1779 | 1300–1800 | `cargo test -p assembly-schema && cargo xtask verify --fast` | Hard — closed lock type/RFC-8785 schema/codegen/golden |
| RTD-003 | #1781 | #1780 | 1200–1800 | `cargo test -p xtask assembly_lock && cargo xtask assembly lock check && cargo xtask verify --fast` | Medium — deterministic generate/check drift |
| RTD-004 | #1782 | #1781 | 1200–1700 | `cargo test -p runtime runtime_config && cargo xtask runtime-baseline verify && cargo xtask verify --fast` | Hard — one snapshot and required typed input |
| RTD-005 | #1783 | #1782 | 1500–1950 | `cargo test -p runtime routes listeners oidc && cargo xtask runtime-baseline verify && cargo xtask verify --fast` | Hard — typed snapshot consumers |
| RTD-006A | #1784 | #1782 | 850–1200 | `cargo test -p runtime infra && cargo test -p postgres -p redis && cargo xtask verify --fast` | Hard — typed PostgreSQL/Redis config |
| RTD-006B | #1785 | #1782 | 900–1300 | `cargo test -p runtime infra && cargo test -p vault -p s3 && cargo xtask verify --fast` | Hard — typed Vault/S3 config |
| RTD-007 | #1786 | #1782 | 1750–2000 | `cargo test -p runtime event_transport distributed_runtime && cargo test -p bootstrap domaintransport eventtransport && cargo xtask verify --fast` | Hard — typed serving transport config |
| RTD-008 | #1787 | #1783, #1784, #1785, #1786 | 900–1300 | `cargo test -p xtask runtime_env_guard && cargo xtask runtime-env guard && cargo xtask verify --fast` | Medium — AST guard with synthetic red/anti-vacuity |
| RTD-009 | #1788 | #1781, #1787 | 1400–1900 | `cargo test -p runtime runtime_plan && cargo xtask assembly validate && cargo xtask verify --fast` | Hard — closed plan types/private construction/fingerprint golden |
| RTD-010 | #1789 | #1788 | 1200–1700 | `cargo test -p runtime runtime_phase && cargo test -p runtime launch_plan && cargo xtask runtime-baseline verify` | Hard — typestate transitions |
| RTD-011 | #1790 | #1789 | 1400–1900 | `cargo test -p runtime listener_plan auth_plan && cargo xtask runtime-baseline verify && cargo xtask verify --fast` | Hard — plan-owned listener finalization |
| RTD-012 | #1791 | #1788 | 1500–2000 | `cargo test -p xtask assembly_provider_codegen && cargo xtask assembly generate-providers --check && cargo xtask verify --fast` | Hard — generated provider catalog |
| RTD-013 | #1792 | #1789, #1791 | 1500–2000 | `cargo test -p runtime provider_plan provider_output && cargo xtask assembly validate && cargo xtask runtime-baseline verify` | Medium — completeness/output bijection |
| RTD-014 | #1793 | #1790, #1792 | 1600–2000 | `cargo test -p runtime domain_placement && cargo test -p bootstrap domaintransport && cargo test -p httpd domain_transport && cargo xtask verify --fast` | Hard — typed domain/placement execution |
| RTD-015 | #1794 | #1790, #1792, #1793 | 1500–2000 | `cargo test -p runtime && cargo xtask runtime-baseline verify && cargo xtask runtime-root guard && cargo xtask verify --fast` | Medium — live-root ratchet |
| RTD-016 | #1795 | #1794 | 1600–2000 | `cargo test -p runtimeexec && cargo test -p runtime launch_plan && cargo xtask layer-deps && cargo xtask verify --fast` | Hard — typed launch dependency graph |
| RTD-017 | #1796 | #1795 | 1400–1900 | `cargo test -p settingsonly && cargo test -p journeys settingsonly_runtime && cargo build -p settingsonly --bin settingsonly-server && cargo xtask assembly validate` | Hard+Medium — typed runtimeexec ownership and binary/image/config/probe/journey closure |
| RTD-018 | #1797 | #1795 | 1600–2000 | `cargo test -p identityaudit && cargo test -p journeys identityaudit_runtime && cargo build -p identityaudit --bin identityaudit-server && cargo xtask assembly validate` | Hard+Medium — typed runtimeexec ownership and binary/image/config/probe/journey closure |
| RTD-019 | #1798 | #1796, #1797 | 1100–1600 | `cargo test -p xtask assembly_artifacts && cargo xtask assembly artifacts check && cargo xtask verify --fast` | Medium — artifact matrix bijection |
| RTD-020 | #1799 | #1794 | 2000–2400 | `cargo test -p postgres revocation --features backend && cargo test -p testkit revocation && cargo xtask schema-rls && cargo xtask verify --fast` | Hard — persistent revocation/database constraints |
| RTD-021 | #1800 | #1794 | 500–900 | `cargo test -p runtime vault && cargo test -p journeys security_provider_closeout && cargo xtask assembly validate && cargo xtask verify --fast` | Hard — typed Vault allowlist |
| RTD-022 | #1801 | #1798, #1799, #1800 | 1800–2400 | `cargo xtask assembly validate && cargo test -p journeys production_runtime two_replica_runtime && RSS_SMOKE_MODE=release ./deploy/smoke.sh && cargo xtask verify --fast` | Hard — production manifest constraints |
| RTD-023 | #1802 | #1781, #1794, #1798 | 1200–1700 | `cargo test -p assembly-schema deployment_plan && cargo test -p xtask deployment_plan && cargo xtask deployment plan check && cargo xtask verify --fast` | Hard — RuntimePlan-bound DeploymentPlan schema-to-render golden |
| RTD-024 | #1803 | #1802 | 1700–2000 | `helm lint deploy/helm/rss && helm template rss deploy/helm/rss -f deploy/helm/rss/values/runtime.yaml && cargo xtask deployment plan check` | Medium — Helm render/check drift |
| RTD-025 | #1804 | #1803 | 2200–3000 | `helm lint deploy/helm/rss && cargo xtask deployment policy check && kubeconform -strict deploy/rendered/*.yaml && cargo xtask deployment plan check` | Medium — deployment security policy |
| RTD-026 | #1805 | #1801, #1804 | 1500–2000 | `cargo test -p xtask deployment_policy deployment_kind && cargo xtask deployment kind-test --assembly runtime && cargo xtask verify --fast` | Medium — policy/kind acceptance |
| RTD-027 | #1806 | #1794, #1798, #1802 | 1400–1900 | `cargo test -p runtimeexec inventory && cargo test -p httpserve inventory_auth && cargo test -p journeys runtime_inventory && cargo xtask verify --fast` | Hard+Medium — three-fingerprint DTO/codegen and typed authorization surface |
| RTD-028 | #1807 | #1798, #1805 | 1600–2000 | `cargo xtask release evidence check && cosign verify --certificate-identity-regexp ... && syft attest/verify in release fixture && cargo xtask verify --fast` | Medium — three-fingerprint OCI evidence verifier |
| RTD-029 | #1808 | #1801, #1805, #1806 | 700–1100 | `markdown/link/command lint && tabletop review against kind/two-replica evidence && cargo xtask docs verify` | Medium — executable operations acceptance |
| RTD-030 | #1809 | #1801, #1805, #1807, #1808 | 900–1400 | `cargo test -p xtask ci_gate && bash .github/scripts/ci-evidence.selftest.sh && cargo xtask ci-plan selftest && cargo xtask verify --fast` | Medium — same-head three-fingerprint local aggregate gate |

## 缺口与 owner

Program order remains S01 #1779; S02 #1780; S03 #1781; S04 #1782; S05 #1783–#1786; S06 #1787; S07 #1788; S08 #1789/#1791; S09 #1790/#1792; S10 #1793; S11 #1794; S12 #1795/#1799/#1800; S13 #1796/#1797; S14 #1798; S15 #1801/#1802; S16 #1803/#1806; S17 #1804; S18 #1805; S19 #1807/#1808; S20 #1809. Recompute from the latest epic comment when tracker dependencies change.

File mutexes remain unchanged: S05 serializes the shared runtime config/root; S09 serializes runtime composition; S12 serializes runtimeexec/security root work; S13 serializes the shared Dockerfile. Safe groups remain S08, S15, S16, and S19, with no more than two implementation workflows active.

The strict project Wave 1–4 window contains #1779, #1780, #1781, and #1782 respectively; #1783–#1809 remain beyond that bounded window. Source program increments do not override dependency order.

Each owner must land its listed carrier and red/green evidence before its target can be described as current production closure. `fixtures/task-baseline.json` is the exact machine mirror of all rows and 52 edges; tracker sequence drift fails #1779. RTD-006A and RTD-006B remain separate implementation rows and budgets.
