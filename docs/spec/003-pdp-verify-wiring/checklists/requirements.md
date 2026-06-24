# Specification Quality Checklist: PDP 验签接线（#1109 剩余 W）

**Purpose**: Validate specification completeness and quality before proceeding to planning
**Created**: 2026-06-24
**Feature**: [spec.md](../spec.md)

## Content Quality

- [~] No implementation details (languages, frameworks, APIs)（部分满足：本 feature 为内部框架安全规格，保留已冻接缝名词（diport::Pdp / VerifiedClaims / from_verified_jwt / OidcProvider）+ 供应链约束（RustCrypto / 禁 ring·rsa）作追踪锚；纯用户侧行为仍以验收场景表达）
- [x] Focused on user value and business needs（运维真验签 + 域作者信任边界）
- [x] Written for non-technical stakeholders（认证「有效放行/无效拒」语义可读）
- [x] All mandatory sections completed

> 说明：本 feature 是框架安全能力（验签接线），「用户」= 平台运维/部署者 + 域 crate 作者。spec 保留已冻接缝名词与供应链约束作追踪锚，但需求/验收以行为与可观测结果表达，具体 crypto 库/JWKS 栈/crate 落位留 plan/research。

## Requirement Completeness

- [x] No [NEEDS CLARIFICATION] markers remain（三决策已经 AskUserQuestion：范围=剩余 W / 含 JWKS / 全流程）
- [x] Requirements are testable and unambiguous
- [x] Success criteria are measurable
- [x] Success criteria are technology-agnostic (no implementation details)（SC 以「验签正确/拒绝路径覆盖/无禁用 crate/同批门」表达）
- [x] All acceptance scenarios are defined（含拒绝路径 + alg confusion + JWKS 轮转）
- [x] Edge cases are identified（验签空窗/alg=none·confusion/service隔离/PdpError 泄漏/层序/JWKS 不可达）
- [x] Scope is clearly bounded（类型层已合并不重做；本批 = adapter+httpserve+组合根+e2e）
- [x] Dependencies and assumptions identified（PR 208/211 前置；ADR-006；供应链约束；分层禁 httpserve→authn）

## Feature Readiness

- [x] All functional requirements have clear acceptance criteria（FR-001..014 ↔ SC-001..008 ↔ US1-4 验收）
- [x] User scenarios cover primary flows（verifier / 放行接缝 / 生产接线e2e / JWKS）
- [x] Feature meets measurable outcomes defined in Success Criteria
- [x] No implementation details leak into specification（除追踪锚）

## Notes

- 4 user story（US1 verifier / US2 httpserve 放行 / US3 生产接线+e2e / US4 JWKS），P1=认证链打通三件，P2=JWKS。每个独立可测。
- FR-001..014 含安全同批门（FR-010）、不回归（FR-012）、拆解约束（FR-013）、治理≥Medium（FR-014）。
- **关键澄清**：#1109 body 把类型层描述成待落地，实际已由 PR 208/211 合并；本 feature 仅剩余 W 接线，已在背景 + Assumptions + 1109 评论坐实。
- 唯一 open risk：JWKS HTTP/TLS license-clean 栈选型（research.md R3），属 PR-A2 实施裁定，不阻塞 spec / 认证链打通（静态 key 先行）；**裸 plain-HTTP 已否决**（评审 F2），不可得则退静态 key。
- **内置 review 修订（codex round 0，6 findings 全修）**：F1 信任根守卫由 Soft/defer **升 Medium 入 PR-C T004.6**（#1199 折入 #1198 关闭）；F2 禁明文 JWKS；F3 验收降为 `Authenticated`(facet) 放行（完整 Principal 传播属 W）；F4 feature.json→真实路径；F5 label type-enhancement；F6 补 `oidc_jwks_ready` probe。
