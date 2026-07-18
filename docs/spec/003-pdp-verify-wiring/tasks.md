# Tasks: PDP 验签接线（#1109 剩余 W）

**Input**: specs/003-pdp-verify-wiring/{spec,plan,research,data-model}.md + contracts/
**Tracking**: Azure Boards #1109 · Epic #991（W 宽扇出）· ADR-006
**粒度**: 任务 = PR。正好 4 个 PR（T001–T004），每个 ≤2000 行净增删（例外书面理由）。

## 约定

- `[P]` = 该 PR 与**同 wave** 其他 PR 无文件交叉、无相互依赖、安全门允许，可并行开发。
- 每 PR 走 TDD：先写测试（FAIL）→ 在冻结接缝内兑现 body → 治理/lint 闭环 → clippy/fmt 0 warning。
- 等级：本 feature 不动 wire contract / generated → 全部 L1 / 无等级（验签为纯计算 + 进程内接线）。
- 同文件归同 PR；T001 落 `StaticKeySource`（具体）+ 构造器签名留稳，T003（#1197）引入闭合 `enum KeySource { Static, Jwks }` 统一新增 `JwksKeySource` **不改 `OidcProvider::new` 签名**，保 T003∥T004 解耦。
- **安全同批门（ADR-006 §5，最高约束）**：仅 T004 启用生产认证，且 blocked-by T001（真 verifier）。
  - **T002 单独 merge 安全充要条件**：进程中无代码向 request 注入 `httpserve::Authenticated`（该类型 T002 首次定义，注入唯一在 T004 `auth_bridge.rs`）→ Require 路由仍 401。T004.1 e2e 须含「T001/T002 单独 merge 态 Require 仍 401」回归用例。
  - **stub 防线（Medium，PR-C 内交付，不 defer）**：`deny.toml` oidc wrapper 拦「依赖测试 stub adapter crate」（Medium）；但 bins 在 dylint 组合根白名单可合法 `impl Pdp` → bins 生产内联 always-allow impl 不被 deny/dylint 拦。故 **T004.6 必须**补 governance 守卫（`cargo xtask`/dylint）扫 bins 生产 `src/` 的 `impl diport::Pdp`，仅放行 `#[cfg(test)]`/dev-dep（评审 F1：信任根锁不接受 Soft、不 defer）。

---

## Wave 1 — 认证链两端（critical path）

### T001 [P] [US1] PR-A1 · oidc adapter impl `diport::Pdp`（ES256+HS256 + 静态 KeySource）
**触及**: `adapters/oidc/src/{lib,verify,claims}.rs` · `adapters/oidc/Cargo.toml` · 根 `Cargo.toml`（p256/hmac/sha2 入 `[workspace.dependencies]`）· `docs/references/framework-comparison.md`（新增 authn/jwt 对标行）· **等级**: 无（adapter 内部，不动 wire contract）· **blocked-by**: 无（diport::Pdp 已合并，立即可开工）· **并行**: 与 T002 并行（adapters/oidc vs crates/httpserve 零交叉）。

- [ ] T001.1 [US1] 先写表驱动测试（rstest + 注入 FixedClock）：合法 ES256/HS256→Ok(VerifiedClaims) 断言 subject/tenant/kind；坏签名/坏 MAC/段数≠3/`alg=none`/RS256/未知/空 subject→InvalidSignature；exp 过期/nbf 未到→Expired；kid 无匹配/iss-aud 不符/alg-key 混淆→Untrusted；RFC7515 known-answer 向量；anti-vacuity（先证正确签名通过）；Debug 脱敏（无 token/key 字节）—— 全 FAIL
- [ ] T001.2 [US1] 根 `Cargo.toml` 加 `p256`(feature ecdsa)/`hmac`/`sha2` 到 `[workspace.dependencies]`；`adapters/oidc/Cargo.toml` opt-in（+ base64/serde/serde_json）；`cargo deny check` 绿（无 ring/rsa）
- [ ] T001.3 [US1] `claims.rs`：claims DTO（exp/nbf/iat/iss/aud/sub/tenant/kind）+ `PdpError` fail-closed 映射表（data-model §映射）
- [ ] T001.4 [US1] `verify.rs`：三段解析 → `SupportedAlg` 白名单选验签器（alg=none/RS256/未知拒）→ 签名校验（ES256 p256 / HS256 常数时间，复用 `primitives::crypto`）→ exp/nbf（注入 Clock + leeway）→ iss/aud → 映射 `VerifiedClaims`；alg-key 一致性闸
- [ ] T001.5 [US1] `lib.rs`：`OidcProvider`（key_set/service_key_set HS256-only/clock 必填位参/issuers/audience/leeway）+ `StaticKeySource`（构造期解析，签名跨 T003 稳定）+ `impl Pdp`（native AFIT，service_token 路径隔离）+ 保留 `impl ManagedResource`（去 todo!()）
- [ ] T001.6 [US1] oidc smoke test 追加 `assert_pdp(PhantomData::<OidcProvider>)`（维持 ADAPTER-PORT-FREEZE-04：去掉 impl Pdp 即编译失败，anti-vacuity）；framework-comparison.md 新增 authn/jwt 验签行（WebFetch 实拉 RustCrypto/JWT + rust-spiffe 校准 `ref:`）；覆盖率 ≥80%；`nextest`/`clippy -D warnings`/`fmt`/`layer-deps`/`dylint`（impl Pdp 合法）绿

### T002 [P] [US2] PR-B · httpserve `Authenticated` 证据 + enforce 放行（fail-closed 默认）
**触及**: `crates/httpserve/src/{auth,lib}.rs`（**无新 path dep**）· `crates/httpserve/tests/runtime.rs` · **等级**: L1 · **blocked-by**: 无 · **并行**: 与 T001 并行。

- [ ] T002.1 [US2] 先写测试（`axum::http` + `tower::ServiceExt::oneshot`）：注入 `scheme` 匹配的 `Authenticated`→Require 路由 200（**新正向用例，当前恒 401 → FAIL**）；不注入→401 / **scheme 不匹配（Jwt 证据 vs `Require(Mtls)`）→401** / **`Anonymous` 证据→401** / `opt_out=Public`→200 / 无 AuthPlan→403（既有用例复用做不回归基线）
- [ ] T002.2 [US2] `auth.rs`：定义 `Authenticated` extension（基础级、脱敏标量 `scheme: RequiredScheme` + `principal_kind`，零 authn 依赖，私有字段 + `new` funnel）；`reject_if_needed` 改为读 request extension 的 `Authenticated`→ 非 `Anonymous` 且 `scheme()` exact-match `Require(required)` 则放行、否则 fail-closed 401
- [ ] T002.3 [US2] `lib.rs`：导出 `Authenticated`；`finalize_auth` 文档更新（层序：验签桥由组合根外层装配；**签名不改**，httpserve Cargo.toml 不新增 path dep）
- [ ] T002.4 [US2] 覆盖率 ≥80%；`nextest`/`clippy -D warnings`/`fmt`/`layer-deps`（httpserve 无新 path dep）绿

---

## Wave 2 — JWKS + 生产接线（blocked-by W1）

### T003 [P] [US4] PR-A2 · oidc JWKS key 解析 + 缓存 + 轮转（本地文件源 + 外部 agent 刷新，#1197）
**触及**: `adapters/oidc/src/jwks.rs`（新）+ `config.rs`（`KeySet`/`enum KeySource`）+ `jws.rs`（kid 解析）+ `verify.rs`（kid 候选）+ `lib.rs`（接 `JwksKeySource`，**不改构造器签名**）· `adapters/oidc/Cargo.toml`（tokio/tokio-util，**零 HTTP/TLS**）· 根 `Cargo.toml` · **等级**: 无 · **blocked-by**: T001（共用 `adapters/oidc`，W1 后无 live 冲突；引入 `KeySet`/`enum KeySource`）· **并行**: 与 T004 并行（adapters/oidc vs bins 零交叉）。

> **决断（#1197，见 research.md R3）**：无 license-clean 成熟 rustls TLS provider + in-app HTTPS 拉 JWKS 是零信任生产规避的少数派 → 采纳 R3 次选**本地文件源 + 外部 agent 刷新**，in-app 零 HTTP/TLS provider。in-app HTTPS 直连外部标准 IdP = follow-up。

- [x] T003.1 [US4] 先写测试（fake JWKS **文件源**，dev-only）：kid=k1 token 验签通过；轮转（重写文件 + reload）后 k2 通过、k1 移除→旧 token fail-closed；源不可读/空/畸形→构造期 fail-fast 拒；刷新失败保留 last-good + 对应 profile readiness=false（degraded）；**无 in-app 网络 transport**（决断改文件源后，「裸 plain-HTTP 端点拒」转化为「零 in-app HTTP/TLS」，deny 守）—— ✅ 全绿
- [x] T003.2 [US4] research.md R3 决断 HTTP/TLS 栈：实测穷举 rustls provider 全生态（ring/aws-lc=OpenSSL 派生禁、rustls-rustcrypto=alpha、graviola=未审计、symcrypt=非纯 Rust）+ 零信任框架 key 分发范式 → 采纳本地文件源（次选，非兜底）；`cargo deny check` 绿（零新增 crypto/TLS provider）
- [x] T003.2b [US4] 最终选型结论 + 部署约束回写 research.md R3 决断段 + spec.md FR-005/US4（本地文件源；写入方负责 TLS + 完整性；路径经文件权限/Secret RBAC 保护；应用只读 + fail-closed）
- [x] T003.3 [US4] `jwks.rs`：`JwksKeySource`（本地文件源，经**闭合 `enum KeySource`** 接入，非新 trait——规避 trait_variant 白名单）：读 JWKS 文档（RFC 7517/7518，EC P-256→ES256 / oct→HS256）+ 按 kid 缓存 + 后台 poll 轮转 + fail-closed；`jws.rs` 加 kid 解析、`verify.rs` 按 kid 选候选；`lib.rs` 接入（`OidcProvider::new` 签名不变）
- [x] T003.4 [US4] `OidcProvider::shutdown` 级联 `KeySource::shutdown` → `JwksKeySource` 停后台 poll 任务 + await 收敛（`ManagedResource` 真实关闭，对齐 ShutdownStack）；覆盖率 ≥80%；`nextest`/`clippy`/`fmt`/`deny`/`layer-deps`/`xtask verify --fast` 绿
- [ ] T003.5 [US4] profile readiness probes `rss_access_token_jwks_ready` / `federated_access_token_jwks_ready`（依赖可用性 probe，带 `_ready` 后缀，遵 observability.md §Readyz Probe）：**本 adapter 切片仅暴露 `JwksKeySource::is_ready()` 状态 + 刷新失败→degraded 测试**；probe **注册点** + verbose readyz 裁剪敏感字段 + tracing/metric 失败计数（评审 F6）= 组合根接线，下放 **T004**（probe 经 Domain::init/Registry 注册）
  - **T004 接线时补**（#254 review 派生，避免本切片速增未消费字段 YAGNI）：① `consecutive_failures` 累计计数（success 清零/failure 递增）供 verbose readyz 分级告警「刚降级 vs 连续失败数小时」；② poll 任务 panic watchdog（正常运行期 task 意外死亡时 `is_ready()` 不自动转 false，需 watch handle 状态）。本切片已为刷新失败记 `error_kind` 闭值标签（运维分流）。

### T004 [US3] PR-C · 组合根注入 + verify-bridge + 埋点 + e2e（启用生产认证·安全同批）
**触及**: `bins/{server,rss}/src/{main,auth_bridge}.rs` · `bins/{server,rss}/Cargo.toml`（首次加 httpserve/authn/oidc/diport/primitives/axum/tower/tokio/config）· `bins/{server,rss}/tests/auth_e2e.rs` · **等级**: L1 · **blocked-by**: **T001（真 verifier OidcProvider:Pdp）+ T002（httpserve::Authenticated 放行接缝）** · **并行**: 与 T003 并行（bins vs adapters/oidc 零交叉）。

- [ ] T004.1 [US3] 先写 e2e 集成测试（dev-dep/feature 门控）：有效 JWT（真 OidcProvider 静态 key 验签）→200+`Authenticated`(`scheme`=Jwt + principal_kind facet) `scheme()` exact-match 注入放行（**本批不断言 handler 读完整 Principal——属 W**，评审 F3）；无 token/坏签名/过期/错 aud→401/403（拒绝路径全覆盖）；**T001/T002 单独 merge 态 Require 仍 401 回归用例**；tracing span 断言 `authz.decision`+`principal.kind`、无 subject/token 泄漏；stub Pdp 仅 `[dev-dependencies]` —— FAIL
- [ ] T004.2 [US3] `auth_bridge.rs`（**各 bin 各一份**——bins/server 与 bins/rss 是独立 crate 不共享 src；逻辑小，漂移再提取 `assemblies/authwire`）：axum 中间件 extract Authorization→`authn::verify_jwt`/`verify_service_token`(注入 `&DynPdp`)→ok **内联** `httpserve::Authenticated::new(verified_scheme, principal.kind())`（`verified_scheme: RequiredScheme` = 验签桥实际验证的方案，须与入站 `RawCredential` scheme 一致；非 `From<&Principal>` trait）注入 request、err fail-closed 401；tracing span（ok→allow+principal.kind；err→deny+PdpError 变体；无 PII）—— 落地 authn lib.rs:280 `NOTE(#1109)` 承诺
- [ ] T004.3 [US3] `main.rs`（server+rss）：从配置构造 `OidcProvider`→`Box<DynPdp>`（必填位参）；`Registry::finalize_routes`→每 listener router→`httpserve::finalize_auth(router,plan)`→**外层** `.layer(verify_bridge(pdp))`；JWKS/issuer/audience/key 配置注入
- [ ] T004.4 [US3] 安全同批门核对：`cargo build --release` 依赖图无 stub Pdp + 无禁用 crypto crate；仅 T004 启用生产认证（T001/T002/T003 单独 merge 后 Require 端点仍 401）；`Box<DynPdp>` 必填编译期守
- [ ] T004.6 [US3] **信任根 Medium 守卫（评审 F1，本 PR 必交付，不 defer）**：`cargo xtask` governance（或 dylint）扫 bins 生产 `src/` 的 `impl diport::Pdp`，仅放行 `#[cfg(test)]`/dev-dep，生产内联 always-allow impl → fail；synthetic red case + anti-vacuity（守卫非恒真）；INVARIANT 记守卫 rustdoc
- [ ] T004.5 [US3] 不回归断言（ADR-006 ①②）：VerifiedClaims 仅 Pdp mint、from_verified_* 仅收 newtype；覆盖率 ≥80%；`nextest`/`clippy -D warnings`/`fmt`/`layer-deps`（bins=组合根可依赖全部）绿

---

## 依赖图（DAG）

```
T001 (A1 verifier) ──┬──→ T003 (A2 JWKS)
T002 (B 放行接缝) ───┤
T001 ────────────────┴──→ T004 (C 组合根+e2e) ←── T002

Wave 1 [P]: T001 ∥ T002   （文件零交叉；单独 merge 均不放行端点 → 零验签空窗）
Wave 2 [P]: T003 ∥ T004   （均 blocked-by W1；adapters/oidc vs bins 零交叉）
```

**安全同批门坐实**：T004（唯一启用生产认证）blocked-by T001（真 verifier，W1 已 merged）→ T004 落地即「真 verifier + 认证挂载」同批，零验签空窗；T003 仅追加 JWKS 能力。

## Azure Boards 子 issue 映射

| Task | 子 issue | label | blocked-by |
|------|---------|-------|-----------|
| T001 | PR-A1 | area-auth, type-enhancement, pri-p1, cx-3, backlog | — |
| T002 | PR-B | area-auth, type-enhancement, pri-p1, cx-2, backlog | — |
| T003 | PR-A2 | area-auth, type-enhancement, pri-p2, cx-2, backlog | A1 |
| T004 | PR-C | area-auth, type-enhancement, pri-p1, cx-3, backlog | A1, B |

全部 `subissue-link` 到 #1109；wave/并行排序评论贴 #1109。

> **评审 F1 修订**：信任根 Medium 守卫（governance 扫 bins 生产 `impl Pdp`）由原「deferred follow-up #1199」**折入 PR-C（T004.6），不再单列 defer**；#1199 已关闭并指向 #1198。
