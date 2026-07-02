# rss vs gocell — 首席架构师能力缺口综合报告

> **现行·非冻结** · gocell→rss 能力缺口 backlog（2026-06-24 评估）。
> 与同目录 `gocell-*.md`（2026-06-21 **冻结**迁移映射快照）不同，本文是基于 gocell 全能力面
> 与 rss 当前规划（`docs/rules/architecture.md` 现行单源 + 现存 crate/contract/spec）的细粒度 diff，
> 用于驱动后续 ADR / feature spec 立项；现行架构单源仍以 `docs/rules/architecture.md` 为准。
>
> 方法：10 能力域 fan-out（gocell 枚举 → rss 覆盖核查 → 对抗式深搜证伪），留下 **92 条 confirmed-gap**。

冻结基线：2026-06-21 gocell→rss 迁移映射快照 · 评估日：2026-06-24

---

## 1. 一句话结论

rss 的 crate 骨架与一致性引擎（L0–L4 抽象、outbox/saga/projection/reconcile 的接缝与值类型）规划扎实，但**三整块运行期能力域几乎零落点**：(1) **设备 PKI 信任链**（EST 注册前端、证书授权/签发 funnel、撤销+CRL、softca 两级 CA、mTLS 对等认证）——一条从设备 onboarding 到证书退役的链全缺；(2) **凭据失效与会话撤销的运行期协议**（authz-epoch、refresh reuse 检测+级联吊销、account lockout、CredentialFence、不透明 refresh token 存储）——authn 当前只有值类型 newtype；(3) **HTTP 安全中间件栈与脱敏 funnel 的实现物**（请求侧幂等、限流/body-limit/安全头、IPHash/free-form scrub/递归脱敏、签名游标）——规则文档写了意图但 secure/httpserve 无承载代码。此外 **运行时契约注册表 registrycore** 被架构单源主动缩窄成「submit/list」，蒸发了整个 out-of-tree 治理控制面（7 态审批 + conformance 探测 + egress admission + 每租户 RLS）——这是被「蒸发」措辞掩盖的最大高危单点。

---

## 2. 按优先级分级的 Gap 清单（已合并跨域重复项）

### P0 — 必补（安全/正确性核心，零信任/MDM 基石；不补即留运行期漏洞）

| # | 能力 | gocell 出处 | rss 为何没规划到 | 建议落点 | 风险 |
|---|------|------------|----------------|---------|------|
| P0-1 | **EST RFC7030 设备注册前端**（/simpleenroll·/simplereenroll·/cacerts + 三态鉴权 + enrollment-credential token-intent 防 confusion + PKCS#7 degenerate CMS + jti 重放下沉 + per-IP 限速）。合并 HTTP域 #5、L4域 #7、adapter域 #6 | cellmodules/deviceidentity + ADR-1904/1895(2026-06-20 落地，紧贴冻结) | 迁移映射 package-overview L204 该行 demo/durable 两栏均标「—」，无 crate 槽位；contracts/ 无 deviceidentity；大量逻辑冻结前一天落地、映射未细化 | 新建 `deviceidentity` 域 crate + `contracts/http/deviceidentity`（owner: `_framework`）+ httpserve device-mTLS listener 类型 + `enrollment_credential` token-intent newtype（authn）；独立 feature spec | 设备零信任 onboarding 整条链缺失，无信任根入口 |
| P0-2 | **证书授权/签发 funnel + 撤销 + CRL + softca 两级 CA**（AuthorizeEnroll→SignConstraints + AuthorizedCertRequest typed 保证授权先于签名 + deny-by-default SAN + CertScope tenant 隔离 + RevocationStore + DER CRL 单调 Number + 私钥永不出 seam custody + root→intermediate split）。合并 L4域 #5/#6/#15/#16/#17、adapter域 #5 | certsigning/{authorizer,signer,revocation}.go + softca/{ca,ledger}.go + ADR-1895 | diport::Signer 是 provider 无关「签字节」port，无 cert 授权语义；deviceloop CertSignRequest 是裸签发参数无授权门；adapters/softca 仅 impl Signer 骨架 body=todo!()；全仓 CRL/revocation 命中全是 projection append-only DB REVOKE，与证书无关 | `deviceloop` 内建 certsigning seam（IssuedCert+TrustBundle + Sign 唯一入口 sealed funnel）；`diport` 新增 RevocationStore port（CertScope 必填位置参）；`adapters/softca` 实现两级 CA + 共享 Ledger（signer/revocation 同源 correct-by-construction）+ 私钥 unexported custody | PKI 签发安全模型缺失：授权缺陷放大为越权签发；无撤销=设备退役/密钥泄漏无法吊销 |
| P0-3 | **凭据失效运行期协议**（authz_epoch 行级 provenance + 严格 `!=` epoch 比对拒未来 epoch + revoked/inactive/repoErr 统一 401 防枚举 + BumpAuthzEpoch 一次性吊销 + role-revoke bump / role-assign 不 bump 的 scope 缩放语义）。合并 HTTP域 #5、域Cell #1 | accesscore/sessionlogin + sessionvalidate + credentialinvalidate + ADR-1400 §A3/A6/A8/A13/A15 | authn/src/lib.rs Session 仅 id/principal/expires_at 三字段，无 epoch/revoked_at；AuthnError 无 EpochStale；authz-epoch 全仓零命中（仅冻结快照）；architecture.md authn 行仅命名槽位 | `authn` crate：Session 增 authz_epoch 字段 + CredentialEvent 枚举 + sessionvalidate epoch 校验（diport::Pdp 侧）；新建 access 域 credential-invalidate event contract；起 feature spec 锁 stale-epoch/严格比对/单 envelope 不变式与测试矩阵 | 撤权后旧 token 在新凭据下仍有效（P1 安全缺口）；账号枚举侧信道 |
| P0-4 | **不透明 refresh token 存储 + reuse 检测级联吊销 + __Host- cookie 投递**（selector/verifier split 仅存 SHA256(verifier) + append-only lineage + reuse detection cascade + GC worker + detached time-bounded tx + 统一 401 防侧信道 + HttpOnly/Secure/SameSite=Strict/__Host- dual-channel）。合并 HTTP域 #8、域Cell #2 | refresh/{types,opaque,store,gc_worker}.go + ADR-1278 + accesscore/sessionrefresh | authn RefreshToken 仅 String newtype（redacted Debug + new/as_str），无 split/lineage/reuse/rotation/GC/cookie；secure/cookie.rs 仅通用 RFC6265 校验无属性设置；contracts 无 refresh 契约 | `authn`：OpaqueRefreshToken（selector.verifier + SHA256 存储）+ lineage + reuse-cascade；refresh store/gc_worker 经 diport+postgres/redis adapter；__Host- cookie 投递经 httpserve；起 spec | refresh token 被窃后无重放检测=持久会话劫持；XSS 可读取无 HttpOnly 的 token |
| P0-5 | **CredentialFence sealed FenceToken**（撤销三连 session.RevokeForSubject / refresh.RevokeUser / BumpAuthzEpoch 经 capability-proof token + MustHave 防御性检查原子执行） | credentialfence/fencetoken.go + ADR-1400 §A16 | 全仓 credentialfence/fencetoken/credentialinvalidate 零命中；authn 无任何撤销/fence 机制 | `authn` 新增 credentialfence 模块（sealed FenceToken newtype + 受控 Mint funnel + MustHave，对齐 vocab::ContractOwner sealed 范式） | 漏调撤销致旧会话在新凭据下仍有效（与 P0-3 同源、互为强制） |
| P0-6 | **ABAC PDP 完整决策语义**（deny-overrides + Obligations/FieldMask 通道 + 5 operator + 跨属性 eq_attr 所有权 + default-deny + baseline 规则集 + owner/self/device-self 所有权语义）。合并 域Cell #5/#6 | accesscore/authorizationdecide + abac/{operator,policy,rule}.go + baseline.go + ADR-2020 | identity PolicyRule 仅 attribute_key+expected_value 纯等值；evaluate_abac rustdoc 写「全部满足才 Allow」=**无 deny-overrides，无法表达禁止覆盖允许**；vocab::Decision 是裸 2 值无 obligation 通道；无 operator/baseline/device-self | `vocab::Decision` 增 Obligations/FieldMask（复用 RowVisibility sealed obligation）；`identity` PolicyRule 增 operator 枚举 + 跨属性 operator + builtinBaseline 规则集 + subject==resource/device-kind-gated 谓词；evaluate_abac 改 deny-overrides | 零信任授权核心退化：无法表达「显式拒绝」，策略组合不安全 |
| P0-7 | **运行时契约注册表 registrycore 完整控制面**（7 态 sealed 审批状态机 submitted→probing→conformant→pending-approval→approved→active→retired/rejected + 自动 conformance 探测 + 四元组唯一性+ceiling 校验 + 不重启激活转发 + **egress allowlist admission 防 SSRF/内网 metadata** + 每租户 PK+FORCE RLS+append-only history）。合并 分布式域 #5/#6/#7 | corecells/registrycore + ADR-303 核心裁决1/2 + 威胁矩阵 T1-T12 | architecture.md L70 + rust-mapping.md L66 **主动把 registrycore 缩窄成「submit/list」**；contractreg 仅 4 态线性弃用状态机（Draft→Active→Deprecated→Retired），与 7 态分支审批完全不同；conformance/pending-approval/egress/SSRF 全仓零命中；#1015 被列「优先级最低搭车 Phase 3」掩盖高危 | `contractreg` 扩到 7 态 sealed 审批状态机 + conformance port + 唯一性/ceiling 校验；域形 repo port 带 tenant 必填位置参 + L1 原子；postgres adapter FORCE RLS + serving role + 复用 append-only REVOKE/dylint；egress allowlist 在 conformance 出站路径强制禁 link-local/loopback/metadata；新建 rss ADR 对齐 ADR-303 | 恶意注册/审批旁路/命名空间冲突 + 框架主动出站时 SSRF 窃取内网 metadata + 跨租户读泄漏/历史篡改 |
| P0-8 | **审计哈希链 HMAC 协议 + 重启恢复 + per-tenant 子链 + append-only fail-closed**（keyed HMAC-SHA256 byte-for-byte 字段顺序冻结 + key≥32B + NamespaceID[a-z_]≤48 + 重启 strict tail-verify + content-fingerprint 幂等去重 + advisory-lock 串行 + 每租户 genesis + FORCE RLS + 空-tenant→DLX fail-closed appender）。合并 可观测域 #1/#2/#3/#15、域Cell #7/#8 | audit/ledger/protocol.go + cross_tenant_store.go + ADR-1042/1618 | audit/domain/mod.rs link_hash **无 HMAC key 入参**（`prev_hash‖entry_content→hash` 可被任意重算，丧失防篡改）；无 content-fingerprint/tail-verify/advisory-lock/NamespaceID；002 spec 的 EventId 去重是**消费侧重投去重**非**写链侧 content-addressed**；journey 标 audit_chain=out_of_scope(W) | `audit` crate domain link_hash 加 HMAC key 入参（keyed hasher 注入）+ content-fingerprint 幂等 + tail-verify 接 bootstrap 启动序列；advisory-lock/namespace/per-tenant 子链落 postgres adapter；空-tenant→DLX 提为类型层/构造器强制；新建 `docs/rules/audit-ledger.md` 承接 byte-format 单源 + INVARIANT 随 golden 冻结 | 审计链无密钥=可伪造，防篡改属性不成立；跨租户审计泄漏；重投重写链 |
| P0-9 | **Leader-elect FencedWriter 单一写面结构强制 + restricted serving-pool 角色探针**。残留子能力：(a) FencedWriter「消费方结构上无法发未 fenced 写」的 sealed funnel **应 Hard 化而非退化成运行期 CAS 测试**；(b) LeaseToken 完整字段集；(c) 单调-epoch vs UUID identity-fencing 区分；(d) serving-role NOSUPERUSER+NOBYPASSRLS 运行期 pg_roles 探针 fail-closed。合并 事件域 reconcile-fencing、codegen域 #6 | reconcile/{leader,fenced}.go + ADR-661 + ADR-1676 | reconcile.md/spec-002 P11 已规划 LeaderElector/FencedWriter 概念（COVERED），但 RECONCILE-FENCE-MONO-01 标 Medium「运行期 CAS+测试」，**未 Hard 化单一写面结构**；serving-role 探针：tenancy.md 有文字要求但 syshealth ProbeRegistry 仅骨架，FORCE RLS 对 BYPASSRLS 角色运行期 no-op、误连 admin 角色则租户隔离静默失效 | spec-002 P11 落 diport 时把 FencedWriter 做成 sealed 单一写面 funnel（Hard）；adapters/postgres serving pool 新增 capability probe（查 pg_roles，rolsuper/rolbypassrls fail-closed）注册进 syshealth（critical 探针）；tenancy.md 把「serving-role 无 bypass」从文字升级为运行期不变式 | stale-epoch 写绕过；serving 池误连 admin 角色→租户隔离运行期失效且无兜底 |

### P1 — 应补（功能完整性 / 运维可辨性 / 抗 DoS；缺则生产边界条件出错）

| # | 能力 | gocell 出处 | rss 现状 | 建议落点 | 风险 |
|---|------|------------|---------|---------|------|
| P1-1 | **HTTP 请求侧幂等 middleware**（Idempotency-Key + RecordedResponse 回放 blob + body fingerprint mismatch→422+per-field diff + (tenant,subject,method,path,key) 五元组隔离 + 凭据响应 exempt funnel + 三键 Lua 原子 + store fail-closed）。合并 HTTP域 #1、事件域 #1 | http/idempotency/ + ADR-1043/1449 | consistency idempotency 是**消费侧** EventId claim-or-skip，与 HTTP 请求侧正交（ADR-1043 明示非平行抽象）；Redis 键形 `_runtime:<tenant>:{key}:resp\|lease\|fp` 已预留但仅键名 | `httpserve` 新增 idempotency tower 层（或 `httpidem` crate），store 经 diport（Redis/PG），exempt 用 PrimaryRoute 同款类型级 opt-out funnel；Redis 键形可直接复用 | 重复 POST 产生重复副作用；凭据响应被回放 |
| P1-2 | **HTTP 中间件栈 + BodyLimit-先于-auth 位序不变式**（RateLimit/BodyLimit/SecurityHeaders/CSRF/CookieSession/RealIP/AccessLog；429/413/HSTS/X-Frame/CSP；request-size-first 安全位序）。合并 HTTP域 #2、adapter域 #3（限流） | http/middleware/ + ADR-1043 §3 #1988 + ratelimit/token_bucket.go | httpserve/middleware.rs 仅 request_id/trace/panic_recovery；adapters/ratelimit 仅 impl ManagedResource body=todo!() 未被接；BodyLimit-先于-auth 安全不变式零规划 | `httpserve` 中间件子模块（tower-http 接 body-limit/security-headers，ratelimit adapter 接 429）；`diport` 新增 RateLimiter port（allow(key)→Decision）；observability.md 或新 spec 锁 BodyLimit→auth 位序 | 未限流请求体先过 auth=放大攻击面；无限流=brute-force/凭据爆破/DoS |
| P1-3 | **L4 设备命令队列**（Status 状态机 Pending→Sent→Delivered→Succeeded/Failed/Expired/Canceled + 转换表 + Attempt 重试 + 三层超时 ScheduleToSend/SendToComplete/Overall + Sweeper 超期扫描 + active-uniqueness PG partial unique index + MaxPendingPerDevice 抗 DoS 配额）。合并 L4域 #1/#2/#3/#4 | command/{status,entry,advance,sweeper,queue}.go + ADR-1822 | spec-002 的 command 表明确「复用 outbox 表」=CQRS dispatch bus 语义，**不是设备投递回执状态机**；deviceloop CertLifecycleState 是证书态；MaxPendingPerDevice(2026-06-20 落地)映射未覆盖；active-uniqueness 全仓零命中 | 新建 `devicecmd` crate 或 deviceloop command 子模块（L4）：Status 闭值集+转换表+Entry 生命周期；DeadlineFor 做 L0 纯计算表驱动；SweepOnce 后台 worker；enqueue 路径 partial unique index + 配额 429；独立 feature spec（spec-002 command 不可复用） | 设备命令投递回执整套缺失；被攻陷设备耗尽队列 |
| P1-4 | **explicit-subject PDP 授权桥**（SubjectDescriptor sealed 无 privileged 构造器 + SubjectAuthorizer.AuthorizeAs 第二评估入口 + caller-allowlist funnel + PDP-backed certsigning Authorizer 复用桥）。合并 HTTP域 #6、L4域 #8 | subject_descriptor.go + certsigning/pdpauthz + ADR-1904 D1-D5 | identity PDP 只接 principal-backed subject（ctx-principal 单入口）；diport 无 Pdp port（#1109 占位）；cert 授权/背景 reconcile 无 HTTP principal 无法复用同一 PDP | `diport` 落 Pdp port 时增 authorize_as(SubjectDescriptor)；SubjectDescriptor 为 sealed 值类型（无 admin/super-admin 构造器 + caller-allowlist funnel）；与 reconcile system identity 共用 background 授权路径 | cert/background 路径长出平行授权逻辑→policy 漂移（**P0-2/P0-1 的 enroll 授权将无处接 PDP**） |
| P1-5 | **投影身份安全**（projection Apply 运行时清空 ambient principal + 安装 SystemPrincipal + 跨租户 journal 纵深防护，防 rebuild 触发者/后台 tailer ctx 穿透造成审计 impersonation） | ADR-1609 §4.1 + rebuild.go | 全仓 systemprincipal/install.*principal 投影语境零命中；ProjectionEvent trait 仅 topic/lsn/payload 无身份载体；FR-020 是 write-side envelope subject，非 projection Apply 运行身份；ADR-002 称 Rust 无 ambient context 但**投影载体也未设计 system 身份显式安装入口** | `consistency`/src/projection.rs 的 Projector 接缝补 projection-run 身份语义（因 Rust 无 ambient ctx，作 harness 注入的显式必填参数，对齐 AI-robust Hard）；spec 规划「投影 Apply 以稳定 system 身份运行、与触发者解耦」+ 跨租户纵深 | 被「载体简化为纯 topic/lsn/payload」掩盖的审计 impersonation（P1 安全） |
| P1-6 | **reconcile system producer identity 运行期安装**（Loop.process chokepoint positively install tenantless system 身份覆写四 principal ctx key + strip ambient principal 防 dedup tenant 维度泄漏）。残留 reconcile-identity 子能力 | reconcile/identity.go + ADR-1821 | RECONCILE-TENANCY-REQ-01 必填 sealed Tenancy 是「声明 stance」已 COVERED；但 ADR-1821 核心「Loop chokepoint 运行期覆写 ambient 身份」无规划；consistency reconcile Context 只提「承载租户命名空间句柄」 | `consistency` reconcile Loop harness 在 process chokepoint 经 runctx 安装 system RequestCtx（actor/subject/tenant/session 覆写）+ RECONCILE-SYSTEM-IDENTITY-INSTALL 守卫 fail-fast | lifecycle ctx 残留 principal 静默改 dedup tenant 维度→跨租户 collision |
| P1-7 | **出站 webhook dispatcher + 入站 receiver capability-token 有序闭环**（HMAC-SHA256 签名 + SSRF egress 守卫 + per-(tenant,endpoint) circuit breaker + 失败按 HEALTH 非 payload validity 分类 + DLX + 入站 verified→claimed→handler 类型级有序）。合并 事件域 #3、adapter域 #9 | webhook/dispatch/ + circuit.go + ADR-1541/1159 | circuit breaker 纯原语 COVERED（primitives/circuitbreaker.rs），但唯一生产消费方 dispatcher 整体缺失；HmacSha256 原语也就绪；ssrf/egress 全仓零命中 | 新建 `webhook` 服务/域 crate 消费 primitives::circuitbreaker + HmacSha256，breaker key=(TenantId,EndpointId)，SSRF egress 用 sealed allowlist，receiver token 用类型级有序 marker；接 outbox DLX；订阅经 contract.toml | 跨租户 webhook DoS；SSRF；handler 在验签/claim 前执行 |
| P1-8 | **MQTT adapter requeue 语义 + app-level DLT**（Option C leave-unacked + $dead/<topic> 死信 + SupportsRequeue=false + 按序-PUBACK HoL stall 规避 + poison ack-as-poison + fail-closed mqtt_dlx_failed_total） | mqtt/{subscriber,deadletter}.go + ADR-050/048 | adapters/mqtt 仅 impl Publisher+ManagedResource body=todo!()，无 Subscriber/DLT/requeue；eventbus.md §DLX 是 broker-native（AMQP），不覆盖 MQTT 无 DLX 需 $dead app-level 的特殊语义 | `adapters/mqtt` 补 Subscriber impl + $dead app-level DLT + SupportsRequeue=false；eventbus.md 补 MQTT-specific requeue Option C/HoL/fail-closed-drop 语义节 | 设备命令下行 transport 可靠性边界缺失（MDM 命令丢失/HoL 阻塞） |
| P1-9 | **Vault Transit 信封加密 KeyProvider + AEAD 显式 AAD 绑定 + config value 加密**（provider-可换 Encrypt/Decrypt DI port + 本地 AES-GCM DEK/EDK + AAD=cell/tenant/key 复合绑定防跨 entry/跨租重用（GoCell 原口径；RSS 目标维度 = tenant/config-key/field/schema-version，见 ADR-011 §D2）+ key-id rotation 常数时间匹配）。合并 内核域 #4/#7、adapter域 #1、域Cell #10 | vault/transit_provider.go + aeadutil/gcm.go + verifykeyid.go + configcore/crypto/aad.go | **observe-redaction 已交付（#1359/#1360，observe-time）但 at-rest 加密仍缺**：diport 无 KeyProvider；secure/aead.rs Aead trait `seal(plaintext)`/`open(ct)` **无 aad 参数**；settings ConfigValue 仍明文 newtype。（primitives/crypto.rs doc 指向不存在 diport::KeyProvider 的 doc 落空 → **本 PR 已修正指向 ADR-011**） | **设计单源 = ADR-011（字段级数据保护边界，本 PR 落地）**；拆三 Feature 自底向上：**#1465** framework 底座（`secure` AAD/ciphertext envelope/AEAD v2 `seal/open` 带 aad + contract `x-protection` authoring/validate/breaking，不接 Vault）→ **#1466** KeyProvider+Vault（`diport` KeyProvider/ValueTransformer + `adapters/vault` encrypt/decrypt/**rewrap** + current-primary/previous-read 轮换 + constant_time_eq key-id）→ **#1467** settings ConfigValue 加密（AAD 绑 tenant/config-key/field/schema-version + 旧明文兼容/迁移 + backfill/rewrap + 可选 blind index）。验收清单单源见 ADR-011 §D7 | 静态数据无加密；AAD 缺失=密文可跨 tenant/跨 key 重放（安全语义削减） |
| P1-10 | **PII 脱敏 funnel 三件**：(a) IPHash keyed-HMAC sealed PII funnel（明文 IP 永不进 outbox/broker/DLX/audit + salt≥32B fail-fast）；(b) free-form 子串 scrub（Authorization/连接串/JSON/key=value 正则 fail-closed）；(c) replayable payload 递归脱敏 + panic 值脱敏。合并 内核域 #1/#2/#6 | redaction/redaction.go（IPHash/RedactString/RedactPayload/RedactPanic） | secure/redaction.rs 仅按 key 名整值替换 + redact_error 顶层直通；无 HMAC/salt/正则/连接串/递归；secure/Cargo.toml 无 hmac/sha2 依赖；observability.md L24/L102 写了 free-form scrub/PII hash 强制规则但 secure crate **无实现物=rule-vs-impl 落差** | `secure`：新增 IPHash sealed newtype（私有字段 + 唯一 HashIP(salt,ip) 构造器 + 无 Deserialize）+ MIN_IP_HASH_SALT_BYTES + 组合根 salt fail-fast；补 redact_string 正则 ruleset + redact_error 经其清洗；redact_json_payload 递归；事件 schema 用 clientIpHash 字段类型 | PG DSN 明文 password 进 io::Error.to_string()→直通 trace；replayable 存储明文 IP 长期驻留跨信任边界泄漏 |
| P1-11 | **签名游标 tamper-proof cursor**（HMAC-SHA256 keyset 游标 + 强制 scope(排序列 hash)+context(查询指纹) + ValidateCursorScope + current/previous 双 key rotation + MaxCursorTokenBytes 防 DoS） | query/cursor.go | vocab/query.rs Cursor::parse 仅 base64url，无 HMAC/scope/context/rotation/上限；tenancy.md 无游标↔行权限绑定 | `vocab::Cursor` 升签名变体或新增 `vocab::query::CursorCodec`（HMAC-SHA256+强制 scope/context+上限），HMAC 复用 primitives::crypto MacVerifier | 多租户下未签名游标可伪造越 sort/scope=IDOR/scope-escape |
| P1-12 | **account lockout 自动锁定**（Threshold=5/StaleWindow=15m/LockoutTTL=15m + RecordFailure/RecordSuccess/TryLazyUnlock + 计数与会话写同 tx）+ 凭据-版本 pin（SnapshotPasswordVersion + FOR UPDATE 重读防并发竞态）。合并 域Cell #3/#4 | accesscore/internal/accountlockout/ + credentialauthority/ | identity 仅 AccountStatus::Locked 枚举值，无失败计数器/Threshold/RecordFailure/lazy-unlock；唯一落点 rewrite-sequence L29 journey 名占位；password-version 全仓零命中 | `identity` 域新建 internal/accountlockout 策略（L0）+ RecordFailure/TryLazyUnlock + 计数随会话同 L1 tx；password-version 防竞态依赖真实凭据模型先落地 | brute-force 无锁定；并发改密竞态 |
| P1-13 | **RBAC 角色变更→会话同步**（sessionlogout 订阅 role.assigned/revoked HandleRoleChanged + rbacassign.Revoke→credentialinvalidate 吊销，Assign 增量不吊销）+ **gRPC session verify RPC**（grpc.auth.session.verify.v1 令牌内省 + mTLS + session:verify baseline）。合并 域Cell #13/#14 | accesscore/sessionlogout + rbacassign + sessionverifyrpc | identity 有静态 RBAC 求值但无 role 变更事件订阅/Revoke 联动/role event contract；contracts 无 grpc kind；依赖 P0-3 epoch | `identity`/access 域新建 role.assigned/revoked event contract + sessionlogout consumer + rbacassign.Revoke→epoch bump 联动；先引入 grpc contract kind + codegen | 撤权后旧 token 仍带旧角色 |

### P2 — 可选（运维可辨性 / 部署形态 / 前瞻；非首发安全核心）

| # | 能力 | 落点 | 说明 |
|---|------|------|------|
| P2-1 | **Saga 终态语义 + 三层 timeout + heartbeat 续租**（Expired/Failed/CompensationFailed 运维可辨终态 + Step/总/heartbeat 三层 + per-step lease 续租）。合并 L3域 #1/#2 | `consistency`/saga.rs 新增 SagaTerminalStatus 闭值枚举 + eventexec saga executor per-step timeout/Heartbeater；spec-002 data-model 补 expired/compensation_failed | 补偿失败路由 dead-letter 丢失终态可辨性；长步 leader 假死无续租 |
| P2-2 | **Projection rebuild 四阶段状态机**（Phase 枚举 Stop→Reset→Replay→Catchup + 非阻塞读 Phase() + 控制面 rebuild 端点 202/409/404 + replay-lag/rebuild-duration metrics） | `consistency`/projection.rs frozen Phase 枚举 + admin listener rebuild 端点 + observ metrics | 核心 replay 在（COVERED），运维级 rebuild 编排面缺 |
| P2-3 | **cert-renewal 确定性 jitter + certlifecycle 8 态封闭词汇 + certdeps topology-gated resolver + mTLS server builder/PeerIdentity**。合并 L4域 #9/#10/#11/#12 | `deviceloop` L0 纯函数 renewal_fraction（sha256 派生 70-90%）+ 8 态对齐；`bootstrap` certdeps sealed resolver（demo→in-mem softca，postgres→fail-closed）；`httpserve` mTLS server builder + PeerIdentity 冻结字段集 | fleet 防惊群；postgres 拓扑静默用 dev CA 换信任锚 |
| P2-4 | **distlock Lock-as-Resource + 续约 manager + cross-cell transport 二态 + DeploymentTopology + spiffeid CellID/CellSet**。合并 分布式域 #1/#2/#3/#4、事件域 #2 | `distributed` 已有 Lock/Locker 值语义 + diport LockStore port + `DomainTransport` seam / transport metrics 闭值集；后续新建 `spiffeid` crate（CellID/CellSet sealed，对标 rust-spiffe）；bootstrap sealed DeploymentTopology；cross-bind/VerifyConnection/all-or-nothing 写 docs/rules 新 §Cross-cell mTLS | transport seam（DomainTransport/transport_mode）已 COVERED；残留续约 manager + 部署拓扑基座 + 对等认证不变式 |
| P2-5 | **outbox 失活率 tracker + consumer lease 续租**（DirectEmitter fail-open 丢事件比率→degraded readyz + Receipt.Extend 后台续租 LeaseTTL/3 防长 handler lease 过期）。合并 事件域 #4/#5 | `consistency` outbox FailOpenTracker（RecordSuccess/RecordDrop+Tripped 比率）接 readyz；InboxStore 加 extend(ttl)→LeaseExpired + ConsumerBase 后台续租任务 | worker 存活 probe 已规划（FR-004/005），emit 丢弃率+长 handler 续租正交未规划 |
| P2-6 | **可观测性实现物**：slog/tracing sink fail-closed redaction seal（process-global default）+ metrics 子系统 collector 框架 + sealed CellLabel resolver + syscore HealthView 跨 cell 聚合 + sysinfo 端点 + gRPC circuit breaker/rate-limit/cell-attribution 拦截器 + websocket Hub + contract_id→span 绑定。合并 可观测域 #6/#7/#8/#9/#10/#11/#12/#13/#14、adapter域 #4 | `observ` tracing Layer（消费 secure::redact_error + contract_id span attr）+ 各子系统 collector + #1076 sealed domain/cell resolver；`syshealth` HealthView projection + sysinfo 模块 + admin/health/cells 端点；`adapters/websocket` 新建 + `adapters/grpc` tower Layer | 规则有意图（C），承载它的 Layer/Hub 实现无 crate 落点；多数随 P8（grpc/ws 全量）落地 |
| P2-7 | **codegen/契约清单载体**：grpc/proto contract kind + (proto package,service) 唯一性+method overlay 校验 + contracts/shared/ $ref 共享 schema + contract-derived handler codegen funnel（endpoints 块→typed handler 经单 funnel + golden 锁鉴权字面量）+ TS emitter + generate catalog。合并 codegen域 #1/#2/#4/#5/#7 | `xtask` manifest.rs 加 Grpc variant + contracts/grpc 槽位 + prost/tonic codegen + validate 规则；contracts/shared 槽位 + $ref 解析；manifest endpoints block（需解冻 CONTRACT-FREEZE-01）+ handler codegen funnel + 鉴权字面量 golden | 授权语义在 tenancy.md 完整锚定（C），但 Hard codegen funnel 载体缺=授权接线退回组合根手挂运行期 enforce，丢失「改路由丢 resource 即 golden 红」属性 |
| P2-8 | **ctxcancel 取消语义双向转译**（Canceled→499/Warn 保 5xx SLO vs DeadlineExceeded→504/Error 喂告警）+ derive-service-keys per-domain HMAC 子密钥派生 + Redis Cluster 模式。合并 内核域 #5、codegen域 #3、adapter域 #10 | `vocab::CoreErrorKind` 增 {ClientCanceled,ServerTimeout} + ctxcancel helper（additive 非破坏）；`authn` per-domain HMAC 子密钥派生 + split/provisioned keyring（split 部署 master 单进程被攻陷可伪造域间 token=high）；adapters/redis ClusterMode | derive-service-keys 实为 P0 级安全（split 部署伪造），此处因依赖 split 拓扑落地时序列 P2；client-cancel/server-timeout 当前塌进 Internal 污染 5xx SLO |

---

## 3. 按 rss crate 归类的承接建议表

| crate / 路径 | 待补能力 |
|------|---------|
| **authn** | authz_epoch 会话失效模型 + CredentialEvent（P0-3）；OpaqueRefreshToken split/lineage/reuse-cascade/GC（P0-4）；credentialfence sealed FenceToken（P0-5）；enrollment-credential token-intent newtype（P0-1）；per-domain HMAC 子密钥派生 + split/provisioned keyring（P2-8）；role.assigned/revoked 联动 epoch bump（P1-13） |
| **identity** | ABAC deny-overrides + operator 枚举 + 跨属性 + builtinBaseline + owner/self/device-self 所有权（P0-6）；account lockout 策略 + RecordFailure/lazy-unlock（P1-12）；role 变更事件订阅 + rbacassign.Revoke 联动（P1-13） |
| **vocab** | Decision 增 Obligations/FieldMask 通道（P0-6）；Cursor 升签名变体 / query::CursorCodec HMAC（P1-11）；CoreErrorKind 增 ClientCanceled(499)/ServerTimeout(504)（P2-8） |
| **secure** | IPHash sealed PII funnel + MIN_IP_HASH_SALT_BYTES（P1-10a）；redact_string 正则 ruleset + redact_error 清洗（P1-10b）；redact_json_payload 递归 + panic 值脱敏（P1-10c）；Aead::seal/open 增 aad 参数（P1-9） |
| **primitives** | KeyId::parse(provider,version)+match_key_id 经 constant_time_eq（P1-9，随 KeyProvider 落地） |
| **diport** | KeyProvider DI port（P1-9）；Pdp port + authorize_as(SubjectDescriptor)（P1-4）；RateLimiter port（P1-2）；RevocationStore port（P0-2）；Locker port + 续约引擎（P2-4） |
| **consistency** | projection Apply system 身份显式注入入口（P1-5）；reconcile Loop chokepoint install system identity + strip ambient（P1-6）；FencedWriter sealed 单一写面 funnel Hard 化（P0-9a）；SagaTerminalStatus 闭值枚举（P2-1）；projection Phase 枚举 + rebuild 编排（P2-2）；FailOpenTracker + InboxStore.extend(ttl)（P2-5） |
| **eventexec** | saga executor per-step timeout + Heartbeater（P2-1）；ConsumerBase 后台 lease 续租（P2-5）；audit appender ActorMode require-explicit DLX（P0-8 配套） |
| **deviceloop / 新 devicecmd** | certsigning seam（IssuedCert+TrustBundle + Sign sealed funnel + AuthorizedCertRequest）（P0-2）；设备命令队列 Status 状态机+三层超时+sweeper+active-uniqueness+配额（P1-3，建议独立 crate）；renewal_fraction L0 jitter + certlifecycle 8 态（P2-3） |
| **新 deviceidentity 域 crate** | EST 三端点 + 三态鉴权 + PKCS#7 degenerate CMS + jti 重放（P0-1） |
| **distributed / 新 spiffeid crate** | Lock/Locker 值语义 + 三态信号 + 续约 manager（P2-4）；spiffeid CellID/CellSet sealed + cross-cell mTLS 对等认证；cross-cell transport 二态实现（P2-4） |
| **bootstrap** | sealed DeploymentTopology（HostedCellSet 非空 fail-closed）（P2-4）；certdeps topology-gated resolver（P2-3）；audit 重启 tail-verify 接启动序列（P0-8） |
| **settings** | ConfigVersionSnapshot + Publish/Rollback CAS + version-published/rollback event（P1 配置版本化）；ConfigValue 加密路径 + AADForConfig（P1-9）；evaluate_flag 一致性哈希分桶不变式（P2，槽位已就绪） |
| **audit** | link_hash 加 HMAC key 入参 + content-fingerprint 幂等 + tail-verify（P0-8）；per-tenant 子链 + 空-tenant→DLX appender + ActorMode（P0-8） |
| **contractreg** | 7 态 sealed 审批状态机 + conformance port + 唯一性/ceiling 校验 + egress allowlist admission + 域形 repo port tenant 必填位置参（P0-7） |
| **observ** | tracing Layer（redaction seal + contract_id span attr）+ 子系统 collector + sealed CellLabel/domain resolver（#1076）+ gRPC 拦截器（P2-6） |
| **syshealth** | HealthView 跨 cell 聚合 + sysinfo 模块 + admin/health/cells 端点 + serving-role capability probe（P0-9d/P2-6） |
| **httpserve** | 请求侧幂等 middleware（P1-1）；中间件栈 + BodyLimit-先于-auth 位序（P1-2）；mTLS server builder + PeerIdentity（P2-3）；__Host- cookie 投递（P0-4） |
| **adapters/{postgres,vault,mqtt,redis,softca,grpc,ratelimit,websocket}** | postgres：serving-role 探针 + FORCE RLS + append-only history（P0-7/P0-9d）；vault：Transit 信封加密 + 认证生命周期（P1-9）；mqtt：Subscriber + $dead DLT（P1-8）；softca：两级 CA + 共享 Ledger + 私钥 custody（P0-2）；redis：Cluster 模式（P2）；grpc：TLS 三模式 + 拦截器（P2-6）；ratelimit：token-bucket allow/window（P1-2）；websocket：新建 Hub + tokio-tungstenite（P2-6） |
| **xtask** | grpc/proto contract kind + codegen + validate；contracts/shared $ref；contract-derived handler codegen funnel + 鉴权 golden；TS emitter（P2-7） |
| **新 webhook 服务 crate** | dispatcher（HMAC 签名 + SSRF egress + per-tenant circuit breaker + DLX）+ receiver 有序闭环（P1-7） |

---

## 4. 特别标注

### ① 2026-06-21 冻结后 / 紧贴冻结落地、迁移映射完全未覆盖的能力

这些 gocell 能力在冻结评估窗口边缘或之后落地，4 篇迁移映射文档（package-overview/crate-mapping/rewrite-sequence/eval-checklist）**未覆盖或仅一行带过**，rss 侧无对应 ADR/spec/crate body：

- **MaxPendingPerDevice 每设备 pending 命令上限**（commit a609b61af，2026-06-20，冻结前一天）— 抗 DoS 资源边界，映射未提（P1-3）。
- **EST jti 重放下沉 + /cacerts per-IP 限速**（ADR-1895 Amendment 2026-06-20，commit 043add59b）— 映射 package-overview L204 整行标「—」（P0-1）。
- **outbox failopen_tracker**（2026-06-15）— 迁移映射未提，rss 仅有 worker 存活 probe（P2-5）。
- **HTTP 请求侧幂等 middleware**（2026-06-19 pre-freeze）— 仅 rewrite-sequence L27 时间线一笔（P1-1）。
- **cross-cell transport mTLS ADR-2263**（2026-06-17 Accepted）— 接近冻结日的零信任关键 ADR，rss 无对应物（P2-4）。
- **contractgen TypeScript emitter ADR-2004**（2026-06-13）— 早于冻结但映射漏列（P2-7）。
- **审计 admin 全链验证 runner**（2026-06-19）— 早于冻结但映射未提（P0-8 配套）。
- **registrycore 完整控制面 ADR-303**（2026-06-16）+ **HTTP owner-scoped contract-derived authz ADR-2355**（2026-06-20）— rss 无 ADR/spec 对齐（P0-7/P2-7）。

> **行动**：这批应在下一轮迁移映射刷新中强制纳入，并各自登记 GitHub Issue / ADR，避免「冻结快照」成为永久盲区。

### ② 迁移映射判为「蒸发」但实际掩盖真实功能缺口的

- **registrycore→「submit/list」**（architecture.md L70 + rust-mapping.md L66 主动缩窄）：被缩窄措辞掩盖了**整个 out-of-tree 运行时治理控制面**（7 态审批 + conformance 探测 + egress admission + 每租户 RLS）。这**不是** governance 机制被类型系统吸收——审批状态机/SSRF egress 闸/跨租户隔离是零信任运行期安全能力（P0-7）。**本批最高危的单点。**
- **projection「载体简化为纯 topic/lsn/payload」**：掩盖了 projection Apply 运行身份的 system-principal 安装/审计 impersonation 防护。ADR-002 称 Rust 无 ambient context 正确，但 rss **也未设计 system 身份显式安装入口**——零信任/审计角度仍是真实运行期安全行为缺失（P1-5）。
- **「kernel/fsm 可达性检查被类型系统吸收」**：只吸收 transition-validation governance，**不产出** Expired/CompensationFailed 终态本身——运维可辨终态丢失（P2-1）。
- **「tower Layer 统一 HTTP/gRPC interceptor 顺序结构上消失」**：只覆盖同栈，**不覆盖** BodyLimit-先于-auth 业务安全位序 + gRPC circuit breaker status 分类（功能行为非 ceremony）（P1-2/P2-6）。
- **「diport::Signer 通用签字节 port」当作 cert 签发**：provider-agnostic 签字节 ≠ cert 授权/签发 seam，丢失 SignConstraints/TrustBundle/授权先于签名/私钥 custody（P0-2）。
- **audit link_hash「prev_hash‖entry_content→hash」**：缺 HMAC key=链可被任意重算，防篡改属性根本不成立（P0-8）。
- **Aead seal/open 去掉 aad 参数**：接缝简化掩盖安全语义削减——密文无法绑定 tenant/key，可跨上下文重放（P1-9）。

### ③ 安全 / 零信任缺口单列（MDM / ABAC / 审计 / 证书 / mTLS）

| 类别 | 缺口（优先级） |
|------|--------------|
| **证书 / PKI（设备信任根）** | EST 注册前端（P0-1）；证书授权/签发 funnel + 撤销 + CRL + 私钥 custody + 两级 CA（P0-2）；renewal jitter / 8 态 / certdeps fail-closed resolver（P2-3） |
| **mTLS / 对等认证** | cross-cell transport mTLS + SPIFFE peer-auth + cross-bind/VerifyConnection/all-or-nothing fail-closed（P2-4）；mTLS server builder + PeerIdentity 冻结字段集 + device-mTLS listener（P0-1/P2-3）；gRPC TLS 三模式 fail-closed gate（P2-6） |
| **凭据 / 会话（零信任失效）** | authz-epoch 失效模型（P0-3）；refresh reuse 检测 + 级联吊销 + __Host- cookie（P0-4）；CredentialFence sealed token（P0-5）；account lockout + password-version pin（P1-12）；role 变更→会话同步（P1-13）；per-domain service key 派生 split 部署伪造防护（P2-8） |
| **ABAC / 授权** | deny-overrides + Obligations/FieldMask + operator + baseline + device-self（P0-6）；explicit-subject PDP 桥（P1-4）；contract-derived authz codegen funnel Hard 化（P2-7）；签名游标防 IDOR/scope-escape（P1-11） |
| **审计** | HMAC 链协议 + key≥32B + 重启 tail-verify + content-fingerprint（P0-8）；per-tenant 子链 + FORCE RLS + 空-tenant→DLX appender（P0-8）；trace→audit 反查数据模型 + ActorMode（P0-8/P2-6） |
| **PII / 脱敏（数据防扩散）** | IPHash sealed funnel + salt≥32B（P1-10a）；free-form scrub 连接串/Authorization/JSON（P1-10b）；replayable payload 递归脱敏（P1-10c）；sink-side fail-closed redaction seal（P2-6） |
| **加密 / 静态数据** | Vault Transit 信封加密 + AAD 复合绑定（P1-9）；config value 加密（P1-9）；key-id rotation 常数时间匹配（P1-9） |
| **租户隔离 / RLS** | registrycore 每租户 RLS + serving role NOBYPASSRLS（P0-7）；serving-pool 角色运行期探针 fail-closed（P0-9d）；reconcile system identity install 防 dedup 跨租户 collision（P1-6） |
| **抗 DoS / 防爆破** | HTTP 限流 429 + BodyLimit-先于-auth（P1-2）；webhook per-tenant 熔断 + SSRF egress（P1-7）；MaxPendingPerDevice 配额（P1-3）；MQTT $dead DLT fail-closed（P1-8） |

---

## 5. 不是 gap 的澄清（Rust 类型系统/crate 图原生吸收，正确地不需重写）

读者勿把以下当缺口——这些 gocell 机制因 Rust 编译期载体被**正确蒸发**，无残留功能缺口：

- **跨域隔离 archtest**：gocell 运行期校验「域 cell 互不依赖」，rss 由 **Cargo 依赖图 + deny.toml 编译期强制**（不声明就 import 不到），无需运行期治理测试。
- **kernel/fsm transition-validation governance**：状态机可达性校验由**类型系统**吸收（注意：终态枚举本身仍是 gap，见 ②）。
- **interceptor 顺序 = 中间件顺序不变式（同栈维度）**：HTTP/gRPC 同 tower Layer 栈结构上消失（注意：BodyLimit-先于-auth 业务安全位序仍是 gap）。
- **owner→域 crate 收口**：gocell 运行期 guard，rss 由 sealed `vocab::ContractOwner`（私有内层 enum + 受控构造关联函数）**类型系统强制**，`Framework` 无法解析成域、外部无法 mint。
- **跨域只经 contract 通信**：由 crate 依赖图 + deny.toml 自动守住，无需 governance 测试。
- **必填依赖非 Option / Clock 位置参**：构造器必填参数缺失即编译错误，原生吸收 gocell 的运行期 fail-fast 检查。
- **ambient context 取消**：ADR-002 明确 Rust 无 ambient context（context.Context 隐式传播在 Rust 不存在）——故 gocell 的「清空 ambient principal」本身无需重写；**但**显式 system 身份注入入口仍须设计（这是残留 gap，见 ②，不要与「ambient 取消」混淆）。
- **circuit breaker / HMAC / constant_time_eq 原语**：primitives 已 COVERED（对标 sony/gobreaker、RustCrypto），缺的只是消费方（webhook dispatcher / gRPC 拦截器）。
- **leader-elect / FencedWriter 概念 + LeaseToken.epoch + lost-lease cancel**：reconcile.md + spec-002 P11 已规划 COVERED（残留只是 sealed 单一写面 Hard 化 + LeaseToken 完整字段，见 P0-9）。
- **DI port 归属二分（ADR-003/005）+ sealed-trait + dynosaur 宏白名单**：rss 的 diport/域形 port 范式已是比 gocell 更强的编译期载体，无需补 gocell 等价 archtest。

> 各域 confirmed-gap 均非空——无任何能力域可判「规划已完整」。规划最扎实的是 **L0–L4 一致性引擎的接缝与值类型**（outbox/saga/projection/reconcile 的 trait 和状态枚举骨架齐全），缺的主要是各接缝的**运行期行为实现 + 安全不变式 Hard 化**，而非接缝本身。

---

**首要行动建议**：P0-7（registrycore 蒸发）、P0-1+P0-2（设备 PKI 链）、P0-3~P0-6（凭据失效+ABAC）三组是阻断零信任/MDM 上线的硬门槛，应优先立 ADR 并起 feature spec；其中 P1-4（explicit-subject PDP 桥）是 P0-1/P0-2 的授权前置依赖，需同批规划。② 中列出的「蒸发掩盖缺口」四项应在架构单源（architecture.md / migration 映射）刷新时显式修订措辞，避免 reviewer 据缩窄措辞误判为 COVERED。
