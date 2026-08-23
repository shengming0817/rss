# ADR-013：diport DTO 字节脱敏 — 动态/固定宽度类型 funnel + dylint 下游守卫

- **状态**：Accepted（落地实现：`crates/diport/src/redacted_bytes.rs` + `lints/rss_diport_dto_debug_redacted`）
- **日期**：2026-06-27
- **关联**：issue **#1155**（`[diport] 机器守卫防 DI port DTO/error 新增时 derive(Debug) 复归泄漏`）· Epic #991 · RW-G1（#999）·
  源出 PR #209 内置 review F6（Cx3 处置门判 defer）
- **依赖 ADR**：**ADR-003**（DI dynosaur 派发 → diport port DTO 归属）· **ADR-011**（字段级数据保护边界：observe-redaction vs storage-encryption，本 ADR 属 **observe-redaction** 面的字节 payload 子边界）
- **既有对称范式**：`RedactedSource`（error source 脱敏 newtype，INVARIANT DIPORT-ERR-SOURCE-REDACT-01）+ `rss_diport_error_debug_redacted`（下游 lint，DIPORT-ERR-RAWSOURCE-BAN-01）
- **归属**：framework（DI-infra port DTO 脱敏边界，provider-agnostic）
- **AI-robust 评级**：上游 **Hard（类型系统）** + 下游 **Medium（dylint）**——见 §3 / §6

---

## 1. 背景

#1359/#1360 把 observe-time 字段级 redaction（`securederive::Redact` + `secure` funnel）引入 RSS（ADR-011 §observe-redaction）。
diport 的 DI port 契约 DTO 中，**字节 payload 字段**（`Vec<u8>` —— 事件体 / 签名 / CSR / nonce / 状态快照 / 密钥物料）此前各自**手写
`impl Debug`** 把字节渲染成 `<redacted>`，散落在 ~9 个 DTO（`Signature` / `SignRequest.message` / `Message.payload` /
`PublishRequest.payload` / `CasStoreRequest.{expected,new_value}` / `CasStoreOutcome::Conflict.current` / `FencedWriteRequest.data` /
`DeadLetterRecord.original_payload` 等；saga journal record 不再承载 step output）。

**问题（#1155，源 PR #209 review F6）**：「未来新增 diport DTO 含字节 payload 必须脱敏」对**将来**类型**无前向机器守卫**——
开发者新增一个 `pub struct { f: Vec<u8> }` + `#[derive(Debug)]` 不会被任何 lint / 治理测试拦住。既有 `rss_redact_debug_required`
（REDACT-DEBUG-REQUIRED-01）只按**硬编码类型名单**触发，其 Known problems 自承「新增敏感 DTO 需同步名单」。cargo xtask archrules verify：新机制
最低 Medium，且「能上移到类型系统则**必须**上移」。

error 侧此问题已由 `RedactedSource` newtype（Hard）+ `rss_diport_error_debug_redacted` lint（Medium）的 **funnel** 解决；
本 ADR 对字节 payload 侧落**对称** funnel。

#2180 进一步暴露固定宽度结构字节的缺口：`ArchiveChecksum` 与 PKI policy/SPKI/chain digest 为保留
`[u8; 32]`、`Copy` 和定长 accessor 被逐类型加入 carve-out，会让安全语义退化为不断扩张的名单。固定宽度
字节需要与动态 payload 对称的单一 Hard carrier，而不是为每个 digest 建立例外。

## 2. 决策（动态/固定宽度双 carrier funnel）

新增 sealed newtype `diport::RedactedBytes`（`crates/diport/src/redacted_bytes.rs`），字节 payload 字段从裸 `Vec<u8>` /
`Option<Vec<u8>>` **迁移**到 `RedactedBytes` / `Option<RedactedBytes>`，删除各 DTO 手写 `impl Debug`、struct 改回
`#[derive(Debug)]`（此时安全）。

新增 crate-internal `RedactedFixedBytes<const N: usize>`：私有 `[u8; N]` 固定长度并保持 `Copy`，唯一
`Debug`/`Display` 实现固定脱敏，语义 wrapper 只暴露自身的 typed constructor/accessor。
`ArchiveChecksum`、`PkiPolicyDigest`、`PkiSpkiDigest`、`PkiChainDigest` 全部持有该 carrier；它们不再是
structural carve-out。

**与 error 侧对称（funnel 范式）**：

| 维度 | error source 侧（已存在） | 字节 payload 侧（本 ADR） |
|------|------|------|
| 上游 Hard 类型 | `RedactedSource`，`Debug`/`Display` 恒 `<redacted>` | **`RedactedBytes` / `RedactedFixedBytes<N>`**，`Debug`/`Display` 恒脱敏 |
| 上游 INVARIANT | DIPORT-ERR-SOURCE-REDACT-01 | **DIPORT-DTO-BYTES-REDACT-01** |
| 下游 dylint | `rss_diport_error_debug_redacted`（禁裸 `Box<dyn Error>` source） | **`rss_diport_dto_debug_redacted`**（禁裸字节缓冲字段） |
| 下游 INVARIANT | DIPORT-ERR-RAWSOURCE-BAN-01 | **DIPORT-DTO-RAWBYTES-BAN-01** |

**与 `RedactedSource` 的关键差异**：`RedactedSource` 是 write-only containment（原始错误 owned、不经任何接口暴露）；
两个字节 carrier **暴露受控字节访问**——动态 payload 经 `new/as_bytes/into_bytes`，固定宽度值只经 crate-internal
`new/as_bytes` 供语义 wrapper 转发。payload 需被 adapter 合法收发，
脱敏只作用于 `Debug` / `Display`（防日志 / tracing 泄漏），不阻断字节本身程序化访问。对标 `secrecy::SecretBox`
（redacted `Debug` `[REDACTED]` + `ExposeSecret::expose_secret` 受控访问）。ref: secrecy secrecy/src/lib.rs@main。

## 3. 上下游强度（funnel 两端，cargo xtask archrules verify）

- **上游（Hard，类型系统）**：两个 carrier 的私有字段和唯一 `Debug` / `Display` 实现固定脱敏，随值走；
  `RedactedFixedBytes<N>` 额外由 const generic 锁定长度并保持 `Copy`。任何持有 carrier 的新类型
  `derive(Debug)` 自动安全（INVARIANT DIPORT-DTO-BYTES-REDACT-01，回归见 `redacted_bytes` 单测）。
- **下游（Medium，dylint）**：`rss_diport_dto_debug_redacted`（`LateLintPass::check_field_def`，**Ty 层** typeck 后判定，
  type alias 透明展开）守「diport crate 内 struct 的字节缓冲字段（`Vec<u8>` / `[u8; N]` / `Box<[u8]>` 或 `Option` 包一层）
  必须采纳与语义匹配的 canonical carrier」。接 `cargo dylint --all`（`cargo xtask verify` 一步，`DYLINT_RUSTFLAGS=-D warnings` fail-closed；
  azure 无 CI ⇒ verify 是唯一实际 gate）。anti-vacuity 两向 UI golden：红向 `ui/diport.rs` 裸字节必报、绿向 `ui/not_diport.rs`
  非守护 crate 不报（INVARIANT DIPORT-DTO-RAWBYTES-BAN-01）。

只锁上游（类型存在）不闭环；只锁下游（lint）非 Hard。两端合一才是闭环 funnel：新类型即便不知道 carrier，裸字节字段也被
lint 拦下、强制采纳上游 Hard 类型。

## 4. canonical carrier enrollment 与 carve-out registry

下游 lint 仅精确放行根模块下的两个 Hard carrier（`is_canonical_redacted_carrier`，完整 `DefId` path）：

| canonical carrier | 裸字节合法原因 |
|------|------|
| `redacted_bytes::RedactedBytes` | 动态 payload Hard carrier，自身内层 `Vec<u8>` 是受控持有点 |
| `redacted_bytes::RedactedFixedBytes<N>` | 固定宽度 Hard carrier，自身内层 `[u8; N]` 是受控持有点；`ArchiveChecksum` 与三个 PKI digest 通过它持有字节 |

除此之外，结构性 registry 最终仅保留两个确实不采用上述 funnel 的类型
（`is_structural_carve_out`，完整 `DefId` path，已限 `LOCAL_CRATE=="diport"`）：

| structural carve-out | 裸字节合法原因 |
|------|------|
| `CertSerial`（`revocation_store.rs`） | RFC5280 证书序列号是公开 CRL 字段，`derive(Debug)` **有意可见原值**（非机密，与密码学物料相反） |
| `SecretMaterial`（`secret_resolver.rs`） | 已 `#[derive(secure::Redact)]` `#[redact(sensitivity = secret)]`——完整 Wire + 日志策略由 `secure` 承载（`RedactedBytes` 仅覆盖 `Debug`/`Display`、不含 Wire 范围），故保留 derive(Redact) + 裸 `Vec<u8>` |

**为何用 in-lint 名单而非生产 `#[allow]`**：dylint lint 未加载时（普通 `cargo clippy`），
生产 `#[allow(rss_diport_dto_debug_redacted)]` 触发 `unknown_lints`，工作区无 `unknown_lints=allow` ⇒ `cargo clippy -D warnings` 红。
故 carve-out 收口进 lint 源（`is_structural_carve_out`）+ 本 registry。**新增 carve-out 须同步**：lint 函数名单 + 本表 + UI 绿例
（`ui/diport.rs` G6/G7）。重命名这些类型会使豁免失配 → lint 误报红（UI golden 漂移）即自救。

canonical carrier enrollment 与 structural carve-out 都按完整 `DefId` path 精确匹配。嵌套或兄弟模块同名类型不能冒充
`redacted_bytes::{RedactedBytes, RedactedFixedBytes}`，语义 wrapper 的短名也不会得到豁免。重命名或移动真源会令
lint/UI golden 立即失败，实现路径漂移自救。

## 5. 范围边界

- **仅字节缓冲**（`Vec<u8>` / `[u8; N]` / `Box<[u8]>` / `Option` 包一层）。String-newtype id（`KeyId` / `Topic` / `MessageId` /
  `SigningPurpose`）**刻意 derive(Debug) 显值**（路由 / 归因元数据，非 PII），不在范围、不误报。
- **error source** 由 `RedactedSource` + `rss_diport_error_debug_redacted` 守，本 funnel **不重复**。
- 仅 redact **非字节字段**（String / map）的 DTO（`EnvelopeMetadata` / `RawCredential` / `VerifiedClaims` / `ObjectKey` /
  `OutboxEnvelopeParts`）不在本字节 funnel，手写 / derive(Redact) Debug 不动（无 Vec<u8> 字段 → lint 不命中）。
- 守护范围限 `diport` crate（其它 crate 的字节字段如 HTTP body 缓冲合法、不误报）。

## 6. 威胁矩阵重评（cargo xtask archrules verify：ADR 落地须重评安全模型）

| 威胁 | 处置前 | 处置后 |
|------|--------|--------|
| 新增 diport DTO 字节 payload 裸 `derive(Debug)` → 日志 / tracing 泄漏 PII / 密钥 | **Soft**（靠人记 + review；`rss_redact_debug_required` 名单不覆盖未登记新类型） | **Hard 上游**（采纳对应 carrier 即脱敏）+ **Medium 下游**（lint 拦裸字节、强制采纳） |
| 既有手写 Debug 复归裸 derive（删手写 impl 误加 derive 不脱敏） | Medium（单测） | Hard（字段已是 redacted carrier，derive 安全）+ lint 兜底 |
| 固定宽度 digest 持续扩张逐类型 carve-out | Medium 名单，新增类型默认误报 | 单一 `RedactedFixedBytes<N>` Hard funnel；语义 wrapper 不进入 registry |
| type alias 绕过（`type Bytes = Vec<u8>`） | n/a | 关闭（Ty 层判定透明展开 alias） |
| 公开字节（CertSerial）误脱敏 / secure-governed（SecretMaterial）双重治理 | n/a | carve-out registry（§4）显式放行 + 文档化原因 |
| 字节访问被脱敏阻断（adapter 无法收发 payload） | n/a | `as_bytes`/`into_bytes` 受控访问（非 write-only，区别于 RedactedSource） |

残留风险：lint 仅 `cargo dylint --all`（接 verify）拦，azure 无 CI ⇒ verify 是唯一 gate（与全仓 dylint 同档，Medium 固有）；
`#[cfg(test)]` 子树不扫（test-only 字节字段放行，与 error lint 同范式）。

## 7. enforcement 载体映射

| 约束 | 档 | 载体 |
|------|----|------|
| 持有动态/固定 redacted carrier 即 Debug/Display 脱敏 | Hard | 私有字段 + 唯一 Debug/Display impl（DIPORT-DTO-BYTES-REDACT-01） |
| diport 字节字段必须采纳对应 carrier | Medium | dylint `rss_diport_dto_debug_redacted`（`-D warnings` fail-closed，DIPORT-DTO-RAWBYTES-BAN-01） |
| carve-out 名单与 registry 同步 | Medium | lint `is_structural_carve_out` + UI golden 漂移自救 + 本 ADR §4 |

> 评估过但未采纳：**全域 `forbid derive(Debug)` + 显式豁免清单**（翻转默认）——会改全 DTO 编写范式、对非敏感 enum / POD / id
> newtype 造成大面噪声，收益不抵成本；字节缓冲 funnel 精确命中 PII 形状，已达 Hard 上游，不需翻转默认。**derive(secure::Redact)
> 替代 RedactedBytes**（保留 `Vec<u8>` 字段类型、零调用方扇出）——更简但脱敏 per-struct（靠 lint 守新增），非「随值走」；本 ADR
> 选 RedactedBytes 取最强 Hard + 与 RedactedSource 完全对称（#1155 处置门用户确认）。
