# ADR-011：字段级数据保护边界 — observe redaction 与 storage encryption 分层单源

- **状态**：Accepted（**设计单源**；本 ADR **不实现**任何加解密执行体，只定语义、边界、AAD/envelope 形态与归属。执行体随
  #1465 framework 底座 / #1466 KeyProvider-Vault / #1467 settings ConfigValue 加密逐个落地）
- **日期**：2026-06-27
- **关联**：issue #1478 [blind index 等值查询策略 #1478] · issue #1471 [field-protection ADR] · 子 Feature #1465 [framework 底座] / #1466 [KeyProvider 与 Vault Transit] /
  #1467 [settings ConfigValue 静态加密] · capability gap **P1-9**（`docs/migration-from-gocell/202606240130-006-gocell-rss-capability-gaps.md`）
  · **子设计 ADR-012**（`202606271755-012-settings-configvalue-encryption-design.md`，issue **#1473**：把 §D7 #1467 具体化到 settings —— AADForConfig 字节编码 / 存储列 migration / 旧明文读 + 回滚 / 保护策略分层）
- **依赖 ADR**：**ADR-003**（DI dynosaur 派发 → KeyProvider port 归属）· **ADR-005**（域形 vs infra port category line，本 ADR 复用其归属判据不重证）
- **既有能力**：#1359/#1360 已交付 observe-time 字段级 **redaction**（`securederive::Redact` derive + `secure` redaction funnel）；本 ADR 在其上把 **storage encryption** 划成独立面
- **归属**：framework（数据保护语义边界 / DI 接缝 / provider-agnostic 基础设施治理，正确性要求 provider 可互换）
- **AI-robust 评级**：见 §3 + §6（AAD 必填 / AAD 上下文派生 / deterministic opt-in / no-decrypt-in-debug 落地时 **Hard via 类型系统**；KeyProvider 归属定义面 + impl 面 + 访问审计均 **Medium**）

---

## 1. 背景

#1359/#1360 把字段级 **redaction** 引入 RSS：任意 struct 经 `#[derive(secure::Redact)]` + 字段属性显式声明敏感度与 mode，
派生 fail-closed 的安全 `Debug`（`crates/securederive/src/lib.rs`、`crates/secure/src/redaction.rs`、`docs/rules/observability.md`
§Redaction）。这条能力只作用于**可观测面**（Debug / 日志 / trace / `last_error`）——它把明文挡在「输出到人能看见的地方」之外。

但**静态存储面（at-rest）的加密**至今无统一设计单源。P1-9 capability gap 仍指出四项缺口：`diport` 无 `KeyProvider` port；
`secure::Aead` 的 `seal(plaintext)`/`open(ct)` **无 AAD 参数**（`crates/secure/src/aead.rs`，纯接缝）；`primitives/crypto.rs` rustdoc
指向**不存在**的 `diport::KeyProvider`（doc 落空）；`settings` `ConfigValue` 仍是明文 newtype（`crates/settings/src/domain/mod.rs`，
Debug 脱敏 + 敏感 key 拒写，材料不落库但无加密）。

若不先立设计边界直接实现，redaction（脱敏展示）/ encryption（静态加密）/ secret resolver（外部 store 坐标引用）/ Vault signer
（签名）四件事容易混成一套模糊能力。本 ADR 把**字段级数据保护边界**定为架构单源：哪些是 observe-time、哪些是 at-rest、AAD 为何
必填、envelope 形态、deterministic 何时 opt-in、debug 面为何永不 decrypt、KeyProvider port 归属谁、能力如何拆成三个 feature
自底向上长出，以及每条约束落地时钉哪一档 enforcement 载体。

## 2. 决策（字段级数据保护边界单源）

### D1 — observe-redaction 与 storage-encryption 双层分离

两条正交的数据保护面，**不混用、不互相替代**：

| 面 | 触发时机 | 保护对象 | 载体 | 状态 |
|----|---------|---------|------|------|
| **observe-redaction** | observe-time（Debug / 日志 / trace / `last_error`） | 「值被人/外部看见」 | `securederive::Redact` + `secure` redaction funnel | **已交付**（#1359/#1360） |
| **storage-encryption** | at-rest（落库 / 跨信任边界持久化） | 「值在静态存储被读取」 | `secure` AEAD v2 envelope + `diport::KeyProvider` + 域持久化路径 | **待落**（#1465/#1466/#1467） |

不变式：**redaction ≠ encryption**；**debug / 日志 / trace 面永不出现解密结果**（D5）。对标 `redactable`
（`TracingRedactedExt` 在 subscriber 之前脱敏，observe-time redaction 与 at-rest encryption 完全解耦）。

### D1b — 声明层 vs 加解密层（framework 底座 #1465 的边界）

保护语义分两层落地，framework 底座只立**声明层**，不接真实加解密：

- **authoring / 声明面**：contract `*.schema.json` 经 `x-protection` 声明字段需加密保护，`cargo xtask contract validate` /
  `breaking` 守门（与既有 `x-pii` / `x-redaction` 同源范式，observability.md §Redaction「contract → generated 字段策略」）。
- **generated 携带保护元数据**，但**不触发真实加解密**——生成类型只标「此字段受保护 + AAD 维度」，加解密在消费侧经注入的
  `KeyProvider` 完成。
- framework 底座（#1465）在 `secure` 立 **AAD / ciphertext envelope / AEAD v2** 基础类型 + `x-protection` validate/breaking gate，
  **不接 Vault、不改业务持久化**。真实 envelope 加解密 = #1466（provider）+ #1467（settings 持久化）。

### D2 — AAD 必填（跨上下文重放防御）

storage-encryption 的 AEAD `seal`/`open` **必须携带 AAD**（additional authenticated data），不是可选项：

- AAD = **复合域坐标绑定**。字段级粒度 = **tenant / config-key / field / schema-version**（取自 #1467），把密文绑死到它所属的
  租户 + 配置键 + 字段 + schema 版本——任一维度不匹配则 `open` fail-closed，杜绝跨 entry / 跨租 / 跨字段 / 跨版本重放。
- 本 ADR 声明 `secure::Aead`(v2) 的 `seal`/`open` 增 `aad` 参数（**仅设计声明**，执行体在 #1465 立类型 / #1466 / #1467 impl）。
- **`open()` 时 AAD 必须从受信派生上下文重新派生**（tenant 取自 Principal/JWT 或经授权维护身份，config-key/field/schema 取自被解密
  记录的已知坐标），**绝不把 envelope 中存储的 AAD 直接回灌给 `open()`**——否则攻击者整体复制 `(ciphertext, stored_aad)` 跨租，`open`
  用 stored AAD 自洽验签成功 = 跨租重放绕过（AEAD 的跨租绑定只在 open 用「上下文派生 AAD」时才成立）。存储的 AAD 仅供标识 / 路由 / 审计。
  受信派生上下文有**两类来源**（均从可信记录坐标重派生、均禁回灌 stored bytes）：① **已鉴权请求上下文**（HTTP / RPC，tenant 取自
  Principal/JWT）；② **经授权的维护 / 迁移上下文**（backfill / rewrap / key rotation 等离线路径，无 HTTP 请求但在授权下按记录坐标重派生）。
  INVARIANT `FIELDPROT-AAD-DERIVE-FROM-CTX-01`（Hard 化方向：`open(aad: &DerivedAad)`，`DerivedAad` 只可经受控 funnel `ProtectionContext`
  从上述两类受信源构造，外部不可裸拼 stored bytes）。
- AAD 内容本身**非机密**（绑定不保密，可随 envelope 元数据存供标识/审计）——对齐 AWS encryption context「绑定而非加密」语义；
  但其**完整性由 AEAD tag 覆盖**，任一 AAD 维度被篡改（如改 schema-version 试探降级）→ `open` 认证失败 fail-closed。

对标：Vault Transit `context` 参数（decrypt 时强制一致）+ AWS Encryption SDK encryption context（绑定到 message header，best
practice）。**RSS 偏离 = 取 Vault 的强制性**：RSS 的 AAD 在类型层必填（D2 Hard），不做 AWS 式可选。

### D3 — Envelope 格式 + key 轮换

- **格式**：版本前缀 `vN:` + 本地随机 DEK（data key）加密 plaintext → 本地 AES-GCM；DEK 经 master/wrapping key 包裹为 EDK
  （encrypted data key）；AAD 维度随 envelope 元数据。对标 Vault `vault:vN:` 密文版本前缀 + AWS EDK（unique DEK per message）。
- **nonce 唯一性（AES-GCM 安全关键）**：每次 `seal` 用唯一 nonce（96-bit 随机或 per-DEK 计数器），**(DEK, nonce) 绝不重用**——
  AES-GCM 下 (key, nonce) 重用会泄漏 GHASH 认证子密钥（catastrophic forgery）。列入 #1466 验收。
- **轮换**：采 **current-primary 写 + previous-read 兼容 + rewrap**（取自 #1466）——新写一律用 current-primary key；旧密文按其
  key-id/version 用 previous-read key 解；`rewrap` 把旧密文重新包裹到 current-primary，不重新加密 plaintext（对标 Vault Transit
  `rewrap`）。key-id 匹配走 **常数时间比较**（`constant_time_eq`，复用 `primitives::crypto`）防 timing oracle。

### D4 — Blind index（HMAC keyed-hash）为唯一等值查询机制；AES-SIV deterministic-AEAD 不用于 blind index

**默认非确定**：标准 AEAD 用随机 nonce，相同 plaintext 产不同 ciphertext（默认 off，安全优先）。等值查询需求由旁路 HMAC blind index 满足，**不**通过将主密文改为确定性 AEAD 来实现。

两条「按索引列查询」路径存在本质区别；本 ADR **采纳 HMAC blind index（路径 B）**，否决 AES-SIV（路径 A，见 §7 备选）：

- **路径 A（已否决）—— deterministic-AEAD（AES-SIV）**：值本身用确定性 AEAD 加密，相同明文总产同一密文，密文即可直接等值查询。
  代价：**值密文全泄漏相等性**（pattern leak 范围最大）。对标证据见 Tink DAEAD「leaks plaintext equality」文档（§对标证据）。
- **路径 B（已采纳）—— HMAC blind index（CipherSweet 模型）**：值**仍用随机化 AEAD**（主密文不泄漏相等性），旁路额外一列写入
  截断 keyed-HMAC 作为等值查询索引。索引列仅泄漏「经截断钝化的等值性」；主密文的相等性不暴露。已落代码：
  `crates/secure/src/blind_index.rs`（issue #1478，commit 3750ed17）。

**实现规范（与已落代码一致）**：

1. **子密钥派生**：每条 blind index 按 (tenant / domain / field / index-name) 四维独立派生子密钥：
   `tenant` 在 runtime API 中必须先收敛为 `vocab::tenant::TenantId`（canonical UUID，非裸字符串）。
   `derive_subkey = HMAC-SHA256(root_key, lp(CONTEXT) ‖ lp(tenant.to_string()) ‖ lp(domain) ‖ lp(field) ‖ lp(index_name))`，
   `lp(x) = u64-BE(len(x)) ‖ x`（长度前缀防拼接歧义），CONTEXT = `b"rss.blind-index.subkey.v1"` 域分隔（任一
   变更漂移不同子密钥）。子密钥隔离：一个 index 密钥泄漏不影响同字段其他 index 或同租户其他字段。派生维度中
   domain + index-name 是代码侧命名空间（灵活）；**authoring 声明侧稳定子集 = tenant / config-key / field**（见下）。

2. **截断（FilterBits）**：索引值 = HMAC-SHA256 截取 `FilterBits`（`1..=256`，默认 256 bit；末字节按高位保留，余位清低位）。
   截断越小 → 碰撞越多 → 等值性泄漏越钝 / 误命中越多；误命中由解密后比对过滤兜底。默认 256 bit（最精确），
   字段 owner 可调低并在字段声明处文档化权衡（低基数/可接受相等性暴露的字段）。

3. **规范化管道（Transform）**：`BlindIndex` funnel 在计算 HMAC 前按声明的 `Transform` 序列规范化输入
   （`Lowercase / Trim / DigitsOnly / LastN`）。**写路径与查询路径须使用同一 transform 链**，否则等值查询静默失效；
   `BlindIndex` 结构将 transform 链与 scope / filterBits 绑定，低层函数不对 crate 外公开，类型层强制写/查同源
   （`BlindIndex::index` / `BlindIndex::lookup_set`）。

4. **轮换窗口**：新写一律用 current 子密钥；查询用 `lookup_set`（current + previous OR-set），旧索引值经 previous
   子密钥计算后绑入 `WHERE idx IN ($1, $2, …)` 查询；该查询只产出候选集，命中行须经可信 AAD 解密后再按同一
   transform 链明文比对，过滤 FilterBits 截断碰撞。schema 演进须 re-index（与 #1467 rewrap 计划联动）。

5. **等值-only 不变式**：`BlindIndexValue` 不 derive `Ord`/`PartialOrd`/`Eq`，仅 `subtle::ConstantTimeEq`（防 timing oracle）；
   无 range / prefix / sort API ⇒ 范围 / 前缀查询类型层不可表达（`FIELDPROT-BLINDIDX-EQUALITYONLY-01`，Hard，§3）。

**稳定子集 scope（与 D2 对齐）**：blind index 子密钥派生使用**不含 schema-version** 的稳定子集（tenant/config-key/field），
确保 schema 演进后旧 index 值与新查询仍相等。代价：binding 范围比主密文 AAD 窄 schema-version 一维，须文档化；
schema 演进时 blind index 仍须 re-index。稳定维度在 authoring 面经 `x-protection.aad`（稳定子集，拒 `schemaVersion`）声明。

**Authoring 声明面 = `x-protection.mode=blindIndex`（#1468，单源）**：blind index 的 contract authoring 不另立平行注解——
统一经 #1468 的 `x-protection{atRest:encrypt, mode:blindIndex, keyScope, aad:[tenant,configKey,field], reason}` 声明，
`cargo xtask contract validate` R17 `SchemaProtection` fail-closed（`mode=deterministic|blindIndex` 须非空 reason +
稳定子集 aad 排除 schemaVersion）、`contract breaking` `PROTECTION_POLICY_CHANGED` 守漂移（INVARIANT
`CONTRACT-PROTECTION-POLICY-01`，Medium，#1468 承载）。本 ADR 不再引入独立 `x-blind-index` 注解（避免双授权路径）。

**运行体 = `secure::blind_index`（本 PR #1478）**：上述 authoring `mode=blindIndex` 的真实 HMAC 计算由 `crates/secure/src/blind_index.rs`
提供（子密钥派生 / 截断 / 规范化 / 轮换 / 等值-only），经 #1465/#1466 KeyProvider 接线消费。authoring（#1468 声明）+ runtime
（#1478 原语）分层落地，不重复。

**`FIELDPROT-DETERMINISTIC-OPTIN-01`**（Hard，typed-function-choice）仍守「确定/非确定拆不同 API，不靠 bool flag 默认值」——
AES-SIV deterministic-AEAD 路径整体在 RSS 不使用（无代码实现，§7 已否决）；`mode=blindIndex` 的运行体即本 PR 的 HMAC 旁路索引。

对标：CipherSweet（per-(table,col,index) HMAC-SHA256 子密钥 + filterBits 截断 + transformations[]，见 §对标证据）。
Tink DAEAD「leaks plaintext equality」作为 AES-SIV 路径的否决论据（§7 备选 + §对标证据）。

### D5 — no-decrypt-in-debug

- 密文容器（`secure::Ciphertext` 已 `#[redact(sensitivity = secret)]` → `Ciphertext(<redacted>)`）与**解密结果**类型在 Debug / 日志 / trace 面
  **永不渲染明文**：`ConfigValue` 加密后 Debug 仍不解密（取自 #1467）；解密产出经 `secrecy::Secret<T>` 式封装 / `#[redact(sensitivity = secret)]`。
- KeyProvider 的解密访问经**审计路径**、错误源**脱敏**（取自 #1466，避免错误链泄漏密钥材料 / 明文）。INVARIANT
  `FIELDPROT-KEYPROV-AUDIT-01`（Medium，§3）；其中「错误源脱敏」同属 `FIELDPROT-NODBG-DECRYPT-01` 家族（不泄漏 secret 到可观测面）。
- 对标 `secrecy` crate（`Secret<T>` 的 `Debug` = `[REDACTED]` + `Drop` 触发 zeroize；`ExposeSecret` trait 强制显式访问审计点）。

### D6 — KeyProvider port 归属 diport（provider-agnostic infra port）

`KeyProvider` / `ValueTransformer` 是**可替换 provider 的 DI 注入 port**（签名只引基础 / `generated` / port 自定义类型，不引域
实体），按 ADR-005 §2.1 category line → 归 **`diport`**（ADR-003 范式，dynosaur Send 变体），**不放域 crate**。归属反向测试
（「此 port 能否在 `diport` 内编译而不让 diport 新增域依赖」=能）见 ADR-005 §2.1，本 ADR 不重证。`adapters/vault` 经 DIP 内向边
impl，不被域依赖。本 ADR 即修正 `primitives/crypto.rs` / `secure/aead.rs` 指向本 ADR（消除 doc 落空）。

### D7 — 3-feature 拆分 + 单源验收清单

能力拆为三个 feature 自底向上长出，本 ADR 是其**共同设计单源 + 单源验收清单**（逐条对齐各 feature body 的验收标准 + INVARIANT ID）：

**#1465 framework 底座**（声明层，不接 Vault / 不改持久化）
- [ ] redaction↔encryption 职责边界有 ADR / rules 单源（**=本 ADR-011 + observability.md 同步**）。
- [ ] `secure` 具备 AAD / ciphertext envelope / **AEAD v2** 基础类型（`seal`/`open` 带 `aad`，`FIELDPROT-AAD-MANDATORY-01`）。
- [ ] `open(aad)` 的 AAD 经 `ProtectionContext`（已鉴权请求 + 经授权维护/迁移两类受信源）派生、不可裸拼 stored bytes（`FIELDPROT-AAD-DERIVE-FROM-CTX-01`）。
- [x] contract authoring 支持 `x-protection` + `validate` / `breaking` gate。（delivered by #1468——单独立项的 authoring+gate 切片：contract validate R17 `SchemaProtection` + breaking `PROTECTION_POLICY_CHANGED` + `x-at-rest` 强制覆盖 + 文档）
- [ ] generated 携带保护元数据但**不触发真实加解密**。

**#1466 KeyProvider 与 Vault Transit 加解密**（provider 层）
- [ ] `diport` 有 `KeyProvider` / `ValueTransformer` port（dynosaur Send 变体，错误源脱敏，`DIPORT-MACRO-CONFINE-01′` / `DIPORT-IMPL-ALLOWLIST-01`）。
- [ ] `adapters/vault` 实现 encrypt / decrypt / **rewrap** 路径。
- [ ] AES-GCM (DEK, nonce) 唯一性：每次加密唯一 nonce、DEK 不跨 message 重用（D3）。
- [ ] 支持 key id / version / **current-primary + previous-read** 轮换（D3）。
- [ ] AAD mismatch + 跨租 / 跨字段 replay 均 **fail-closed**（`FIELDPROT-AAD-MANDATORY-01`）。
- [ ] master-key compromise 应急运维流程记录（rewrap 仅重包裹 DEK、不覆盖此场景，须全量 DEK 重加密，D3/§5）。

**#1467 settings ConfigValue 静态加密落地**（持久化层）
- [ ] `ConfigValue` 持久化用加密 envelope，Debug 仍不解密（`FIELDPROT-NODBG-DECRYPT-01`）。
- [ ] AAD 绑定 **tenant / config-key / field / schema-version**，跨上下文不可解（D2）。
- [ ] 旧明文读有兼容策略 + 迁移计划（previous-read / backfill）。
- [ ] backfill / **rewrap** / key rotation 离线路径经**经授权维护 `ProtectionContext`** 按记录坐标重派生 AAD（无 HTTP 请求上下文，`FIELDPROT-AAD-DERIVE-FROM-CTX-01`）+ runbook + 集成测试覆盖；可选 **blind index** 等值查询（D4 deterministic opt-in，用稳定子集 AAD、schema 演进须 re-index）。

## 3. INVARIANT / 载体落点（AI-robust：每决策钉 Hard/Medium 载体，禁止 Soft）

本 ADR 为后续 3 feature **预先指定 enforcement 载体**，防落地退化成口头约定 / 运行期治理测试：

| 决策 | INVARIANT | 评级 | 载体 |
|------|-----------|------|------|
| D2 AAD 必填 | `FIELDPROT-AAD-MANDATORY-01` | **Hard（构造器/签名必填参数 + newtype funnel）** | `secure::Aead`(v2) `seal`/`open` 的 `aad: &Aad` 为**必填位置参**（非 `Option`），缺失即编译错误；`Aad` 复合坐标经受控构造 funnel（外部不可裸拼任意 AAD） |
| D4 deterministic 默认 off | `FIELDPROT-DETERMINISTIC-OPTIN-01` | **Hard（typed function choice）** | 确定 / 非确定拆不同 API 或 explicit opt-in 类型，默认随机；不靠 bool flag 默认值表达 |
| D4 blind-index 等值-only（runtime，本 PR #1478） | `FIELDPROT-BLINDIDX-EQUALITYONLY-01` | **Hard（类型系统）** | `BlindIndexValue`（`crates/secure/src/blind_index.rs`）不 derive `Ord`/`PartialOrd`/`Eq`、仅 `subtle::ConstantTimeEq`；无 range/prefix API ⇒ 范围/前缀查询类型层不可表达。与 authoring 门 `CONTRACT-PROTECTION-POLICY-01`（#1468，`x-protection.mode=blindIndex` 须 reason + 稳定子集 aad）互补：authoring 声明 + runtime 类型两档共守等值边界 |
| D2 AAD 派生来源 | `FIELDPROT-AAD-DERIVE-FROM-CTX-01` | **Hard（newtype + 构造封闭）** | `open(aad: &DerivedAad)`，`DerivedAad` 只可经受控 funnel `ProtectionContext`（已鉴权请求 + 经授权维护/迁移两类受信源）构造，外部无法用 DB stored bytes 裸拼 → 杜绝跨租重放 |
| D5 no-decrypt-in-debug | `FIELDPROT-NODBG-DECRYPT-01` | **Hard（类型系统）** | 密文经 `#[redact(sensitivity = secret)]`（`Ciphertext` 已有）、解密产出经 `secrecy::Secret<T>` 封装——两种机制各封 `Debug`，类型层杜绝明文进 Debug |
| D5 KeyProvider 访问审计 | `FIELDPROT-KEYPROV-AUDIT-01` | **Medium（governance + tracing）** | KeyProvider 解密访问经 tracing span 审计 + 错误源脱敏（错误链不泄漏密钥/明文）；落地 #1466 由 `cargo xtask` 审计路径治理测试守 |
| D6 KeyProvider 归属 diport | `DIPORT-MACRO-CONFINE-01′`（定义面）/ `DIPORT-IMPL-ALLOWLIST-01`（impl 面） | **Medium 定义面 + Medium impl 面** | cargo-deny 宏依赖白名单（`-01′`）守「port 只在 diport 定义」；dylint `rss_diport_impl_allowlist` 守「impl 只在 adapter / 组合根」（ADR-003 §4.2） |

本 PR（#1471）只**声明**这些载体与 INVARIANT ID（设计单源），**不实现**——执行体各归 #1465（AAD-MANDATORY / AAD-DERIVE-FROM-CTX /
DETERMINISTIC / NODBG 类型）/ #1466（DIPORT-* + KEYPROV-AUDIT 守卫）/ #1467（NODBG 落 ConfigValue）。无 Soft 新增 enforcement。

## 4. 后果

- **正**：字段级数据保护有单源边界（redaction / encryption 不再混淆）；三个 feature 自底向上长、共享一份验收清单；
  AAD 必填 + deterministic opt-in + no-decrypt-in-debug 在落地时由类型系统免费成立（Hard）；**零新增 crate / 零新增分层**
  （沿用 `secure` + `diport` + 域持久化路径，envelope / AEAD v2 是 `secure` 内类型演进）。
- **负 / 代价**：① `secure::Aead` 从 v1（无 aad）演进到 v2（带 aad）是破坏式签名变更，但 pre-GA 窗口内 in-repo 调用方随同一
  feature 原子更新（api-versioning.md §兼容窗口），无 wire 影响；② deterministic opt-in 字段需逐个评估 pattern-leak 风险，认知成本
  落在字段 owner（由 D4 文档化权衡 + review 兜）；③ AAD schema-version 维度要求 schema 演进时显式纳入 rewrap 计划（#1467 runbook）。
- **下游**：#1465 → #1466 → #1467 按 §D7 顺序落地，每步勾对应验收 checklist + INVARIANT。

## 5. 威胁矩阵

| 威胁 | 缺失的约束 | 缓解（本 ADR 决策） |
|------|-----------|---------------------|
| 跨租 / 跨 key / 跨字段密文重放 | AAD 缺失或可选 | D2 AAD 必填（Hard `FIELDPROT-AAD-MANDATORY-01`）+ 复合域坐标绑定 |
| 复制 `(ciphertext, stored_aad)` 跨租（open 用存储 AAD 自洽验签） | `open` 从 DB 加载 stored AAD 而非上下文派生 | D2 `FIELDPROT-AAD-DERIVE-FROM-CTX-01`（`open` AAD 经 `ProtectionContext` 从受信源派生，stored AAD 仅标识/审计） |
| AAD / envelope 元数据被篡改（降级试探） | AAD 明文可改 | AEAD tag 覆盖 AAD：任一维度被改 → `open` 认证失败 fail-closed（D2/D3） |
| AES-GCM (DEK, nonce) 重用 | nonce 唯一性未强制 | D3 每次 `seal` 唯一 nonce、(DEK,nonce) 不重用（#1466 验收） |
| 主密钥（master/wrapping key）泄漏 | 无紧急替换路径 | 超出 `rewrap`（仅重包裹 DEK）；属 KMS 运维规程，#1466 记录 master-key-compromise 应急（全量 DEK 重加密） |
| 主密文相等性泄漏（pattern leak，AES-SIV 路径） | AES-SIV deterministic-AEAD 误用 / 默认开 | D4 AES-SIV 路径整体否决（§7）；RSS 不实现 AES-SIV blind index，`FIELDPROT-DETERMINISTIC-OPTIN-01` 守 typed-function-choice |
| HMAC blind index 索引列频率/字典分析（旁路泄漏） | 索引列相等性可观察，可离线频率/字典攻击 | D4 FilterBits 截断钝化（默认 256 bit，可调低）+ opt-in 仅限低基数/可接受字段（`x-protection.mode=blindIndex` 的 reason 必填文档化，#1468 R17）+ 等值-only 不保序（无序位不可排序遍历） |
| HMAC blind index 截断碰撞 → 误命中 | 索引列不精确匹配返回错误行 | D4 截断设计语义：碰撞候选由解密后明文比对过滤兜底（不是 bug，是 Bloom-ish 权衡；FilterBits 调高可降碰撞率） |
| 明文经 Debug / 日志 / trace 泄漏 | 解密结果可渲染 | D5 no-decrypt-in-debug（Hard `FIELDPROT-NODBG-DECRYPT-01`） |
| 静态数据无加密（settings 现状） | ConfigValue 明文落库 | D1/D3 storage-encryption envelope（#1467 落地） |
| 密钥材料经错误链泄漏 | 错误源未脱敏 | D5 KeyProvider 访问审计 + 错误源脱敏（#1466） |
| key-id 匹配 timing oracle | 非常数时间比较 | D3 `constant_time_eq`（`primitives::crypto`） |

## 6. AI-robust 分级汇总

见 §3 载体表。enforcement 落地时为 Hard（类型系统 / 构造器必填参数 / newtype 构造封闭 / typed function choice）或 Medium
（diport 定义面 cargo-deny `DIPORT-MACRO-CONFINE-01′` + impl 面 dylint allowlist；KeyProvider 审计路径 `cargo xtask` governance
测试）。无 Soft 新增 enforcement。ADR 本身是设计单源文档，不创建新 enforcement 机制——它**规定**后续 feature 的载体档位，
禁止 feature 落地时退化。

## 7. 备选（为何不取）

- **AAD 可选（AWS 式 best-practice 但不强制）**：被否决——RSS 是零信任 / MDM 治理方向，跨租重放是首发安全核心，AAD 必须类型层
  必填（取 Vault 强制性），不接受「忘记传 context = 静默可重放」。
- **blind index 机制改用 AES-SIV deterministic-AEAD（值即确定性密文）**：被否决——AES-SIV 令值密文本身全泄漏相等性（任何能读主密文列者均可观察哪些行有相同值，pattern leak 范围最大）；而 HMAC blind index 旁路方案使主密文保持随机化 AEAD，仅旁路索引列泄漏经截断钝化的等值性，安全边界优于 AES-SIV。AES-SIV「leaks plaintext equality」代价由 Tink DAEAD 文档明确（§对标证据）。RSS 采纳 HMAC blind index（CipherSweet 模型，`crates/secure/src/blind_index.rs`）。
- **deterministic 默认 on（便于查询）**：被否决——默认暴露明文相等性违反安全优先；blind index 是特例，按字段 opt-in 并文档化代价。
- **把 redaction 直接当 encryption（同一套能力）**：被否决——observe-time 脱敏与 at-rest 加密正交（D1），混用会让「日志看不见」被
  误当「存储安全」，留静态明文。
- **KeyProvider 放域 crate**：被否决——provider-agnostic infra port 放域 crate 会让 adapter→域 反向依赖、层序倒置（ADR-005
  category line），归 `diport`。

## 对标证据（ref）

- `ref: paragonie/ciphersweet src/EncryptedRow.php@master`（https://github.com/paragonie/ciphersweet）—
  per-(table,col,index) HMAC-SHA256 子密钥（`EncryptedRow::addBlindIndex`）；`ref: paragonie/ciphersweet src/BlindIndex.php@master` —
  filterBits 截断（`$filterBitLength`）+ transformations[]（`Lowercase`/`FourDigitYear` 等同款 transform 链）；
  `ref: paragonie/ciphersweet src/Backend/BoringCrypto.php@master` — bit-mask 截断实现；对应 D4 子密钥派生 /
  FilterBits 截断 / Transform 规范化管道三实现要点（`crates/secure/src/blind_index.rs` 与之同形）。
- `ref: hashicorp/vault builtin/logical/transit/path_encrypt.go@main` — envelope encryption + `context`(≈AAD) decrypt 时强制一致
  + convergent v3 PRF-derived nonce + `rewrap` 重包裹，对应 D2（AAD 强制）/ D3（envelope + 轮换）/ D4（deterministic opt-in）。
- `ref: tink-crypto/tink-go daead/subtle/aes_siv.go@main`（https://developers.google.com/tink/deterministic-aead）— DeterministicAEAD
  = AES256-SIV（S2V + CMAC），AAD 作为 SIV 输入；文档明确 deterministic「leaks plaintext equality」代价，对应 D4 deterministic opt-in + blind index AAD 维度 + 权衡文档化。
- `ref: awslabs/aws-encryption-sdk-specification framework/structures.md@master`（https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html）
  — encryption context as AAD（绑定到 message header、非机密、best practice）+ key commitment，对应 D2（AAD 绑定语义）/ D3（EDK 结构）。
- `ref: iqlusioninc/crates secrecy/src/lib.rs@main`（https://docs.rs/secrecy）— `Secret<T>` + `ExposeSecret` trait，`Debug` =
  `[REDACTED]` + `Drop` zeroize，对应 D5 no-decrypt-in-debug + KeyProvider 访问审计路径。
- `ref: sformisano/redactable`（tracing 集成）— observe-time redaction（subscriber 之前脱敏）与 at-rest encryption 解耦，
  对应 D1 双层分离。
