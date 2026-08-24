# ADR-012：settings `ConfigValue` 静态加密 — AAD 编码 + migration + 保护策略分层（settings 具体设计单源）

- **状态**：Accepted（**设计单源**；本 ADR 最初不实现任何加解密 / migration 执行体，只把 ADR-011 通用字段保护边界
  **具体化到 settings `ConfigValue`**：`AADForConfig` 字节编码、存储列 / migration 形态、旧明文维护 + 回滚路径、
  `EncryptedConfigValue`/envelope 归属、保护策略分层。#1477 已落地执行体与 `0029` migration，仍**不跑批量迁移**）
- **日期**：2026-06-27
- **关联**：issue **#1473** [settings-encryption — ConfigValue AAD + migration design] · **父 ADR-011**
  [字段级数据保护边界]（本 ADR 是其 §D7「#1467 settings ConfigValue 静态加密」checklist 的 settings 具体化，
  并补齐 ADR-011 对 settings 留下的 under-spec）· #1465 framework 底座 · #1466 KeyProvider/Vault ·
  #1467 settings ConfigValue 静态加密 · #1612 Postgres persistence capability 收口
- **依赖 ADR**：**ADR-004**（`ConfigValue` 冻结终态 → 加密落持久化边界、不改域类型）· **ADR-005**（域形 vs
  provider-agnostic infra port category line → `KeyProvider` 归 `diport`，本 ADR 复用不重证）· **ADR-011**
  （AAD 必填 / 上下文派生 / envelope / 轮换 / no-decrypt-in-debug 通用语义，本 ADR 继承不重证）
- **底座依赖（已由 #1477 消耗）**：底座 framework（`secure` AEAD v2 带 `aad` + `Aad` +
  `ProtectionContext` funnel）→ KeyProvider/Vault（`diport::KeyProvider`/`ValueTransformer` + `adapters/vault`
  加解密 / rewrap）。#1477 复用这些底座，不新增 settings domain crypto abstraction。
- **AI-robust 评级**：见 §3 + §6（AAD 组合 / field 常量 / canonical 字节 / envelope 版本 / 边界约束落地时
  **Hard via 类型系统 + golden**；adapter 侧不调用 AEAD 密码原语与 KeyProvider 访问审计为 **Medium**；**无 Soft 新增**）

---

> **#1477 implementation note**：落地实现没有引入本文 sketch 中独立的 `AADForConfig` 编码器，而是直接使用现有
> `secure::ProtectionContext::authenticated_request(tenant, config_key, "settings.config.value", 1).derive()` 作为 AAD
> 单源。四个维度仍是 tenant / config key / field / scheme；scheme 固定为 `1`，field 固定为
> `settings.config.value`。Postgres 新写恒为 scheme `1`；legacy scheme `0` 仅能由已授权 maintenance
> backfill 处理，serving 读取 fail-closed。部署或解除 legacy plaintext 启动门前必须先完成 backfill。

> **#1612 decision upgrade**：backfill/rewrap 已使读、写、维护共享 provider 身份成为可执行不变式。
> Postgres 因此拥有单一 move-only `ConfigValueCrypto`持久化能力（一个 provider、一个 key、一个私有
> canonical AAD policy），而非 settings 域 crypto abstraction。serving AAD 只经 authenticated-request 路径；
> maintenance AAD 额外必须持有 sealed `ConfigValueMaintenanceCapability`。旧 protection pair 与可交换
> read/write provider lane 被原子删除，但 field=`settings.config.value`、scheme=`1` 和 canonical AAD 字节保持不变，
> 以继续解密已持久化密文。该形状参考 CipherSweet 聚合 engine/field/AAD policy 的 `EncryptedRow`：
> `ref: paragonie/ciphersweet src/EncryptedRow.php`。

## 1. 背景

2026-06-27 本 ADR 做决策时，`settings::ConfigValue`（`crates/settings/src/domain/mod.rs`）是 opaque `String` newtype：Debug 已脱敏
（`ConfigValue(<redacted>)`）、`SettingKey::parse` 用子串黑名单（`secret`/`token`/`password`/`credential`）fail-closed
拒敏感 key——但这两项都只作用在 **observe 面 + 写入校验**，**落库仍是明文**：Postgres `config_entries.value text NOT NULL`
（`adapters/postgres/migrations/0006_create_config.sql`）持久态在脱敏边界之外。这是本 ADR 需要闭合的 at-rest 问题。

后续 #1465–#1467 与 #1477 已将设计落到 `KeyProvider`、protection/AAD 类型、contract protection 校验、
`0029_add_config_value_encryption.sql` 及 settings protection/maintenance 集成测试；本节仅记录决策时的输入，不是当前状态清单。

ADR-011 已把**字段级数据保护边界**立为架构单源：observe-redaction 与 storage-encryption 双层分离（D1），AAD 必填且
**从受信上下文派生、绝不回灌 stored bytes**（D2），envelope `vN:` + DEK/EDK + 轮换（D3），deterministic 默认 off
（D4），no-decrypt-in-debug（D5），`KeyProvider` 归 `diport`（D6），能力拆三 feature 自底向上长（D7）。但 ADR-011 是
**通用边界**——它对 settings 这个具体落地点留了若干 under-spec：`ConfigValue` 是**单个 opaque 值、无子字段**，那 AAD 的
「field」「scheme-version」维度具体取什么？存储列怎么演进才既满足 only-add 迁移又支持轮换/backfill？旧明文怎么经授权 maintenance 收敛？
回滚到底指什么？错误怎么分流？seal 与 DB 事务谁先谁后？

本 ADR 把这些 settings 具体问题钉死，作为 **settings ConfigValue 静态加密的设计单源**，并作为后续实现 PR 的决策输入。
**本 ADR 不引入任何新 crate / 新分层**——通用 AAD/envelope 归 `secure`、`KeyProvider` 归 `diport`，
`ConfigValueCrypto` 与私有 `ConfigValueAadPolicy` 归 `adapters/postgres` 持久化边界。

## 2. 决策（settings ConfigValue 静态加密单源）

### D1 — 加密落**持久化边界**，`ConfigValue` 域类型不动

`ConfigValue` 是 **ADR-004 冻结终态**（opaque-String、`pub(crate)`、`hydrate(明文)` / `value() -> &str` 契约不破）。
静态加密是 **at-rest 持久化关注点**（ADR-011 D1），故：

- **seal 点 = `config_repo::cas_insert`（写）**：决策时 `cas_insert` bind `entry.value()` 明文；落地实现改为 bind
  `value_enc`/`key_id`/`protection_scheme`（`value` bind NULL）。
- **open 点 = `config_repo::hydrate_row`（读）**：按 `protection_scheme` 分支（D6），密文→明文后再
  `ConfigEntry::hydrate(key, 明文, tenant, version)`。`ConfigValue` 全程**不知道**自己被加密过。
- **域 crate 不新增 `diport` 依赖**：加解密能力（注入的 `KeyProvider`/`ValueTransformer`）只进 `adapters/postgres`
  这个组合根可触达的边界，不进纯域 crate（否则破 ADR-005 层序 + 把 async/fallible I/O 拖进 L0 纯逻辑）。

> 这是本 ADR 最大的 review trap：**任何把 envelope 字段塞进 `ConfigValue`、给 `ConfigValue` 加
> `encrypted()` 方法、或在域层调 `KeyProvider` 的提案都违反 ADR-004 冻结 + ADR-005 层序，必须驳回。**

### D2 — canonical AAD policy 归 Postgres persistence capability

两级 funnel，无捷径（对应 ADR-011 D2 `FIELDPROT-AAD-DERIVE-FROM-CTX-01`）：

- **`secure`（底座 framework）** 持有 opaque `Aad`（**无 public 字节构造器**，不能从 DB stored bytes 裸拼）+ 封闭
  `ProtectionContext`（仿 `runctx::RequestCtx` sealing：私有字段、不 derive `Deserialize`、redacted `Debug`、
  capability-gated 构造；两类受信源 = **①已鉴权请求**（tenant 取自 Principal/JWT）/ **②经授权维护/迁移**（无 HTTP
  请求、按记录坐标重派生；**维护类 `ProtectionContext` 必须只经 operator service token（已认证的授权维护身份）+
  强制 audit 注入构造**（每次维护上下文构造 emit 一条 audit event）；**禁止 Soft 门控**（「有 bin 执行权限」不足）；
  构造强制**落在底座**（`ProtectionContext` 定义处 = `secure`/底座），本 ADR 钉死 settings 维护路径（backfill/rewrap）
  对它的依赖与要求；底座未提供该受控构造前，实现 PR **不得**落地维护路径；见 `CONFIGENC-MAINT-CTX-AUTHZ-01`））
  + length-prefixed `AadBuilder`。
- **`adapters/postgres`** 的私有 `ConfigValueAadPolicy` 持有 field/scheme 唯一真源，且分别经
  serving authenticated-request 与 capability-gated authorized-maintenance typed method 派生 AAD。composition 只组装
  provider/key，不得读取、覆盖或复制 persistence field/scheme。

#### Historical superseded sketch — settings-owned `AADForConfig`

以下 D2–D4 草图只保留为决策历史，已被 #1477 的 `ProtectionContext` canonical encoder 和 #1612 的
Postgres-private policy 取代，**不是当前 ownership/API 规范**：

```rust
// ---- 草图（非可编译；依赖底座 secure::Aad / ProtectionContext，未落地）----

// 协议/envelope SCHEME 版本 —— 与 ConfigEntry 的 CAS `version` 是两回事（见 D4）。
// 类型保持 `u16`（AAD canonical 固定 `u16_be` 2 字节），DB 用 `integer`(i32) 留头寸，写入路径 `u16 → i32` 是无损 cast。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProtectionSchemeVersion(u16);

// 稳定 field 判别串。ConfigValue 无子字段 ⇒ 单一编译期常量（不可随 call-site 漂移）。
const CONFIG_VALUE_FIELD: &[u8] = b"settings.config.value";

/// 加密码器：每个 envelope scheme 一个实现，scheme 版本是**类型级关联常量**（非运行期值）。
/// **对外唯一入口是 `aad_for_config(ctx, key)`——scheme 由 `Self::SCHEME_VERSION` 注入、调用方拿不到也传不进**，
/// 把「scheme 只能来自 codec 关联常量」从文档约定上移成类型层 Hard（见 `CONFIGENC-AAD-COMPOSE-01`）。
pub trait ProtectionCodec {
    /// 本码器的 envelope scheme 版本（编译期固定，单源派生 AAD 的 scheme 维 + envelope `vN:` 前缀）。
    const SCHEME_VERSION: ProtectionSchemeVersion;

    /// 组装本码器的 config AAD —— scheme 取自 `Self::SCHEME_VERSION`，入参只剩受信坐标
    /// （tenant 取自 ctx、config_key 是校验过的 newtype）；codec 的 `seal`/`open` 内部调用本方法，外部不另传 scheme。
    fn aad_for_config(ctx: &secure::ProtectionContext, config_key: &SettingKey) -> secure::Aad {
        AADForConfig::build(ctx, config_key, Self::SCHEME_VERSION)
    }
}

/// config AAD 的 length-prefix 组装器（**codec 内部**，`pub(crate)`：只由 `ProtectionCodec::aad_for_config` 调，
/// 外部模块拿不到 ⇒ `scheme` 不可由调用方自由传入，`CONFIGENC-AAD-COMPOSE-01` 类型层 Hard）。
pub(crate) struct AADForConfig;
impl AADForConfig {
    pub(crate) fn build(
        ctx: &secure::ProtectionContext,         // 受信 tenant（Hard：必填位置参，非 Option）
        config_key: &SettingKey,
        scheme: ProtectionSchemeVersion,         // 仅由 codec 传入 Self::SCHEME_VERSION，非外部自由传
    ) -> secure::Aad {
        secure::AadBuilder::new(ctx)             // tenant 由 ctx 注入
            .push(b"scheme", &scheme.0.to_be_bytes())
            .push(b"key",    config_key.as_str().as_bytes())
            .push(b"field",  CONFIG_VALUE_FIELD)
            .finish()
    }
}
```

#### Historical D3 — canonical 字节编码草图

`AADForConfig` 产出的字节是承载跨租/跨 entry 重放防御的安全契约，须**域分隔 + 长度前缀**，并 golden 锁死：

```
canonical = MAGIC(b"rss.aad.v1")                              // 域分隔：与任何其它 AAD 用途不可混
          || LP(b"tenant") || LP(tenant.as_uuid().as_bytes()) // 16 原始 UUID 字节（非字符串）
          || LP(b"scheme") || LP(u16_be(scheme))
          || LP(b"key")    || LP(config_key utf8)
          || LP(b"field")  || LP(b"settings.config.value")
其中  LP(x) = u32_be(x.len()) || x
      MAGIC(x) = x 的裸字节（b"rss.aad.v1" 即 10 字节，**不加长度前缀**，作固定域分隔前缀）；其后所有维度均 LP(label)||LP(value) 模式
```

取舍理由：

- **length-prefix + label** 杜绝拼接歧义——无前缀时 `tenant="a",key="bc"` 与 `tenant="ab",key="c"` 可拼出同一 AAD、
  允许跨记录重放；加 `LP` 后任意维度边界唯一。
- **tenant 用 16 原始 UUID 字节**（`TenantId::as_uuid().as_bytes()`），非字符串——大小写/格式变体无法对同一租户产两份 AAD。
- **`MAGIC` 域前缀** 把 config AAD 与未来其它 AAD 用途（feature flag、别的域）隔开，密文连**跨域**重放都不可（不止跨 entry）。
- 这是 ADR-011 D2 通用「tenant / config-key / field / scheme-version」复合在 settings 的具体实例，四维一一对应。

#### Historical D4 — field/scheme 草图

ADR-011 D2 的复合维度对**多字段结构 + per-field `x-protection`** 描述清晰，但 `ConfigValue` 是单个 schema-less opaque 值，
两维需明确取值：

- **「field」= 编译期常量 `settings.config.value`**：`ConfigValue` 无子字段粒度，field 维退化成固定判别串
  （`CONFIGENC-FIELD-CONST-01`，常量 ⇒ 不可随 call-site 漂移）。
- **「scheme-version」= 保护/envelope **scheme** 版本，**不是** CAS row `version`**：config 的 row `version` 是 CAS 计数器
  （PK 组件、`max(version)+1` 算术），且值本身 schema-less（ADR-004 冻结、无 contract schema 可演进）。故 AAD 的
  scheme-version 取 **codec 关联常量**（`ProtectionSchemeVersion`），它**跨 rewrap 不变**（rewrap 只重包裹 DEK、不改
  scheme），仅在 envelope 格式本身升级时 bump。**公开面经 `ProtectionCodec::aad_for_config(ctx, key)`，scheme 由
  `Self::SCHEME_VERSION`（类型级关联常量）注入、调用方不接收也无从传入**；length-prefix 组装器 `AADForConfig::build`
  降为 `pub(crate)` codec 内部，外部模块拿不到 ⇒「scheme 只能来自 codec 关联常量」是**类型层 Hard、非文档约定**
  （消降级面，见 `CONFIGENC-AAD-COMPOSE-01`）。
  - **派生来源辨析（避免误读为「信任 stored bytes」）**：读时 envelope 的 `vN:` 前缀**只用来选码器**，不作受信输入；
    选中的码器用**自身关联常量**重派生 AAD scheme 维。downgrade 试探（把 `v2:` 改成 `v1:`）→ 选 v1 码器 → 用 v1 常量建 AAD
    → AEAD tag（在 v2 下算的）验证失败 → `open` fail-closed。这正是 ADR-011「改 scheme-version 试探降级 → 认证失败」。
    旧码器保留只读（previous-read），移除的码器直接解析失败。

### D5 — 存储列策略 = **新增列**（scheme 驱动表示 + maintenance backfill）

**推荐 Option (b)：在 `config_entries` 上加列，`value` 仅保留作 legacy maintenance backfill 输入，表示检测靠权威的 `protection_scheme` 列、
不靠前缀嗅探。#1477 落地 migration 编号为 `0029_add_config_value_encryption.sql`：

```sql
-- 0029_add_config_value_encryption.sql （forward-only；本迁移不做 backfill/rewrite）
ALTER TABLE config_entries
    ALTER COLUMN value DROP NOT NULL,
    ADD COLUMN protection_scheme integer  NOT NULL DEFAULT 0, -- 0=legacy 明文在 value；1=envelope 在 value_enc
    ADD COLUMN value_enc          bytea    NULL,              -- envelope bytes；legacy 行 NULL
    ADD COLUMN key_id             text     NULL;              -- 包裹 DEK 的 wrapping-key id/version（轮换用）

-- 只用 DEFAULT 0 给既有行物化 legacy 表示；随后移除默认，省略 protection_scheme 的旧 INSERT shape fail-closed。
ALTER TABLE config_entries
    ALTER COLUMN protection_scheme DROP DEFAULT;

-- 唯一表示不变式（DB 层防御纵深）；legacy 行满足第一分支，新加密行满足第二分支。
ALTER TABLE config_entries
    ADD CONSTRAINT config_entries_value_representation_chk CHECK (
        (protection_scheme = 0 AND value IS NOT NULL AND value_enc IS NULL AND key_id IS NULL)
     OR (protection_scheme = 1 AND value IS NULL AND value_enc IS NOT NULL AND key_id IS NOT NULL)
    );
```

为何这是**无批量迁移**：`integer NOT NULL DEFAULT 0` 在 PG 11+ 是 catalog-only（常量默认无 table rewrite），全部 legacy
行立即读回 `scheme=0`；`value_enc`/`key_id` 可空无需 backfill；随后 `DROP DEFAULT` 让省略新列的旧写形态在 DB 层失败，避免迁移后继续写入 plaintext；
CHECK 只验证既有 legacy 表示不变式和新 encrypted 表示，不重写行数据。
**复用 0012 既有 RLS**（表级，新列自动继承；`rss_app` 已有 UPDATE grant ⇒ 后续就地 rewrap/backfill 引擎层放行）；
**CAS PK `(tenant_id, config_key, version)` / `cas_insert` / co-tx / tombstone / `latest_version` 结构不变**——只是 value 的表示位置变了。

**为何不取 Option (a)「`value text` 原地 + `vN:` 前缀嗅探」**：① legacy 明文值可能合法地以 `"v1:"` 开头 → 前缀嗅探把明文当密文，
无 fail-closed 保证；② 没有可查询的 `key_id`（轮换）/ 没有 backfill 游标谓词（`WHERE protection_scheme=0`）/ 没有 rewrap 审计计数位；
③ envelope 是二进制（EDK+nonce+tag），base64 塞 text 浪费 ~33% 且重引编码接缝（`bytea` 才对，0003/0013/0017/0018 先例）；
④ 未来 blind index（D4 deterministic，settings 实务不需要）也无处落列。**为何不取 Option (c) 新表**：破坏统一读路径/单语句 CAS/co-tx
单 INSERT 原子性，重交 RLS 三件套 + grant + 第二 PK 同步，且数据与 config 行 1:1 无收益。

### D6 — 旧明文 serving 门 + 回滚 + 失败模式（全 fail-closed）

**读检测是 scheme 驱动（权威），不靠内容嗅探**——`hydrate_row` 按 `protection_scheme` 分支，`find`/`find_version` SQL 增列：

```sql
SELECT config_key, value, value_enc, key_id, protection_scheme, version, deleted
FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2 ORDER BY version DESC LIMIT 1
```

- `scheme = 0` → serving 立即返回 `ProtectionAuthFailure`，**不调 key、不调 KeyProvider、不 hydrate 明文**；
  只有持有 `ConfigValueMaintenanceCapability` 的 backfill 路径可以读取并改写该表示。
- `scheme >= 1` → 读 `value_enc`+`key_id` → 从受信坐标派生 AAD（D2/D7）→ 经注入 open 路径解密 → `hydrate`。
- **失败绝不回退明文**：`scheme>=1` 解密失败一律返 `ConfigRepoError`，**永不**返回密文、**永不**静默跳过、**永不**降级明文。
- `latest_version` 不变（只读 `max(version)`，version 永不加密）。

**「回滚」三义**（forward-only / only-add 无 `.down.sql`）：

1. **schema 回滚** = 一条**新前向迁移**，绝不在代码仍读列时 drop 列。pre-GA 窗口内 drop `value_enc`/`protection_scheme`
   只有在反向 decrypt-and-rewrite（#3）把所有行还原成 `scheme=0` 之后才安全 ⇒ schema 回滚是**最后**一步。
2. **rollout kill-switch**：#1477 明确不提供 plaintext-write feature flag。运行时代码的 `PgConfigRepo`
   构造器必填 move-only `ConfigValueCrypto`（单一共享 `KeyProvider` handle + `KeyName` + 私有 AAD policy），新写一律 seal 后落
   `scheme=1`；回滚不能靠新写降级明文，只能按 #1/#3 的前向迁移 / 授权 rewrite 流程执行。
3. **全量反向** = 授权维护 decrypt-and-rewrite job（反向 backfill，#3 同 D7 模型）：授权 `ProtectionContext` 下按租户解密
   `scheme>=1` 行、就地 UPDATE 回 `scheme=0` 明文（不 bump version）。完成后才轮到 #1 schema 回滚。

**失败模式表（F1–F6，全 fail-closed）**：

| # | 失败 | 触发 | 行为 | 恢复 |
|---|------|------|------|------|
| F1 | KeyProvider 读时不可用 | 读 `scheme>=1` 行时 Vault/KMS 不可达 | `open` 跑不了 → 读返 `ConfigRepoError::ProtectionUnavailable`（infra），**无明文回退** | 瞬态：provider 恢复后重试；legacy `scheme=0` 在 serving 中始终拒绝，须经授权 backfill |
| F2 | KeyProvider 写时不可用 | 新写 seal / DEK-wrap 调用失败 | seal 在 DB 事务**打开前**失败（D8）→ 写干净失败、**零持久化**、co-tx 从未打开 | 恢复 KeyProvider 后重试；不提供明文写降级 |
| F3 | key 已轮换、previous-read 在 | 行用旧 `key_id` 封 | `open` 按 `key_id` 选 previous-read key（常数时间匹配）→ 成功 | 正常；lazy/batch rewrap（D7）顺手迁到 current-primary |
| F4 | key 丢失/不在 keyring | 行 `key_id` 的 wrapping key 没了（KMS 数据丢失/坏轮换） | `open` 失败 fail-closed；该行**不可恢复** | 超出 rewrap（只重包裹**可恢复**DEK）；属 ADR-011 §5 master-key 丢失 runbook ⇒ KMS 持久性是硬外部依赖 |
| F5 | 读时 AAD 不匹配（篡改/跨租/降级） | copy `(ciphertext, stored_aad)` 跨租/跨 key，或改 scheme | AAD 从受信坐标重派生（D2）**绝不取 stored bytes**；AEAD tag 覆盖 AAD → 认证失败 → `ConfigRepoError::ProtectionAuthFailure` fail-closed | 安全事件：脱敏日志 + 告警；不返数据 |
| F6 | CHECK 违反 | bug 写出不一致 (scheme,value,value_enc) 元组 | DB 拒 INSERT/UPDATE（`config_entries_value_representation_chk`） | 引擎层在持久化前抓住 bug |

### D7 — 迁移执行模型

三种形态，#1477 只上第一种（新写恒加密），其余 deferred：

- **(a) encrypt-on-write going forward（已由 #1477 上线）**：`cas_insert`（含 `save` + co-tx `save_and_append_outbox`）用
  current-primary key 封新版本 → 写 `scheme>=1`/`value_enc`/`key_id`/`value=NULL`；旧版本保持明文直到 backfill。写已在
  `set_local_tenant` 内 ⇒ 自动 tenant-scoped。tombstone 也写 `scheme>=1`/`value_enc`/`key_id`/`value=NULL`，但 no-op delete
  （key 不存在 / latest 已 tombstone）先经 DB 判定并直接返回，不因 KeyProvider 不可用破坏幂等删除语义。
- **(b) lazy rewrap on read（可选、默认 off）**：`scheme>=1` 行 `key_id != current-primary` 时，`open` 成功后把 DEK 重包裹到
  current-primary、就地 UPDATE `value_enc`+`key_id`、**同 version、无 outbox 事件**（明文未变 ⇒ CAS/version/`event_id` 语义不变）。
  推荐**默认关**（把读变成写、需请求 principal 下 UPDATE、加延迟）；权威 rewrap 走批量 job (c)。若开则须最佳努力、rewrap UPDATE
  失败不得让读失败；rewrap UPDATE 失败**须**在当前 tracing span record 一个 `WARN` event（字段含**脱敏后** `key_id` + `error`
  类型，**不含**密钥材料），**不得 swallow**；监控侧按该 WARN 做 lazy-rewrap-failure-rate 告警（防轮换卡死成盲区）。
- **(c) 批量 backfill / rewrap job（deferred、仅授权维护）**：跑在**专用 admin/维护 bin 或 `cargo xtask`**，**不是 axum
  请求 handler**；operator 授权凭据驱动、非 HTTP Principal。逐租户 `SET LOCAL rss.tenant_id`（RLS 正确，连 `rss_app` 用既有
  UPDATE grant）；PK `(tenant_id, config_key, version)` 游标分块逐块提交、谓词 `WHERE protection_scheme=0 AND deleted=false`；
  每行就地 UPDATE 按 PK 原子置 `value_enc`/`key_id`/`scheme>=1`/`value=NULL`（一语句满足 CHECK），**不 bump version**
  （保 history/`find_version`/`event_id`）；覆盖所有 live 版本（每历史版本经 `find_version` 独立可读）、**跳 tombstone**；
  每行 AAD 由**该行坐标**在授权维护 `ProtectionContext` 下重派生（ADR-011 `FIELDPROT-AAD-DERIVE-FROM-CTX-01` 维护源、无 HTTP 上下文）。

  **幂等性**来自谓词 `WHERE protection_scheme=0`（重跑天然跳过已加密行，恒成立）；**resumable** 指 job 把最后已提交游标
  持久化到**专用 backfill checkpoint 表**（如 `config_value_backfill_checkpoint(job_id, tenant_id, last_config_key,
  last_version, batch_status, updated_at)`，落地编号续 migration），崩溃后从断点续跑而非全表重扫。**不复用既有 `checkpoint`
  表**——它只有单个 `offset_lsn bigint`（saga/projection 的 `Lsn` 位点，`diport::checkpoint_store` 也仅暴露 `Lsn` offset），
  装不下 `(tenant_id, config_key, version)` 复合游标。两性质并存、来源不同，分别成立。

  **审计要求**（该 job 在授权维护上下文下解密全租户全版本明文，blast radius 最大，须强可见性）：① job 启动/完成/中断写
  audit sink（用 `crates/audit` 结构化 audit event，记 operator/service-token subject + tenant 范围 + job 参数）；② 每提交
  一批 emit metric `configenc.backfill.rows_processed{status}`——**label 仅闭值集**（`status` 经 typed `as_label()`；可加
  `job_type`/`phase` 等有界维），**tenant 不进 label**（开放基数，违反 `crates/observ`、`secure::redact_error` 与 typed metric enums
  不进 label」）；**tenant 范围 / 逐行定位走 ① 的 audit event + 结构化日志 / span 字段**；③ 见 §3 `CONFIGENC-BACKFILL-AUDIT-01`。
  此要求与继承的 `FIELDPROT-KEYPROV-AUDIT-01`（守每次解密调用）互补：本条守 **job 生命周期**高层可见性。

### D8 — seal / DB 事务顺序（ops 约束，补 ADR-011 空白）

seal（含 KeyProvider/Vault 生成/包裹 DEK 的**网络往返**）必须在 `producer_tx` 打开 Postgres 事务**之前**完成；
事务体只 bind 已封装字节。**禁止**持 DB 事务 / 行锁跨 KMS 网络调用（会把锁时长与事务存活绑到 KMS 延迟）。逻辑 seal 点 =
「先产出 envelope 字节，**再**进 `business_write` 闭包 INSERT」。ADR-011 未触及事务/KMS 调用顺序，settings 落地须显式遵守。

### D9 — 决策时错误分流（已落地）

决策时 `ConfigRepoError`（`#[non_exhaustive]`）仅有 `VersionConflict`/`Storage`，因此本 ADR 要求新增两个变体；
当前 `crates/settings/src/domain/mod.rs` 已承载：

- **`ProtectionUnavailable`**（对应 F1：KeyProvider/KMS 不可达，瞬态可重试）
- **`ProtectionAuthFailure`**（对应 F5：AEAD tag 校验失败 = 篡改/跨租/降级，安全事件、不可重试、触发 security incident）

单变体无法达成 F1/F5 两路区分（把二者都映射成 `Storage` 会丢运维区分度）。该变更是对 `#[non_exhaustive]` 枚举的
**增量**，**不触碰冻结的 `ConfigValue`**、保持 fail-closed，给 ops 两条独立可告警信号——F1 走 infra-availability 告警、
F5 走 security incident 告警（见 §3 `CONFIGENC-ERR-SPLIT-01`）。

### D10 — 保护策略分层（「重构」方向：config / secret-ref / feature-flag 三类不同保护）

| 数据类 | 决策时基线 | 决策目标 | 保护机制 | 存储 | AAD 适用 |
|--------|----|----------------|----------|------|----------|
| **普通 config 值** | 明文 `value text` + 脱敏 Debug + 敏感 key 拒写 | 可选 at-rest AEAD envelope；**敏感 key 拒写保留** | Postgres `ConfigValueCrypto` 经 `KeyProvider` 加解密，私有 policy 绑四维 | `config_entries`（D5 新增列） | **是**：tenant / config_key / `settings.config.value` / scheme |
| **secret refs** | 坐标-only、材料从不落库（**已正确**） | 不变 | `SecretResolver` 在调用栈把坐标解析成 `SecretMaterial`（ZeroizeOnDrop、无 Clone） | `secret_refs`（仅坐标） | **N/A**：无材料落库，保护委托外部 store + transit auth |
| **feature-flag 值** | settings 不提供该产品面（#2070 deferred） | 出现真实 consumer/provider 后重新设计 | 未定 | 未定 | **N/A**：`MAGIC` 域分隔仍为未来其它 AAD 用途预留 |

**`SettingKey` 敏感 key 拒写保留**（即使加密上线）：config 加密是「偶发敏感 config 的纵深防御」（如连接串恰含主机名），
**不是**受认可的 secret store——真 secret 走 `SecretRef` 路径（外部 store、轮换、从不 at-rest，`SecretKey::parse` 本就豁免子串守卫）。
全局放开守卫会重开 ADR-011 at-rest 线正防的威胁、并稀释这套干净的双路径分类。未来若确需放开，须经**显式 per-namespace
「encrypted」capability marker（typed function choice / 独立构造器）**，**绝不** blanket relax 子串守卫；该 marker 未落地前守卫不动。

### D11 — KeyProvider readiness 能力门（启动 fail-fast / readiness probe）

KeyProvider/KMS 不可用**不能只停在读时 `ProtectionUnavailable`**（D6 F1）——否则实例可能 `ready` 后才在真实请求里暴露 KMS
不可达。须在实例就绪前设**能力门**（对齐 `crates/observ`、`secure::redact_error` 与 runtime typed finalizer 的强依赖
fail-fast）：

- **readiness probe `keyprovider_ready`**（或等价 `ManagedResource` readiness）：探测注入的 KeyProvider 可达性；不可达 →
  实例 not-ready、不进流量轮转（只影响 readiness，不影响 liveness）。
- **启动语义**：#1477 后 Postgres settings 新写恒加密，因此生产 runtime 将 KeyProvider 作为 settings 强依赖：
  `RSS_SETTINGS_CONFIG_VALUE_KEY_NAME` 缺失、Vault Transit 配置缺失或启动自检 encrypt+decrypt 失败均 fail-fast；运行期 sampler
  失败则 `keyprovider_ready` 变 unhealthy，不静默带病 ready。
- **legacy 明文门**：迁移后 runtime 默认用 migrator 连接扫描全库 `config_entries.protection_scheme=0`；命中即
  fail-fast。`RSS_SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES=true` 仅作为 backfill 前短期豁免，新写路径仍只写
  encrypted scheme。
- 落地归底座 KeyProvider port（probe 名）+ settings 持久化（`PgConfigRepo` 构造接线）；probe 名是运维契约（改名同步
  dashboard/alert/tests）。见 §3 `CONFIGENC-KEYPROV-READY-01`。

## 3. INVARIANT / 载体落点（AI-robust：每条钉 Hard/Medium，禁 Soft）

主题 `CONFIGENC` 为本 ADR 新增 settings 具体载体；通用 ID（`FIELDPROT-*`）/ 原语 ID（`CRYPTO-*`）在载体不变时**继承** ADR-011 / primitives。

| 保证 | INVARIANT | 评级 | 载体 | 新（#1473）/ 继承 |
|------|-----------|------|------|-------------------|
| seal/open AAD 必填 | `FIELDPROT-AAD-MANDATORY-01` | **Hard** | AEAD v2 `seal/open(aad: &Aad)` 必填位置参（非 `Option`） | 继承（底座） |
| AAD 从受信上下文派生、不取 stored bytes | `FIELDPROT-AAD-DERIVE-FROM-CTX-01` | **Hard** | `Aad` 无 public 字节 ctor；只 `AadBuilder::new(&ProtectionContext)` 可 mint；`ProtectionContext` sealed（私有字段 / 无 Deserialize / capability-gated ctor，仿 runctx） | 继承（底座） |
| config AAD 恰由四个受信维组合，scheme 来自编译期常量、公开面不收 scheme 参 | `CONFIGENC-AAD-COMPOSE-01` | **Hard** | `ConfigValueAadPolicy` 私有 field/scheme；serving/maintenance typed method 内部调用 `ProtectionContext`，外部无 getter/setter/policy 入口 | **新（#1473）** |
| field 判别串稳定 | `CONFIGENC-FIELD-CONST-01` | **Hard** | `ConfigValueAadPolicy::FIELD` 私有编译期常量（不可随 call-site 漂移） | **新（#1473）** |
| AAD canonical 字节冻结 | `CONFIGENC-AAD-CANON-01` | **Hard** | length-prefixed 编码器的 golden 字节向量测试（格式漂移=字节 diff，仿 serde golden） | **新（#1473）** |
| Debug/日志/trace 不解密 | `FIELDPROT-NODBG-DECRYPT-01` | **Hard** | envelope 只持 `secure::Ciphertext`（`#[redact(sensitivity = secret)]`）、无明文字段；`open` 产出经 `secrecy::Secret`/`Zeroizing` 直喂 `ConfigValue::new`；`ConfigValue` Debug 已脱敏 | 继承（底座/#1467）；settings 载体新 |
| envelope 版本恒在 | `CONFIGENC-ENVELOPE-VERSION-01` | **Hard**（存在）+ **Hard**（格式 golden） | `Envelope.version` 非 `Option` 字段；`decode` 拒未知/缺失前缀 fail-closed；`vN:` 前缀 golden 锁 | **新（#1473）** |
| key-id 常数时间匹配 | `CRYPTO-CONST-TIME-01` | **Medium** | 复用 `primitives::crypto::constant_time_eq` 做轮换 key-id 匹配（无新 `==` 路径） | 继承（primitives） |
| 加密限于持久化边界（域 `ConfigValue` 不动、冻结） | `CONFIGENC-BOUNDARY-01` | **Hard**（域侧）+ **Medium**（adapter 侧） | Hard：`ConfigValue` 不改 / `pub(crate)` / 无 envelope 字段，ADR-004 冻结 + `rss_domain_no_serialize` dylint 已守；Medium：governance/dylint 守 settings domain 模块不持有 persistence AAD policy 或调用密码原语 | **新（#1473）** |
| deterministic 默认 off（ConfigValue v1 不开 blind index） | `FIELDPROT-DETERMINISTIC-OPTIN-01` | **Hard** | 默认随机 nonce AEAD；deterministic 仅经独立 opt-in API（typed function choice）。若未来需等值查询，`AADForConfig` 须提供**稳定子集**变体（去 `scheme`，ADR-011 D4）——独立函数、非 flag | 继承（底座）；settings 注记新 |
| F1/F5 两路错误可独立告警 | `CONFIGENC-ERR-SPLIT-01` | **Hard**（`#[non_exhaustive]` 枚举穷举 = 编译期）+ **Medium**（ops 告警把 F5 路由到 security incident 的 governance/集成测试） | 两变体类型存在（`ProtectionUnavailable` / `ProtectionAuthFailure`）+ F5 告警路由集成测试 | **新（#1473）** |
| legacy plaintext 默认阻断 | `CONFIGENC-LEGACY-PLAINTEXT-GATE-01` | **Medium**（启动能力门 + 集成测试） | `PgRuntimeDeps::setup` 在 migration 后扫描 `config_entries.protection_scheme=0`；默认 `Deny` fail-fast，显式临时 env 仅放行启动，不恢复 plaintext write | **新（#1473）** |
| backfill job 生命周期可审计 | `CONFIGENC-BACKFILL-AUDIT-01` | **Medium**（`cargo xtask` governance 或集成测试守 backfill 有审计路径） | audit sink 写入 + metric emit 集成测试 | **新（#1473）** |
| 维护 ProtectionContext 须 operator token + 强制审计 | `CONFIGENC-MAINT-CTX-AUTHZ-01` | **Medium**（底座 capability-gated 构造若可做成则 Hard；否则 governance/集成测试守「维护 ProtectionContext 构造须 operator token + audit」） | 受控构造 funnel + 审计 governance 测试 | **新（#1473）** |
| KeyProvider 不可用前置能力门（非仅读错误） | `CONFIGENC-KEYPROV-READY-01` | **Medium**（readiness probe + 启动 fail-fast 的 governance/集成测试） | `RSS_SETTINGS_CONFIG_VALUE_KEY_NAME` 必填 + 启动 encrypt/decrypt self-check + `keyprovider_ready` probe（`_ready` 后缀）运行期采样 fail-closed | **新（#1473）** |

落地分布：`FIELDPROT-AAD-*` / `FIELDPROT-DETERMINISTIC` / `Aad` / `ProtectionContext` / `Envelope` 类型在底座 framework；
`CRYPTO-CONST-TIME` 在 primitives（已存在）+ KeyProvider 轮换匹配；`CONFIGENC-*` + `FIELDPROT-NODBG-DECRYPT` 落 settings 持久化。
**无 Soft 新增**；主导载体为编译期（构造器必填参 / sealed newtype funnel / 编译期常量 / 非 Option 字段 / golden 字节冻结）。

## 4. 后果

- **正**：settings 静态加密有具体设计单源（AAD 编码 / 列形态 / legacy maintenance / 回滚 / 错误 / 顺序全钉死）；**零新增 crate / 零新增分层**
  （沿用 `secure` + `diport` + `adapters/postgres` 持久化边界）；加密是纯 adapter-边界变换，域 `ConfigValue`（冻结）与 secret-ref
  路径不动，唯一域向改动是 adapter 注入 `KeyProvider`/`ValueTransformer`（构造器必填参）+ 每次读写建 `ProtectionContext`；
  AAD 必填 / 派生自上下文 / no-decrypt-in-debug / canonical 字节落地时由类型系统 + golden 免费成立（Hard）。
- **决策时的负 / 代价**：① 本设计当时 **blocked-by 底座**（AEAD v2 + `KeyProvider`），规划落地排在其后；② `ProtectionContext` 接缝非平凡——
  `config_repo` 当时仅有裸 `TenantId` 参，设计要求把 capability-gated `ProtectionContext`（含「授权维护」变体供 backfill）
  接进读写路径；当前 `config_repo` 已使用 authenticated/authorized-maintenance `ProtectionContext`；
  ③ deterministic/blind-index 对 settings **实务无用**（config 按 key 查、从不按 value 查）⇒ 默认不开，仅靠 D5 列形态保留可扩展性。
- **决策时的下游顺序**：底座 framework → KeyProvider/Vault → **本设计落地（settings 持久化）**；
  现行实施状态以 tracker 和 §1 的 executable carrier 为准。

## 5. 威胁矩阵（继承 ADR-011 + settings 具体化）

| 威胁 | 缺失的约束 | 缓解（本 ADR 决策） |
|------|-----------|---------------------|
| settings 静态明文落库（决策时基线） | ConfigValue 明文落 `value text` | D1/D5 storage-encryption envelope（encrypt-on-write + backfill） |
| copy `(ciphertext, stored_aad)` 跨租（open 用存储 AAD 自洽验签） | `open` 从 row 取 stored AAD 而非上下文派生 | D2 `FIELDPROT-AAD-DERIVE-FROM-CTX-01`（AAD 经 `ProtectionContext` 从受信坐标重派生，stored 仅标识/审计） |
| 跨租/跨 key/跨字段密文重放 | AAD 缺失或可选 | D2/D3 四维复合 AAD + length-prefix + `MAGIC` 域分隔（`CONFIGENC-AAD-COMPOSE/CANON`） |
| 改 scheme 试探降级 | scheme-version 可篡改 / 信任 stored byte | D4 scheme 取码器关联常量、`vN:` 仅选码器；AEAD tag 覆盖 AAD → 降级认证失败 fail-closed |
| 解密结果经 Debug/日志/trace 泄漏 | 明文可渲染 | D6/§3 `FIELDPROT-NODBG-DECRYPT-01`（envelope 无明文字段 + `secrecy::Secret` 产出 + ConfigValue 脱敏 Debug） |
| 解密失败静默回退明文 | 无 fail-closed | D6 `scheme>=1` 失败一律 `ConfigRepoError`、永不回退明文；F1→`ProtectionUnavailable`（瞬态可重试）、F5→`ProtectionAuthFailure`（安全事件、触发 security incident） |
| 持 DB 锁跨 KMS 网络调用（锁放大/活性绑 KMS） | 事务/seal 顺序未定 | D8 seal（含 Vault 往返）在事务打开前完成 |
| 不一致 (scheme,value,value_enc) 写入 | 无表示约束 | D5 `config_entries_value_representation_chk`（DB 层防御纵深，F6） |
| key-id 匹配 timing oracle | 非常数时间比较 | §3 `CRYPTO-CONST-TIME-01`（`primitives::crypto::constant_time_eq`） |
| master/wrapping key 丢失 | 无应急路径 | 超出 rewrap（仅重包裹可恢复 DEK）；属 ADR-011 §5 master-key 丢失 runbook（F4，KMS 持久性硬依赖） |
| 真 secret 误经 config 加密路径"洗白" | 放开敏感 key 拒写 | D10 拒写保留；真 secret 走 `SecretRef`；放开须显式 per-namespace capability marker |
| 维护路径无授权/无审计 → 全库 config 明文被滥用解密 | 维护 ProtectionContext 无 capability gate | D2 + `CONFIGENC-MAINT-CTX-AUTHZ-01`（operator token + 强制审计 + 禁 Soft 门控） |
| 实例带病 `ready` → 加密读/写在真实请求期才暴露 KMS 不可达 | KeyProvider 不可用仅作读错误、无前置能力门 | D11 + `CONFIGENC-KEYPROV-READY-01`（`keyprovider_ready` probe + 强依赖启动 fail-fast/readiness 降级） |

## 6. AI-robust 分级汇总

见 §3 载体表。本 ADR 是**设计单源文档，不创建新 enforcement 机制**——它**规定**落地时各 INVARIANT 的载体档位（与 ADR-011
同范式），禁止实现时退化。新增 `CONFIGENC-*` 全部 Hard（类型系统 / 构造器必填参 / 编译期常量 / 非 Option 字段 / golden
字节冻结）或 Medium（adapter 不调用 AEAD 密码原语的 governance/dylint、F5 告警路由测试、backfill 审计路径测试、维护上下文授权测试、KeyProvider readiness/启动 fail-fast 测试）；继承 ID 沿用 ADR-011/primitives 既有载体。**无 Soft 新增**。

## 7. 备选（为何不取）

- **改 `ConfigValue` 域类型（加 envelope 字段 / `encrypted()` 方法 / 域层调 KeyProvider）**：被否决——破 ADR-004 冻结、
  把 infra async/fallible I/O 拖进 L0 纯域、破 ADR-005 层序。加密须落持久化边界（D1）。
- **`KeyProvider` 放域 crate**：被否决——provider-agnostic infra port 放域 crate 会致 adapter→域 反向依赖、层序倒置
  （ADR-005 category line），归 `diport`（ADR-011 D6）。
- **存储 Option (a) 前缀嗅探 / Option (c) 新表**：被否决（D5 详述）——前缀嗅探不 fail-closed、无轮换/backfill 元数据位、
  二进制塞 text；新表破统一读路径 + CAS/co-tx 原子性、重交 RLS/grant、无收益。
- **deterministic 默认 on（便于查询）**：被否决——settings 无按 value 等值查询需求，默认暴露明文相等性违反安全优先；
  blind index 仅在确有需求时 per-field opt-in、用稳定子集 AAD（ADR-011 D4），本设计 v1 不开。
- **放开 `SettingKey` 敏感 key 拒写（因已有加密）**：被否决（D10）——config 加密是纵深防御非 secret store；放开须显式
  capability marker，不 blanket relax。

## 对标证据（ref:）

- `ref: hashicorp/vault builtin/logical/transit/path_encrypt.go@main` — envelope encryption + `context`(≈AAD) decrypt 时
  强制一致 + `rewrap` 重包裹 DEK，对应 D1/D3（envelope + 轮换）/ D7（rewrap 语义）/ D2（AAD 强制一致）。
- `ref: tink-crypto/tink-go daead/subtle/aes_siv.go@main`（https://developers.google.com/tink/deterministic-aead）—
  DeterministicAEAD = AES256-SIV、AAD 作 SIV 输入、文档明确 deterministic「leaks plaintext equality」代价，对应 D4
  （settings 默认不开 blind index、若开须稳定子集 AAD）。
- `ref: awslabs/aws-encryption-sdk-specification framework/structures.md@master`
  （https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html）— encryption context as AAD
  （绑定到 message header、非机密、best practice）+ key commitment，对应 D2（AAD 绑定语义）/ D3（EDK 结构）。
- `ref: iqlusioninc/crates secrecy/src/lib.rs@main`（https://docs.rs/secrecy）— `Secret<T>` + `ExposeSecret`，`Debug` =
  `[REDACTED]` + `Drop` zeroize，对应 D6/§3 no-decrypt-in-debug（解密产出经 `secrecy::Secret`）。
