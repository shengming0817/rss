# ADR-008：wire 破坏式变更检测门 — xtask JSON-Schema-diff（对标 Buf WIRE_JSON，不迁 protobuf）

- **状态**：Accepted（裁决 Feature #1131 deep-research 缺口之 wire 版本治理门形态；2026-12-31 兼容窗口到期前落地的设计前置）
- **日期**：2026-06-23
- **关联**：issue #1140 [ADR wire 破坏式变更检测门 — Buf 式] · epic #991 / Feature #1131 · gate **实现走单独 backlog PBI**（见 §8）
- **依赖 ADR / 规则**：`api-versioning.md` §兼容窗口（pre-GA wire 破坏窗口至 2026-12-31）· `contract-fanout.md`（契约扇出闭环）
- **归属**：framework（wire 契约版本治理，provider-agnostic 工具门）
- **AI-robust 评级**：见 §6

---

## 1. 背景

RSS wire contract 是 **JSON Schema**（`contracts/{kind}/{domain}/{version}/*.schema.json`，字段 camelCase 名而非 protobuf field number），HTTP / event / command body 走 serde。版本治理现状双轴：

- **轴 A（库 crate 公开 API）**：`cargo-semver-checks` / `cargo public-api` 守 Rust exported 符号。
- **轴 B（wire contract）**：版本目录 `contracts/{kind}/{domain}/{version+1}/` 隔离破坏式变更；**pre-GA 窗口（至 2026-12-31）允许原地改 active 版本**（无外部 wire 消费方，全部 in-repo 调用方随同 PR 原子更新）。

**缺口**：`cargo-semver-checks` 只守轴 A，**不检测 JSON Schema wire 字段**（轴 B）。`xtask` 现有契约校验 R1–R11（`xtask/src/contract/validate.rs`：manifest 元数据 + schema 引用完整性 + 标识符语法）**无跨版本 wire schema diff 破坏检测**。pre-GA 窗口内 active 版本破坏只靠**人工扇出检查**（contract-fanout.md 清单），无机器门——破坏可漏网。

**待裁决**：用什么形态建 wire 破坏自动门。

---

## 2. 决策

> **不迁 protobuf、不引 Buf CLI；在 `xtask` 新增 `cargo xtask contract breaking [--against <git-ref>]`，对 `contracts/**/*.schema.json` 做跨版本 JSON-Schema diff，对标 Buf WIRE_JSON 规则分类。本 ADR 只裁决 + 设计规则集，gate 代码实现走单独 PBI。**

裁决要点：

1. **形态 = xtask 内建 schema-diff 门**，与既有 R1–R11、`cargo-semver-checks`（轴 A）互补无重叠（轴 B）。
2. **规则集对标 Buf WIRE_JSON 类别**（JSON 序列化用字段名，与 RSS camelCase wire 最贴近），见 §3。
3. **窗口分级行为**：pre-GA（至 2026-12-31）`warn`；窗口后对 `lifecycle=active` 契约升 `deny`。
4. **本 ADR 不写 gate 代码**——实现另开 backlog PBI（§8）。

### 2.1 对标依据（Buf 破坏规则）

Buf 对 protobuf 破坏规则分三严级（从宽到严）：**WIRE**（守二进制编码）⊂ **WIRE_JSON**（守二进制 + JSON 编码，JSON 用字段名）⊂ **FILE**（守生成代码）。RSS wire 是 JSON body、字段用名，语义最贴 **WIRE_JSON**（如 `FIELD_NO_DELETE_UNLESS_NAME_RESERVED`、`ENUM_VALUE_NO_DELETE_UNLESS_NAME_RESERVED`、`FIELD_WIRE_JSON_COMPATIBLE_TYPE`、`MESSAGE_SAME_REQUIRED_FIELDS`）。

**偏离理由（不迁 protobuf / 不引 Buf）**：Buf 守的是 protobuf schema，field number 是其稳定锚点；RSS wire 是 JSON Schema，迁 protobuf 会引入 `prost`/`tonic` 大型依赖链、改变全部 wire 序列化、破坏现有 serde camelCase 约定与 `generated/` codegen 流水线，代价远超收益。故**借 Buf 的规则分类思想**，在 JSON Schema 上自建等价检测，而非搬运工具。

---

## 3. 范式（gate 设计 — 规则集 + diff 算法）

### 3.1 建议规则集（对标 Buf WIRE_JSON，适配 JSON Schema）

| 规则 ID | 检测内容（破坏） | Buf 对等 |
|---------|-----------------|----------|
| `FIELD_NO_DELETE` | `properties` 中已有字段被删除（旧有新无） | `FIELD_NO_DELETE_UNLESS_NAME_RESERVED` |
| `REQUIRED_FIELD_ADDED` | `required` 数组新增字段（旧请求缺该字段即破坏） | `MESSAGE_SAME_REQUIRED_FIELDS` |
| `FIELD_TYPE_CHANGED` | `properties.*.type` 不兼容变更（如 `string`→`integer`） | `FIELD_WIRE_JSON_COMPATIBLE_TYPE` |
| `FIELD_FORMAT_CHANGED` | `format` 变更影响解码语义（如 `int64`→`date-time`） | `FIELD_WIRE_JSON_COMPATIBLE_TYPE`（扩展） |
| `ENUM_VALUE_DELETED` | `enum` 数组已有值被移除 | `ENUM_VALUE_NO_DELETE_UNLESS_NAME_RESERVED` |
| `ADDITIONAL_PROPS_TIGHTENED` | `additionalProperties` `true`→`false`（拒旧 payload 扩展字段） | `FIELD_WIRE_JSON_COMPATIBLE_TYPE`（收紧语义） |
| `NULLABLE_REMOVED` | 字段 `type: [T, "null"]`→`T`（收紧） | `FIELD_WIRE_JSON_COMPATIBLE_TYPE` |
| `HTTP_STATUS_CODE_CHANGED` | `contract.toml` 成功响应 HTTP 状态码变更（如 200→201） | `RPC_SAME_RESPONSE_TYPE`（精神对等） |
| `AUTH_REQUIREMENT_CHANGED` | `auth.required` `false`→`true`（收紧鉴权） | `RPC_SAME_IDEMPOTENCY_LEVEL`（精神对等） |
| `IDEMPOTENCY_LEVEL_CHANGED` | `idempotency` 语义变更（`idempotent`→`no-idempotent`） | `RPC_SAME_IDEMPOTENCY_LEVEL` |

> **manifest schema 前置**：上表后三条规则（`HTTP_STATUS_CODE_CHANGED` / `AUTH_REQUIREMENT_CHANGED` / `IDEMPOTENCY_LEVEL_CHANGED`）依赖 `contract.toml` 的 status code / `auth.required` / `idempotency` 字段——这些字段当前**未在 manifest schema（`xtask/src/contract/manifest.rs` + R1–R11）中声明**（现有 `contract.toml` 仅 `id`/`kind`/`domain`/`version`/`owner`/`consistencyLevel`/`lifecycle`/`[schemas]`）。**gate 实现 PBI 须先扩展 manifest schema 承载这些字段，再实现对应规则**；首版 gate 可只落实 schema 内字段已支持的前 7 条（properties/required/enum/type/format/additionalProperties/nullable），后三条标为「第二期、依赖 manifest 扩展」（§8 登记）。

### 3.2 diff 算法要点

- **基准**：`git show {base-ref}:contracts/...` 读旧版 schema（`--against` 默认 `origin/develop`；本地可传 `HEAD~1`），与 working tree 对比。
- **比对**：`serde_json::Value` 树递归 `properties` / `required` / `enum` / `type` / `format` / `additionalProperties`；`contract.toml` 侧比对 status code / auth.required / idempotency / consistencyLevel。
- **方向**：只检 **已有 active contract 的既有字段**的删除 / 收紧 / 变更——**新增可选字段不报**（向后兼容语义，对齐 api-versioning.md「新增可选响应字段留当前版本」）。
- **共存**：R1–R11 校验 manifest 元数据 + schema 文件存在性（结构）；本 gate 只校验 schema **内容跨版本 diff**（语义破坏），不重叠。与 `cargo-semver-checks`（轴 A）分工互补。
- **anti-vacuity（守卫不恒真，ai-robust 第 4 档强制）**：每条规则配 synthetic red case——最小样本「旧 schema 含字段 X + 新 schema 删 X ⇒ gate 必须产出 `FIELD_NO_DELETE` finding」；其余规则同形（旧/新 schema 对 + 预期 finding），由 gate PBI 逐条补全。CI 须有至少一个 active contract 破坏的 red case 防止 guard 恒真（绿 case = 仅新增可选字段不报）。

---

## 4. 后果

- **正**：轴 B 获得机器门，pre-GA 窗口期破坏感知化、窗口后破坏 fail-closed；复用现有 JSON Schema + git，零新增 wire 表达层；规则集可随 GA 临近增量收紧。
- **负 / 代价**：schema-diff 是运行期 governance 检测（非编译期），需维护规则实现 + synthetic red case；JSON Schema 语义破坏的判定面（如 `oneOf`/`$ref` 嵌套）需逐步覆盖，首版可能漏检复杂构造——由「窗口内 warn」缓冲、逐版补规则。
- **下游**：gate 实现 PBI 落地后接入 `cargo xtask verify`（azure 无 CI ⇒ verify 是唯一实际 gate）；窗口到期（2026-12-31）前复核升 `deny`。

### 4.1 窗口分级行为（对齐 api-versioning.md §兼容窗口）

- **pre-GA（至 2026-12-31）**：所有规则 `warn`——`xtask contract breaking` **退出码仍 0**（不 block `verify`），但输出结构化 finding 列表供 PR author 感知。对应 Buf `warn` 模式。原地改 active 版本仍合法（窗口政策），但破坏被显式记录。
- **窗口后（2026-12-31 起）**：对 `lifecycle=active` 契约的破坏规则升 `deny`——**退出码改为 1（block `verify`，fail-closed）**；`draft` / `deprecated` 版本长期保持 `warn`-only（退出码 0）。破坏式 wire 变更须走新版本目录 `contracts/{kind}/{domain}/{version+1}/`。
- **提前收紧（对齐 api-versioning.md §兼容窗口）**：若 RSS 在 2026-12-31 前**进入 GA 或出现外部 wire 消费方**，active 契约破坏规则**提前升 `deny`**，不等窗口截止日。本条与 api-versioning.md「rss 进入 GA 或出现外部 wire 消费方时即提前收紧」同源，避免窗口期出现外部消费方时 gate 行为与规则文件不一致。
- **注**：§6 称 gate「接入 `verify` fail-closed」指的是 **deny 阶段**的语义（退出码 1）；warn 阶段 gate 在场但不阻断（退出码 0），二者非矛盾——warn 是「在场即记录」、deny 是「在场即拦截」。

---

## 5. 威胁矩阵 / amendment 声明

**amendment 声明**：本 ADR **不 amend** 既有 ADR；与 api-versioning.md §兼容窗口同源（提前收紧条款已对齐，§4.1）。威胁面 / 覆盖边界如下：

| 威胁 | 暴露条件 | 缓解 | enforcement 档位 |
|------|---------|------|-----------------|
| **窗口期 active 版本 wire 破坏漏网** | pre-GA（至 2026-12-31）gate `warn` 不 block；in-repo 消费方随 PR 原子更新，破坏被记录但不拦截 | pre-GA 全部 in-repo 调用方同 PR 原子更新（窗口政策前提）；warn finding 显式记录供感知 | **Soft 过渡**（窗口政策）→ 窗口后 / 提前收紧后 **Medium**（deny） |
| **窗口期出现外部消费方但 gate 仍 warn** | 2026-12-31 前进入 GA 或出现外部 wire 消费方 | §4.1 提前收紧：active 契约规则提前升 deny（与 api-versioning.md 同源） | **Medium**（提前升 deny） |
| gate 漏检复杂构造（`oneOf`/`$ref` 嵌套） | 首版规则未覆盖嵌套 schema | 窗口内 warn 缓冲；§8 规则覆盖增量逐版补；anti-vacuity red case 防恒真 | **Medium**（增量 + red case） |
| gate 未落地前破坏靠人工 | gate PBI 未交付 | 人工 contract-fanout 清单（Soft 技术债，§6 已标注 + §8 登记 pri-p2） | **Soft 过渡**（已排期消除） |

---

## 6. AI-robust 分级（本 ADR 引入 / 修改的 enforcement）

| 约束 | 评级 | 载体 |
|------|------|------|
| 本 ADR 为纯决策 + 设计记录，**当前不新增 enforcement**（gate 实现走单独 PBI） | —（N/A） | 规则集 + 窗口分级成文 |
| **过渡期现状（gate PBI 落地前）**：wire 破坏检测仍依赖人工 `contract-fanout` 检查清单 | **Soft（临时技术债）** | 人工扇出清单——此 Soft 期是 ADR-008 本身引入的技术债，gate PBI 落地即消除；PBI 优先级须反映此覆盖空白（pri-p2，§8 登记） |
| `xtask contract breaking` gate（实现 PBI 交付） | **Medium（运行期 governance）** | `cargo xtask` 子命令 + synthetic red case + anti-vacuity（守卫不恒真），接入 `verify` fail-closed |

> **Soft 过渡期说明（防误读 `—（N/A）`）**：本 ADR 裁决了一个「当前尚无机器守卫」的约束——这不违反 ai-robust「Soft 禁止立项」，因为**立的是 Medium 目标 + 已排期 gate PBI**，Soft 只是 PBI 落地前的过渡现状（已显式标注 + 登记），非「停留 Soft 作为终态」。ai-robust 禁的是「新增机制只能做到 Soft 且无升级路径」。

**为何 Medium 而非 Hard**：JSON Schema 跨版本语义破坏（字段删除 / required 收紧 / enum 删值）**无法用类型系统 / crate 依赖图 / 可见性表达**——它是声明源文件内容的历史 diff，须运行期读取两版本 schema 比对。按 ai-robust 四档载体，属第 4 档「运行期 governance 测试」（仅用于类型 / crate 图管不到的边界），**仍是 Medium CI 门、非 Soft**（有 synthetic red + anti-vacuity）。无更靠前载体可上移——这是 wire 契约 diff 的固有性质。无 Soft 新增 enforcement。

---

## 7. 备选（为何不取）

- **迁 wire 到 protobuf + 接 Buf CLI breaking 门**：直接复用工业成熟工具。**否决**——全量 wire 表达层重写（`prost`/`tonic` 依赖链 + 改全部序列化 + 破坏 serde camelCase + `generated/` codegen 冲突），代价远超收益；Buf 的规则思想可借，工具无需搬运。
- **暂不建自动门，pre-GA 继续靠人工扇出检查**：零实现成本。**否决**——2026-12-31 窗口到期前无机器门，active 版本原地破坏可漏网（人工扇出易遗漏）；ai-robust 要求新增约束至少机器可判定，纯人工清单是 Soft，不接受。

---

## 8. Follow-up

- **gate 实现 PBI（本 ADR 不交付）**：**issue #1147** `[infra-ci] 实现 xtask contract breaking JSON-Schema-diff 门（ADR-008 落地）`（area-tooling / type-enhancement / pri-p2 / cx-3），交付 §3 规则集（首版 7 条 + 后 3 条依赖 manifest schema 扩展）+ diff 算法 + synthetic red case / anti-vacuity + 接入 `cargo xtask verify`。
- **窗口到期复核（2026-12-31 前）**：按 §4.1 把 active 契约破坏规则由 `warn` 升 `deny`，与 api-versioning.md §兼容窗口同步收紧。
- **规则覆盖增量**：首版覆盖 §3.1 平铺规则；`oneOf`/`anyOf`/`$ref` 嵌套构造的破坏判定随实测 wire 复杂度增量补。

## 对标证据（ref）

- `ref: bufbuild/buf docs/breaking/rules@main` — Buf 破坏规则 WIRE / WIRE_JSON / FILE 三严级分类（`FIELD_NO_DELETE_UNLESS_NAME_RESERVED` / `ENUM_VALUE_NO_DELETE_UNLESS_NAME_RESERVED` / `FIELD_WIRE_JSON_COMPATIBLE_TYPE` / `MESSAGE_SAME_REQUIRED_FIELDS` 等），§3.1 规则集的概念来源（借规则思想、不迁 protobuf）。
