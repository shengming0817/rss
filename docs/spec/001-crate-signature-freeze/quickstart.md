# Quickstart — 签名冻结验证指南

> 如何验证某层签名冻结"成立"。不含实现代码；实现细节在 tasks.md / 实现 PR。

## 前置

- workspace 骨架已就绪（#993，已合并）。
- **实施前置（非验证前置）**：ADR-002(#994 context) + ADR-003(#995 dynosaur) 已落地（横切）；ADR-001(#996 关闭逆序) 已落地（验 PR-2/PR-3 时）；**diport 落地**（PR-diport：建 crate + dynosaur 可行性验证）gate PR-3/4/5；#998 generated 可用（验 PR-4 wire 引用时）。
- conventions（PR-0，单源 ADR-004）已合并并为本层引用。

## 验证步骤（每个 freeze unit 通用）

```bash
# 1. 编译 smoke —— 冻结成立的主信号
cargo build -p <crate1> -p <crate2> ...        # 单 unit
cargo build --workspace                          # 全部 unit 合并后

# 2. lint 干净
cargo clippy -p <crate...> --all-targets -- -D warnings

# 3. mock 可构造性 + object safety + DI 接线（PORT-SHAPE-01/02/03）
cargo nextest run -p <crate...>                  # 仅 shape 测试，无行为断言

# 4. 封装面 baseline（仅基础/引擎层 PR-1/PR-2；入口由 PR-0 落地）
cargo xtask public-api          # 生成 baseline（包装 cargo-public-api，需 nightly rustdoc-json）
cargo xtask public-api --check  # 漂移门：与 committed baseline 比对（不在 cargo xtask verify 聚合内）
```

## 各层预期结果

| unit | 通过判据 |
|---|---|
| **PR-0** | ADR-004 conventions 合并 + conventions.md 薄引用；`cargo xtask public-api` 工具入口就绪 |
| **PR-1** 基础 | `cargo build -p vocab -p ids -p secure -p support -p runctx` 绿；public-api baseline 已 commit；无内部分组依赖（deny 绿） |
| **PR-2** 引擎 | `cargo build -p consistency -p primitives` 绿；L0 引擎 trait 泛型静态分发编译过；不依赖服务/域/adapters |
| **PR-diport** | `cargo build -p diport` 绿；DI port trait dyn-compatible（`trybuild` compile-pass/fail）；`deny.toml` wrappers 绿（dynosaur 仅 diport）；ADR-003 §8 三风险已验证；architecture.md/deny.toml/rust-standards/domain-patterns 已回写 |
| **PR-3** 服务 | 7 服务 crate `cargo build` 绿；`Domain::init` 返回 Result（不 panic）；非 DI 接缝（RouteGroup/Disposition/HandlerFn）冻结；DI port 已在 diport；不依赖域/adapters |
| **PR-4** 域 | 5 域 crate `cargo build` 绿；域间无 import（deny 绿）；domain 类型未 derive Serialize（编译/grep 核）；DI repo port 已在 diport |
| **PR-5** adapters | 12 adapter `cargo build` 绿；raw client `pub(crate)`（不泄漏）；native AFIT impl diport trait；adapter 保持 forbid(unsafe_code)；不被任何域 crate 依赖（deny 绿） |
| **GATE** 收口 | `cargo build --workspace` 全绿 + 签名 review 通过 → 放行 W 宽扇出 (#1000–#1016) |

## 并行拆分建议（增并行度）

- 同层 unit 可在 tasks 中再拆"子 PR"（如 PR-1 拆 `vocab`/`ids` 一组、`secure`/`support`/`runctx` 一组），因同层 crate 互不依赖。
- PR-4（域）与 PR-5（adapters）触不同 crate → 全程可并行（均在 PR-diport 后）。
- 跨层严格串行：任一层 PR 合并前，其"上游门"列出的层必须已合并（DI port 消费方 PR-3/4/5 均门于 PR-diport）。

## 失败排查

- `cargo build` 报 DI port trait 不 dyn-compatible（`Box<DynX>` 编不过）→ 检查 dynosaur 宏 `#[dynosaur::dynosaur(DynX = dyn(box) X)]` 是否就位、trait 是否违反 dyn-compatible（泛型方法/返回 Self/impl Trait，ADR-003 §4.6）。
- `forbid(unsafe_code)` 阻断 dynosaur 生成点 → 该 trait 误放在 diport 以外；DI port 必须定义在 diport（仅 diport 有 forbid→deny 例外，ADR-003 §3）。
- mock 编译失败 → dynosaur/native-AFIT 下 mockall 形态以 PR-diport 验证结论为准（data-model 待决项#6）。
- 覆盖率门 CI 红 → PR body 缺覆盖率豁免声明（ADR-004 C8）。
- deny.toml 红 → 跨域 import / 域依赖 adapter（违 FR-009），或 dynosaur 依赖出现在 diport 以外（违 C11），按分层 + wrappers 修依赖。
