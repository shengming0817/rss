# GoCell 以 Rust 为主：CI 适配方案（参考 gocell 现有 CI）

> **归档·冻结** · 2026-06-21 GoCell→Rust 迁移评估快照（target 命名已对齐 RSS）· **非现行规则**。
> 现行架构单源见 `docs/rules/architecture.md`；本批只读冻结，仅供迁移评估溯源。
>
> 生成日期：2026-06-21 · 接三档 Cargo 适配，逐项映射 gocell 现有 CI 在 Rust 版的去向
> 配套文档：[gocell-package-overview.md](./gocell-package-overview.md) · [gocell-rust-tradeoff.md](./gocell-rust-tradeoff.md) · [gocell-rewrite-sequence.md](./gocell-rewrite-sequence.md) · [gocell-rust-crate-mapping.md](./gocell-rust-crate-mapping.md) · [gocell-rust-directory-structure.md](./gocell-rust-directory-structure.md) · [gocell-rust-eval-checklist.md](./gocell-rust-eval-checklist.md)

## 一、gocell CI 现状（基线）

11 个 GitHub Actions workflow（RSS 当前 CI 承载面为 GitHub Actions；本地 `make verify` / `make ci` 与 CI 共用 `cargo xtask` 门集）：

| workflow | 内容 |
|---|---|
| `ci.yml` / `pr-check.yml` → `_build-lint.yml` | build-test（go build + golangci-lint + 覆盖率，5 分片）、integration-test（testcontainers）、sonarcloud、os-smoke（mac/win）、examples-smoke（启 ssobff + /readyz） |
| `governance.yml`（Governance Strict） | `make verify` 按 bucket 扇出：codegen golden / generated drift / archtest invariants 子集 / go.work 多模块 build·test funnel / gofumpt 等 |
| `security-static.yml` | CodeQL(Go 数据流 SAST) + Semgrep(p/golang) |
| `security-vuln.yml` | govulncheck（Go 漏洞库 + 调用图可达性） |
| `test-race.yml` | `go test -race`（unit + pg-integration 两 lane） |
| `archtest-nightly.yml` | 全 archtest 矩阵（24 分片，~628 测试，进程隔离，schedule-driven） |
| `mqtt-tls-nightly.yml` / `otel-collector-nightly.yml` | adapter 专项真集成（nightly） |
| `release.yml` | 发布 |

## 二、gocell CI → Rust 去向映射

| gocell CI 项 | 作用 | Rust 去向 | 保留? |
|---|---|---|---|
| build-test（go build，5 分片） | 编译 | `cargo build --workspace --all-features --all-targets` | **保留↑**（顺带吸收分层/required-deps/sealed/穷尽 → 编译错） |
| golangci-lint（PR diff 模式） | lint | `cargo clippy --all-targets --all-features -- -D warnings` + `clippy.toml` | **保留**（+吸收 clock/import/panic 纪律 archtest） |
| gofumpt | 格式 | `cargo fmt --check` | 保留 |
| 单测（5 分片）+ 覆盖率门 | 测试/覆盖 | `cargo nextest run --workspace` + `cargo llvm-cov` 阈值 | 保留（进程隔离原生，**分片多余**） |
| integration-test（testcontainers） | 集成 | `cargo nextest` + `testcontainers-rs` | 保留（同形） |
| **test-race（`-race`）** | 数据竞争 | `Send`/`Sync` 编译期 | **塌进编译器**（残留 `miri`/tsan 仅当有 unsafe 并发） |
| **archtest-nightly（24 分片，~628）** | 架构不变量 | 编译器 + `cargo-deny` + `dylint` | **大部分蒸发**（残留 dylint 进 PR，**无需 nightly 矩阵**） |
| governance：codegen golden / generated drift | 生成物漂移 | `cargo insta`（快照） | 保留（换载体） |
| governance：archtest invariants 子集 | 轻量不变量 | `dylint` + `cargo-deny` | 收缩 |
| governance：go.work 多模块 build/test funnel | 多模块编排 | `cargo --workspace`（原生成员） | **脚手架蒸发**（hack/lib/modules.sh 那套全没） |
| depguard（分层禁依赖） | 分层 | `cargo-deny` bans + crate 依赖图 | 保留（更硬：不声明就编不过） |
| security-vuln（govulncheck） | 供应链漏洞 | `cargo-deny advisories`（RustSec）+ `cargo audit` | 保留（换库） |
| security-static：CodeQL | 数据流 SAST | CodeQL Rust（**preview，弱于 Go**） | 保留但**弱化** |
| security-static：Semgrep | 模式 SAST | Semgrep Rust（规则较薄） | 保留但弱化 |
| os-smoke（mac/win 矩阵） | 跨平台 | `cargo build/test` matrix | 按需保留（控制面常 Linux-only） |
| examples-smoke（启 ssobff，/readyz） | 启动冒烟 | 启 `server` bin + curl `/readyz` | 保留（同形） |
| —（gocell 在 governance 里做 authoring-schema SemVer） | 公共 API SemVer（轴 A） | `cargo-semver-checks` + `cargo-public-api` | **对应保留/强化**（原生破坏式 API 检查） |
| nightly adapter 集成（mqtt-tls/otel） | adapter 真集成 | 同形 nightly（若该 adapter 在） | 保留 |
| sonarcloud | 覆盖聚合 + 质量门 | `cargo llvm-cov`→Sonar（可选）；质量门大半被 clippy 吸收 | 可选保留 |
| release | 发布 | `cargo build --release` / `cargo-dist` | 保留 |

## 三、Rust 版实际保留的 CI 闸门（精简后）

1. **`cargo build --workspace --all-features --all-targets`** — 编译即闸门（吃掉分层/required/sealed/穷尽/数据竞争一大半）
2. **`cargo clippy -- -D warnings` + `clippy.toml`** — lint + clock/import/panic 纪律（`disallowed-methods`/`disallowed-types`）
3. **`cargo fmt --check`**
4. **`cargo nextest run`（+ testcontainers 集成）** + **`cargo llvm-cov`** 覆盖率阈值（引擎与基础 crate `consistency`/`primitives`/`vocab`/`ids` ≥90% / 新增 ≥80%，沿用 gocell 覆盖率口径）
5. **`cargo-deny`** — advisories（漏洞）+ bans（=分层）+ licenses + sources，一把抓
6. **`cargo dylint`** — 残留真要 AST 级的少数不变量（个位数，进 PR 不进 nightly）
7. **`cargo insta`** — 生成代码/wire schema 的 golden 快照
8. **`xtask` 校验器** — 契约扇出闭环 + L0–L4 一致性 governance + wire 版本策略（**三档里语言无关、框架自建的那部分，原样留**）
9. **`cargo-semver-checks` + `cargo-public-api`** — 公共 API SemVer（轴 A）
10. **examples-smoke**（启 server + /readyz）、**SAST**（Semgrep + CodeQL-Rust preview，弱化）、**release**

> 聚合入口 `cargo xtask verify`（`make verify` 薄 alias）**已落地（#1023）**：串 fmt + meta（contract validate / layer-deps / codegen --check）+ build + clippy + nextest（含 insta 快照测试）+ deny + dylint（`-D warnings` fail-closed），本地与 CI 同源——对应 gocell 的 `make verify`，契合 azure `no-ci` 降级本地跑。coverage(llvm-cov) 阈值（per-PR-diff 语义）与 `public-api` baseline 冻结门语义不同、不入 verify；bash automation selftest 折入仍 backlog。

## 四、三处最大变化

- **race 检测整条没了** → `-race` 运行时抽查变 `Send`/`Sync` 编译期；只有写 `unsafe` 并发才补 `miri`/tsan（控制面几乎没 unsafe；测并发数据结构可选 `loom`）。
- **archtest-nightly 24 分片矩阵消失** → ~200 archtest 里一半进编译器、三成进 `cargo-deny`/`clippy`/`insta`，残留 `dylint` 几条进 PR-time，**不再需要 schedule-driven 大矩阵 + 进程隔离 harness + slowgate 预算治理**。
- **go.work 多模块 funnel 全部蒸发** → gocell CI 大量复杂度（per-adapter import-path 模式、nested-module 边界处理、hack/lib/modules.sh、bucket 注解派生、per-module govulncheck/SARIF 批次）在 Cargo workspace 下是 `cargo --workspace` 原生覆盖。

## 五、净效应

gocell 那 11 个 workflow 在 Rust 下大致收敛成：

- **PR workflow** ≈ `build` + `clippy/fmt` + `nextest/llvm-cov` + `cargo-deny` + `insta` + `dylint` + `xtask verify` + `cargo-semver-checks` + examples-smoke +（弱化）SAST
- **nightly** ≈ 基本只剩 adapter 真集成（mqtt-tls / otel 等，若该 adapter 存在）
- **release** ≈ `cargo-dist`

**保留的项不少，但每个更薄，整体闸门数与脚手架显著缩小**——与 [gocell-rust-tradeoff.md](./gocell-rust-tradeoff.md) / [gocell-rust-crate-mapping.md](./gocell-rust-crate-mapping.md) 的"治理表面积大幅收缩、安全地板抬高"一致。

## 六、待核实 / 决策点

1. **CodeQL Rust 成熟度**：截至 2026-01 为 preview，弱于 Go SAST；若要强 SAST 需评估当时状态，或更依赖 clippy 安全 lint + `cargo-deny` advisories。
2. **覆盖率阈值口径**（**已定**）：沿用 gocell 覆盖率纪律——引擎与基础 crate（`consistency`/`primitives`/`vocab`/`ids`）≥90%、新增 ≥80%（见 `.claude/rules/rss/rust-standards.md`）。
3. **runner/forge**：CI 落 GitHub Actions；workflow 文件形态由 GitHub Actions 承载，闸门集合仍由 `cargo xtask` 决定。
