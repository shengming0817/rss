# RSS 对标框架参考（framework-comparison）

> **入口单一事实源** · `explorer` / `developer` / `ship` / `fix` 查「当前模块对标哪个开源项目」的入口。
>
> 概念级映射真源在 [`CLAUDE.md` §参考框架](../../CLAUDE.md)；本文件在其上补 **repo 坐标 + 关键源码起点路径**，
> 供 `WebFetch` 拉 raw 源码对比。新建 / 重构层内模块前，explorer 按下表 step 1 确定 primary / secondary 对标。
> 路径列是**起点**，explorer 用 `WebSearch` 校准具体文件与行号（仓库布局会变）。

## 模块对标表

| RSS 模块 / 层 | primary 对标（owner/repo） | 关键源码起点路径 | secondary / Rust 生态 |
|---------------|---------------------------|-----------------|----------------------|
| 域 crate 生命周期 / init + 契约校验（`bootstrap`） | `kubernetes/kubernetes` | `pkg/controller/` · `staging/src/k8s.io/client-go/tools/cache/` | `kube-rs/kube`（`kube-runtime/src/controller/`） |
| 域 crate 运行时 / 依赖注入（组合根 `assemblies` / `bins`） | `uber-go/fx` | `app.go` · `module.go` | `AzureMarker/shaku` / 构造器注入 |
| 代码生成（`generated` / build.rs / proc-macro） | `zeromicro/go-zero` goctl | `tools/goctl/api/gogen/` | proc-macro（`dtolnay/syn` · `quote`） |
| 中间件（`httpserve` tower 层） | `go-kratos/kratos` | `middleware/middleware.go` | `tower-rs/tower`（`tower/src/builder/`） |
| HTTP server（`httpserve`） | — | — | `tokio-rs/axum`（`axum/src/routing/`） |
| 事件驱动（`eventexec` / EventBus） | `ThreeDotsLabs/watermill` | `message/router.go` · `pubsub/gochannel/` | — |

raw 拉取 URL 形态：`https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}`
（branch 多为 `master` 或 `main`，404 时换分支重试；大文件先 `Grep`/`WebSearch` 定位行号再局部拉取）。

## Rust 标准库参考

> `fix` 技能（标准库 / 核心生态优先）查此表：有既定做法时遵循，不自创。语言层细则见 `.claude/rules/rss/rust-standards.md`。

| 场景 | 标准库 / 核心生态做法 |
|------|----------------------|
| 错误类型 | `thiserror`（库错误枚举）/ `anyhow`（应用边界），见 `error-handling.md` |
| 时间 | `Clock` trait 注入（构造器位置参），禁止默认系统时钟 |
| 集合 / 迭代 | 入参优先 `&[T]` / `impl Iterator`，避免无谓 `clone` |
| 序列化 | 仅 contract / DTO derive `serde`，domain 类型不 derive |
| 并发 | tokio task + `CancellationToken`，资源 RAII 清理 |
| HTTP 测试 | `tower::ServiceExt::oneshot` + `axum::http` 驱动 handler |

## 维护

模块新增 / 对标变更时同步本表，并与 `CLAUDE.md` §参考框架 概念表保持一致：
**概念真源在 `CLAUDE.md`，坐标真源在本文件**。表中无匹配模块时，explorer 须 fail-loud（见 `.claude/agents/explorer.md` step 1），不静默吐空结论。
