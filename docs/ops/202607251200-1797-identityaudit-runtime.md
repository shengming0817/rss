# identityaudit 独立运行手册

> #1797。本文是 `identityaudit-server` 与 `identityaudit-runtime` 的 operator 入口。配置语义单源为
> `assemblies/identityaudit/src/config.rs`，部署契约为提交的 Draft-07
> `assemblies/identityaudit/config.schema.json`。
>
> ref: `oxidecomputer/omicron nexus/src/lib.rs@3298185e6cb3f6934a581122101e52988dc81895`

## 运行闭包

identityaudit 只装配 Identity、Audit 及其声明的持久 provider。登录产生的 `session-created` 先与身份变更
同事务写入 PostgreSQL outbox，再经 broker relay/consumer 写入 Audit 哈希链；HTTP 鉴权决策同时保留独立的
持久 `PgAuthAuditSink`。两条审计路径用途不同，不得用 auth sink 代替跨域事件闭环。

该 binary 暴露三个独立 loopback listener：Primary 默认 `127.0.0.1:8080`，承载 `/api/v1/identity`；Admin
默认 `127.0.0.1:8081`，承载 `/api/v1/audit` 与 `GET /api/v1/runtime/inventory`；Health 默认
`127.0.0.1:8083`，承载 `/health/v1/{healthz,readyz,metrics}`。inventory 要求
`runtime:inventory:read` 并沿用 Admin listener 的 RSS User 认证、Identity durable role-grant 授权和持久审计 funnel；global/operator 只描述进程资源没有 tenant owner，调用者仍必须携带 tenant-bound current AuthGrant，并在同 tenant 获得精确 permission binding；无 grant 返回 403，RSS Admin/SuperAdmin token 仍被 verifier 拒绝。失败时不会执行 handler。进程没有
TLS listener capability；外部流量必须由外部 delivery 系统在同一网络命名空间配置 TLS proxy 转发，不能把配置改成
wildcard bind。

## 构建与镜像

仓库根执行：

```bash
./hack/cargo.sh build -p identityaudit --bin identityaudit-server
./hack/cargo.sh run -p identityaudit --bin identityaudit-server -- --help
docker build --target identityaudit-runtime -t rss-identityaudit:1797 .
```

`identityaudit-runtime` 不是默认最终 stage，必须显式传 `--target`。镜像使用 distroless nonroot
（uid 65532），固定入口 `/usr/local/bin/identityaudit-server`，只复制该 binary 与
`/usr/share/rss/identityaudit/config.schema.json`；普通 `docker build .` 仍产出 full runtime。

## 配置与 secret

启动只接受一个闭合配置文档：

```bash
identityaudit-server --config /etc/rss/identityaudit.toml
```

未知字段、未知 schema 版本、明文 secret、任意环境变量名和兼容别名均拒绝。所有 secret 只能使用 schema
列出的 typed reference，并由部署密管注入对应环境；不得把 secret 写入 TOML、argv、镜像层或日志。JWKS、
密码 blocklist 与私有 CA 等文件按配置路径只读挂载，配置与这些文件必须作为同一 generation 原子发布。

外部 delivery 系统必须将镜像、配置和 secret 作为同一 generation 发布与回滚。OCI provenance 与不可变
镜像选择由外部 builder/release 流程证明；应用不读取外部 delivery manifest，也不提供旧 schema 双读、别名
或 fallback。

生产配置还有四项必须显式满足的安全闭包：

- `identity.issuer/audience` 必须与 `oidc.issuer/audience` 分别完全相同，禁止 mint 与 verify 信任域漂移；
- `RSS_IDENTITYAUDIT_VAULT_SIGNER_TOKEN` 只授权 signing key 的 `transit/sign`，
  `RSS_IDENTITYAUDIT_VAULT_DLX_TOKEN` 只授权 DLX key 的 `transit/encrypt`、`decrypt`、`rewrap`，两 token 必须不同；
- `eventing.auditChainKeyId` 固定为 `1`。首次启动仅允许在空 Audit ledger 上把 key 身份写入 PostgreSQL；后续
  启动必须与该 durable guard 相同，错误 secret 会在接流量前失败。轮换必须引入新的显式 schema/migration，
  不存在自动兼容或静默继承；
- tenant authority TTL 显式配置为至少 3600 秒（示例为 3600），clock skew 最大 300 秒（示例为 60）。
  broker backlog 必须在 `TTL - skew` 前告警和处置；超过授权窗口的消息 fail-closed，不得通过放宽校验重放。

`0073` 不是滚动兼容 migration：应用前必须 quiesce 并停止全部旧 audit writer，确认 migration ledger
仍为 72；提交后确认 ledger 为 73，只允许新 binary 在 durable key probe 通过后开放流量。提交前失败按
ledger=72 恢复旧 generation；提交后失败只能修复新配置或增加新的前向 migration，禁止恢复旧 binary、
补默认值、双写或 down migration。完整 catalog/ACL/连接 time fence 见
`adapters/postgres/migrations/README.md` 的 `0073 audit-chain key pin`。

## 探针与终止

- `/health/v1/healthz`：进程存活；
- `/health/v1/readyz`：聚合 PostgreSQL、Vault signer、Vault DLX key、RSS access JWKS、broker relay/consumer 与
  Audit sink；Vault 两项由持续 capability 操作验证，不以一次启动成功代替运行期健康；
- `/health/v1/metrics`：Prometheus 文本，仅供本机或同网络命名空间 collector。

只有 readyz 返回 200 后才接收 Primary/Admin 流量。SIGTERM/SIGINT 由 `runtimeexec` 统一接管，停止 listener
后按 LIFO 精确一次 drain provider、relay、consumer 与 domain worker。应用总 drain budget 为 50 秒，外部
launcher 的 termination allowance 必须至少 60 秒，并保留 5 秒退出缓冲；强制 SIGKILL 不提供 drain 保证。

## Artifact 验收

默认构建中的 binary contract：

```bash
./hack/cargo.sh test -p identityaudit --test artifact_acceptance
```

新镜像 contract：

```bash
./hack/identityaudit-artifact-acceptance.sh
```

binary target 保持默认可执行；脚本构建新 `identityaudit-runtime` 镜像，并显式启用
`artifact-acceptance` feature、只选择 `runtime_image_acceptance` target。两个 target
复用同一执行契约，分别验证 `--help` 以及缺失 `--config` 时的 fail-closed 行为；image 不再依赖
`#[ignore]` 或 `--include-ignored`。业务登录、真实 outbox→broker→Audit 哈希链与优雅关闭由
`journeys/tests/identityaudit_runtime.rs` 负责，artifact 测试不使用伪 provider 冒充该闭环。
