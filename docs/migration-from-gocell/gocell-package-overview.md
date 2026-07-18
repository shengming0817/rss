# GoCell 包能力全景图

> **归档·冻结** · 2026-06-21 GoCell→Rust 迁移评估快照（target 命名已对齐 RSS）· **非现行规则**。
> 现行架构单源见 `docs/rules/architecture.md`；本批只读冻结，仅供迁移评估溯源。
>
> 生成日期：2026-06-21 · 由分层探索子 agent 扫描代码库后汇总
> 配套文档：[gocell-rust-tradeoff.md](./gocell-rust-tradeoff.md) · [gocell-rewrite-sequence.md](./gocell-rewrite-sequence.md) · [gocell-rust-crate-mapping.md](./gocell-rust-crate-mapping.md) · [gocell-rust-directory-structure.md](./gocell-rust-directory-structure.md) · [gocell-rust-ci-plan.md](./gocell-rust-ci-plan.md) · [gocell-rust-eval-checklist.md](./gocell-rust-eval-checklist.md)

## 总览：GoCell 是什么

一个 **Cell-native Go 工程底座**。核心抽象是 **Cell（自治业务单元）+ Slice（Cell 内聚子单元）+ Contract（跨 Cell 唯一通信边界）**。通过一致性分级 **L0→L4** 把"纯计算 / 本地事务 / outbox 事件 / 跨 Cell 最终一致 / 设备长延迟闭环"做成可声明、可治理、可代码生成的运行时模型。

依赖方向严格单向：`kernel ← runtime ← corecells`，`adapters` 实现接口，`cellmodules` 是唯一能依赖所有层的 Composition Root。

一致性等级：

| 级别 | 含义 | 场景 |
|------|------|------|
| L0 LocalOnly | 单 slice 内部本地处理 | 纯计算、校验 |
| L1 LocalTx | 单 cell 本地事务 | session 创建、审计写入 |
| L2 OutboxFact | 本地事务 + outbox 发布 | session.created 事件、config.entry-upserted 事件 |
| L3 WorkflowEventual | 跨 cell 最终一致 | 查询投影、CQRS、Saga |
| L4 DeviceLatent | 设备长延迟闭环 | 命令回执、证书续期、状态收敛 |

---

## 一、framework/kernel/ —— 底座灵魂（只依赖 stdlib + pkg + yaml）

**模型与治理三件套**

| 包 | 能力 |
|---|---|
| `cell` | Cell/Slice 运行时抽象：身份、生命周期（Init/Start/Stop）、Registrar、BaseCell |
| `cellvocab` | 治理词汇表单源：CellType / ContractKind / ContractRole / Level 枚举 + 解析器 + 拓扑校验 |
| `metadata` | cell.yaml / slice.yaml / contract.yaml / assembly.yaml / journey.yaml 的单一解析与建模 |
| `governance` | YAML 元数据编译期验证规则引擎（引用完整性、拓扑合法性、格式合规） |
| `contractspec` / `registry` | 契约端点运行时描述符（sealed）+ 不可变注册表 + 运行时注册状态机 |

**L0–L4 编程模型与状态机**

| 包 | 一致性级 | 能力 |
|---|---|---|
| `outbox` | L2/L3 | 事务外发箱核心接口、ConsumerBase（幂等+去重）、Entry（sealed，`NewEntry` 唯一入口） |
| `command` | L4 | 设备命令队列状态机、三层超时、Sweeper 超期扫描 |
| `saga` | L3 | saga 编排状态机 + 转换函数（Pending→Running→Compensated…），纯数据 |
| `reconcile` | L4 | 期望状态收敛控制环（K8s controller 风格）：level-triggered、指数退避、Leader Election + FencedWriter |
| `projection` | L3 | CQRS 投影生命周期：Apply 钩子、Checkpoint、rebuild 四阶段、exactly-once |
| `idempotency` | — | 消费幂等 Claim/Commit/Release 两阶段 |

**基础设施抽象（隐藏平台依赖）**

`clock`（强制注入时间，禁直调 stdlib time）、`crypto`（KeyProvider/ValueTransformer 接口）、`auth`（AuthPlan + 5 种 ListenerAuth：NoAuth/RssAccessToken/FederatedAccessToken/MTLS/ServiceToken）、`healthz`（ProbeName typed）、`webhook`（HMAC-SHA256 签名纯计算）、`circuitbreaker`（三态熔断）、`lifecycle`（ContextCloser/ManagedResource）、`assembly`（FIFO 启动 LIFO 停止编排）、`wrapper`（contract↔可观测性绑定）、`fsm`（转换可达性）、`depgraph`（依赖图模型）、`metautil`（元数据大小限制共享源）、`observability`（Counter/Histogram/Provider 抽象）、`journey`（J-*.yaml 编目）、`verify`（verify 声明完整性检查）、`crypto`、`ctxkeys`（Cell 模型标识 typed key）。

---

## 二、framework/pkg/ —— 跨层共享词汇表与工具（只依赖 stdlib）

**核心数据模型（无实现，纯词汇）**

- `errcode` — 三通道隔离错误码（Message const literal / PublicDetail 4xx 可下发 / InternalDetail 仅日志）、前缀所有权注册、sealed Error
- `authz` — PDP 决策 Decision（sealed，Allow/Deny 唯一入口）、Effect、Obligations/FieldMask、deny-overrides
- `tenant` — TenantID（sealed canonical UUID）+ RowScope/RowVisibility RLS 谓词 + CrossTenantVisibility
- `projection` — 列掩码 PEP（ResourceProjection sealed）
- `query` — keyset 分页 + cursor 编解码 + 排序

**sealed 标识 / 单源类型（AI-robust Hard 范本，"单源 + 不可伪造"）**

- `idutil` — `SafeID` sealed wire 标识 + `NewUUID`
- `spiffeid` — `CellID`/`CellSet` sealed SPIFFE 身份（cross-cell mTLS）
- `scaffoldid` — `ScaffoldID` scaffold 标识符单源
- `migration` — `Namespace` layer-free 迁移命名空间值类型
- `yamlsafe` — `Scalar` 安全 round-trip 的 typed YAML 标量
- `contractpath` — contract ID → package/import path 唯一转换
- `pgrepoapproved` — `Approval` token，唯一「批准直执 SQL」的 sealed funnel
- `panicregister` — `Approved(reason, value)`，生产唯一批准的 panic 入口

**context 与错误转译**

- `ctxkeys` — 可观测性/网络标识 context key（request/correlation/trace/peer）
- `ctxutil` — `WithDetachedTimeout`，跨 goroutine 脱离父 ctx 的超时
- `ctxcancel` — context 取消 → errcode 转译（`Detect`/`Wrap`/`WrapOrInfra`）
- `validation` — 字段校验 `RequireNotEmpty` + `IsNilInterface`（构造器 fail-fast）

**安全 / 脱敏 / 加密（fail-closed 原语）**

- `redaction` — 脱敏 + IP hash + slog 集成
- `aeadutil` — 纯 AES-GCM（`EncryptGCM` + self-contained 变体）
- `securecookie` — 安全 cookie（加密 + 签名 + timestamp）
- `secutil` — `ValidateTLSEndpoint` 等安全工具
- `pathsafe` — 路径遍历 / 符号链接防御 + 原子写入
- `fspath` — symlink-aware root-containment 唯一谓词 `IsWithinRoot`
- `cmdrun` — 工具路径验证 + 命令执行（CLI 跑 goimports/gofumpt）

**HTTP / 网络 / 持久化 / 测试辅助**

- `httputil` — JSON 响应/错误信封/分页/UUID 路径参数
- `netutil` — `IsValidNetworkAddress` / `IsLoopbackEndpoint`
- `logutil` — `Sanitize` / `SafeAddr`（安全输出 user-controlled 值）
- `observability` — `SafeObserve`，包 metrics 调用防 panic
- `pgquery` — keyset 分页 SQL 生成
- `csvparam` — CSV flag/query 参数解析（`Parse`/`ParseAllowed` 闭值集）
- `testutil` — 测试 I/O + `testtime` 超时常量 + `SyncBuffer` + log 断言

---

## 三、framework/runtime/ —— 通用运行时（http / auth / worker / 可观测性）

> 导入规则：仅可依赖 stdlib + kernel + pkg，明确禁止 adapters / corecells。

**HTTP & 路由**

- `http/router` — chi 兼容，每 listener 一路由器，auto-wire 中间件栈（RequestID/CellAttribution/Tracing/AccessLog/Metrics）
- `http/middleware` — 限流/熔断/CSRF/CookieSession/BodyLimit/SecurityHeaders/Recovery
- `http/health` — /healthz（存活）+ /readyz（就绪，分层依赖报告）
- `http/idempotency` — HTTP 幂等凭证存储（内存，可替换）
- `http/cellmw` — Cell 属性注入

**认证授权**

- `auth` — JWT 签发验证、服务令牌、Principal（device/user/service）、PDP Authorizer、RequirePermission、设备证书签发/验证
- `auth/session` — 会话协议（指纹模式、撤销触发、AuthzEpoch）
- `auth/refresh` — 刷新令牌存储 + 过期 GC
- `auth/credentialfence` — 跨边界凭证栅栏令牌
- `auth/config` — 认证方法配置 + 权限表达式编译

**启动与装配**

- `bootstrap` — 12 阶段统一生命周期编排，多 listener（primary/health/internal/webhook）+ 认证链绑定 + fail-closed
- `composition` — Composition Root 抽象（Builder/App/CellModule/SharedDeps），禁导入 adapters/Provider（funnel 密封在 cmd）
- `config` — YAML + env 覆盖 + 热更新（Watch/Reload）
- `lifecycle` — 多资源生命周期聚合
- `shutdown` — SIGINT/SIGTERM 信号驱动有序关闭
- `worker` — 后台 Worker 组（PeriodicWorker/LazyWorker）

**事件与异步执行引擎**

- `outbox` — Store 接口 + Relay 中继（消费外发箱 → emit 到发布者）+ 故障预算 + 待处理深度观测
- `eventbus` — 内存事件总线（仅开发/测试）
- `eventrouter` — 事件采集聚合（可观测性）
- `saga` — saga 执行引擎（读 journal → 执行 Step → 写 journal+outbox）+ 分布式领导选举 + 五态终止
- `saga/executor` — 单 Step 隔离执行 + heartbeat 续约（Step.Run 在 txRunner 外）
- `saga/tailer` — saga journal 投影 catch-up tailer（fenced checkpoint + 毒事件死信）
- `command` — 命令类型注册表
- `certlifecycle` — 设备证书 L4 续期 reconciler（70-90% jitter，fenced 原子提交）
- `certsigning` — CA 签名 seam（不含私钥，sealed 值类型 + signConstraints fail-closed）
- `crypto` — 密钥管理运行时绑定（LocalAESKeyProvider）

**分布式与跨 Cell**

- `distlock` — 厂家中立分布式锁（Lock 作为资源，三态终止信号，"效率锁非正确性锁"）
- `state/cas` — 乐观并发 CAS（版本冲突检测，cell 私有实体无共享 Store）
- `transport` — 跨 Cell 同步调用 seam（InProcessTransport / RemoteHTTPTransport，contract 级 HTTP 非 cell 级 RPC，transport_mode 指标）

**可观测性与系统**

- `observability/metrics` — HTTP/gRPC/Event/Saga/Config 指标收集器框架（adapter 实现 Prometheus）
- `observability/logging` — slog handler，从 context 提取 trace/request/cell ID + sink 端脱敏
- `observability/healthz` — 就绪探针聚合（背景并发求值，三态严重度）
- `sysinfo` / `syshealth` — 系统元信息 + 整体健康综合评估
- `grpc/interceptor` — gRPC 一元/流式拦截器链（10 环节，同步 HTTP 中间件顺序）
- `audit/ledger` — 追加式 HMAC 链式审计日志（协议 + 开发存储）
- `webhook` — 入站 webhook 三段式幂等流程（签名验证 → 声明凭证 → 处理器）
- `websocket` — Hub 模式连接管理（signal-first 广播 + 心跳）
- `schemavalidate` / `devtools`

---

## 四、corecells/ —— 平台 Cell 实现

| Cell | ID | Type | 级别 | 能力 | Slice 数 |
|---|---|---|---|---|---|
| **accesscore** | accesscore | core | L3 | 身份管理、会话生命周期、RBAC/ABAC 授权、密码变更（CAS）、设备 IP 锁定、gRPC session verify、bootstrap admin | 12 |
| **configcore** | configcore | core | L3 | 版本化配置 CRUD、变更发布、feature flag、订阅缓存（tombstone-GC）、CAS 乐观并发 | 7 |
| **auditcore** | auditcore | core | L2 | 防篡改 HMAC 审计链（relay + bootstrap 双链）、事件消费、跨租户 admin 读（#1810） | 6 |
| **registrycore** | registrycore | core | L1 | 运行时契约声明/治理 submit + list（governance gate） | 3 |
| **syscore** | syscore | support | L1 | 跨 Cell 健康聚合、系统元信息（无状态） | 2 |

**accesscore slices**：sessionlogin / sessionrefresh / sessionlogout / sessionvalidate / sessionverifyrpc(gRPC) / identitymanage / policymanage / rbaccheck / rbacassign / authorizationdecide / configreceive / setup

**configcore slices**：configwrite / configread / configreadinternal / configpublish / configsubscribe / featureflag / flagwrite

**auditcore slices**：auditappendbootstrap / auditappendsession / auditappenduser / auditappendconfig / auditappendrole / auditquery

---

## 五、cellmodules/ —— Composition Root（唯一可依赖所有层）

把 Cell 绑定到 adapter，对外暴露 `Module() composition.CellModule`。核心模式是 **Topology-Gated 选型**（demo/memory vs postgres，缺依赖一律 fail-closed 不降级）。

**Cell 模块**：`configcore` / `accesscore` / `auditcore` / `syscore`

**基础设施 resolver**：

| 模块 | 职责 | Demo/Memory | Postgres |
|---|---|---|---|
| `eventtransport` | 事件总线选型 | InMemoryEventBus | RabbitMQ AMQP |
| `replaydeps` | claimer + nonce store | InMemClaimer + InMemNonceStore | Redis |
| `sagaprojectiondeps` | journal + checkpoint + DLX + locker | MemJournal + InProcessDriver | PGJournal + Redis(multi-pod) |
| `celltransport` | 跨 Cell 同步调用 | InProcessTransport | RemoteHTTPTransport + mTLS |
| `percellpg` | per-cell DSN 分组（纯决策无 I/O） | — | N distinct DSN → N instance |
| `certdeps` | 证书签名 CA + 撤销存储 | softca.DevCA | fail-closed（无持久化 CA） |
| `cellsecrets` | 密钥/cursor/HMAC 加载 | demo key（denylist 防误用） | env real key（fail-closed） |
| `celltls` | 跨 Cell 传输 mTLS 客户端 | plaintext loopback | mTLS + SPIFFE 校验 |
| `deviceidentity` / `deviceserving` | EST 设备证书注册/续期（RFC 7030） | — | — |
| `webhooksource` | webhook 源加载解密 | — | postgres + key provider |
| `grpclistener` | gRPC server 初始化 | — | — |

**Fail-Closed 不变性**：postgres 模式缺失依赖（key/pool/broker URL）启动失败，不降级回内存。各 in-memory 单 pod 原语只经 sealed resolver 的 demo 分支可达（archtest funnel 守卫）。

---

## 六、adapters / cmd / examples / contracts / tools

**adapters/**（14+ 外部适配，实现 kernel/runtime 接口）

| Adapter | 实现接口 | 底层库 |
|---|---|---|
| postgres | Pool / TxManager / Migrator | pgx/v5 |
| redis | distlock.Driver / Claimer / Cache / NonceStore | go-redis/v9 |
| rabbitmq | outbox.Publisher/Subscriber / ConsumerBase | amqp091-go |
| mqtt | outbox.Publisher/Subscriber（sealed ClientID/TopicNamespace） | paho.golang |
| websocket | runtime/websocket.Conn | coder/websocket |
| s3 | ObjectUploader | aws-sdk-go-v2 |
| oidc | Provider/IDToken/Token | coreos/go-oidc |
| grpc | ManagedResource + service 注册 funnel | grpc-go |
| otel | wrapper.Tracer（W3C 传播） | otel SDK |
| prometheus | metrics.Provider | client_golang |
| vault | crypto.KeyProvider（Transit 信封加密） | hashicorp/vault |
| softca | certsigning.Signer / RevocationStore | stdlib crypto |
| ratelimit | middleware.RateLimiter | x/time/rate |

**cmd/**

- `gocell` — 治理 CLI（不进运行时）：validate / scaffold / generate（contractgen/cellgen/required-deps/shared-schema）/ check / verify / graph / export / derive-service-keys
- `corebundle` — 运行时 Composition Root 部署二进制：三 listener（Primary/Internal/Health）+ per-cell PG/broker seam + bootstrap LIFO 回滚

**examples/**

- `ssobff` — 三 Cell 单进程 SSO BFF（accesscore + auditcore + configcore，PostgreSQL）
- `todoorder` — 业务 Cell 示例（订单管理 + contract 定义）
- `iotdevice` — L4 设备示例（命令轮询 + reconcile loop + gRPC ABAC + MQTT）
- `corebundlestarter` — 最小 Composition Root 集成

**contracts/**（跨 Cell 唯一通信单源，`{kind}/{domain}/{version}/`）

| Kind | 数量 | 内容 |
|---|---|---|
| http | ~90+ | method/path/successStatus/auth.permission/request+response schema |
| event | ~18 | topic/payload/headers/delivery semantics/幂等 key |
| grpc | 2 | .proto + mTLS（session verify、conformance） |
| shared | — | CAS / deviceidentity / errors 共享 schema |
| command / projection | 0 | 预留 |

**tools/**

- `codegen` — contractgen / cellgen / requireddepsgen / sharedschema / cellmodulemeta；单一 Render 出口（goimports + gofumpt）+ golden 漂移检测（VerifyInWorktree）
- `archtest` — ~200+ 架构不变量（saga / cert / mqtt / handler / distlock / assembly / probename 等），AST 扫描 + type scan + callsite inventory + golden 对标，强制 sealed funnel
- 其他：depgraph / metricschema / pg-migrate / protobuild / nogo（自定义分析器）/ e2egate / releasesmoke 等

---

## 分层依赖规则速查

| 层 | 允许依赖 | 禁止依赖 |
|----|----------|----------|
| kernel | 标准库、pkg、yaml parser | runtime、adapters、corecells |
| pkg | 标准库 | kernel、corecells、runtime、adapters |
| runtime | kernel、pkg | corecells、adapters |
| corecells | kernel、runtime | adapters（通过接口解耦） |
| adapters | kernel、runtime | corecells |
| cellmodules | 所有层 | 无（Composition Root） |
| examples | 所有层 | 无 |
