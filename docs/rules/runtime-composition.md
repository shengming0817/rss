# Runtime Composition 规则

本文拥有 assembly manifest、AssemblyLock、RuntimePlan、provider closure、共享接线与 lifecycle 的稳定边界。

## 声明与派生链

- Assembly manifest 声明 domains、contracts、providers、listeners 与 workflow activation；未知、重复、空必填项
  fail-closed。
- generated modules/providers、AssemblyLock 与 RuntimePlan 必须从同一规范化 manifest 单向派生，禁止手写旁路、
  fallback、双写或运行期重新解释。
- AssemblyLock 固定 repository identity；RuntimePlan 固定本次启动的 typed config/provider/lifecycle identity。
- artifact classification、展示 inventory 和健康报告不得反向修改 manifest、lock 或 plan identity。

## Provider closure

- active capability 必须有唯一 official provider constructor、配置身份、health/readiness 与 lifecycle owner。
- production root 只能消费 generated provider catalog；不得按字符串、环境变量或同名类型动态发现 provider。
- provider 不可用、capability 缺失、声明与 live closure 不一致时启动失败，不降级到 memory/demo provider。
- omitted/disabled workflow 不得构造 store、worker、route、probe 或 registry。

## SharedRuntimeDeps

`INVARIANT: WIRING-DEPS-INFRA-ONLY-01 { level = "Medium", exec = "check", source = "code" }`。

- `SharedRuntimeDeps` 只含共享基础设施与 provider value object；不得含 domain service、domain repo 或 domain output。
- allowed roots 与 exact exception 只在 `xtask/runtime-deps-guard.toml` 声明；文档不复制成员。
- 缺失、空 discovery、未知 root、宽泛 wrapper 或 malformed config 必须由 `cargo xtask runtime-deps guard`
  fail-closed；无 hardcoded fallback。
- 域服务留在所属 `wire_X`，跨域行为只经 contract。

## Lifecycle

- composition root 拥有 prepare/start/readiness/drain/shutdown；域 init 不做外部 I/O 或后台 spawn。
- startup 是有界事务：任一步失败必须按逆序回滚已启动资源并保留脱敏因果链。
- readiness 只在全部 required provider 与 worker 达成同一 plan identity 后为真。
- process runtime 是 listener activation、completion supervision、readiness revocation、root cancellation、signal
  priority、unexpected-exit reporting 与 total/LIFO drain 的唯一 owner。adapter 只能返回由真实 bound socket
  铸造的 opaque listener receipt；readiness 前必须消费非空 listener receipt，root cancellation 前的任何
  terminal listener state 都必须 fail-closed。
- drain 先停止 admission，再等待有界在途任务，最后关闭 provider；超时返回失败而非伪造 clean shutdown。
- RuntimeExec 是 listener activation、completion supervision、readiness revocation、root cancellation、signal
  priority 与 LIFO drain 的唯一 owner。HTTP adapter 只能通过消费真实 bound socket 铸造 opaque
  `ListenerTaskRegistration`；非空 sealed listener receipt 是 readiness 的必填证明，root cancellation 前任一
  listener terminal 都永久 fail-closed。
- config reload 只能原子切换完整 validated snapshot；candidate 失败保留 last-good。

## 载体

- Hard：typed manifest/schema、generated Rust、private constructors、sealed RuntimePlan/receipt。
- Medium：assembly validate、runtime-deps guard、provider conformance 与 lifecycle tests；committed
  lock/runtime-plan raw-byte drift 只在 candidate/release final HEAD 验证，不进入普通 PR affected CI。
- build-time repository verification 与 RuntimePlan 的 manifest + verified-lock bound parse 必须继续
  fail-closed；将 raw-byte drift 延后到 candidate/release 不得产生未验证执行旁路。
- production process/config/provider join 只有经正式 production acceptance 才进入 T3。
