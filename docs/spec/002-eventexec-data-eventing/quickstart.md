# Phase 1 Quickstart: 双拓扑端到端验证

验证「数据持久化 + 事件处理」在 **demo（in-mem）** 与 **durable（postgres/redis/amqp）** 两拓扑均成立。实现细节见 data-model.md / tasks.md；本文件只给可运行的验证场景与期望结果。

## 前置

```bash
# 工具链（当前即可用）
rustup show                      # stable 1.96（rust-toolchain.toml）
cargo nextest --version          # 进程隔离测试
```

> **durable 拓扑基建尚未交付**：本地 postgres + rabbitmq（以及需要 Redis 的其它机制）的 `docker/dev-stack.yml`
> 当前仓库**不存在**，由 T003（postgres 基座）/ T006（amqp）随 adapter 落地时交付。
> 在此之前，下文「durable 集成测试」与「场景验证」中标注 durable 的步骤**不可直接运行**；
> demo（in-mem）路径与单测/治理则当前即可跑。

## 单测 / 治理（每个 PR 必跑）

```bash
cargo build --workspace
cargo nextest run --workspace                 # 含各等级表驱动/原子性/幂等/replay 单测（fake 替身）
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo xtask verify                            # 分层依赖 + 契约扇出 + 治理 #[test] + dylint(-D warnings)
```

期望：全绿；`consistency` 覆盖率 ≥90%，新增代码 ≥80%。

## durable 集成测试（feature 门控，待基建交付后可跑）

> ⚠️ 当前 workspace **尚无 `integration` feature**，下列命令暂不可执行。该 feature 由 T003/T005/T006
> 在相应 adapter crate（`adapters/{postgres,redis,amqp}`）的 `Cargo.toml` 定义 `[features] integration = []`
> + `#[cfg(feature="integration")]` 隔离真实 pg/redis/amqp 测试时落地（package-scoped，避免 workspace 假设）。

```bash
# 待 adapter PR 定义 integration feature + dev-stack.yml 起容器后：
cargo nextest run -p rss-postgres -p rss-redis -p rss-amqp --features integration   # 真 pg/redis/amqp
```

## 场景验证（按 user story）

### SC-002 事件零丢失（P4+P5+P8）
1. demo：登录 → outbox entry 持久化 → relay 中继 → audit 消费 append（journey 绿）。
2. durable：杀 relay 进程于「发布后 CAS 前」→ 重启 → 同事件被 audit 再收到 → 幂等去重 → 审计仅一条。
- 期望：at-least-once + 幂等 = 有效一次；审计无重复。

### SC-003 事务原子性（P4）
- 触发会话创建事务回滚 → 查 outbox 表无该 entry。

### SC-005 fail-closed（P5/P6）
- durable 拓扑去掉 broker URL / redis 配置 → 启动 → 期望进程 `Err` 退出，日志明示缺配置；**绝不**以 in-mem 启动。

### SC-006 saga 逆序补偿（P9）
- 3-step saga，第 2 步返回失败 / timeout / 重试预算耗尽 → journal 记录逆序 compensate 已完成前缀 → saga 终态 failed；补偿 timeout / 预算耗尽 → saga dead-letter。

### SC-007 投影续投（P10）
- 处理 100 事件、checkpoint=50 → 重启 → 续投 51–100（无重复无遗漏）；从 0 重放结果与增量一致。
- `cargo clippy`/`cargo dylint` 拒含 `DELETE FROM projection_events` 的 synthetic red case。

### SC-008 reconcile fencing（P11）
- 缺 Tenancy 参 → `cargo build` 编译失败（Hard）。
- 多副本 2 实例并发 acquire lease → 仅一成功 dispatch；epoch 1 写后以 epoch 1 再写被拒、epoch 2 受。

### command 双侧对称（P12）
- 新增 command 契约 → `cargo xtask`（codegen）→ 生成 emit/register wrapper。
- 删除 generated 的 emit 或 register wrapper 任一侧（如 codegen `render_command_glue` 丢侧）→ `cargo xtask verify` 双侧对称治理（COMMAND-SYMMETRY-01）失败。
  > **能力边界（mechanism-landing）**：command authoring 由私有 `CommandSpec`、policy-exclusive wrapper 与 reviewed DTO 类型封闭；AST 只检查生产 provider impl/callsite 集合，不承担 authoring seal。真实 consumer handler 注册仍由 active contract topology 校验。

> **bridge 延迟落地**：generated wrapper 的 `emitter: &E`（`E: CommandEmit`）和 `registrar: &mut Reg`（`Reg: CommandRegister`）由组合根（bin / assembly crate）的 bridge impl 提供。该 impl 随**第一个真实命令消费域**一并接线，不在本 mechanism-landing PR 中包含。bridge 接线细节见 `docs/rules/eventbus.md` §Command dispatch。

## 验收出口
- 上述命令/场景已覆盖 **SC-002/003/005/006/007/008** + command 双侧；其余 SC（SC-001/004/009/010）由各实现 PR 的 CI 门覆盖（SC-001: `cargo build --workspace && cargo nextest run`；SC-004: L2 幂等治理 #[test]；SC-009: `cargo llvm-cov`；SC-010: PR 行数/DAG 检查）。
- 每个 PR 在其 wave 内独立可测、独立可 demo。
