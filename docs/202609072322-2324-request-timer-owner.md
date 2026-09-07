# #2324 共享执行时间原语

状态：PR #956 外部审查 F1，采用方案 A，实现与定向验证完成，待固定 artifact 和最终 CI。

## 决策与事实

用户要求彻底、不向后兼容、优雅简洁。Platform 新增的公共 ExecutionTimer 与消息库既有
Clock / ExecutionTimer 承担相同的单调时间和截止唤醒职责。消息 RealtimeClock 最终也映射
Tokio Instant；Duration 起点主要服务表示和受控测试，没有发现业务必须隔离两套时间原语的证据。
消息 PgTimer 已使用内部类型擦除，泛型与动态存储差异也不要求两个公共 owner。

原 F1 评级 P1 / Cx4 / IN_SCOPE。最初推荐 B 偏重迁移范围；用户追问 A/B 哪个更彻底后，
复核真实消费者，修订推荐 A。澄清请求 Q-f028960965e142e8bf54ac8e8e0acbf0 等待 120 秒后
expired，按用户预先给定的无响应采用推荐项规则执行 A；没有收到选择 A 的显式回答。

## 方案比较

| 方案 | 范围与原理 | 优点 | 取舍 |
|---|---|---|---|
| A（采用） | request-context 唯一持有公共时间原语，原子迁移全部请求、消息及 adapter 消费者 | 消除重复定义和时间转换，无兼容路径 | 跨组件 API 迁移，须完整编译及行为验证 |
| B | Platform 改名 RequestTimer，明确请求专属边界 | 改动小，可消除通用命名歧义 | 两套公共时间抽象仍存在，不满足本轮彻底消除重复的目标 |
| C | 保持当前接口，将统一工作 defer | 当前交付变化最少 | 已确认的重复 owner 和命名歧义均遗留 |

A 在本 PR 完成。迁移不涉及持久化/网络时间格式；当前 Rust API 无已发布或仓外冻结承诺，
按 api-versioning.md 原子替换，不保留 alias、re-export、shim、兼容 feature 或第二条调用路径。

## 最终能力边界

1. rss-request-context 拥有 Clock、ExecutionTimer、Deadline 和 DeadlineOverflow。
   时刻采用 std::time::Instant；from_timeout 只读一次注入时钟，溢出返回类型化错误，capped 不延长父期限。
2. 公共 timer 返回 impl Future；Platform 与 PG 在私有存储边界进行类型擦除。
   私有擦除不是第二个公共 port，消费方仅实现 canonical ExecutionTimer。
3. 删除 Platform 的 ExecutionTimer / DeadlineFuture 与消息库 Clock / ExecutionTimer /
   MonotonicInstant / AbsoluteDeadline。生产、testkit、测试、README 和独立消费 fixture 直接导入 canonical owner。
4. 消息 ExecutionBudget、ExecutionDeadlines、OperationDeadline 与 within 保留消息 owner。
   OperationDeadline 只表示 provider 调用当下的剩余预算快照；reconcile 直接投影剩余预算，删除旧 BridgeClock。
5. 请求 handler 优先与消息 deadline 优先的执行仲裁保持各自职责；共用时间不合并两套状态机。
   timer 必须独立唤醒，cooperative budget 耗尽不能屏蔽已到期截止时间。
6. 受控时钟使用固定 Instant 起点；FakeClock::advance 溢出显式返回 DeadlineOverflow 且不改变时钟。
   溢出测试定位运行平台真实 Instant 表示上限。
   墙钟、持久化时间以及其它能力的专属执行协议不冒充同一单调时间原语。

## 实施与验收计划

- 主 agent 原子迁移公共 owner、全部生产 adapter 与测试消费者；不派发 fix 子 agent。
- 共享 Deadline 测试先验证缺失公共接口导致编译失败，再覆盖零预算、缩短与溢出。
- 同一个具体 timer 和同一 cutoff 同时驱动 Platform 请求与消息 within，实际验证二者超时。
- 保留请求释放、取消、cooperative starvation、消息重试/结算/溢出和独立 feature 消费验证。
- 同步 canonical consumer/README/独立锁文件，实际运行 source 和固定 revision artifact。
- 提交、推送、冲突预检、pm:fix、needs-check-fix 后运行 canonical CI，并延迟检查外部复核状态。

## 参考

- 仓内 primary：transactional-messaging 的 policy.rs、PG PgTimer、runtime RealtimeClock、testkit FakeClock。
- docs/rules/dependency-policy.md：共享类型唯一 owner，公开接口表达真实能力；私有存储不要求公共抽象分叉。
- docs/rules/api-versioning.md：Foundation/common primitive 只有一个 owner，替换删除重叠类型，不保留兼容路径。
- ref: tower tower/src/timeout/mod.rs@tower-0.5.2 — 请求层持有超时仲裁，时间原语与业务结果分离。
  https://github.com/tower-rs/tower/blob/tower-0.5.2/tower/src/timeout/mod.rs
- 本仓使用显式 provider-neutral timer，不复制 Tower 对 Tokio 的固定绑定。
