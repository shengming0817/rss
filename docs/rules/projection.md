# Projection 规则

本文拥有 projection target、apply/checkpoint、顺序、切换与恢复。

## Target 与 apply

- active projection 必须声明唯一 target、input contract、partition key、checkpoint store 与 owner。
- apply 使用 typed event/envelope；不得接受 raw payload/topic 或从 body 推导 tenant/schema identity。
- domain mutation 与 checkpoint 必须在同一 target transaction，或由明确的 idempotent/fenced protocol 连接。
- duplicate/old checkpoint 返回 no-op；同 position 不同 content 是冲突并 fail-closed。

## 顺序证明

`INVARIANT: PROJECTION-SERIAL-WITNESS-01`：需要 serial apply 的 harness/runtime 必须消费不可伪造的
`SerialInOrderGuarantor`；不能以配置、测试名或文档声明替代。

`PARTITION-SERIAL-IMPL-ALLOWLIST-01`：witness 只能由获准 adapter/composition 实现，typed allowlist 与
production reachability 提供 Medium 纵深证明。

## Checkpoint

- checkpoint identity 包含 tenant、projection、partition、source position 与 generation。
- compare-and-set 必须拒绝 regression、跨 generation 写入与 stale writer；commit order 使用真实 source order，
  不以普通 sequence 猜测数据库提交顺序。
- append-only event/receipt store 对 serving role revoke UPDATE/DELETE；物理 maintenance 使用独立 capability。

## Rebuild 与切换

- rebuild 写新 generation/target，不原地清空 canonical target。
- candidate 从固定 source position 构建并校验；first-green 后原子切 canonical pointer，再退役旧 target。
- 不保留双写、fallback、alias 或长期 shadow read。失败时旧 canonical 保持不变。
- 大历史 seek 必须使用可索引 checkpoint/source position；运行成本不得随无关历史线性增长。

## Failure 与 carrier

- source unavailable、checkpoint conflict、tenant mismatch、apply/commit unknown 或 witness 缺失均 fail-closed。
- Hard：typed target/checkpoint/generation、sealed witness、private apply transaction。
- Medium：provider conformance、real database ordering/restart/rebuild proof 与 projection governance gates。
- projection 不自动获得 T3；production join 必须独立获得 production acceptance。
