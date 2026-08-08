# Implementation Plan: Platform Application waist 与外部消费证明

## 本规格 PR

#2041 只确定 Platform application 的能力边界、禁止面、依赖 DAG 和 proof owner。不实现 façade、package、external
repository、SemVer fixture、profile 或 runtime behavior。

## 后续交付 DAG

```text
#2042 -> (#2044 + #2045) -> #2047 -> #2048

#2045 + #2048 -> #2049 thin façade

#2050 -> #2051 shared packaging mechanics

#2049 + #2051 -> #2052 final façade proof + independent T2 consumer
```

精确依赖为 `#2049 blocked-by #2045,#2048`，`#2052 blocked-by #2051,#2049`。

## 阶段

### Phase A — API design（#2045）

- 从真实应用场景定义最小能力类别和 exact public signature。
- 对每个 internal 类型选择隐藏、只读 projection、wrapper 或受控 adapter；不得直接 re-export ownership detail。
- 使用 compile-positive/negative fixture 证明设计可用且禁止面关闭，不实现 façade runtime behavior。

### Phase B — Thin façade（#2049）

- 只实现 #2045 接纳的 API，优先复用现有类型与逻辑。
- 由 #2048 的 release-check 和 compile fixture 覆盖直接/间接泄漏。
- 不接真实 provider、不创建 DI container、不改变 startup/readiness/drain 行为。

### Phase C — Independent consumer（#2052）

- 在 #2051 已证明共享 mechanics、#2049 已完成 façade 后，从同一 revision 生成实际 façade `.crate` 并建立独立 consumer；
  早于 #2049 的 package 结果不具 canonical 效力。
- consumer compile-use 全部承诺能力，并用公开 typed builder 启动有界 application seam、执行一次 verified-context
  handler request、观察 Conditions/Diagnostics，再经 `RuntimeHandle` 停止。
- 负例拒绝 internal import、verified authority mint 与敏感 detail 泄漏，并建立 N-1→N fixture seed。
- T2 fixture 不启动 Reference Extension、真实 provider 或 production journey，不新增 T3。

## 回滚与兼容

API design、façade 和 consumer 分三个可独立回滚 outcome。façade 首次建立时不保留 internal path 兼容层；产生真实
Release API consumer 后，后续兼容与弃用由 release-selected baseline 和 consumer fixture 共同拥有。
