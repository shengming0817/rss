# Tasks: Platform Application waist 与外部消费证明

本文件不复制 tracker 实时状态，只保存稳定 PBI identity、依赖、outcome 和 canonical proof。

| Logical ID | PBI | Outcome | Blocked-by | Canonical proof |
|---|---:|---|---|---|
| RSS-NW-004 | #2045 | Platform waist exact API、internal 泄漏与 public detail 边界 | #2042 | compile-positive/negative + sensitive-detail fixtures |
| RSS-NW-005 | #2047 | release-selected API baseline | #2044, #2045 | `cargo public-api` owner separation |
| RSS-NW-006 | #2048 | compatibility、SemVer 与泄漏进入既有 release-check | #2047 | release-check positive/synthetic negative fixtures |
| RSS-NW-015 | #2049 | 薄 Platform Public façade | #2045, #2048 | façade tests + release baseline + forbidden leakage proof |
| RSS-NW-010 | #2051 | 共享 packaging mechanics，不授予 façade verdict | #2050 | release-check generate/unpack/external-build fixtures |
| RSS-NW-016 | #2052 | 同 revision final façade proof、独立 T2 consumer 与 SemVer seed | #2051, #2049 | actual `.crate` + startup/request/shutdown + negative imports + N-1→N fixture |

## #2041 入库任务

- [x] 定义应用作者能力类别，而不提前冻结具体 Rust symbol。
- [x] 明确可信 context 的只读/mint 边界及完整 internal 禁止面。
- [x] 将 façade、共享 mechanics 和 final façade/T2 consumer proof 分成可回滚 outcome。
- [x] 拒绝用 Reference Extension、仓内 assembly 或 example 替代外部 consumer。
- [x] 不引入 Platform schema、DI container、Provider SPI、profile activation 或 T3。

## 后续 PBI 共同约束

- exact API 必须从真实外部应用场景和当前类型推导，不为未来可能性创建 trait。
- façade 只适配现有行为；任何 provider/profile/runtime closure 属于其它独立 PBI。
- internal 泄漏优先由 Cargo、visibility、private/sealed type 消除，再用 compile fixture 和 release-check 补证。
- consumer 必须拥有独立 repository/lockfile，只从 #2049 同一 revision 的 actual package 消费并执行完整有界 waist seam。
