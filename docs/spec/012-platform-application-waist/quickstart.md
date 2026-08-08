# Quickstart: Platform Application waist 规格入口

## 当前规格验证

运行 [`Spec 010 quickstart`](../010-release-surface-convergence/quickstart.md) 中统一的一次性结构、链接、advisory 和
仓库验证命令。Markdown 不是 API 或架构 enforcement carrier。

## 开始后续 PBI 前

1. 回读 #2045、#2049 或 #2052 及其全部 `Blocked-by`。
2. 从当前 Cargo graph、public API、assembly/profile metadata 和真实 consumer 需求重新读取事实。
3. 确认 [`Spec 010`](../010-release-surface-convergence/spec.md) 的 release selection、baseline 与 release-check owner
   已按依赖落地。
4. 对所有公开输入/输出检查 direct、re-export、generic、error 和 conversion 泄漏路径。
5. 只使用 owner PBI 实际检入的 compile/package/consumer 命令；本文不提供未来占位命令。

## 验收顺序

```text
exact API design and negative boundary
-> thin façade with unchanged runtime behavior
-> shared packaging mechanics
-> same-revision final façade proof
-> bounded T2 consumer: typed startup -> verified request -> diagnostics -> RuntimeHandle shutdown
-> negative boundary and N-1 to N SemVer seed
```

Reference Extension、仓内 assembly smoke 或 production journey 均不能替代最后一步；T2 proof 不得扩张为真实 provider 或 T3。
