# Consistency / Effect Posture 报告

## 按需生成诊断报告

报告只写 stdout，调用方显式重定向：

```bash
cargo xtask consistency report --format json > consistency-posture.json
cargo xtask consistency report --format markdown > consistency-posture.md
```

CLI 不提供默认格式、alias 或 `--output`。缺失、重复、未知 `--format` 以及任何尾参都会失败。相同源码状态
连续运行应字节一致，便于操作者复核同一次诊断；完整输出不是 canonical baseline，仓库不提交 snapshot，
当前 CI 也不生成或上传这份静态报告。

JSON 只输出 `schemaVersion = 4`，不保留旧 alias 或双 schema；receipt coverage 固定
`localOnlyReceiptCoverage` 和每条 contract 的显式 `sourceReceiptRegistration`
（`evidence=sourceRegistered`、`enforcement=failClosed`、`status=registered|missing|notApplicable`）；missing 产生 `missingLocalOnlyReceipt` finding 并令顶层 `status=failed`，但 sourceRegistered 不表示本次执行 route test；旧消费者必须直接升级解析 v4。

## 检查规则

- `status = "passed"`：production mount、LocalOnly static proof 与 receipt coverage 均无 finding。
- `status = "failed"`：命令仍以 0 退出并完整输出 finding，便于人工诊断；消费方必须读取顶层
  `status`，不能把进程成功误当作 posture 通过。
- 采集、结构或渲染失败：在写 stdout 前失败，因此 stdout 为空。
- stdout 写入本身失败：进程非零退出，但重定向文件可能已截断；写入不是原子发布。消费方必须同时检查退出码
  并完整解析 JSON（Markdown 至少检查成功退出）；需要人工留存或转交时不得使用失败产物。
- 非 LocalOnly 的 `declarationOnly/notApplicable` 只是声明展示，不证明运行期实际调用。
- receipt provenance 的 duplicate、unknown、stale、marker/ID/mounted ROUTE/GET 错配、decoy/bait observer、
  空或 wrong-but-finalized routes、provider/factory 参数/真实 seam 不闭合、alias/wrapper、cfg/sibling bait、隐藏控制流、
  非顶层 statement、未 fail-loud 解包或未用 `::core::assert_eq!` 断言 receipt 是结构错误，
  在 stdout 写入前失败；它们与合法但尚未登记的 `missing` 不同。
- framework-owned HTTP 的 `owner` 固定显示 `_framework`；其 mount source 必须来自唯一声明该 contract id 的
  assembly，并通过启动期 `validate_framework_serving` 对 generated expected evidence 与实际 mounted evidence
  做 exact-set 校验。缺失、重复、错配或未声明的 framework mount 均 fail-closed。

artifact 只含 contract id、owner、route declaration、workspace-relative mount source、静态分类 finding 和
低基数 receipt coverage；不含
时间、主机、绝对路径、Git SHA、tenant/device 标识或 runtime 请求数据。该报告不覆盖 auth/scope、非 port
副作用或完整零信任 posture；运行时 conformance 边界见 #1694。

该报告不是 enforcement carrier；阻断 verdict 仍由 `consistency local-only-effects` typed gate 给出。
