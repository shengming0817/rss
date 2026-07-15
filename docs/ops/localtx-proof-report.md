# LocalTx Static Proof Report

LocalTx proof report 把 `localtx-coverage` 使用的同一份 typed inventory 投影成机器可读 JSON 或供人工审阅的
Markdown。两个格式的 `evidenceScope = "staticInventory"`：它们只描述仓库中已声明、生成和接线的静态证据，
不会重新扫描另一套 evidence，也不会增加运行期结论。

## Generate

CLI 必须显式选择完整格式名；没有默认格式，不接受 `md` alias，也不接受 `--output`：

```bash
cargo xtask localtx report --format json > localtx-proof.json
cargo xtask localtx report --format markdown > localtx-proof.md
```

同一 revision、同一 workspace 状态下，两个格式都从同一 static inventory 渲染，排序稳定；同一格式连续生成的
结果可以做 byte-for-byte 比较。报告不包含时间戳、Git SHA、主机名、绝对路径、tenant/device 实例、secret、
payload、SQL 或运行时结果。仓库不提交 live proof snapshot；CI artifact 或本地临时输出才是消费载体。

## JSON schema v1

JSON 顶层对象恰好包含下列 required fields；字段缺失、类型错误、重复/乱序集合或 unknown field 都是结构不匹配，
消费者必须 fail closed。遇到未知 `schemaVersion` 也必须拒绝，不能猜测或降级解释：

- `schemaVersion: integer`，当前固定为 `1`；`status: "passed" | "failed"`；
  `evidenceScope: "staticInventory"`；`activeLocalTxContractCount: integer`。
- `operations: object`，包含 `validation: "referenceOnly"`、
  `includedInReportStatus: false`、typed `metrics` / `alerts` / `retryPressure`，以及 workspace-relative
  `rules` / `runbook` 路径。
- `findings: array`，每项恰好包含 string `rule`、`subject`、`detail`。
- `contracts: array`，每项包含 string `contractId` / `owner`、typed `capability`、manifest/generated/route/test
  `evidence`、`backendProfiles` 和 `journey`。每个 backend profile 显式给出 `providerStatus` 与 `status`，
  以及 sources、required/observed/missing probes；journey 包含 spec、fixture、runner、scenarios。

`contracts` 按 `contractId`，`findings` 按 `(rule, subject, detail)`，backend profiles 按
`(provider, fixture)`，scenarios 按 `kind`，所有 sources/probes 按 wire string 严格升序；这些集合禁止重复。
报告生成器会先规范化再校验，消费者可据此 byte-compare。

Schema v1 的 exact golden 是
[`xtask/tests/golden/localtx-proof.json`](../../xtask/tests/golden/localtx-proof.json)。它是用于冻结字段、类型和
排序的 synthetic fixture，不是当前 workspace 的 live proof，也不能当作 CI 或生产 verdict。

## Verdict and publication

报告区分 policy finding 与结构故障：

- inventory 完整收集后发现 policy finding 时，JSON 的 `status = "failed"`（Markdown 也显示 failed），命令仍以
  exit code 0 结束。自动消费者不能仅看进程成功；必须完整解析输出并显式检查 `status`。
- malformed TOML/Rust、重复 identity、registry/journey 结构矛盾、symlink/root escape 或 render failure 是结构
  故障：命令以 exit code non-zero 结束且 stdout is empty，不生成可消费报告。
- stdout writer failure 同样是非零退出，但 shell 重定向可能已经留下截断文件。消费者必须同时检查退出码、完整
  解析 JSON/Markdown，再把临时目录 atomic 发布；绝不能把文件存在当作成功。

`status` 只由同一 static inventory 的 policy findings 决定。`operations.validation = "referenceOnly"` 且
`operations.includedInReportStatus = false`：运维引用、promtool、真实 backend 和 CI job/artifact 状态都不参与
报告 verdict，不能从 `status = "passed"` 推断它们已执行或通过。

推荐把两个格式写到同一临时目录，确认两条命令均成功且 JSON 可完整解析、`status` 已判定之后，再在同一文件
系统中 rename 临时目录。若 status 为 failed，可以保存报告用于诊断，但不得把它当作通过证明。

## Evidence boundary

`evidenceScope = "staticInventory"` 明确排除运行期验证。本报告：

- does not run `promtool`，也不代表告警规则已被 Prometheus 工具验证；
- does not run a real backend，也不证明 Postgres transaction settlement；
- does not replace #1776 所负责的 required real-backend/same-head evidence；
- 不读取或声明部署、请求、租户、设备、数据库或机密数据。

因此报告可以回答“当前仓库的 LocalTx 静态证据是否闭合、缺在哪里”，不能回答“真实 backend 是否已执行、某次
事务是否提交、某次告警是否实际触发”。真实后端 verdict 只来自对应 integration evidence。

## Operations projection

每份报告的 operations 区只引用已存在的运维 carrier：

- metrics：`localtx_retry_attempts_total`、`localtx_final_total`、`localtx_attempts`；
- unsafe-settlement alerts：`LocalTxCommitUnknown`、`LocalTxRollbackFailed`；
- rules：`docs/ops/localtx-alerts.rules.yaml`；
- runbook：`docs/runbooks/202607130312-1705-localtx-unsafe-settlement.md`。

这些 identity 由 `observ` owner crate 的字段私有、闭类型 operations descriptor 单源定义；真实 metric emitter、
proof report 和 observ contract/dashboard tests 均消费该 descriptor，不在 report 中维护第二份 metric、alert 或
path 清单。生成报告前，xtask 会把 descriptor 与真实 alert YAML 做双向 exact-set 校验，并核对每条 LocalTx alert
的 final-status filter、metric、runbook path/anchor，同时确认 retry-pressure metric 属于 descriptor 的 metric
闭集。缺失、额外、重复或漂移属于结构故障：命令非零退出且 stdout 为空。该静态一致性校验仍是
`referenceOnly`，不会改变 `status`，也不声称执行了 promtool 或真实告警。

`commit_unknown` 与 `rollback_failed` 都可能已经产生 durable effect，禁止自动或盲目 replay。retry-pressure
是 diagnostic-only：retry exhaustion 不 page；诊断时使用上述指标并结合数据库可用性与请求错误率，告警语义仍
以 rules 和 runbook 为准。

## CI artifact discovery

GitHub Actions 的 `ci-plan` job 在 same-head checkout 后原子生成两个文件，并上传 artifact
`localtx-proof-${run_id}-${run_attempt}`。artifact 内必须同时存在 `localtx-proof.json` 和
`localtx-proof.md`，`if-no-files-found: error`，retention 为 30 days。结构故障时生成步骤在 atomic rename 前
失败，最终目录不存在，因此 proof artifact 不会发布；缺文件不能被当作空报告或 pass。

Azure carrier 不属于 #1777 的 required evidence；消费者不要在 Azure 中寻找同名 artifact，也不要把其他 CI
结果合并进本报告的 `status`。

## Consumer checklist

1. 用 canonical CLI 生成到临时位置并检查进程退出码。
2. 完整解析结果，验证 schema version、`evidenceScope`，再 parse `status`；unknown schema 必须 fail closed。
3. status 为 failed 时消费 `findings` 定位静态证据缺口，不把 exit code 0 解释为 pass。
4. 只有结构完整且 verdict 已明确的文件才能 atomic 发布；Markdown 与 JSON 应来自同一 revision。
5. 需要真实 Postgres 结论时转到 #1776 的 required evidence，不从静态报告推断运行期结果。
