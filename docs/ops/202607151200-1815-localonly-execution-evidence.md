# LocalOnly execution evidence：Azure 阻断激活手册

## 边界

`azure-pipelines.yml` 是窄 build-validation carrier：它只执行 typed
`ci-local-only` job 并发布 `localonly-execution.json`。contract、package、test
target 与 exact filter 均由 xtask inventory 决定，YAML 不维护第二份清单。

该 validation 不等于完整且可监控的 ship CI，所以 `AZURE_HAS_CI` 必须保持
`false`。实现 PR 只关联 #1815，不使用 `Fixes #1815`，也不得在 Azure policy
激活和同一上下文 RED/GREEN 验收之前关闭 #1815。

## 合并后激活

前提是 Azure 项目已有可用的 Microsoft-hosted Ubuntu agent 配额（pipeline 的
`pool.vmImage` 固定为 `ubuntu-latest`），操作者具备 Build 与 Repository policy
管理权限。先确认 `develop` 已包含本实现，再执行：

```bash
bash hack/automation/forge.sh pipeline-create \
  rss-local-only rss develop azure-pipelines.yml
bash hack/automation/forge.sh pipeline-policy \
  rss-local-only rss develop "RSS LocalOnly Execution"
```

两条命令都是 create-or-verify：pipeline 若已存在，其 repo、default branch 与
YAML path 必须完全相符，否则 fail-closed；同名 policy 唯一时，drift 通过 Azure
Policy Configurations 7.1 的精确 `PUT` 收敛（不用会吞掉整数零值的
`az repos policy build update`），随后严格 read-back 以下持久化值：

参考：[Policy Configurations Update API](https://learn.microsoft.com/en-us/rest/api/azure/devops/policy/configurations/update?view=azure-devops-rest-7.1)、
[Azure build validation policy](https://learn.microsoft.com/en-us/azure/devops/repos/git/branch-policies?view=azure-devops#build-validation)。

- pipeline `rss-local-only`，repo `rss`，branch `develop`，YAML
  `azure-pipelines.yml`；
- display name `RSS LocalOnly Execution`；
- blocking、enabled；
- exact `refs/heads/develop` scope；
- `queueOnSourceUpdateOnly=false`、`manualQueueOnly=false`、
  `validDuration=0`、无 path filter。

`queueOnSourceUpdateOnly=false` 与 `validDuration=0` 是一个不可拆分的 freshness
约束：source 或受保护的 target `develop` 任一更新都会使旧结果立即失效并排队
新 build，不能复用针对旧 target tip 的绿色结果。

保留命令输出中的 pipeline ID 与 policy ID。任一 read-back 失败均表示
Acceptance Incomplete，不得手工忽略。

## 同一 policy RED/GREEN

1. 从最新 `develop` 建立临时验证分支和 PR；不要合并该 PR。
2. RED commit 只在一个 canonical LocalOnly contract 的 post-check 成功路径中
   抑制 marker，禁止修改 registry、source receipt 或 Azure YAML。等待
   `RSS LocalOnly Execution` 阻断，并记录 Azure run ID、失败原因与 policy ID。
3. GREEN commit 仅撤销 RED 改动。等待同一个 policy context 通过，下载
   `localonly-execution` artifact，确认报告为 schema v1，且
   active/source/executed 三个排序集合均为当前 canonical 6/6。
4. GREEN 后保持验证 PR 的 source revision 不变，让 `develop` 前移；确认同一个
   policy 自动产生不同 run ID，且该 run 针对新的 target tip 重新通过 6/6。
   记录前后 target revision 与 freshness run ID。若只改变 source 才重跑，则
   policy 语义仍不合格。
5. 关闭而不合并临时 PR；在 #1815 评论 policy ID、RED/GREEN/freshness run ID、
   前后 target revision 与报告摘要。
6. 只有 policy read-back、上述同一上下文 RED/GREEN 与 target-update freshness
   均成立后，才能关闭 #1815。否则明确记录 Acceptance Incomplete 并保持 issue
   open。
