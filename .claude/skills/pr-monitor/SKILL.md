---
name: pr-monitor
description: "PR 状态单次接力检查：按唯一 pr-status 标签路由，读取可读评论核对提交与 findings；默认按状态接力 review/fix/check，--role 可限制接力范围。自身不贴评论、不切标签。"
argument-hint: "<PR#> --mode=auto [--role=fix|review]"
allowed-tools: [Bash, Read, Skill]
---

# PR 状态单次接力检查

ship/fix 按 `PROJECT.md` §5 等待后调用一次；每次最多启动一个后续技能，完成即返回，不自行轮询或嵌套启动监控。
桌面 prmonitor 是按配置标签触发任务的独立应用，本技能不管理它的配置或运行锁。

## 输入

`<PR#> --mode=auto [--role=fix|review]`。PR 号允许 `#` 前缀；不传 role 时按状态自动选择动作；显式 role=fix/review 仅过滤可接力阶段。
拒绝非正整数 PR、未知参数及非 fix/review 的 role。

## 读取与核对

```bash
bash hack/automation/forge.sh pr-state <PR#>
bash hack/automation/forge.sh pr-refs <PR#>
bash hack/automation/pr-comments.sh json <PR#>
```

任何读取失败都报告并结束，不当作无评论或未修复。PR 已关闭则结束。
只接受一个 §2.5 定义的 `pr-status/*`，且不能同时残留 `pr-review/*`；缺失、未知或冲突标签只报告，不派发。
从受信评论按 `createdAt` 选择各类型最新正文，按以下表格决定动作：

| 状态 | 默认动作 |
|---|---|
| `in-progress` | 报告实施中并结束 |
| `needs-review` | 调 `/pr-review <PR#>` 完整审查当前 head |
| `needs-fix` | 核对最新 review 的提交 SHA 与 live head 一致且有阻断 findings，再调 `/fix <PR#>` |
| `needs-check` | 核对最新 fix 的提交 SHA 与 live head 一致，且有对应 review findings，再调 `/pr-review <PR#> --check` |
| `ready` | 核对最新 review 对当前 head 的通过结论，报告审查通过并结束；不声明 CI 或合并条件满足 |

显式 `--role=fix` 只接力 needs-fix；`--role=review` 只接力 needs-review/needs-check。其它待处理状态只报告，不因 role 不匹配改标签。ship/fix 的默认调用不加 role 过滤，能兜底全部待处理阶段。

评论缺少明确提交 SHA、结论或与当前 head 不一致时，只报告需要重新审查；不会猜测旧评论对应的提交。
同类评论按最新选择，不能为了得到匹配 SHA 回退到更早一条。
fix 自动轮次按 `PROJECT.md` §5 计数，满 3 轮停止自动修复；check 不受该上限阻挡。
Cx、scope 和具体修复由 `/fix` 从完整 findings 自行判断。

## 派发与收尾

- 派发前再读一次 PR 状态和 head；与本次快照不一致则结束，避免依据过期快照启动。
- 同一会话不重复接力已启动的同一 PR/提交/阶段；已知有另一执行者工作时只报告。跨进程调度去重由调用方负责，本技能不提供持久化锁或 exactly-once 保证。
- fix 开始和执行期间保持 `needs-fix`，完成后由 fix 切 `needs-check`；review/check 的结论与切状态由 pr-review 完成。
- 不直接修改评论、标签或代码。合并冲突交给 ship/fix 的冲突预检；不要在检查器中推送一个未经复核的新 head。
- 返回本次观察、执行动作或未执行原因；后续 monitor 由原调用方安排，不在本次检查内循环。
