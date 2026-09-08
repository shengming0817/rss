
See [CLAUDE.md](./CLAUDE.md)

项目能力边界读取 [docs/rules/project-scope.md](./docs/rules/project-scope.md)；其它稳定规则直接从
`docs/rules/*.md` 发现。

## 本地仓库与参考目录

| 仓库 / 目录 | 本地绝对路径 | 用途 |
|---|---|---|
| rss-mdm | `/Users/shengming/Documents/code/rss/rss-mdm` | Windows / macOS 企业终端管理产品的 Rust 服务端仓库，拥有 Inventory、MDM 业务、应用装配与产品验收。 |
| rss-mdm-agent | `/Users/shengming/Documents/code/rss/rss-mdm-agent` | 独立 Rust 终端 Agent 仓库，承接设备侧采集与执行；当前为空仓库，具体能力按产品路线实施。 |
| rss-web | `/Users/shengming/Documents/code/rss/rss-web` | RSS 浏览器前端仓库，拥有应用壳、UI、会话交互与 HTTP API 消费。 |
| rss-identity | `/Users/shengming/Documents/code/rss/rss-identity` | 独立身份服务产品仓库，拥有本地认证、租户联合身份接入与服务端会话；资源级业务授权由消费产品持有。 |
| rss-external-check | `/Users/shengming/Documents/code/rss/rss-external-check` | RSS 独立源码 / 固定候选 artifact 消费验证的可再生执行目录，由 Git 忽略；不持有唯一源码或唯一验收记录，隔离要求见 `docs/rules/verification-scope.md`。 |
| WinMDM 历史快照 | `/Users/shengming/Documents/code/rss/rss-mdm/reference/winmdm20260220-develop` | 历史实现与来源证据参考，由 Git 忽略；来源与恢复方式见 `rss-mdm/reference/README.md`，快照内协作规则不作为当前仓库规则。 |

产品仓库独立维护，进入对应仓库修改前读取其协作规则。以上本地目录位置不改变 RSS 主仓与产品仓的能力边界。

使用系统自带git /usr/bin/git

需要用户回答问题、选择方案或批准计划时，优先调用 MCP 工具
`prmonitor_human.ask_via_feishu`，让用户可以在 Codex 弹窗或飞书卡片中回答；
任一端的首个有效回答为准。MCP 不可用时回退到 Codex 原生提问。延时两分钟，若无响应，则按推荐选项继续。
约束：`purpose` 仅短标签（UTF-8 ≤128 字节，长说明放 `message`）；
`questions[].options` 必须是 `string[]` 纯文案，禁止 `{label,description}` 对象。

行数限制只用于设计阶段，实施阶段可忽略。

工具执行权限和沙箱批准始终使用 Codex 原生审批，不得通过飞书代替。
