
See [CLAUDE.md](./CLAUDE.md)

使用系统自带git /usr/bin/git

需要用户回答问题、选择方案或批准计划时，优先调用 MCP 工具
`prmonitor_human.ask_via_feishu`，让用户可以在 Codex 弹窗或飞书卡片中回答；
任一端的首个有效回答为准。MCP 不可用时回退到 Codex 原生提问。若无响应，则按推荐选项继续。

行数限制只用于设计阶段，实施阶段可忽略。

工具执行权限和沙箱批准始终使用 Codex 原生审批，不得通过飞书代替。
