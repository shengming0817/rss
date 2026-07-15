# prmonitor 通知与人工问答

本目录为 RSS 项目启用两条互补路径：

- `hooks.json` 在 Codex 等待原生人工输入、等待权限批准、等待计划批准和任务停止时，
  通过 prmonitor 消息基础通道发送飞书通知。
- `config.toml` 启用全局定义的 `prmonitor_human` MCP。Codex 需要用户回答问题、
  选择方案或批准计划时，优先调用 `ask_via_feishu`；Codex 弹窗和飞书卡片中
  首个有效回答获胜。

工具执行权限和沙箱批准不经过飞书，仍使用 Codex 原生审批。

原生 `request_user_input` 尚无独立稳定 hook 事件，因此当前 watcher 只是 best-effort
兼容层：它通过有版本边界的 parser 读取新增 transcript 记录，未知格式与投递失败只写
有限、低敏的本地静态诊断，不阻塞 Codex。MCP `ask_via_feishu` 是需要可靠双向回答时的
主路径。

## Python 环境

Hook 只使用标准库。入口依次选择项目 `.venv/bin/python` 和 `/usr/bin/python3`，
两者都不可用时静默跳过，不阻塞 Codex。创建首选环境：

```bash
/opt/homebrew/bin/uv venv .venv \
  --python /opt/homebrew/bin/python3.14 \
  --no-python-downloads
```

验证主路径与降级路径：

```bash
.venv/bin/python -m unittest discover -s .codex/hooks -p 'test_*.py'
/usr/bin/python3 -m unittest discover -s .codex/hooks -p 'test_*.py'
```

`make verify-hooks` 使用系统 Python 执行同一测试，并已接入 `make verify-fast`。

## Codex 配置

用户级 `~/.codex/config.toml` 保存服务地址和 Local API bearer token；仓库只负责启用：

```toml
[mcp_servers.prmonitor_human]
url = "http://127.0.0.1:8788/api/mcp"
http_headers = { Authorization = "Bearer <prmonitor localApiToken>" }
enabled = false
required = false
startup_timeout_sec = 5
tool_timeout_sec = 3900
enabled_tools = ["ask_via_feishu"]
default_tools_approval_mode = "approve"

[mcp_servers.prmonitor_human.tools.ask_via_feishu]
approval_mode = "approve"
```

项目 `.codex/config.toml` 将该服务改为 `enabled = true`，允许 MCP elicitation
触发人工弹窗，同时保留其他原生批准类别。Codex 只在可信项目中加载项目配置和 hooks；修改配置后需要启动全新任务，
并在 `/hooks` 中信任新的 hook hash。使用 `/mcp` 检查服务和工具状态。

## prmonitor 配置

在 prmonitor 中：

1. 启用 Local API，监听 `127.0.0.1:8788`，并保持用户配置中的 bearer token 与
   `localApiToken` 一致。
2. 启用飞书集成 `feishu-b8a9ec7f`，填写 App ID、App Secret 和 Bot Open ID，
   允许会话 `oc_42f0b43f40dc692c5d29b4b6df9f632e`。
3. 飞书开放平台为应用订阅 `im.message.receive_v1` 和新版 `card.action.trigger`；
   入站使用官方长连接，不配置公网 Webhook 或 tunnel。
4. 保证开发版和已安装版不会同时使用同一组飞书应用凭据。

Hook 的消息路由和内容策略属于用户本机配置，不在仓库内提供默认收件人。创建
`~/Library/Application Support/com.ghbvf.prmonitor/codex-hooks.json`，权限设为 `0600`：

```json
{
  "integration_id": "feishu-b8a9ec7f",
  "conversation_id": "oc_42f0b43f40dc692c5d29b4b6df9f632e",
  "include_content": true
}
```

`include_content` 默认是 `false`；设为 `true` 是显式允许发送问题、任务 prompt、事件详情
和最后回复。也可用 `PRMONITOR_HOOK_CONFIG` 指向其他用户级配置。Stop 会清除本轮 prompt
缓存和 MCP marker；`diagnostics.json` 只保留最近 64 条静态失败分类，不含消息正文、token
或完整命令。

## 验收

启动 prmonitor 后，新建 Codex 任务，依次验证：

1. 普通任务停止只收到一条“任务已停止”。
2. 原生 `request_user_input` 收到一条“等待人工输入”。
3. `ask_via_feishu` 同时显示 Codex 弹窗和飞书卡片；任一端回答后另一端关闭或失效。
4. 计划批准只发送一张交互卡片，不再由 Stop hook 重复发送计划消息。
5. 工具权限请求仍由 Codex 原生权限弹窗处理，hook 仅发送旁路通知。
