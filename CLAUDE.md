# RSS 协作说明

RSS 是面向 Rust 社区的一致性与持久化执行 library workspace。本文件是协作入口，只拥有工作方式；
架构与工程规则按各自 owner 读取，不在此重复定义：

- [项目范围](docs/rules/project-scope.md)：能力准入、仓内外边界与处置状态。
- [架构与依赖](docs/rules/dependency-policy.md)：crate 划分、依赖方向与复杂度取舍。
- [版本规则](docs/rules/api-versioning.md)：公共 API、wire 兼容与退出。
- [验证范围](docs/rules/verification-scope.md)：验证深度、消费组合与发布收尾。
- [AI-robust](docs/rules/ai-robust.md)：约束强度与证据要求。
- [Rust 规范](docs/rules/rust-standards.md)与[错误处理](docs/rules/error-handling.md)：语言与错误边界。

## 工作方式

- 与用户的所有沟通默认使用中文（对话回复、方案讨论、PR / review 说明）
- 修改前先查看目标文件与相关 `docs/rules/*.md`
- 提交信息遵循 Conventional Commits
- 涉及功能或行为变更时，同步更新对应文档
- 被 `.gitignore` 忽略的文件禁止 `git add -f`
- 需求判断 / 方案设计 / review 默认考虑 MDM / 零信任治理与安全边界，不按隐含单租户 / 无设备场景推进

## 临时项目规则：历史能力提取来源

历史能力提取统一以历史 tag `baseline/pre-community-core-20260902`、固定 commit
`5b63e10a1b396b0ff70b7d1e6e55db296cd7a891` 中的记录为来源。
全部相关历史能力提取完成后删除本规则。

## 修改代码前

1. 先 `Read` 目标文件，`Grep` 搜索已有实现
2. 编辑循环按改动类型运行最小复现测试；收尾统一运行 `make ci CI_BASE=<remote>/develop`。它按 Cargo
   reverse dependency closure 选择 package，并运行标准 check/nextest/clippy；影响分析异常保守回退
   `make ci-full`。10 分钟预算由调用方承担，`make ci-full` 仍是 develop/release 或人工显式入口
3. 只改需要改的

## 参考框架

新建或重构层内模块时，先用 `WebFetch` 读对标源码，commit message 注明 `ref: {framework} {file}`。
读源码优先 Rust 工业对标；Go / Java / .NET 等框架仅作低优先级的架构范式或概念出处。

对标时按受影响模块直接选择 primary upstream 源码并记录可追溯 `ref:`；不以仓内说明文档代替源码证据。

## Sandbox 提权

`git push/pull/fetch` 和 forge CLI（`gh` / `az` / `glab`）命令须用 `dangerouslyDisableSandbox: true`。

## 文档命名规则

格式：`yyyyMMddHHmm-编号-实际功能或问题.md`
示例：`202603281443-022-compliance-api-review.md`
