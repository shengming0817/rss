# Contributing to RSS

English is the governing text of this document. The Simplified Chinese section is a
convenience translation.

## Before contributing

- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Report vulnerabilities privately according to [SECURITY.md](SECURITY.md); do not open a public
  issue for a suspected vulnerability.
- Read [README.md](README.md), [CLAUDE.md](CLAUDE.md), and the relevant documents under
  `docs/rules/` before changing code or behavior.
- Keep the change within [`docs/rules/project-scope.md`](docs/rules/project-scope.md). Open or
  reference an issue that states the intended outcome.

## Development and pull requests

1. Branch from the current `develop` branch and keep the change focused.
2. Add or update the smallest test that proves the behavior. Run focused checks while developing
   and the repository's affected preflight before handoff.
3. Update the owning documentation whenever behavior, a public interface, or an operational
   contract changes.
4. Use Conventional Commits. Do not commit secrets, generated local credentials, ignored files,
   build products, or registry artifacts.
5. In the pull request, explain the motivation, compatibility and security impact, linked issues,
   and exact verification performed.

Review is maintainer-led. A listed maintainer decides whether the change is in scope, requests
changes when evidence is incomplete, and merges only after required checks pass. Submission does
not guarantee acceptance.

## Licensing

Unless explicitly stated otherwise before submission, contributions accepted into RSS are licensed
under the repository's [MIT License](LICENSE). RSS does not require a contributor license agreement
or Developer Certificate of Origin sign-off.

---

# 为 RSS 做贡献

本文档以英文部分为准，简体中文部分为便于阅读的翻译。

## 贡献前

- 遵守[行为准则](CODE_OF_CONDUCT.md)。
- 按 [SECURITY.md](SECURITY.md) 私密报告漏洞；疑似漏洞不得提交公开 issue。
- 修改代码或行为前阅读 [README.md](README.md)、[CLAUDE.md](CLAUDE.md) 及相关
  `docs/rules/` 文档。
- 变更不得越过 [`docs/rules/project-scope.md`](docs/rules/project-scope.md)，并应创建或引用说明预期结果的
  issue。

## 开发与 Pull Request

1. 从当前 `develop` 分支创建分支，保持改动聚焦。
2. 添加或更新能证明行为的最小测试；开发时运行定向检查，交接前运行仓库 affected preflight。
3. 行为、公开接口或运维契约变化时，同步更新唯一 owner 文档。
4. 使用 Conventional Commits；不得提交 secret、本地生成凭据、被忽略文件、构建产物或 registry artifact。
5. PR 中说明动机、兼容性与安全影响、关联 issue 和实际执行的精确验证。

项目采用 maintainer-led review。列名维护者判定范围、在证据不足时要求修改，并只在 required checks 通过后合并。
提交贡献不保证一定被接受。

## 许可

除非提交前另有明确约定，被 RSS 接受的贡献按仓库 [MIT License](LICENSE) 许可。RSS 不要求签署贡献者许可协议，
也不要求 Developer Certificate of Origin sign-off。
