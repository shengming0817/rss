# Security Policy

English is the governing text of this document. The Simplified Chinese section is a
convenience translation.

## Supported versions

Before the first public release, security maintenance applies only to the current `develop` branch;
internal builds and candidates carry no public support promise. After publication, each published
crate's latest non-yanked minor release line is supported by default. Older lines for a crate
receive fixes only when a maintainer explicitly announces an exception.

## Reporting a vulnerability

Email **shengming.jiang@outlook.com** privately. Do not open a public issue or discussion. Include,
when possible:

- the affected revision or released version;
- the affected component and configuration;
- reproduction steps or a minimal proof of concept;
- impact, prerequisites, and any known mitigations; and
- whether the report or details have already been shared elsewhere.

Do not send production secrets, personal data, or unnecessary exploit data. If a secret may have
been exposed, rotate or revoke it immediately; a repository rollback or yank cannot erase a
published secret.

## Response and disclosure

The maintainer normally acknowledges a report within three business days and provides an initial
status within seven business days. These are response targets, not remediation or disclosure SLAs.
The maintainer validates impact, coordinates a fix and advisory when appropriate, and agrees on a
disclosure date with the reporter. Credit is offered unless the reporter requests anonymity.

If the report concerns the sole maintainer or the private channel is unavailable, use the repository
host's private abuse or security-reporting channel. Do not disclose sensitive details publicly merely
because the primary channel is unavailable.

---

# 安全策略

本文档以英文部分为准，简体中文部分为便于阅读的翻译。

## 支持版本

首次公开发布前，只维护当前 `develop` 分支的安全问题；内部构建与 candidate 不构成公开支持承诺。公开发布后，
默认分别支持每个已发布 crate 最新且未被 yank 的 minor release line。某个 crate 的旧版本线仅在维护者明确公告例外
时获得修复。

## 报告漏洞

请私密发送邮件至 **shengming.jiang@outlook.com**，不要创建公开 issue 或 discussion。条件允许时请包含：

- 受影响的 revision 或已发布版本；
- 受影响组件和配置；
- 复现步骤或最小 proof of concept；
- 影响、前置条件和已知缓解措施；
- 报告或细节是否已提供给其他人。

请勿发送生产 secret、个人数据或不必要的利用数据。若 secret 可能已泄露，应立即轮换或撤销；源码回滚或 yank
无法抹除已经发布的 secret。

## 响应与披露

维护者通常在三个工作日内确认报告，并在七个工作日内提供首次状态。这些是响应目标，不是修复或披露 SLA。
维护者会验证影响、在适用时协调修复和 advisory，并与报告者约定披露时间。除非报告者要求匿名，否则将提供致谢。

若报告涉及唯一维护者，或私密渠道不可用，请使用仓库托管方的私密 abuse/security-reporting 渠道。不得仅因主渠道
不可用而公开敏感细节。
