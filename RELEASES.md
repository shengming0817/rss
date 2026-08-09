# RSS Release Policy

English is the governing text of this document. The Simplified Chinese section is a
convenience translation.

## Scope and authority

Only packages in the positive Release Surface may be released. Internal packages, candidates, and
successful packaging tests are not releases or publication approval. A listed maintainer must
approve every release and perform the registry publication manually; CI must not upload crates.

## Versions and preparation

Public crates follow Semantic Versioning independently. Before 1.0, a breaking public API change
requires at least a minor version bump; from 1.0 onward it requires a major version bump. Every
release must have a reviewed changelog entry, an immutable source revision, the canonical package
and release-check evidence required by the owning specification, and successful consumption of the
final artifact outside the workspace. An RC label or tag does not publish an artifact.

Immediately before first publication, recheck the exact crate name and verify the intended crates.io
owners. Names observed as available earlier are not reservations. After publication, add
`github:shengming0817:rss-maintainers` as an owner and verify the resulting owner list.

## Deprecation

Deprecations identify a replacement and appear in the changelog. For releases at or above 1.0, a
deprecated API remains available for at least one minor release unless retaining it creates a
security or correctness hazard. Pre-1.0 removals still require the appropriate SemVer bump and clear
migration notes.

## Yank and rollback

Yank only a version that is unsound, security-sensitive, materially broken, or published with
critical artifact or metadata errors. A yank is not deletion and must not be used to rewrite history.
Publish a corrected version when possible and document the impact. Roll back repository changes with
a new reviewed commit; roll back a released artifact with a new version and, when justified, yank the
bad version. Rotate exposed credentials immediately because neither revert nor yank removes them.

---

# RSS 发布策略

本文档以英文部分为准，简体中文部分为便于阅读的翻译。

## 范围与授权

只有进入正向 Release Surface 的 package 才能发布。internal package、candidate 和成功的 packaging test 都不构成
release 或发布批准。每次发布必须由列名维护者批准并人工执行 registry publish；CI 不得上传 crate。

## 版本与准备

公共 crate 独立遵循 Semantic Versioning。1.0 前，公开 API 的破坏式变更至少升级 minor；1.0 起必须升级 major。
每次发布必须具备受 review 的 changelog、不可变源码 revision、所属规格要求的 canonical package/release-check 证据，
并从 workspace 外成功消费最终 artifact。RC label 或 tag 不会自动发布 artifact。

首次发布前必须重新检查精确 crate 名称并验证预期 crates.io owner；此前观察到名称可用不等于保留。发布后把
`github:shengming0817:rss-maintainers` 加为 owner，并验证最终 owner 列表。

## 弃用

弃用必须说明替代方案并进入 changelog。对 1.0 及以上版本，被弃用 API 至少保留一个 minor release；若继续保留会造成
安全或正确性风险则可例外。1.0 前的删除仍需匹配 SemVer bump，并提供清晰迁移说明。

## Yank 与回滚

只有版本存在 unsound、安全风险、实质性损坏或关键 artifact/metadata 错误时才执行 yank。yank 不是删除，不得用于
改写历史；应尽可能发布修正版并记录影响。仓库变更通过新的受 review commit 回滚；已发布 artifact 通过新版本回滚，
必要时 yank 错误版本。凭据泄露必须立即轮换，因为 revert 和 yank 都无法将其删除。
