# RSS Release Policy

English is the governing text of this document. The Simplified Chinese section is a
convenience translation.

## Scope and authority

Only packages in the positive Release Surface may be released. A listed maintainer must approve
every release and perform the registry publication manually; CI must not upload crates.

## Preparation

Package versioning and breaking changes follow the
[API and contract version rules](docs/rules/api-versioning.md). Every release has a reviewed
changelog entry and an immutable source revision.

External-consumer validation belongs to the owning Epic closeout. Registry validation uses the
exact published version.

Immediately before first publication, recheck the exact crate name and verify the intended crates.io
owners. Names observed as available earlier are not reservations. After publication, add
`github:shengming0817:rss-maintainers` as an owner and verify the resulting owner list.

## Release Candidate closeout

A listed maintainer may approve an exact source revision as a Release Candidate only after reading
the package identity and version from Cargo metadata, reviewing the candidate's current public API, and
running the owning specification's same-revision package proof. The approval record identifies every
approved package, version, source revision, archive digest, and intended registry owner. Packages
exercised by an aggregate proof but omitted from that tuple are not approved.

Same-revision digests, command results, and the maintainer decision belong in the issue or pull
request review record. They must not be copied into the repository as a receipt registry or current
status list. The reviewed version notes remain in [CHANGELOG.md](CHANGELOG.md), while Cargo metadata,
published versions or release tags, maintainer identity, and this policy remain their stable owners.
RC approval does not create a tag, reserve a registry name, upload a package, or change registry
ownership; publication retains the separate manual checks above.

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

只有进入正向 Release Surface 的 package 才能发布。每次发布必须由列名维护者批准并人工执行 registry publish；
CI 不得上传 crate。

## 准备

package 版本与 breaking change 遵循 [API 与 Contract 版本规则](docs/rules/api-versioning.md)。每次发布具备受 review 的
changelog 和不可变源码 revision。

外部 consumer 验证归所属 Epic 收尾；registry 验证使用精确的已发布版本。

首次发布前必须重新检查精确 crate 名称并验证预期 crates.io owner；此前观察到名称可用不等于保留。发布后把
`github:shengming0817:rss-maintainers` 加为 owner，并验证最终 owner 列表。

## Release Candidate closeout

列名维护者只有在从 Cargo metadata 回读 package identity/version、审查 candidate 当前 public API，并运行所属规格的
same-revision package proof 后，才能批准一个精确 source revision 成为 Release Candidate。批准记录必须逐项列出
获批 package、version、source revision、archive digest 与预期 registry owner；
aggregate proof 即使执行了其它 package，只要未进入该 tuple，就不构成对它们的批准。

same-revision digest、命令结果与维护者裁决只进入 issue 或 PR review 记录，不得复制进仓库形成 receipt registry 或
当前状态清单。受 review 的版本说明归 [CHANGELOG.md](CHANGELOG.md)，Cargo metadata、已发布版本或 release tag、维护者身份
与本文分别保持各自稳定 owner。RC 批准不创建 tag、不保留 registry 名称、不上传 package，也不改变 registry owner；
实际发布仍须单独完成上文的人工检查。

## Yank 与回滚

只有版本存在 unsound、安全风险、实质性损坏或关键 artifact/metadata 错误时才执行 yank。yank 不是删除，不得用于
改写历史；应尽可能发布修正版并记录影响。仓库变更通过新的受 review commit 回滚；已发布 artifact 通过新版本回滚，
必要时 yank 错误版本。凭据泄露必须立即轮换，因为 revert 和 yank 都无法将其删除。
