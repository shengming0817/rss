# RSS Governance

English is the governing text of this document. The Simplified Chinese section is a
convenience translation.

## Model and roles

RSS is maintainer-led. Maintainers own scope decisions, architecture and release policy, repository
administration, security response, Code of Conduct enforcement, and registry custody. Contributors
may propose and review changes but do not obtain these authorities through contribution volume.
Current maintainers and machine identities are listed in [MAINTAINERS.md](MAINTAINERS.md).

## Decisions

Normal decisions are recorded in issues and pull requests. The relevant maintainer weighs project
scope, technical evidence, compatibility, security, and long-term maintenance; consensus is sought,
but a listed maintainer makes the final decision. Security incidents and Code of Conduct reports may
be handled privately, with the public record limited to information safe to disclose.

Governance changes require a pull request that updates this document and `MAINTAINERS.md` where
applicable. Repository access, registry ownership, and maintainer status are separate grants and must
be changed explicitly; none is inferred from the others.

## Maintainer lifecycle

New maintainers must demonstrate sustained project judgment and accept the security, moderation,
release, and custody duties described here. Existing maintainers approve additions, removals, and
role changes. A departing maintainer transfers repository and registry access before removal.
Unavailability does not automatically transfer authority; recovery must use the verified controls of
the repository host and registry, followed by a public governance change.

## Registry custody

The canonical future crates.io team is `github:shengming0817:rss-maintainers`. The team is closed,
its membership is explicit, and it has `maintain` access to the canonical
[`shengming0817/rss`](https://github.com/shengming0817/rss) repository. Creating the team does not
reserve crate names or authorize publication. A crate may add the team as registry owner only after
the crate exists and a maintainer has separately approved publication.

---

# RSS 治理

本文档以英文部分为准，简体中文部分为便于阅读的翻译。

## 模型与角色

RSS 采用 maintainer-led 治理。维护者负责范围裁决、架构与发布策略、仓库管理、安全响应、行为准则执行和 registry
托管。贡献者可以提案和 review，但贡献数量不会自动授予上述权限。当前维护者及其机器身份列于
[MAINTAINERS.md](MAINTAINERS.md)。

## 决策

普通决策记录在 issue 与 PR 中。相关维护者综合项目范围、技术证据、兼容性、安全和长期维护成本；项目寻求共识，
但最终由列名维护者裁决。安全事件和行为准则报告可以私密处理，公开记录只保留可安全披露的信息。

治理变化必须通过 PR 修改本文档，并在适用时同步 `MAINTAINERS.md`。仓库访问、registry ownership 与维护者身份是
相互独立的显式授权，不能互相推导。

## 维护者生命周期

新维护者必须持续展示项目判断力，并接受本文规定的安全、moderation、发布和托管职责。新增、移除或变更角色由现有
维护者批准。维护者离任前应完成仓库与 registry 权限移交。失联不会自动转移权限；恢复必须使用仓库托管方和 registry
已验证的控制面，并随后公开更新治理记录。

## Registry 托管

未来 crates.io 团队的规范坐标是 `github:shengming0817:rss-maintainers`。团队为 closed，成员显式管理，并对规范仓库
[`shengming0817/rss`](https://github.com/shengming0817/rss) 拥有 `maintain` 权限。创建团队不等于保留 crate 名称，
也不授权发布。只有 crate 已存在且维护者另行批准发布后，才能把该团队加入 registry owner。
