## Summary

<!-- 一句话描述这个 PR 做了什么 -->

## Why / 背景

<!-- 为什么改：要解决的问题 / 触发原因 / 预期结果（让 reviewer 不用翻 issue 也能懂动机）-->

## Refs

<!-- 关联 issue / ADR / plan，如 $(bash hack/automation/forge.sh pr-close-ref NNN)（azure 产 Fixes #NNN，github/gitlab 产 Closes #NNN）；对标参考 ref: framework file -->

## Risk / 兼容性

<!-- 破坏性变更 / migration / wire 契约影响 / 需同步的消费方；无则写「无」 -->

## Production acceptance evidence

<!--
仅当 PR 新增、扩展、替换或重新声明 T3 production acceptance carrier，或切换 production assembly artifact
journey 时保留本节；其余 PR 删除整节。逐项对应 issue 中的 evidence plan，语义见
`docs/rules/project-scope.md` §Production acceptance evidence plan 与 carrier replacement。
-->

- Evidence plan: `<issue / Evidence ID 列表>`
- Final HEAD: `<commit SHA>`

### <Evidence ID>

- Official product profile: `<产品面 ADR 已接纳的精确 profile>`
- Profile state: `<hardening-authorized | active；activation 写 hardening-authorized → active；candidate（无 trigger）不得保留本节>`
- T3 owner: `<ProfileLifecycleJoin | AcceptedValueStreamJoin>`
- Production artifact: `<hardening-authorized：唯一 designated artifact；active：唯一 canonical artifact；replacement 同时列 old canonical 与 new designated candidate>`
- Canonical proof owner: `<T3 / exact executable target and assertion>`
- T1/T2 receipt: `<exact command/target → result → same-head receipt>`
- T3 incremental proof / production join hazard: `<final-HEAD assertion → 唯一 production-only 失效模式>`
- Lower-layer gap: `<为何 T1/T2 无法观测该失效模式>`
- T3 receipt: `<independent selector → result / elapsed time / resources>`
- Change kind: `<activation | extension-or-redeclaration | replacement>`
- Candidate first green: `<commit SHA / receipt，早于 activation、owner/assertion 更新或 replacement cutover>`
- Carrier transition: `<activation：first-green 后 designated artifact → canonical artifact，已原子 activation/register；extension-or-redeclaration：canonical owner/assertion 前 → 后，修改后 first-green 才接纳；replacement：old 保持 canonical 至 new candidate first-green，再原子切 selector 且已删 old target/harness/script/env；无 successor 时列退出依据与无残留验证；仅 artifact journey replacement 列 assemblies/artifacts.toml 修改>`
- Final-head verification: `<变更后的 canonical carrier receipt + ./hack/cargo.sh xtask assembly artifacts check；无 successor 退役则填旧 selector/target/harness/script/env 无残留检查与产品承诺退出依据>`

## Test plan

- [ ] `make ci CI_BASE=<remote>/develop` 10 分钟有界本地通过（只分析已提交差异；重型门 `DEFERRED` 到 nightly/develop，不追加 `make ci-full`）
