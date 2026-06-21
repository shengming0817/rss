## Summary

<!-- 一句话描述这个 PR 做了什么 -->

## Why / 背景

<!-- 为什么改：要解决的问题 / 触发原因 / 预期结果（让 reviewer 不用翻 issue 也能懂动机）-->

## Refs

<!-- 关联 issue / ADR / plan，如 $(bash hack/automation/forge.sh pr-close-ref NNN)（azure 产 Fixes #NNN，github/gitlab 产 Closes #NNN）；对标参考 ref: framework file -->

## Risk / 兼容性

<!-- 破坏性变更 / migration / wire 契约影响 / 需同步的消费方；无则写「无」 -->

## Test plan

- [ ] `cargo build --workspace` 本地通过
- [ ] `cargo test --workspace`（或修改的 crate）本地通过（涉及逻辑变更时）
- [ ] `cargo fmt --check` + `cargo clippy --workspace --all-targets -- -D warnings` 0 warnings
- [ ] `cargo audit` 无新增漏洞（涉及依赖变更时）
