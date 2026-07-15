## Summary

<!-- 一句话描述这个 PR 做了什么 -->

## Why / 背景

<!-- 为什么改：要解决的问题 / 触发原因 / 预期结果（让 reviewer 不用翻 issue 也能懂动机）-->

## Refs

<!-- 关联 issue / ADR / plan，如 $(bash hack/automation/forge.sh pr-close-ref NNN)（azure 产 Fixes #NNN，github/gitlab 产 Closes #NNN）；对标参考 ref: framework file -->

## Risk / 兼容性

<!-- 破坏性变更 / migration / wire 契约影响 / 需同步的消费方；无则写「无」 -->

## Test plan

- [ ] `make ci CI_BASE=<remote>/develop` 本地通过（只分析已提交差异；typed 影响模型选择 preflight）
