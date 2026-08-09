# Quickstart: Platform Application waist 规格入口

## 当前规格验证

#2045 exact contract 的最小验证：

```bash
./hack/cargo.sh test -p xtask --test platform_application_waist_trybuild
cargo test --manifest-path xtask/tests/fixtures/platform_application_waist/Cargo.toml
./hack/cargo.sh test -p authn --test trybuild
./hack/cargo.sh test -p assembly-schema --test private_fields_trybuild
```

第一个命令证明临时 contract 的正负编译边界；第二个命令只验证 façade-owned identifier/error/detail 模型。后两个命令
复用真实 verified authority 与 assembly/runtime plan 的现有 Hard 边界。它们都不是 package、SemVer 或独立 T2 证明。

## 开始后续 PBI 前

1. 回读 #2045、#2049 或 #2052 及其全部 `Blocked-by`。
2. 从当前 Cargo graph、public API、assembly/profile metadata 和真实 consumer 需求重新读取事实。
3. 确认 [`Spec 010`](../010-release-surface-convergence/spec.md) 的 release selection、baseline 与 release-check owner
   已按依赖落地。
4. 对所有公开输入/输出检查 direct、re-export、generic、error 和 conversion 泄漏路径。
5. #2049 必须移动 exact contract 并删除 fixture；#2048/#2052 只使用各自实际检入的 release/package/consumer 命令。

## 验收顺序

```text
exact API design and negative boundary
-> thin façade with unchanged runtime behavior
-> shared packaging mechanics
-> same-revision final façade proof
-> bounded T2 consumer: typed startup -> verified request -> diagnostics -> RuntimeHandle shutdown
-> negative boundary and N-1 to N SemVer seed
```

Reference Extension、仓内 assembly smoke 或 production journey 均不能替代最后一步；T2 proof 不得扩张为真实 provider 或 T3。
