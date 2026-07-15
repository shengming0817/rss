# Quickstart: Runtime Deployment SpecKit v2

## 当前事实

These commands validate a target baseline, not implemented runtime/deployment behavior. Run them from the #1779 worktree; do not edit `docs/spec/001-runtime-assembly-plan/`.

## 目标能力

Run the focused PR-scope check. Its selftest exercises invalid Draft-07 schemas/instances, exact-edge rewiring, fingerprint byte/domain/input drift, task-baseline drift, and non-vacuity:

```bash
cargo xtask runtime-deployment-spec --selftest --against origin/develop
```

This checks the active pointer and artifacts, Draft-07 meta-schemas plus valid/invalid instances, recursive closure, secret/version boundaries, RFC-8785 fingerprint vectors, exact task/tracker parity, the 31-node/52-edge/depth-20 graph, immutable 001 lineage, diff scope, and zero generated churn. The approved Cx3 revision has no LOC cap.

Run the repository gates. `verify --fast` is the Medium aggregate; its typed Meta registry invokes the same selftest in-process without assuming a base ref:

```bash
./hack/cargo.sh xtask doc-contracts
./hack/cargo.sh xtask archrules verify
./hack/cargo.sh xtask verify --fast
make verify-fast
./hack/cargo.sh check --workspace --all-targets
/usr/bin/git diff --check "$(/usr/bin/git merge-base origin/develop HEAD)"
```

## 缺口与 owner

These commands do not prove future runtime Rust, Helm, inventory, OCI, same-head receipt, or active-PR scheduling capability. Each owner runs its exact tracker sequence from `tasks.md` after landing its carrier. #1779's content validator is Medium because its selftest is a typed `verify --fast` member; #1809 later binds exact same-head receipts through local `ci-gate` and does not grant forge activation.
