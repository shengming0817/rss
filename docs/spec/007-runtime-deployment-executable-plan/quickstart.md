# Quickstart: Runtime Deployment SpecKit v2

## 当前事实

The SpecKit command validates the frozen target baseline. The focused DeploymentPlan commands below
validate the landed RuntimePlan-bound protocol plus the committed runtime, settingsonly, and
identityaudit generated-plan set. Run them from the active worktree; do not edit
`docs/spec/001-runtime-assembly-plan/`.

## 目标能力

Run the repository machine-input check. Its selftest exercises invalid Draft-07 schemas/instances, fingerprint byte/domain/input drift, and non-vacuity:

```bash
cargo xtask runtime-deployment-spec --selftest
cargo test -p assembly-schema deployment_plan
cargo test -p xtask deployment_plan
cargo xtask deployment plan check
```

This checks the active pointer, Draft-07 schemas plus valid/invalid instances, recursive closure, secret/version boundaries, and RFC-8785 fingerprint vectors. It does not parse or freeze planning Markdown.

Run the repository gates. `verify --fast` is the Medium aggregate; its typed Meta registry invokes the same selftest in-process:

```bash
./hack/cargo.sh xtask archrules verify
./hack/cargo.sh xtask verify --fast
make verify-fast
./hack/cargo.sh check --workspace --all-targets
/usr/bin/git diff --check "$(/usr/bin/git merge-base origin/develop HEAD)"
```

## 缺口与 owner

These commands prove the frozen SpecKit carrier and the landed DeploymentPlan protocol/generated-set
closure; they do not prove Helm rendering, deployment policy/kind acceptance, protected
RuntimeInventory, or OCI same-head/signature receipts. Each future
owner runs its exact tracker sequence from `tasks.md` after landing its carrier. #1779's content
validator is Medium because its selftest is a typed `verify --fast` member; #1809 later binds exact
same-head receipts through local `ci-gate` and does not grant forge activation.
