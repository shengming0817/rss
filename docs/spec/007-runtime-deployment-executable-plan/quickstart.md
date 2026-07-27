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
helm lint deploy/helm/rss
helm template rss deploy/helm/rss -f deploy/helm/rss/values/runtime.yaml
helm template rss deploy/helm/rss -f deploy/helm/rss/values/settingsonly.yaml
helm template rss deploy/helm/rss -f deploy/helm/rss/values/identityaudit.yaml
```

Helm's semantic version must be exactly `v4.2.0`; the DeploymentPlan check itself runs the three-profile lint/render
closure and compares chart-local plans, selector values/schema, and committed render goldens without
writing. These commands also check the active pointer, Draft-07 schemas plus valid/invalid instances,
recursive closure, secret/version boundaries, and RFC-8785 fingerprint vectors. They do not parse or
freeze planning Markdown.

Run the repository gates. `verify --fast` is the Medium aggregate; its typed Meta registry invokes the same selftest in-process:

```bash
./hack/cargo.sh xtask archrules verify
./hack/cargo.sh xtask verify --fast
make verify-fast
./hack/cargo.sh check --workspace --all-targets
/usr/bin/git diff --check "$(/usr/bin/git merge-base origin/develop HEAD)"
```

## 缺口与 owner

These commands prove the frozen SpecKit carrier, landed DeploymentPlan generated set, and #1803's
repository-static Helm profile/render closure. They do not execute install/upgrade/rollback, map
secret references, add sidecars, or prove #1804 deployment policy, #1805 kind acceptance, protected
RuntimeInventory, or OCI same-head/signature receipts. Each future
owner runs its exact tracker sequence from `tasks.md` after landing its carrier. #1779's content
validator is Medium because its selftest is a typed `verify --fast` member; #1809 later binds exact
same-head receipts through local `ci-gate` and does not grant forge activation. #1803 rollback is a
whole-change revert of chart/tooling/generated files; no cluster, database, or secret state is mutated.
