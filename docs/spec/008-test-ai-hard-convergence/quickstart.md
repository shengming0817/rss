# Quickstart: 校准与验证

## 当前事实复核

```bash
rg -n "CertLifecycleState|CertReconcileCtx|reconcile_cert|CertSignRequest" crates/deviceloop
rg -n '#\[ignore' --glob '*.rs' adapters/vault adapters/postgres assemblies/identityaudit journeys adapters/crypto
test -f adapters/postgres/src/integration_tests.rs
test -d adapters/postgres/src/integration_tests
rg -n "provider_conformance_catalog!" adapters/postgres adapters/amqp
```

第一条预期无输出；其余输出用于确认 live target、薄 façade + 私有 seam 子树仍在位，以及当前 enrollment，不是固定 LOC/文件数 golden。

## Spec 结构

```bash
test -f docs/spec/008-test-ai-hard-convergence/spec.md
test -f docs/spec/008-test-ai-hard-convergence/plan.md
test -f docs/spec/008-test-ai-hard-convergence/tasks.md
test -f docs/spec/008-test-ai-hard-convergence/research.md
test -f docs/spec/008-test-ai-hard-convergence/data-model.md
test -f docs/spec/008-test-ai-hard-convergence/quickstart.md
test -f docs/spec/008-test-ai-hard-convergence/checklists/requirements.md
if rg -n '待''填写|PLACE''HOLDER|TO''DO|T''BD' docs/spec/008-test-ai-hard-convergence; then
  exit 1
fi
```

创建 Azure work item 并回填 ID 后，最后一段应无输出并返回成功。

## PR 收尾

```bash
make ci CI_BASE=origin/develop
```

本规格 PR 是 docs-only；命令验证 affected governance plan，不声称运行 PostgreSQL、AMQP、Vault 或 image smoke。
