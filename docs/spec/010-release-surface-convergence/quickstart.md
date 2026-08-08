# Quickstart: Release Surface 规格校准

本文件中的结构和链接检查是 #2041 的一次性 specification smoke，不是 Markdown enforcement carrier。

## 校验设计文档

从包含本规格的 worktree 根目录运行：

```bash
(
  set -euo pipefail
  for spec_dir in \
    docs/spec/010-release-surface-convergence \
    docs/spec/011-standalone-component-first-release \
    docs/spec/012-platform-application-waist
  do
    expected_files=$(printf '%s\n' plan.md quickstart.md research.md spec.md tasks.md)
    actual_files=$(find "$spec_dir" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; | sort)
    test "$actual_files" = "$expected_files"
    test "$(find "$spec_dir" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" -eq 5
    for file in spec.md research.md plan.md tasks.md quickstart.md; do
      test -s "$spec_dir/$file"
    done
    test -z "$(find "$spec_dir" -type f \( -name '*.schema' -o -name '*.schema.*' -o -name '*.json' -o -name '*.yaml' -o -name '*.yml' -o -name '*.toml' \) -print -quit)"
  done

  test -d docs/spec/009-observability-priority-levels
  test ! -e docs/spec/009-''release-surface-convergence
  test ! -e docs/spec/010-''standalone-component-first-release
  test ! -e docs/spec/011-''platform-application-waist

  find \
    docs/spec/010-release-surface-convergence \
    docs/spec/011-standalone-component-first-release \
    docs/spec/012-platform-application-waist \
    -type f -name '*.md' -print0 |
    xargs -0 perl -ne 'while (/\[[^]]+\]\((?!https?:|#)([^)#]+)(?:#[^)]+)?\)/g) { $p=$1; $p=~s/%20/ /g; $base=$ARGV; $base=~s{/[^/]+$}{}; $path=$p=~m{^/}?$p:"$base/$p"; die "$ARGV: missing $p\n" unless -e $path }'
)
```

一次性 advisory review；命中后由 reviewer 判断，不接入 CI：

```bash
legacy_terms='62''/62|Product''Plane|Release''Status|Support''Status|PLACE''HOLDER|T''BD|/''Users/'
if rg -n "$legacy_terms" \
  docs/spec/010-release-surface-convergence \
  docs/spec/011-standalone-component-first-release \
  docs/spec/012-platform-application-waist; then
  exit 1
fi
```

## 本规格 PR 验证

```bash
/usr/bin/git diff --check
/usr/bin/git diff --check origin/develop...HEAD
make verify-fast
make ci CI_BASE=origin/develop
```

第一条 diff check 用于提交前工作树，第二条用于提交后的完整 PR diff。`make ci` 只在全部文档提交后统一运行一次。
失败时先收集完整失败集，再批量修复并统一复验；不追加 `make ci-full`。

## 后续实现入口

后续 PBI 必须使用其实现时已检入的 canonical command。当前规格不预建 Release Surface、release API 或 package
verification 命令，也不以占位命令伪装已存在的 proof。
