#!/usr/bin/env bash
# 对标产出门（ship 阶段6 / fix 复用）：PR body 必含「有结构的 ref:」或「有非空理由的豁免句」。
# Soft→Medium 机器守卫：剥 HTML 注释（避开 PR 模版占位 `ref: framework file`）+ 校验值非空，
# 杜绝 bare `ref: ` / 空豁免的裸 substring 绕过。
# 用法: pr-benchmark-gate.sh <pr-body-file>   # 0=通过 1=缺对标产出
#       pr-benchmark-gate.sh selftest          # 红/绿回归（anti-vacuity）
set -uo pipefail

# ref: {framework} {path}（冒号后至少两个非空 token）；行首或 list marker 前缀均可
REF_RE='(^|[[:space:]])ref:[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]'
# 本 PR 无需对标：<非空理由>（全角冒号后至少一个非空字符）
EXEMPT_RE='本 PR 无需对标：[[:space:]]*[^[:space:]]'

_check() { # <body-file> -> 0 通过 / 1 缺
	local body
	body="$(sed '/<!--/,/-->/d' "$1")" # 剥 HTML 注释（含模版占位）
	if grep -Eq "$REF_RE" <<<"$body"; then return 0; fi
	if grep -Eq "$EXEMPT_RE" <<<"$body"; then return 0; fi
	return 1
}

_selftest() {
	local rc=0 tmp got
	tmp="$(mktemp)"
	_case() { # <期望 pass|fail> <名称> <body>
		printf '%s\n' "$3" >"$tmp"
		if _check "$tmp"; then got=pass; else got=fail; fi
		if [ "$got" = "$1" ]; then echo "ok   [$1] $2"; else
			echo "FAIL [期望$1 得$got] $2"
			rc=1
		fi
	}
	_case pass "有效 ref（带@ref）" 'ref: kratos middleware/middleware.go@main'
	_case pass "有效 ref（无@ref）" 'ref: axum axum/src/routing/method_routing.rs'
	_case pass "list marker ref" '- ref: tower tower/src/builder/mod.rs'
	_case pass "有效豁免" '本 PR 无需对标：治理文档无同类框架'
	_case fail "bare ref 空值" 'ref: '
	_case fail "ref 仅 1 token" 'ref: kratos'
	_case fail "空豁免" '本 PR 无需对标：'
	_case fail "豁免仅空格" '本 PR 无需对标：   '
	_case fail "仅模版注释占位" '<!-- 对标参考 ref: framework file -->'
	_case fail "啥也没填" 'just a normal body'
	rm -f "$tmp"
	if [ $rc -eq 0 ]; then echo "selftest: PASS"; else echo "selftest: FAIL"; fi
	return $rc
}

case "${1:-}" in
selftest) _selftest ;;
"")
	echo "usage: pr-benchmark-gate.sh <pr-body-file> | selftest" >&2
	exit 64
	;;
*)
	if _check "$1"; then exit 0; fi
	echo "对标产出门失败：PR body 缺有效 \`ref: {framework} {path}\` 或非空 \`本 PR 无需对标：<理由>\`。回阶段1补对标。" >&2
	exit 1
	;;
esac
