#!/usr/bin/env bash
# RSS 容器镜像冒烟验收（#1134）：build → up → /readyz 200 → /healthz 200 → /metrics 200 → 加固断言 → teardown。
# 机器可判定的 acceptance harness（make docker-smoke 调用本脚本）。
#
# 用法:  deploy/smoke.sh           # 全流程，结尾 down -v
#        KEEP_UP=1 deploy/smoke.sh # 保留栈（手动排查），不 teardown
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="docker compose -f ${SCRIPT_DIR}/docker-compose.yml"
HEALTH_URL="http://localhost:8083/health/v1"
READY_TIMEOUT="${READY_TIMEOUT:-120}" # 秒：含镜像构建后首启 + 迁移。
# reason: 唯一临时文件——同机并行跑（CI 多 job / 多终端）不互相覆盖 readyz 响应。
READYZ_TMP="$(mktemp)"

log() { printf '\033[1;34m[smoke]\033[0m %s\n' "$*"; }
fail() {
    printf '\033[1;31m[smoke] FAIL:\033[0m %s\n' "$*" >&2
    exit 1
}

cleanup() {
    rm -f "$READYZ_TMP"
    if [ "${KEEP_UP:-0}" = "1" ]; then
        log "KEEP_UP=1：保留栈，跳过 teardown（手动 'docker compose -f ${SCRIPT_DIR}/docker-compose.yml down -v' 清理）"
        return
    fi
    log "teardown：down -v"
    $COMPOSE down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "构建并拉起演示栈（postgres + server）…"
$COMPOSE up --build -d

# ── 闭环 1：/readyz 轮询至 200（PG healthy + 迁移完 + 池就绪）────────────────────────────────────
log "轮询 ${HEALTH_URL}/readyz 至 200（超时 ${READY_TIMEOUT}s）…"
deadline=$((SECONDS + READY_TIMEOUT))
ready=0
while [ $SECONDS -lt $deadline ]; do
    if curl -fsS "${HEALTH_URL}/readyz" >"$READYZ_TMP" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 2
done
[ $ready -eq 1 ] || {
    log "readyz 未在超时内 200；server 日志："
    $COMPOSE logs --tail=50 server >&2 || true
    fail "/readyz 未就绪"
}
log "readyz 200 ✓ → $(cat "$READYZ_TMP")"

# ── 闭环 2：/healthz liveness 恒 200 ──────────────────────────────────────────────────────────────
curl -fsS "${HEALTH_URL}/healthz" >/dev/null || fail "/healthz 非 200"
log "healthz 200 ✓"

# ── 闭环 3：/metrics Prometheus exposition（200 + content-type，#1253）────────────────────────────
# PromExporter::install 随 run() 必装，/metrics 与 RSS_OTEL_ENDPOINT 无关恒可达；content-type 锁 exposition media type。
metrics_ct="$(curl -fsS -o /dev/null -w '%{content_type}' "${HEALTH_URL}/metrics")" \
    || fail "/health/v1/metrics 非 200"
case "$metrics_ct" in
    text/plain*version=0.0.4*) log "metrics 200 ✓（content-type=${metrics_ct}）" ;;
    *) fail "期望 Prometheus exposition content-type（text/plain; version=0.0.4），实际 '${metrics_ct}'" ;;
esac

# ── 闭环 4：运行时加固断言（非 root + 只读 rootfs）────────────────────────────────────────────────
cid="$($COMPOSE ps -q server)"
[ -n "$cid" ] || fail "找不到 server 容器"
user="$(docker inspect -f '{{.Config.User}}' "$cid")"
ro="$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$cid")"
[ "$user" = "65532:65532" ] || fail "期望非 root user 65532:65532，实际 '${user}'"
[ "$ro" = "true" ] || fail "期望只读 rootfs (ReadonlyRootfs=true)，实际 '${ro}'"
log "加固断言 ✓（user=${user}, read_only=${ro}）"

log "全部冒烟通过 ✅"
