#!/usr/bin/env bash
# RSS 容器镜像冒烟验收（#1134）：build → up → /readyz 200 → /healthz 200 → /metrics 200 → 加固断言 → teardown。
# 机器可判定的 acceptance harness（make docker-smoke 调用本脚本）。
#
# 用法:  RSS_SMOKE_MODE=release deploy/smoke.sh           # release image/demo infra 证据；结尾 down -v
#        RSS_SMOKE_MODE=developer deploy/smoke.sh         # 本地全流程，仍默认禁止 skip
#        RSS_SMOKE_MODE=developer RSS_SMOKE_ALLOW_SKIP=1 deploy/smoke.sh
#                                                        # 仅缺 fixture 时显式非生产跳过
#        RSS_SMOKE_MODE=developer KEEP_UP=1 deploy/smoke.sh # 保留栈（手动排查）
set -euo pipefail

RSS_SMOKE_MODE="${RSS_SMOKE_MODE-}"
RSS_SMOKE_ALLOW_SKIP="${RSS_SMOKE_ALLOW_SKIP-0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="docker compose -f ${SCRIPT_DIR}/docker-compose.yml"
ENV_FILE="${SCRIPT_DIR}/.env.example"
export RSS_PRIMARY_HOST_PORT="${RSS_PRIMARY_HOST_PORT:-18080}"
export RSS_INTERNAL_HOST_PORT="${RSS_INTERNAL_HOST_PORT:-18081}"
export RSS_ADMIN_HOST_PORT="${RSS_ADMIN_HOST_PORT:-18082}"
export RSS_HEALTH_HOST_PORT="${RSS_HEALTH_HOST_PORT:-18083}"
HEALTH_URL="http://localhost:${RSS_HEALTH_HOST_PORT}/health/v1"
READY_TIMEOUT="${READY_TIMEOUT:-120}" # 秒：含镜像构建后首启 + 迁移。
log() { printf '\033[1;34m[smoke]\033[0m %s\n' "$*"; }
fail() {
    printf '\033[1;31m[smoke] FAIL:\033[0m %s\n' "$*" >&2
    exit 1
}
validate_smoke_policy() {
    case "$RSS_SMOKE_MODE" in
        developer|release) ;;
        "") fail "RSS_SMOKE_MODE 必填（developer|release）" ;;
        *) fail "RSS_SMOKE_MODE 非法：仅允许 developer|release" ;;
    esac
    case "$RSS_SMOKE_ALLOW_SKIP" in
        0|1) ;;
        *) fail "RSS_SMOKE_ALLOW_SKIP 非法：仅允许 0|1" ;;
    esac
    if [[ "$RSS_SMOKE_MODE" = "release" && "$RSS_SMOKE_ALLOW_SKIP" = "1" ]]; then
        fail "release smoke 禁止 RSS_SMOKE_ALLOW_SKIP=1"
    fi
    if [[ "$RSS_SMOKE_MODE" = "release" && "${KEEP_UP:-0}" = "1" ]]; then
        fail "release smoke 禁止 KEEP_UP=1"
    fi
}
validate_smoke_policy
read_env_file_value() {
    awk -F= -v key="$1" '$1 == key { print $2; exit }' "$ENV_FILE"
}
assembly_identity_name() {
    local lock="${SCRIPT_DIR}/../assemblies/runtime/assembly.lock.json"
    [[ -f "$lock" ]] || fail "缺少 assembly lock：$lock"
    local name
    name="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["identity"]["name"])' "$lock")" \
        || fail "无法从 assembly lock 读取 identity.name：$lock"
    [[ -n "$name" ]] || fail "assembly lock identity.name 为空：$lock"
    printf '%s\n' "$name"
}
missing_spiffe_fixture() {
    local missing="$1"
    if [[ "$RSS_SMOKE_MODE" = "developer" && "$RSS_SMOKE_ALLOW_SKIP" = "1" ]]; then
        printf '%s\n' 'NOT PRODUCTION EVIDENCE'
        log "developer smoke 显式跳过：Remote/SPIFFE fixture 不完整（缺少 ${missing}）"
        exit 0
    fi
    fail "Remote/SPIFFE fixture 不完整（缺少 ${missing}）"
}
require_spiffe_fixture() {
    # Optional placement workloads are not a SPIFFE gate by themselves. Only when a Remote
    # placement is configured (workload set and differs from assembly.lock.json identity.name)
    # do we require outbound SPIFFE fixture completeness; otherwise continue all-Local.
    local identity_name
    identity_name="$(assembly_identity_name)"
    local has_remote=0
    local key workload
    for key in \
        RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD \
        RSS_SETTINGS_DOMAIN_PLACEMENT_WORKLOAD \
        RSS_AUDIT_DOMAIN_PLACEMENT_WORKLOAD
    do
        workload="$(read_env_file_value "$key")"
        if [[ -n "$workload" && "$workload" != "$identity_name" ]]; then
            has_remote=1
            break
        fi
    done
    if [[ "$has_remote" -eq 0 ]]; then
        return 0
    fi
    local missing=()
    for key in \
        SPIFFE_ENDPOINT_SOCKET \
        RSS_DOMAIN_TRANSPORT_MTLS_LOCAL_SPIFFE_ID
    do
        [[ -n "$(read_env_file_value "$key")" ]] || missing+=("$key")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        missing_spiffe_fixture "${missing[*]}"
    fi
}
s3_canary_interval="$(read_env_file_value RSS_S3_CANARY_INTERVAL_SECS)"
s3_canary_timeout="$(read_env_file_value RSS_S3_CANARY_TIMEOUT_SECS)"
[[ "$s3_canary_interval" =~ ^[0-9]+$ ]] || s3_canary_interval=60
[[ "$s3_canary_timeout" =~ ^[0-9]+$ ]] || s3_canary_timeout=5
S3_DOWN_TIMEOUT="${S3_DOWN_TIMEOUT:-$((s3_canary_interval + s3_canary_timeout + 15))}"
require_spiffe_fixture
# reason: 唯一临时文件——同机并行跑（CI 多 job / 多终端）不互相覆盖 readyz 响应。
READYZ_TMP="$(mktemp)"
vault_paused=0
vault_kv_disabled=0
minio_stopped=0
redis_stopped=0

reset_demo_vault_kv() {
    $COMPOSE exec -T vault sh -ec '
        export VAULT_ADDR=https://127.0.0.1:8200
        export VAULT_CACERT=/vault/tls/vault-ca.pem
        vault secrets enable -path=secret -version=2 kv 2>/dev/null || true
        vault kv put -mount=secret tenants/a/.rss-readiness value=ready >/dev/null
    '
}

cleanup() {
    if [[ $vault_paused -eq 1 ]]; then
        vault_cid="$($COMPOSE ps -q vault 2>/dev/null || true)"
        if [[ -n "$vault_cid" ]]; then
            docker unpause "$vault_cid" >/dev/null 2>&1 || true
        fi
    fi
    if [[ $vault_kv_disabled -eq 1 && "${KEEP_UP:-0}" = "1" ]]; then
        reset_demo_vault_kv >/dev/null 2>&1 || true
    fi
    if [[ $minio_stopped -eq 1 && "${KEEP_UP:-0}" = "1" ]]; then
        $COMPOSE start minio >/dev/null 2>&1 || true
    fi
    if [[ $redis_stopped -eq 1 && "${KEEP_UP:-0}" = "1" ]]; then
        $COMPOSE start redis >/dev/null 2>&1 || true
    fi
    rm -f "$READYZ_TMP"
    if [[ "${KEEP_UP:-0}" = "1" ]]; then
        log "KEEP_UP=1：保留栈，跳过 teardown（手动 'docker compose -f ${SCRIPT_DIR}/docker-compose.yml down -v' 清理）"
        return
    fi
    log "teardown：down -v"
    $COMPOSE down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

teardown() {
    rm -f "$READYZ_TMP"
    if [[ "${KEEP_UP:-0}" = "1" ]]; then
        log "KEEP_UP=1：保留栈，跳过 teardown（手动 'docker compose -f ${SCRIPT_DIR}/docker-compose.yml down -v' 清理）"
    else
        log "teardown：down -v"
        $COMPOSE down -v >/dev/null 2>&1
    fi
}

log "生成演示栈 egress TLS 材料（demo-tls）…"
bash "${SCRIPT_DIR}/demo-tls/generate-demo-cas.sh" >/dev/null \
    || fail "deploy/demo-tls/generate-demo-cas.sh 失败"
[[ -f "${SCRIPT_DIR}/demo-tls/out/postgres/ca.pem" ]] \
    || fail "缺少 demo TLS CA：deploy/demo-tls/out/postgres/ca.pem（先跑 generate-demo-cas.sh）"
[[ -f "${SCRIPT_DIR}/demo-tls/out/redis/ca.pem" ]] \
    || fail "缺少 demo TLS CA：deploy/demo-tls/out/redis/ca.pem"
[[ -f "${SCRIPT_DIR}/demo-tls/out/rabbitmq/ca.pem" ]] \
    || fail "缺少 demo TLS CA：deploy/demo-tls/out/rabbitmq/ca.pem"
[[ -f "${SCRIPT_DIR}/demo-tls/out/minio/CAs/rss-demo-s3-ca.pem" ]] \
    || fail "缺少 demo TLS CA：deploy/demo-tls/out/minio/CAs/rss-demo-s3-ca.pem"
log "demo TLS material ✓"

REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=server-version-identity.sh
source "${SCRIPT_DIR}/server-version-identity.sh"
export GIT_SHA
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)" \
    || fail "无法解析仓库 HEAD 作为 GIT_SHA"
export BUILD_DATE
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    || fail "无法生成 BUILD_DATE"
rss_require_build_identity || fail "构建身份非法（GIT_SHA/BUILD_DATE）"
log "构建演示栈同版本镜像…"
"${SCRIPT_DIR}/compose-secret-boundary.sh" >/dev/null \
    || fail "compose serving Secret boundary 校验失败"
log "compose serving Secret boundary ✓"
$COMPOSE build

# ── 离线 preflight：同一 strict parser，且不注入 Vault/provider env、不发网络请求 ──────────────
version_output="$(docker run --rm --entrypoint /usr/local/bin/server rss-runtime:dev version)" \
    || fail "server version 离线校验失败"
rss_assert_version_matches "$version_output" \
    || fail "server version bake-in 与构建输入不一致：${version_output}"
log "server version bake-in 校验 ✓"

demo_allowlist="$(read_env_file_value RSS_VAULT_TENANT_STORE_ALLOWLIST_JSON)"
validator_output="$(printf '%s\n' "$demo_allowlist" | docker run --rm -i \
    --entrypoint /usr/local/bin/rss rss-operator:dev vault-allowlist validate --stdin)" \
    || fail "合法 Vault allowlist 离线校验失败"
[[ "$validator_output" = "vault allowlist validation succeeded" ]] \
    || fail "合法 Vault allowlist 离线校验输出不是闭合成功分类"
invalid_marker="smoke-secret-allowlist-marker"
if invalid_output="$(printf '%s\n' "{\"bindings\":[],\"$invalid_marker\":true}" | docker run --rm -i \
    --entrypoint /usr/local/bin/rss rss-operator:dev vault-allowlist validate --stdin 2>&1)"; then
    fail "非法 Vault allowlist 被离线校验接受"
fi
[[ "$invalid_output" = "vault allowlist validation failed: invalid-json" ]] \
    || fail "非法 Vault allowlist 未返回闭合静态分类"
[[ "$invalid_output" != *"$invalid_marker"* ]] || fail "Vault allowlist 离线校验泄漏输入"
log "Vault allowlist 离线合法/非法校验 ✓"

log "拉起演示栈（postgres + redis + minio + rabbitmq + vault + server；host health port=${RSS_HEALTH_HOST_PORT}）…"
$COMPOSE up -d

# ── 闭环 1：/readyz 轮询至 200（PG healthy + 迁移完 + 池就绪）────────────────────────────────────
log "轮询 ${HEALTH_URL}/readyz 至 200（超时 ${READY_TIMEOUT}s）…"
deadline=$((SECONDS + READY_TIMEOUT))
ready=0
while [[ $SECONDS -lt $deadline ]]; do
    if curl -fsS "${HEALTH_URL}/readyz" >"$READYZ_TMP" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 2
done
[[ $ready -eq 1 ]] || {
    log "readyz 未在超时内 200；server 日志："
    $COMPOSE logs --tail=50 server >&2 || true
    fail "/readyz 未就绪"
}
log "readyz 200 ✓ → $(cat "$READYZ_TMP")"
grep -q '"name":"redis_ready","status":"healthy"' "$READYZ_TMP" \
    || fail "readyz body 缺 healthy redis_ready probe"
log "redis_ready probe 暴露 ✓"
grep -q '"name":"keyprovider_ready"' "$READYZ_TMP" || fail "readyz body 缺 keyprovider_ready probe"
log "keyprovider_ready probe 暴露 ✓"
grep -q '"name":"vault_secret_resolver_ready","status":"healthy"' "$READYZ_TMP" \
    || fail "readyz body 缺 healthy vault_secret_resolver_ready probe"
log "vault_secret_resolver_ready probe 暴露 ✓"
grep -q '"name":"s3_object_store_ready"' "$READYZ_TMP" || fail "readyz body 缺 s3_object_store_ready probe"
log "s3_object_store_ready probe 暴露 ✓"
grep -q '"name":"domain_transport_ready"' "$READYZ_TMP" || fail "readyz body 缺 domain_transport_ready probe"
log "domain_transport_ready probe 暴露 ✓"

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
[[ -n "$cid" ]] || fail "找不到 server 容器"
user="$(docker inspect -f '{{.Config.User}}' "$cid")"
ro="$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$cid")"
[[ "$user" = "65532:65532" ]] || fail "期望非 root user 65532:65532，实际 '${user}'"
[[ "$ro" = "true" ]] || fail "期望只读 rootfs (ReadonlyRootfs=true)，实际 '${ro}'"
log "加固断言 ✓（user=${user}, read_only=${ro}）"

# ── 闭环 5：Vault/KeyProvider down → readyz 503 ───────────────────────────────────────────────
log "暂停 vault，验证 keyprovider_ready 触发 readyz 503…"
vault_cid="$($COMPOSE ps -q vault)"
[[ -n "$vault_cid" ]] || fail "找不到 vault 容器"
docker pause "$vault_cid" >/dev/null
vault_paused=1
deadline=$((SECONDS + 40))
vault_down=0
while [[ $SECONDS -lt $deadline ]]; do
    code="$(curl -sS -o "$READYZ_TMP" -w '%{http_code}' "${HEALTH_URL}/readyz" || true)"
    if [[ "$code" = "503" ]] \
        && grep -q '"name":"keyprovider_ready","status":"unhealthy"' "$READYZ_TMP"; then
        vault_down=1
        break
    fi
    sleep 1
done
[[ $vault_down -eq 1 ]] || fail "Vault paused 后 /readyz 未返回 503（last=$(cat "$READYZ_TMP")）"
log "Vault paused → keyprovider_ready 503 ✓"
docker unpause "$vault_cid" >/dev/null
vault_paused=0
deadline=$((SECONDS + READY_TIMEOUT))
vault_restored=0
while [[ $SECONDS -lt $deadline ]]; do
    if curl -fsS "${HEALTH_URL}/readyz" >"$READYZ_TMP" 2>/dev/null \
        && grep -q '"name":"keyprovider_ready","status":"healthy"' "$READYZ_TMP"; then
        vault_restored=1
        break
    fi
    sleep 2
done
[[ $vault_restored -eq 1 ]] || fail "Vault 恢复后 /readyz 未回到 200（last=$(cat "$READYZ_TMP")）"
log "Vault 恢复 → readyz 200 ✓"

# ── 闭环 6：仅 Vault KV down → resolver readyz 503，Transit 保持 healthy → 恢复 200 ─────────────
log "禁用 Vault KV mount，验证独立 resolver readiness（Transit 仍健康）…"
$COMPOSE exec -T vault sh -ec '
    export VAULT_ADDR=https://127.0.0.1:8200
    export VAULT_CACERT=/vault/tls/vault-ca.pem
    vault secrets disable secret >/dev/null
'
vault_kv_disabled=1
deadline=$((SECONDS + 40))
vault_kv_down=0
while [[ $SECONDS -lt $deadline ]]; do
    code="$(curl -sS -o "$READYZ_TMP" -w '%{http_code}' "${HEALTH_URL}/readyz" || true)"
    if [[ "$code" = "503" ]] \
        && grep -q '"name":"vault_secret_resolver_ready","status":"unhealthy"' "$READYZ_TMP" \
        && grep -q '"name":"keyprovider_ready","status":"healthy"' "$READYZ_TMP"; then
        vault_kv_down=1
        break
    fi
    sleep 1
done
[[ $vault_kv_down -eq 1 ]] \
    || fail "Vault KV down 后未出现 resolver unhealthy / keyprovider healthy（last=$(cat "$READYZ_TMP")）"
log "Vault KV-only down → vault_secret_resolver_ready 503、keyprovider_ready healthy ✓"
reset_demo_vault_kv
vault_kv_disabled=0
deadline=$((SECONDS + READY_TIMEOUT))
vault_kv_restored=0
while [[ $SECONDS -lt $deadline ]]; do
    if curl -fsS "${HEALTH_URL}/readyz" >"$READYZ_TMP" 2>/dev/null \
        && grep -q '"name":"vault_secret_resolver_ready","status":"healthy"' "$READYZ_TMP"; then
        vault_kv_restored=1
        break
    fi
    sleep 2
done
[[ $vault_kv_restored -eq 1 ]] \
    || fail "Vault KV 恢复后 resolver readiness 未回到 healthy（last=$(cat "$READYZ_TMP")）"
log "Vault KV 恢复 → readyz 200 ✓"

# ── 闭环 7：MinIO down → readyz 503 → 恢复 200 ─────────────────────────────────────────────────
log "停止 minio，验证 s3_object_store_ready 触发 readyz 503…"
$COMPOSE stop minio >/dev/null
minio_stopped=1
deadline=$((SECONDS + S3_DOWN_TIMEOUT))
s3_down=0
while [[ $SECONDS -lt $deadline ]]; do
    code="$(curl -sS -o "$READYZ_TMP" -w '%{http_code}' "${HEALTH_URL}/readyz" || true)"
    if [[ "$code" = "503" ]] \
        && grep -q '"name":"s3_object_store_ready","status":"unhealthy"' "$READYZ_TMP"; then
        s3_down=1
        break
    fi
    sleep 1
done
[[ $s3_down -eq 1 ]] || fail "MinIO down 后 /readyz 未返回 503（last=$(cat "$READYZ_TMP")）"
log "MinIO down → s3_object_store_ready 503 ✓"
$COMPOSE start minio >/dev/null
minio_stopped=0
deadline=$((SECONDS + READY_TIMEOUT))
s3_restored=0
while [[ $SECONDS -lt $deadline ]]; do
    if curl -fsS "${HEALTH_URL}/readyz" >"$READYZ_TMP" 2>/dev/null \
        && grep -q '"name":"s3_object_store_ready","status":"healthy"' "$READYZ_TMP"; then
        s3_restored=1
        break
    fi
    sleep 2
done
[[ $s3_restored -eq 1 ]] || fail "MinIO 恢复后 /readyz 未回到 200（last=$(cat "$READYZ_TMP")）"
log "MinIO 恢复 → readyz 200 ✓"

# ── 闭环 7：Redis down → readyz 503 ────────────────────────────────────────────────────────────
log "停止 redis，验证 readyz 降为 503…"
$COMPOSE stop redis >/dev/null
redis_stopped=1
deadline=$((SECONDS + 20))
redis_down=0
while [[ $SECONDS -lt $deadline ]]; do
    code="$(curl -sS -o "$READYZ_TMP" -w '%{http_code}' "${HEALTH_URL}/readyz" || true)"
    if [[ "$code" = "503" ]] \
        && grep -q '"name":"redis_ready","status":"unhealthy"' "$READYZ_TMP"; then
        redis_down=1
        break
    fi
    sleep 1
done
[[ $redis_down -eq 1 ]] || fail "Redis down 后 /readyz 未返回 503（last=$(cat "$READYZ_TMP")）"
log "Redis down → redis_ready unhealthy、readyz 503 ✓"

log "恢复 redis 并等待 redis_ready healthy、readyz 200…"
$COMPOSE start redis >/dev/null
redis_stopped=0
deadline=$((SECONDS + READY_TIMEOUT))
redis_restored=0
while [[ $SECONDS -lt $deadline ]]; do
    if curl -fsS "${HEALTH_URL}/readyz" >"$READYZ_TMP" 2>/dev/null \
        && grep -q '"name":"redis_ready","status":"healthy"' "$READYZ_TMP"; then
        redis_restored=1
        break
    fi
    sleep 2
done
[[ $redis_restored -eq 1 ]] \
    || fail "Redis 恢复后未出现 redis_ready healthy / readyz 200（last=$(cat "$READYZ_TMP")）"
log "Redis 恢复 → redis_ready healthy、readyz 200 ✓"

# ── 闭环 8：SIGTERM → 完整 drain → exit 0 ──────────────────────────────────────────────────────
log "发送 SIGTERM，验证 server 完整 drain 并正常退出…"
docker kill --signal=TERM "$cid" >/dev/null
deadline=$((SECONDS + 30))
server_state=""
while [[ $SECONDS -lt $deadline ]]; do
    server_state="$(docker inspect -f '{{.State.Status}}:{{.State.ExitCode}}' "$cid")"
    [[ "$server_state" = "exited:0" ]] && break
    sleep 1
done
[[ "$server_state" = "exited:0" ]] || fail "SIGTERM 后 server 未在 30 秒内正常退出（state=${server_state}）"
log "SIGTERM → drain 完成 → exit 0 ✓"

teardown
trap - EXIT
log "全部冒烟通过 ✅"
if [[ "$RSS_SMOKE_MODE" = "release" ]]; then
    printf '%s\n' 'RELEASE IMAGE ON DEMO INFRA EVIDENCE'
fi
