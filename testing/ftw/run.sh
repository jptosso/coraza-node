#!/usr/bin/env bash
# testing/ftw/run.sh — drive the OWASP CRS regression corpus (via
# coreruleset/go-ftw) against one of our FTW-mode example adapters.
#
# Modelled on corazawaf/coraza-caddy/ftw/tests.sh and the Dockerfile.ftw
# pinning pattern. Key differences:
#
#   * No Docker. The target is a Node/Express process booted in-band.
#   * CRS corpus version is read from wasm/version.txt so the tests
#     always match the rules compiled into the WASM.
#   * go-ftw is pinned to GO_FTW_VERSION. Do not pass @latest in
#     committed CI — it defeats reproducibility.
#
# Usage:
#   bash testing/ftw/run.sh                       # express @ :3001, threshold 95
#   bash testing/ftw/run.sh express 3001
#   bash testing/ftw/run.sh fastify 3002 --threshold 98
#   bash testing/ftw/run.sh --adapter=express --port=3001 --include=942
#
# Environment knobs (for CI pinning; normally unset locally):
#   GO_FTW_VERSION   pinned go-ftw tag (default: v2.1.1 — matches caddy).
#   CRS_TAG          force a specific corpus tag; default reads
#                    wasm/version.txt's coreruleset= line.
#   SKIP_BOOT=1      don't boot the adapter — assume something else has it
#                    already bound on PORT (useful for debugging).

set -euo pipefail

GO_FTW_VERSION="${GO_FTW_VERSION:-v2.1.1}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${REPO_ROOT}/testing/ftw/build"
CRS_DIR="${REPO_ROOT}/testing/ftw/.coreruleset"
# Per-adapter overrides if one exists (e.g. ftw-overrides-next.yaml),
# otherwise fall back to the shared file.
OVERRIDES_DEFAULT="${SCRIPT_DIR}/ftw-overrides.yaml"

ADAPTER="express"
PORT=""
THRESHOLD="95"
INCLUDE=""
DEBUG=""
SKIP_BOOT="${SKIP_BOOT:-0}"

# Accept both positional (legacy coraza-caddy style) and --flag forms.
if [[ $# -gt 0 && "$1" != -* ]]; then
  ADAPTER="$1"; shift
  if [[ $# -gt 0 && "$1" != -* ]]; then
    PORT="$1"; shift
  fi
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --adapter=*)   ADAPTER="${1#*=}"; shift ;;
    --adapter)     ADAPTER="$2"; shift 2 ;;
    --port=*)      PORT="${1#*=}"; shift ;;
    --port)        PORT="$2"; shift 2 ;;
    --threshold=*) THRESHOLD="${1#*=}"; shift ;;
    --threshold)   THRESHOLD="$2"; shift 2 ;;
    --include=*)   INCLUDE="${1#*=}"; shift ;;
    --include)     INCLUDE="$2"; shift 2 ;;
    --debug)       DEBUG="--debug"; shift ;;
    --skip-boot)   SKIP_BOOT=1; shift ;;
    -h|--help)
      sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

case "${ADAPTER}" in
  express) DEFAULT_PORT=3001; PKG="@coraza/example-express" ;;
  fastify) DEFAULT_PORT=3002; PKG="@coraza/example-fastify" ;;
  next)    DEFAULT_PORT=3003; PKG="@coraza/example-next" ;;
  nestjs)  DEFAULT_PORT=3004; PKG="@coraza/example-nestjs" ;;
  *) echo "unknown adapter: ${ADAPTER} (express|fastify|next|nestjs)" >&2; exit 2 ;;
esac
PORT="${PORT:-${DEFAULT_PORT}}"

# Prefer an adapter-specific overrides file when present
# (ftw-overrides-next.yaml in particular adds the RESPONSE-95x skips
# that only apply to Next's middleware runtime). Falls back to the
# shared file for every adapter that inspects response bodies.
if [[ -f "${SCRIPT_DIR}/ftw-overrides-${ADAPTER}.yaml" ]]; then
  OVERRIDES="${SCRIPT_DIR}/ftw-overrides-${ADAPTER}.yaml"
else
  OVERRIDES="${OVERRIDES_DEFAULT}"
fi
echo "[ftw] overrides=${OVERRIDES##*/}"

# --- 1. Resolve the CRS version --------------------------------------
if [[ -n "${CRS_TAG:-}" ]]; then
  crs_version="${CRS_TAG#v}"
else
  crs_version="$(awk -F= '/^coreruleset=/{print $2}' "${REPO_ROOT}/wasm/version.txt")"
fi
if [[ -z "${crs_version}" ]]; then
  echo "could not read coreruleset= from wasm/version.txt" >&2
  exit 1
fi
echo "[ftw] adapter=${ADAPTER} port=${PORT} crs=v${crs_version} go-ftw=${GO_FTW_VERSION}"

# --- 2. Fetch & cache the corpus at the pinned tag -------------------
mkdir -p "${BUILD_DIR}" "${CRS_DIR}"
CRS_CHECKOUT="${CRS_DIR}/v${crs_version}"
if [[ ! -d "${CRS_CHECKOUT}" ]]; then
  echo "[ftw] Fetching coreruleset v${crs_version}…"
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" EXIT
  curl -fsSL \
    "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${crs_version}.tar.gz" \
    -o "${tmp}/crs.tar.gz"
  mkdir -p "${CRS_CHECKOUT}"
  tar -xzf "${tmp}/crs.tar.gz" -C "${CRS_CHECKOUT}" --strip-components=1
  rm -rf "${tmp}"
  trap - EXIT
fi
CRS_TESTS_DIR="${CRS_CHECKOUT}/tests/regression/tests"
[[ -d "${CRS_TESTS_DIR}" ]] || { echo "missing tests dir: ${CRS_TESTS_DIR}" >&2; exit 1; }
corpus_size="$(find "${CRS_TESTS_DIR}" -name '*.yaml' | wc -l | tr -d ' ')"
echo "[ftw] Corpus: ${corpus_size} YAML files."

# --- 3. Ensure WASM is present ---------------------------------------
wasm_path="${REPO_ROOT}/packages/core/src/wasm/coraza.wasm"
[[ -f "${wasm_path}" ]] || { echo "missing WASM — run 'pnpm wasm' first." >&2; exit 1; }

# --- 4. Install go-ftw (pinned) --------------------------------------
# Use `go install` so we get a binary at $GOBIN/go-ftw — avoids a
# module-mode `go run` round-trip per invocation.
INSTALL_DIR="${BUILD_DIR}/gobin"
mkdir -p "${INSTALL_DIR}"
export GOBIN="${INSTALL_DIR}"
if [[ ! -x "${GOBIN}/go-ftw" ]]; then
  echo "[ftw] Installing go-ftw@${GO_FTW_VERSION}…"
  # go-ftw follows Go's semantic import versioning — from v2.0.0 the
  # module path gains the /v2 suffix. `go install` rejects an import
  # path that doesn't match the module's own go.mod declaration.
  GO111MODULE=on go install "github.com/coreruleset/go-ftw/v2@${GO_FTW_VERSION}"
fi
FTW_BIN="${GOBIN}/go-ftw"

# --- 5. Boot the adapter (unless --skip-boot) ------------------------
APP_PID=""
cleanup() {
  if [[ -n "${APP_PID}" ]] && kill -0 "${APP_PID}" 2>/dev/null; then
    kill "${APP_PID}" 2>/dev/null || true
    wait "${APP_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ "${SKIP_BOOT}" != "1" ]]; then
  if [[ "${ADAPTER}" == "next" ]]; then
    # Next's Node-runtime middleware requires a production build.
    (cd "${REPO_ROOT}/examples/next-app" && pnpm build) >"${BUILD_DIR}/next-build.log" 2>&1
  fi
  echo "[ftw] Starting ${PKG} on :${PORT}…"
  (
    cd "${REPO_ROOT}"
    FTW=1 PORT="${PORT}" pnpm -F "${PKG}" \
      "$( [[ "${ADAPTER}" == "next" ]] && echo start || echo dev )" \
      > "${BUILD_DIR}/${ADAPTER}.stdout.log" \
      2> "${BUILD_DIR}/${ADAPTER}.stderr.log" &
    echo $! > "${BUILD_DIR}/${ADAPTER}.pid"
  )
  APP_PID="$(cat "${BUILD_DIR}/${ADAPTER}.pid")"

  # Health-probe loop. We accept 200 (echo-all responded) or 403
  # (WAF blocked the bare GET / request — shouldn't happen at PL2
  # but harmless).
  retries=60
  status="000"
  while [[ "${retries}" -gt 0 ]]; do
    status="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/" || true)"
    if [[ "${status}" == "200" || "${status}" == "403" ]]; then
      break
    fi
    if ! kill -0 "${APP_PID}" 2>/dev/null; then
      echo "[ftw] Target process died before becoming ready." >&2
      tail -n 40 "${BUILD_DIR}/${ADAPTER}.stderr.log" >&2 || true
      exit 1
    fi
    sleep 1
    retries=$((retries - 1))
  done
  [[ "${retries}" -gt 0 ]] || {
    echo "[ftw] Target did not come up within 60s." >&2
    tail -n 40 "${BUILD_DIR}/${ADAPTER}.stderr.log" >&2 || true
    exit 1
  }
  echo "[ftw] Target up (status=${status})."
fi

# --- 6. Run go-ftw ---------------------------------------------------
OUT_JSON="${BUILD_DIR}/ftw-result-${ADAPTER}.json"
INCLUDE_FLAG=()
[[ -n "${INCLUDE}" ]] && INCLUDE_FLAG=(--include "${INCLUDE}")

# Connection settings — communicate target host/port via FTW_* env.
# `ftw run` picks up `--host` / `--port` overrides from CLI too; we use
# env vars so the same ftw-overrides.yaml works across matrix legs.
export FTW_TEST_HOST="127.0.0.1"
export FTW_TEST_PORT="${PORT}"

set +e
"${FTW_BIN}" run \
  --dir "${CRS_TESTS_DIR}" \
  --overrides "${OVERRIDES}" \
  --output json \
  --read-timeout 10s \
  --max-marker-retries 50 \
  ${DEBUG} \
  "${INCLUDE_FLAG[@]}" \
  > "${OUT_JSON}"
ftw_exit=$?
set -e

# --- 7. Parse & enforce threshold ------------------------------------
if ! [[ -s "${OUT_JSON}" ]]; then
  echo "[ftw] go-ftw produced no output (exit=${ftw_exit})." >&2
  exit 1
fi

# go-ftw's JSON shape varies slightly by version; probe both names.
if command -v jq >/dev/null 2>&1; then
  total=$(jq -r '(.stats.totalCount // .stats.total // (.Run|length) // 0)' "${OUT_JSON}")
  success=$(jq -r '(.stats.success // .stats.passed // ((.Run // []) | map(select(.Pass==true)) | length) // 0)' "${OUT_JSON}")
  failed=$(jq -r '(.stats.failed // ((.Run // []) | map(select(.Pass==false)) | length) // 0)' "${OUT_JSON}")
  skipped=$(jq -r '(.stats.skipped // .stats.ignored // 0)' "${OUT_JSON}")
else
  total=$(grep -oE '"total[A-Za-z]*"\s*:\s*[0-9]+' "${OUT_JSON}" | head -1 | grep -oE '[0-9]+$' || echo 0)
  success=$(grep -oE '"(success|passed)"\s*:\s*[0-9]+' "${OUT_JSON}" | head -1 | grep -oE '[0-9]+$' || echo 0)
  failed=$(grep -oE '"failed"\s*:\s*[0-9]+' "${OUT_JSON}" | head -1 | grep -oE '[0-9]+$' || echo 0)
  skipped=$(grep -oE '"(skipped|ignored)"\s*:\s*[0-9]+' "${OUT_JSON}" | head -1 | grep -oE '[0-9]+$' || echo 0)
fi

considered=$(( total - skipped ))
if [[ "${considered}" -le 0 ]]; then
  echo "[ftw] No tests were actually executed (total=${total}, skipped=${skipped})." >&2
  exit 1
fi
pct=$(awk -v s="${success}" -v c="${considered}" 'BEGIN { printf "%.2f", (s * 100.0) / c }')

echo ""
echo "========================================"
echo " go-ftw summary (${ADAPTER})"
echo "========================================"
echo "  total:     ${total}"
echo "  passed:    ${success}"
echo "  failed:    ${failed}"
echo "  skipped:   ${skipped}"
echo "  pass rate: ${pct}% (of ${considered} executed)"
echo "  threshold: ${THRESHOLD}%"
echo "  artifact:  ${OUT_JSON}"
echo "========================================"

pass_ok=$(awk -v p="${pct}" -v t="${THRESHOLD}" 'BEGIN { print (p+0 >= t+0) ? 1 : 0 }')
if [[ "${pass_ok}" -ne 1 ]]; then
  echo "[ftw] FAIL — ${pct}% < ${THRESHOLD}%" >&2
  exit 1
fi
echo "[ftw] PASS"
exit 0
