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
#   BOOT_TIMEOUT     seconds to wait for the adapter's port to answer
#                    (default 180).

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

# Prefer an adapter-specific config file when present
# (ftw-overrides-next.yaml in particular adds the RESPONSE-95x skips
# that only apply to Next's middleware runtime). Falls back to the
# shared file for every adapter that inspects response bodies.
#
# Historically these were passed via `--overrides`, but go-ftw v2
# changed that flag to accept a different schema (platform overrides,
# keyed by rule_id). Our legacy files — `testoverride.input` + the
# `ignore` map — are a valid `FTWConfiguration`, so we pass them via
# `--config` instead.
if [[ -f "${SCRIPT_DIR}/ftw-overrides-${ADAPTER}.yaml" ]]; then
  CONFIG_TEMPLATE="${SCRIPT_DIR}/ftw-overrides-${ADAPTER}.yaml"
else
  CONFIG_TEMPLATE="${OVERRIDES_DEFAULT}"
fi
echo "[ftw] config=${CONFIG_TEMPLATE##*/}"

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
# `kill $APP_PID` only signals the pnpm wrapper; pnpm's tsx/node
# grandchild survives, which is what the previous run logged as
# `Terminate orphan process: pid (…) (node)`. We keep a descriptor
# of the child process group so cleanup reaches the whole subtree.
APP_PID=""
APP_PGID=""
cleanup() {
  if [[ -n "${APP_PGID}" ]]; then
    kill -TERM "-${APP_PGID}" 2>/dev/null || true
    sleep 1
    kill -KILL "-${APP_PGID}" 2>/dev/null || true
  elif [[ -n "${APP_PID}" ]] && kill -0 "${APP_PID}" 2>/dev/null; then
    kill "${APP_PID}" 2>/dev/null || true
    wait "${APP_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# CRS compile on first boot takes longer without mimalloc (dropped in
# 188d79b). Give boot a generous budget — healthy adapters reach
# "ready" in ≤2s; the slack absorbs noisy neighbours on shared hosts.
# The loop still short-circuits the moment the port responds.
BOOT_TIMEOUT="${BOOT_TIMEOUT:-180}"

if [[ "${SKIP_BOOT}" != "1" ]]; then
  if [[ "${ADAPTER}" == "next" ]]; then
    # Next's Node-runtime middleware requires a production build.
    (cd "${REPO_ROOT}/examples/next-app" && pnpm build) >"${BUILD_DIR}/next-build.log" 2>&1
  fi
  DEV_OR_START="dev"
  [[ "${ADAPTER}" == "next" ]] && DEV_OR_START="start"
  echo "[ftw] Starting ${PKG} on :${PORT} (boot budget ${BOOT_TIMEOUT}s)…"
  # `setsid` creates a new session so the child gets its own process
  # group; kill -PGID later hits pnpm + tsx + node together. We install
  # the child under its own group leader; `$!` in the subshell
  # captures the setsid process, which becomes PID == PGID.
  ( cd "${REPO_ROOT}" &&
    setsid env FTW=1 POOL=1 POOL_SIZE=4 PORT="${PORT}" pnpm -F "${PKG}" "${DEV_OR_START}" \
      </dev/null \
      > "${BUILD_DIR}/${ADAPTER}.stdout.log" \
      2> "${BUILD_DIR}/${ADAPTER}.stderr.log" &
    echo $! > "${BUILD_DIR}/${ADAPTER}.pid"
  )
  APP_PID="$(cat "${BUILD_DIR}/${ADAPTER}.pid")"
  APP_PGID="${APP_PID}"

  # Health-probe loop. We accept ANY three-digit HTTP status — the
  # probe's only job is to confirm the kernel socket is accepting and
  # the server is parsing HTTP. The actual per-test expectations are
  # handled by go-ftw later. Historically we accepted only 200/403, but
  # if the catch-all route ever fails to match `/` (e.g. a router
  # syntax regression) the probe silently treated the server as "not
  # listening" for 180s — masking a real bug as a boot timeout.
  retries="${BOOT_TIMEOUT}"
  status="000"
  while [[ "${retries}" -gt 0 ]]; do
    status="$(curl -sS -o /dev/null --connect-timeout 2 -w '%{http_code}' "http://127.0.0.1:${PORT}/" 2>/dev/null || true)"
    if [[ "${status}" =~ ^[2-5][0-9][0-9]$ ]]; then
      break
    fi
    if ! kill -0 "${APP_PID}" 2>/dev/null; then
      echo "[ftw] Target process died before becoming ready." >&2
      tail -n 40 "${BUILD_DIR}/${ADAPTER}.stderr.log" 2>/dev/null || true
      tail -n 40 "${BUILD_DIR}/${ADAPTER}.stdout.log" 2>/dev/null || true
      exit 1
    fi
    sleep 1
    retries=$((retries - 1))
  done
  [[ "${retries}" -gt 0 ]] || {
    echo "[ftw] Target did not come up within ${BOOT_TIMEOUT}s." >&2
    tail -n 40 "${BUILD_DIR}/${ADAPTER}.stderr.log" 2>/dev/null || true
    tail -n 40 "${BUILD_DIR}/${ADAPTER}.stdout.log" 2>/dev/null || true
    exit 1
  }
  echo "[ftw] Target up (status=${status})."
fi

# --- 6. Run go-ftw ---------------------------------------------------
OUT_JSON="${BUILD_DIR}/ftw-result-${ADAPTER}.json"
INCLUDE_FLAG=()
[[ -n "${INCLUDE}" ]] && INCLUDE_FLAG=(--include "${INCLUDE}")

# Synthesise a per-run config with the adapter's actual port swapped in.
# CRS test YAMLs hard-code `port: 80` (Apache convention); without the
# testoverride.input.port rewrite, go-ftw tries 127.0.0.1:80 and every
# case fails with `connect: connection refused`.
CONFIG_FILE="${BUILD_DIR}/ftw-config-${ADAPTER}.yaml"
sed -E "s/(^[[:space:]]*port:)[[:space:]]*[0-9]+$/\\1 ${PORT}/" \
  "${CONFIG_TEMPLATE}" > "${CONFIG_FILE}"

# Cloud mode: tell go-ftw to assess each case purely from the HTTP
# status code. Our adapters don't share a common log file go-ftw can
# tail — each block decision surfaces as a 403 response via `onBlock`.
# Without cloud mode go-ftw errors out with `Error: no log file
# supplied` before a single test executes. Cloud mode disables
# log-marker checks; that's acceptable because the CRS corpus tests we
# care about use `status: 403` as their primary assertion.
# Smoke a request the way go-ftw will: bare TCP, no keep-alive assumptions,
# HTTP/1.1. Gives us a concrete signal in the log artifact if the adapter
# serves a simpler curl but rejects go-ftw's raw-TCP style.
echo "[ftw] Pre-flight: direct HTTP/1.1 smoke on /"
curl -sS -o - -D - --max-time 5 "http://127.0.0.1:${PORT}/" || true
echo ""

# Run one test with --debug to capture the exact raw request go-ftw
# sends on the wire. Limited to a single test (911100-1) to keep the
# log artifact readable.
echo "[ftw] Debug replay: single test 911100 with --debug"
set +e
"${FTW_BIN}" run \
  --cloud --debug \
  --config "${CONFIG_FILE}" \
  --dir "${CRS_TESTS_DIR}" \
  --include '^911100' \
  > "${BUILD_DIR}/ftw-debug-${ADAPTER}.log" 2>&1
set -e

set +e
"${FTW_BIN}" run \
  --cloud \
  --config "${CONFIG_FILE}" \
  --dir "${CRS_TESTS_DIR}" \
  --output json \
  --read-timeout 10s \
  ${DEBUG} \
  "${INCLUDE_FLAG[@]}" \
  > "${OUT_JSON}" 2> "${BUILD_DIR}/ftw-stderr-${ADAPTER}.log"
ftw_exit=$?
set -e

if [[ "${ftw_exit}" -ne 0 ]] && ! [[ -s "${OUT_JSON}" ]]; then
  # JSON-mode run produces nothing unless every test completes. If it
  # bailed on a connection-level error we'd have no idea which test.
  # Re-run in progress mode to capture the last test-id that executed;
  # that's the one immediately before the hangup.
  echo "[ftw] JSON run aborted early; re-running with --output normal to locate the failing test"
  "${FTW_BIN}" run \
    --cloud \
    --config "${CONFIG_FILE}" \
    --dir "${CRS_TESTS_DIR}" \
    --output normal \
    --read-timeout 10s \
    "${INCLUDE_FLAG[@]}" \
    > "${BUILD_DIR}/ftw-progress-${ADAPTER}.log" 2>&1 \
    || true
  echo "[ftw] Last 30 lines of progress log:" >&2
  tail -n 30 "${BUILD_DIR}/ftw-progress-${ADAPTER}.log" >&2 || true
fi
if [[ "${ftw_exit}" -ne 0 ]]; then
  echo "[ftw] go-ftw exited with ${ftw_exit}; last 40 stderr lines:" >&2
  tail -n 40 "${BUILD_DIR}/ftw-stderr-${ADAPTER}.log" >&2 || true
fi

# --- 7. Parse & enforce threshold ------------------------------------
if ! [[ -s "${OUT_JSON}" ]]; then
  echo "[ftw] go-ftw produced no output (exit=${ftw_exit})." >&2
  exit 1
fi

# go-ftw v2 JSON shape:
#   {"run": <N>, "success": [...], "failed": [...], "ignored": [...], "skipped": [...], ...}
# Each is an array of test IDs. "run" is the total COUNT of tests
# evaluated. Older go-ftw wrapped stats under `.stats`; probe both.
if command -v jq >/dev/null 2>&1; then
  total=$(jq -r '(.run // .stats.totalCount // .stats.total // 0)' "${OUT_JSON}")
  success=$(jq -r '((.success // []) | length) // .stats.success // .stats.passed // 0' "${OUT_JSON}")
  failed=$(jq -r '((.failed // []) | length) // .stats.failed // 0' "${OUT_JSON}")
  ignored=$(jq -r '((.ignored // []) | length) // .stats.skipped // .stats.ignored // 0' "${OUT_JSON}")
  skipped=$(jq -r '((.skipped // []) | length) // 0' "${OUT_JSON}")
  # v2's "skipped" is tests not matched by --include; "ignored" is
  # tests excluded via testoverride.ignore. For threshold purposes we
  # want the pass rate over all tests the WAF actually saw the request
  # for — i.e. total - skipped - ignored.
  skipped=$(( skipped + ignored ))
else
  total=$(grep -oE '"run"\s*:\s*[0-9]+' "${OUT_JSON}" | head -1 | grep -oE '[0-9]+$' || echo 0)
  success=0; failed=0; skipped=0
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
