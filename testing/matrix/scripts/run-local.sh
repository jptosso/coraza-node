#!/usr/bin/env bash
# testing/matrix/scripts/run-local.sh — run the whole compatibility
# matrix on your laptop and print a pass/fail table.
#
# Env knobs:
#   CASES        space-separated list of cases (default: all non-turbopack)
#   POOL_MODES   subset of "single pool" (default: both)
#   NODE_BINARY  override node (default: whichever `node` is on PATH)
#   MATRIX_PORT  starting port (default: 40000). Each leg consumes one.
#   BOOT_TIMEOUT passed through to check.mjs (default: 45)
#
# This script is deliberately dumb: it loops over cases × pool modes
# serially, boots each server in the background, runs the driver, kills
# the server, and records pass/fail. No parallelism — the WASM compile
# step is memory-heavy and overlapping legs masks real boot-time bugs.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MATRIX_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${MATRIX_DIR}/../.." && pwd)"
CHECK="${SCRIPT_DIR}/check.mjs"

DEFAULT_CASES="express4 express5 fastify5 nestjs11 next15-middleware next15-middleware-turbopack next16-proxy next16-proxy-turbopack plain-esm plain-cjs"
CASES="${CASES:-${DEFAULT_CASES}}"
POOL_MODES="${POOL_MODES:-single pool}"
MATRIX_PORT="${MATRIX_PORT:-40000}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-90}"

BUILD_DIR="${MATRIX_DIR}/.build"
mkdir -p "${BUILD_DIR}"

# Sanity: the core package must be built so workspace:* resolves to the
# real dist/ when each case `import`s it. Most cases use tsx for ESM/CJS
# source directly, but Next requires compiled adapter code.
if [[ ! -d "${REPO_ROOT}/packages/core/dist" ]]; then
  echo "[matrix] @coraza/core/dist missing; run 'pnpm -w build' first" >&2
  exit 2
fi

declare -a RESULTS
port="${MATRIX_PORT}"
fail_count=0

for case_name in ${CASES}; do
  case_dir="${MATRIX_DIR}/cases/${case_name}"
  if [[ ! -d "${case_dir}" ]]; then
    echo "[matrix] unknown case: ${case_name}" >&2
    exit 2
  fi
  # Next cases need a production build once per pool-mode iteration (the
  # build output is reusable but we rebuild to keep the matrix honest).
  if [[ "${case_name}" == next* ]] && [[ "${case_name}" != *turbopack ]]; then
    (cd "${case_dir}" && pnpm build >"${BUILD_DIR}/${case_name}-build.log" 2>&1) || {
      echo "[matrix] ${case_name}: build failed (see ${BUILD_DIR}/${case_name}-build.log)"
      RESULTS+=("${case_name}\tN/A\tBUILD-FAIL")
      fail_count=$((fail_count + 1))
      continue
    }
  fi

  for pool in ${POOL_MODES}; do
    pool_env=""
    [[ "${pool}" == "pool" ]] && pool_env="1"
    port=$((port + 1))
    label="${case_name}/${pool}"
    logfile="${BUILD_DIR}/${case_name}-${pool}.log"
    echo "[matrix] → ${label} on :${port}"

    # `setsid` puts pnpm + every grandchild (tsx, next, node) in a fresh
    # process group so we can kill the whole tree by group id later.
    # Without it, pkill misses nephew processes (Next forks more workers
    # than the immediate child tree shows) and they hold the port,
    # causing the next leg to EADDRINUSE.
    setsid bash -c "cd '${case_dir}' && env \
        PORT='${port}' \
        POOL='${pool_env}' \
        NODE_ENV=production \
        pnpm start \
        >'${logfile}' 2>&1" &
    app_pid=$!

    CASE_PORT="${port}" \
      CASE_NAME="${case_name}" \
      CASE_LABEL="${pool}" \
      BOOT_TIMEOUT="${BOOT_TIMEOUT}" \
      node "${CHECK}"
    rc=$?

    # Kill the whole process group — `setsid` made the leg its own
    # session leader, so its PID equals its PGID. `kill -- -PGID` reaches
    # every descendant in one shot.
    kill -TERM -- "-${app_pid}" 2>/dev/null || true
    sleep 0.5
    kill -KILL -- "-${app_pid}" 2>/dev/null || true
    wait "${app_pid}" 2>/dev/null || true
    # Belt-and-braces: anything still bound to the leg's port escaped
    # the group kill (rare, e.g. a child that called setsid itself).
    if command -v lsof >/dev/null 2>&1; then
      lsof -ti:${port} 2>/dev/null | xargs -r kill -KILL 2>/dev/null || true
    elif command -v fuser >/dev/null 2>&1; then
      fuser -k -KILL "${port}/tcp" 2>/dev/null || true
    fi

    if [[ "${rc}" -eq 0 ]]; then
      RESULTS+=("${label}\tPASS")
    else
      RESULTS+=("${label}\tFAIL(rc=${rc}, log=${logfile})")
      fail_count=$((fail_count + 1))
    fi
  done
done

echo ""
echo "==================== matrix summary ===================="
printf '%b\n' "${RESULTS[@]}"
echo "========================================================"
if [[ "${fail_count}" -gt 0 ]]; then
  echo "[matrix] ${fail_count} leg(s) failed"
  exit 1
fi
echo "[matrix] all legs passed"
