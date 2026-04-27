#!/usr/bin/env bash
# testing/matrix/pm-consumers/run-consumer.sh — boot one
# (case × package-manager) leg against a fresh consumer project that
# installs the published @coraza/* tarballs.
#
# Inputs (env):
#   CASE        one of: express5 | fastify5 | nestjs11 | next16-proxy | plain-esm
#   PM          one of: npm | yarn | pnpm
#   LEG_PORT    base port (default 43000); a per-leg port is derived
#   RUNNER_TEMP path to a writable scratch dir (CI sets this; local
#               default is `/tmp` if unset)
#   TARBALL_DIR path to the dir holding the @coraza/*.tgz tarballs.
#               In CI: ${RUNNER_TEMP}/tarballs (the download-artifact
#               step). Locally: caller exports it.
#   CONSUMER_ROOT scratch dir for the consumer project itself (default
#                ${RUNNER_TEMP:-/tmp}/pm-consumer)
#   BOOT_TIMEOUT seconds for /healthz to come up (default 90; Next +
#               npm cold install is the slowest combo)
#
# The script intentionally avoids `set -e`: it captures the driver's
# exit code separately so it can dump server logs on failure before
# bailing.

set -uo pipefail

CASE="${CASE:?CASE env var required}"
PM="${PM:?PM env var required}"
LEG_PORT="${LEG_PORT:-43000}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-90}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATES_DIR="${REPO_ROOT}/testing/matrix/pm-consumers"
CHECK_SCRIPT="${REPO_ROOT}/testing/matrix/scripts/check.mjs"

SCRATCH="${RUNNER_TEMP:-/tmp}"
TARBALL_DIR="${TARBALL_DIR:-${SCRATCH}/tarballs}"
CONSUMER_ROOT="${CONSUMER_ROOT:-${SCRATCH}/pm-consumer}"

if [[ ! -d "${TARBALL_DIR}" ]]; then
  echo "[pm] tarball dir not found at ${TARBALL_DIR}" >&2
  echo "[pm] hint: run 'pnpm -F \"./packages/*\" build && pnpm pack ...' first" >&2
  exit 2
fi

if ! ls "${TARBALL_DIR}"/*.tgz >/dev/null 2>&1; then
  echo "[pm] no .tgz files under ${TARBALL_DIR}" >&2
  exit 2
fi

template_dir="${TEMPLATES_DIR}/${CASE}"
if [[ ! -d "${template_dir}" ]]; then
  echo "[pm] unknown case: ${CASE}" >&2
  exit 2
fi

# Derive a stable per-leg port. Hash CASE+PM into the offset so two
# legs running in the same runner don't collide if a previous one
# leaked.
hash="$( ( echo -n "${CASE}-${PM}" | sha1sum 2>/dev/null || echo -n "${CASE}-${PM}" | shasum -a 1 ) | head -c 4 )"
port=$(( LEG_PORT + 0x${hash} % 1000 ))

consumer_dir="${CONSUMER_ROOT}/${CASE}-${PM}"
# Log dir is derived from CONSUMER_ROOT (not SCRATCH) so a caller
# overriding CONSUMER_ROOT for an isolated local run gets all artefacts
# (per-leg consumer dirs + their logs) under a single root.
log_dir="${CONSUMER_ROOT}/log"
mkdir -p "${log_dir}"
log_file="${log_dir}/${CASE}-${PM}.log"
install_log="${log_dir}/${CASE}-${PM}.install.log"

rm -rf "${consumer_dir}"
mkdir -p "${consumer_dir}"

echo "[pm] case=${CASE} pm=${PM} port=${port}"
echo "[pm] consumer dir: ${consumer_dir}"
echo "[pm] tarballs: $(ls -1 "${TARBALL_DIR}"/*.tgz | wc -l) file(s) under ${TARBALL_DIR}"

cd "${consumer_dir}"

# ---- 1. init project ----------------------------------------------------
case "${PM}" in
  npm)
    npm init -y >/dev/null
    # type:module so server.mjs ESM imports resolve as expected.
    node -e 'const f=require("fs");const p="package.json";const j=JSON.parse(f.readFileSync(p,"utf8"));j.type="module";f.writeFileSync(p,JSON.stringify(j,null,2)+"\n")'
    ;;
  yarn)
    # corepack-resolved Yarn 4 (Berry). Must be invoked via corepack to
    # avoid PATH order surprises on hosted runners.
    corepack yarn init -y >/dev/null
    # PnP would change module resolution out from under us; we want flat
    # node_modules to actually exercise hoisting against npm.
    cat >.yarnrc.yml <<'EOF'
nodeLinker: node-modules
enableImmutableInstalls: false
EOF
    node -e 'const f=require("fs");const p="package.json";const j=JSON.parse(f.readFileSync(p,"utf8"));j.type="module";f.writeFileSync(p,JSON.stringify(j,null,2)+"\n")'
    ;;
  pnpm)
    corepack pnpm init >/dev/null
    node -e 'const f=require("fs");const p="package.json";const j=JSON.parse(f.readFileSync(p,"utf8"));j.type="module";f.writeFileSync(p,JSON.stringify(j,null,2)+"\n")'
    cat >.npmrc <<'EOF'
auto-install-peers=true
strict-peer-dependencies=false
EOF
    ;;
  *)
    echo "[pm] unknown PM: ${PM}" >&2
    exit 2
    ;;
esac

# ---- 2. assemble dependency list ----------------------------------------
# `framework_deps` are the peer/runtime packages a real consumer would
# install alongside @coraza/<adapter>. We pin to the same major the
# matrix.yml cases use so a Next 17 bump doesn't silently flip behaviour
# under us; bumps belong in a deliberate PR.
case "${CASE}" in
  express5)
    framework_deps=(express@5.0.1)
    runner_deps=()
    runtime_cmd=(node server.mjs)
    ;;
  fastify5)
    framework_deps=(fastify@5)
    runner_deps=()
    runtime_cmd=(node server.mjs)
    ;;
  nestjs11)
    framework_deps=(
      "@nestjs/common@^11.0.0"
      "@nestjs/core@^11.0.0"
      "@nestjs/platform-express@^11.0.0"
      "reflect-metadata@^0.2.2"
      "rxjs@^7.8.1"
    )
    # tsx so the decorator-bearing TS source runs without a separate
    # tsc step. tsconfig.json lives next to server.ts in the template.
    runner_deps=("tsx@^4.19.1" "typescript@^5.6.2")
    runtime_cmd=(npx --yes tsx server.ts)
    ;;
  next16-proxy)
    framework_deps=(
      "next@^16.0.0"
      "react@^18.3.1"
      "react-dom@^18.3.1"
    )
    runner_deps=("typescript@^5.6.2" "@types/react@^18.3.3" "@types/node@^22.7.5")
    runtime_cmd=(npx --yes next start -p "${port}")
    ;;
  plain-esm)
    framework_deps=()
    runner_deps=()
    runtime_cmd=(node server.mjs)
    ;;
esac

# Tarball list — install ALL of them, even on a leg that only imports
# one adapter. The point is to validate every published @coraza/* under
# the target pm.
mapfile -t tarballs < <(ls "${TARBALL_DIR}"/*.tgz)

# ---- 3. install ---------------------------------------------------------
echo "[pm] installing tarballs + framework deps via ${PM}"
case "${PM}" in
  npm)
    npm install --no-audit --no-fund --foreground-scripts \
      "${tarballs[@]}" "${framework_deps[@]}" "${runner_deps[@]}" \
      >"${install_log}" 2>&1
    rc_install=$?
    ;;
  yarn)
    # Yarn 4 doesn't accept '@version' suffixes the same way for local
    # tarballs vs registry entries — splitting the calls is safer.
    corepack yarn add "${tarballs[@]}" >"${install_log}" 2>&1
    rc_install=$?
    if [[ "${rc_install}" -eq 0 && ${#framework_deps[@]} -gt 0 ]]; then
      corepack yarn add "${framework_deps[@]}" >>"${install_log}" 2>&1
      rc_install=$?
    fi
    if [[ "${rc_install}" -eq 0 && ${#runner_deps[@]} -gt 0 ]]; then
      corepack yarn add --dev "${runner_deps[@]}" >>"${install_log}" 2>&1
      rc_install=$?
    fi
    ;;
  pnpm)
    corepack pnpm add "${tarballs[@]}" "${framework_deps[@]}" "${runner_deps[@]}" \
      >"${install_log}" 2>&1
    rc_install=$?
    ;;
esac

if [[ "${rc_install}" -ne 0 ]]; then
  echo "[pm] install FAILED (rc=${rc_install}). Tail of install log:" >&2
  tail -n 100 "${install_log}" >&2 || true
  exit "${rc_install}"
fi

# ---- 4. drop the consumer template into the project ---------------------
# Use a tar pipeline so we don't depend on rsync being on the runner.
( cd "${template_dir}" && tar cf - . ) | tar xf -

# ---- 5. case-specific build step (Next only) ----------------------------
if [[ "${CASE}" == "next16-proxy" ]]; then
  echo "[pm] running 'next build'"
  build_log="${log_dir}/${CASE}-${PM}.build.log"
  npx --yes next build >"${build_log}" 2>&1
  rc_build=$?
  if [[ "${rc_build}" -ne 0 ]]; then
    echo "[pm] next build FAILED (rc=${rc_build}). Tail of build log:" >&2
    tail -n 200 "${build_log}" >&2 || true
    exit "${rc_build}"
  fi
fi

# ---- 6. boot the server -------------------------------------------------
echo "[pm] booting: ${runtime_cmd[*]}"
PORT="${port}" NODE_ENV=production "${runtime_cmd[@]}" >"${log_file}" 2>&1 &
app_pid=$!

# ---- 7. probe via the shared driver -------------------------------------
CASE_PORT="${port}" \
  CASE_HOST="${CASE_HOST:-127.0.0.1}" \
  CASE_NAME="${CASE}-${PM}" \
  BOOT_TIMEOUT="${BOOT_TIMEOUT}" \
  node "${CHECK_SCRIPT}"
rc=$?

# ---- 8. teardown --------------------------------------------------------
kill -TERM "${app_pid}" 2>/dev/null || true
# Reach descendants too — Next forks worker processes that don't sit in
# the immediate child tree.
pkill -TERM -P "${app_pid}" 2>/dev/null || true
sleep 0.5
kill -KILL "${app_pid}" 2>/dev/null || true
pkill -KILL -P "${app_pid}" 2>/dev/null || true
wait "${app_pid}" 2>/dev/null || true

# Belt-and-braces: anything still holding our port escapes the kill tree.
if command -v lsof >/dev/null 2>&1; then
  lsof -ti:"${port}" 2>/dev/null | xargs -r kill -KILL 2>/dev/null || true
elif command -v fuser >/dev/null 2>&1; then
  fuser -k -KILL "${port}/tcp" 2>/dev/null || true
fi

if [[ "${rc}" -ne 0 ]]; then
  echo "::group::${CASE}/${PM} server log"
  tail -n 200 "${log_file}" || true
  echo "::endgroup::"
fi

exit "${rc}"
