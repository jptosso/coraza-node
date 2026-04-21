# Reproducible WASM build for coraza-node.
#
# Produces /coraza.wasm at the image root. The repo's wasm-docker target
# extracts it via `docker create` + `docker cp`.
#
# Uses TinyGo — smaller binary, acceptable perf for Coraza's hot paths.
# Caveat: TinyGo's scheduler=none WASI build has a fixed stack that
# overflows when Go's stdlib regex compiler encounters the very deep
# patterns in CRS's SQLi/XSS rule files. For that workload users need to
# either (a) avoid compiling those specific CRS files, (b) use a reduced
# paranoia level that omits them, or (c) build with standard Go's
# `wasip1` target (see Dockerfile.gowasi — TODO).

FROM golang:1.26.2-bookworm AS builder

ARG TINYGO_VERSION=0.41.0
ENV TINYGO_VERSION=${TINYGO_VERSION}

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       ca-certificates \
       curl \
       build-essential \
  && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/tinygo.deb \
      https://github.com/tinygo-org/tinygo/releases/download/v${TINYGO_VERSION}/tinygo_${TINYGO_VERSION}_amd64.deb \
  && dpkg -i /tmp/tinygo.deb \
  && rm /tmp/tinygo.deb

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .

# Build tags:
#   no_fs_access                   — skip Coraza's /tmp write probe (unavailable under WASI)
#   timetzdata                     — embed tz db (no /usr/share/zoneinfo under WASI)
#   memoize_builders               — Coraza internal perf optimization
#   coraza.rule.no_regex_multiline — smaller regex engine
# `--initial-memory=137625600` (2100 * 65536) bakes CRS's ~137 MiB
# headroom into the memory section at link time — no post-build rewrite.
# CRS's regex compilation allocates heavily enough to OOB the default
# 2-page TinyGo memory before the WASI allocator can memory.grow.
# Keep in sync with CORAZA_INITIAL_PAGES in packages/core/src/wasm.ts.
RUN mkdir -p /out && tinygo build \
      -target=wasip1 \
      -o /out/coraza.wasm \
      -opt=2 \
      -no-debug \
      -gc=precise \
      -scheduler=none \
      -panic=trap \
      -ldflags="-extldflags '-z stack-size=4194304 --initial-memory=137625600'" \
      -tags="no_fs_access timetzdata memoize_builders coraza.rule.no_regex_multiline" \
      . \
  && ls -la /out/coraza.wasm

FROM scratch AS artifact
COPY --from=builder /out/coraza.wasm /coraza.wasm
# Needed so `docker create` has something to bind as the container's initial
# process, even though we never actually run it — we only `docker cp` the
# artifact out.
CMD ["/coraza.wasm"]
