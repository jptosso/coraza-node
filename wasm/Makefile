.PHONY: wasm wasm-docker tidy clean versions test cover bench profile

BIN := build/coraza.wasm
DIST := ../packages/core/src/wasm/coraza.wasm

# Host-toolchain build (requires local TinyGo >=0.34 + Go >=1.22).
wasm: $(BIN)
	@mkdir -p $(dir $(DIST))
	@cp $(BIN) $(DIST)
	@echo "WASM -> $(DIST) ($$(wc -c < $(DIST)) bytes)"

# Docker build — pins TinyGo + Go versions for byte-reproducible output.
# This is the default target used by CI and by `pnpm wasm` at the repo root.
# The final image is FROM scratch (no shell/cat), so we extract via
# `docker create` + `docker cp`.
wasm-docker:
	@mkdir -p $(dir $(DIST))
	docker build -t coraza-node-wasm:local -f Dockerfile .
	@cid=$$(docker create coraza-node-wasm:local) \
		&& docker cp $$cid:/coraza.wasm $(DIST) \
		&& docker rm -f $$cid > /dev/null
	@echo "WASM -> $(DIST) ($$(wc -c < $(DIST)) bytes)"

$(BIN): $(wildcard *.go) go.mod Makefile
	@mkdir -p build
	tinygo build \
		-target=wasi \
		-o $(BIN) \
		-opt=2 \
		-no-debug \
		-gc=conservative \
		-scheduler=none \
		-panic=trap \
		-tags=no_fs_access,timetzdata,memoize_builders,coraza.rule.no_regex_multiline \
		.

tidy:
	go mod tidy

versions:
	@cat version.txt

# Native Go tests (runs every export function natively via the handle-table
# readBytes in host_native.go — the WASM variant is covered by Node E2E).
test:
	go test -race ./...

cover:
	@mkdir -p build
	go test -coverprofile=build/coverage.out ./...
	go tool cover -func=build/coverage.out | tail -1
	go tool cover -html=build/coverage.out -o build/coverage.html
	@echo "HTML coverage -> build/coverage.html"

# Microbenchmarks. ABI parse/serialize + full request pipeline.
# Enables the `wasilibs` tag so we measure against the fast operators
# (Ragel regex + C-compiled XSS detector) — realistic production numbers.
bench:
	go test -tags=wasilibs -bench=. -benchmem -benchtime=2s ./...

# Bench WITHOUT wasilibs, for apples-to-apples comparison with the WASM
# build (which can't link wazero and falls back to Go stdlib regex).
bench-nowasilibs:
	go test -bench=. -benchmem -benchtime=2s ./...

# CPU + memory profiles. View with `go tool pprof -http=:0 build/cpu.prof`.
profile:
	@mkdir -p build
	go test -bench=BenchmarkRequestPipeline_Benign \
		-benchmem \
		-benchtime=5s \
		-cpuprofile=build/cpu.prof \
		-memprofile=build/mem.prof \
		-blockprofile=build/block.prof \
		-mutexprofile=build/mutex.prof \
		./...
	@echo ""
	@echo "Profiles written to wasm/build/. Open with:"
	@echo "  go tool pprof -http=:0 wasm/build/cpu.prof"
	@echo "  go tool pprof -http=:0 wasm/build/mem.prof"

clean:
	rm -rf build
	rm -f $(DIST)
