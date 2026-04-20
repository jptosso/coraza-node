# Copilot instructions

All repository conventions are documented in **[AGENTS.md](../AGENTS.md)** at
the repo root. Read that file first — it covers:

- Architecture (WASM + Go ABI, framework adapters, npm layout)
- Build & test (`pnpm wasm`, `pnpm test`, `pnpm e2e`, `go test`, benchmarks)
- Coverage thresholds and where each layer is tested
- The strict `unsafe` policy for `wasm/host_wasm.go`
- Release flow via Changesets
- A table mapping "what you're changing" → "files to touch"

Do not duplicate guidance into this file — update `AGENTS.md` instead.
