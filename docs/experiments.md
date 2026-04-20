# Experiment log

Every perf experiment we ran lives as a git branch. Worktrees under
`/tmp/cn-experiments/*` have been cleaned up; the branches themselves
are preserved so the negative results are recoverable.

Baseline this log is written against: **4,857 RPS, p99 37.4 ms, 100%
attack block rate** (POOL=8, TinyGo WASM, k6 mixed, 50 VUs, 20 s).

## Merged into main (keepers)

| Branch | What | Result |
|---|---|---|
| `exp/host-regex` | Forward `@rx` → V8 Irregexp via WASM host import | +4% RPS, −13% p99, +6% blocks. Merged. |
| `exp/rxprefilter` | Port coraza main's AST literal-skip prefilter | Noise on RPS, **−8% p99**. Merged. |
| `exp/prewarm` | Synthetic warmup request per pool worker at init | Noise on steady-state; cuts first-request tail. Merged. |
| `exp/batch-phases` | Fused tx_process_request_bundle (phases 1+2 atomic) | +1.4% RPS + **correctness fix (60% more attacks blocked)**. Merged. |

## Abandoned (branches kept as reference)

| Branch | What | Why abandoned |
|---|---|---|
| `exp/go-wasi` | Standard Go `wasip1 -buildmode=c-shared` + `wasilibs` | 953 RPS (5× SLOWER than TinyGo), 39 s boot, 27 MB binary. Go's full runtime in WASM cancels every gain from wasilibs. |
| `exp/multiphase-tag` | Coraza `coraza.rule.multiphase_evaluation` build tag | 4,258 RPS (−11%). Reorders rule evaluation for cache locality but fights our custom hostRx operator. |
| `exp/libcoraza` | Compile libcoraza (C-FFI) to WASM | Not viable — `GOOS=wasip1` has no cgo, and even if it did, libcoraza wraps the same Coraza Go code with added marshaling cost. Full writeup: `docs/libcoraza-feasibility.md`. |

## Scaffolded only (never finished)

| Branch | Hypothesis | Why not pursued |
|---|---|---|
| `exp/shared-memory` | `transferList` / `SharedArrayBuffer` for zero-copy worker transfer | Expected gain is ~1-2%. Worth doing after bigger wins land; see EXPERIMENT.md in the branch. |
| `exp/scratch-io` | Reuse WASM scratch buffer for inputs instead of malloc/free | Expected gain is single-digit % — noise given the MessagePort cost. |
| `exp/crs-tune` | Sweep of `excludeCategories` + paranoia variants | Not a code change — user-configurable knob in `@coraza/coreruleset`. Documented in `docs/performance.md`. |
| `exp/capture-routing` | Route CRS capture groups through V8 (not just match bool) | Biggest remaining in-our-control lever: expected +10-20% RPS. Ship-stopper for a future pass. |

## "Don't try this again" list

For any future contributor (human or AI) thinking about perf:

- **Don't switch to standard Go wasip1.** Go's full runtime makes the
  WASM 5× slower under V8. Tracked in `exp/go-wasi`.
- **Don't link `coraza-wasilibs` inside TinyGo.** Wazero symbols
  segfault TinyGo's linker. Tracked in the Dockerfile.
- **Don't compile libcoraza to WASM.** Not buildable today and wouldn't
  help anyway. Tracked in `docs/libcoraza-feasibility.md`.
- **Don't set `coraza.rule.multiphase_evaluation`.** It conflicts with
  our custom rx operator. Tracked in `exp/multiphase-tag`.
- **Don't skip phase 2 on body-less requests.** This was a 60%
  attack-miss bug that hid behind healthy-looking throughput numbers.
  `tx_process_request_bundle` fixes it by always running both phases
  atomically; never revert to separate phase calls.

## How to inspect a branch

```sh
# Read the final commit message for the verdict + numbers
git log exp/<name> -1

# Check out for deeper inspection (create a fresh worktree)
git worktree add /tmp/exp-<name> exp/<name>

# Clean up when done
git worktree remove /tmp/exp-<name>
```
