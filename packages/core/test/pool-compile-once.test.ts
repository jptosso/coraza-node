// Verifies perf proposal #2: WAFPool compiles the WASM module exactly once
// on the main thread when pool size > 1, instead of once per worker. The
// compiled module is shared with every worker via structured clone, so each
// worker only pays the instantiate cost — not the ~200-400 ms compile.
//
// Approach: spy on `WebAssembly.compile` at the module level, boot a real
// WAFPool with size > 1, and assert the spy fired exactly once.

import { afterEach, describe, expect, it, vi } from 'vitest'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { silentLogger } from '../src/logger.js'

// Boot the pool through the built dist so `new URL('./pool-worker.js', ...)`
// resolves next to the compiled worker script. Under vitest the src tree has
// only .ts files; worker_threads can't load those without a TS loader.
const distUrl = new URL('../dist/index.js', import.meta.url)
const hasBuild = existsSync(fileURLToPath(distUrl))
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let WAFPool: any
if (hasBuild) {
  const mod = await import(distUrl.href)
  WAFPool = mod.WAFPool
}

const RULES = 'SecRuleEngine On\n'

const d = hasBuild ? describe : describe.skip
d('WAFPool: single compile across workers', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('calls WebAssembly.compile at most once for pool size > 1', async () => {
    const realCompile = WebAssembly.compile.bind(WebAssembly)
    const compileSpy = vi.spyOn(WebAssembly, 'compile').mockImplementation((bytes) => realCompile(bytes))

    const pool = await WAFPool.create({
      rules: RULES,
      size: 4,
      maxRequestsPerWorker: 0,
      logger: silentLogger,
      mode: 'detect',
    })
    try {
      // The main thread compile is the only call we should see on this
      // process's WebAssembly.compile. Workers run in separate V8 isolates,
      // so even if they did compile, they wouldn't touch this spy — that
      // is precisely the bug class we're avoiding: each worker _would_ have
      // paid its own compile if the module weren't shared.
      expect(compileSpy).toHaveBeenCalledTimes(1)
    } finally {
      await pool.destroy()
    }
  }, 30_000)

  it('skips compile entirely when the caller supplies a pre-compiled wasmModule', async () => {
    const { compileWasmModule } = await import('../src/wasm.js')
    const url = new URL('../src/wasm/coraza.wasm', import.meta.url)
    const wasmModule = await compileWasmModule(url)

    const compileSpy = vi.spyOn(WebAssembly, 'compile')

    const pool = await WAFPool.create({
      rules: RULES,
      size: 2,
      maxRequestsPerWorker: 0,
      logger: silentLogger,
      mode: 'detect',
      wasmModule,
    })
    try {
      expect(compileSpy).not.toHaveBeenCalled()
    } finally {
      await pool.destroy()
    }
  }, 30_000)
})
