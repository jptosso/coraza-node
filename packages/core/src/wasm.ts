// WASM instantiation. Accepts Node paths, URLs, or raw buffers.
// The result is a ready-to-use Abi wrapper.

import { readFile } from 'node:fs/promises'
import { WASI } from 'node:wasi'
import { fileURLToPath } from 'node:url'
import { Abi, type CorazaExports } from './abi.js'
import { patchInitialMemory } from './wasmPatch.js'
import { createMinimalWasi, useNativeWasi } from './wasi.js'
import { createHostRegex } from './hostRegex.js'
import type { Logger } from './types.js'

// CRS's regex compilation needs ~100 MiB of linear memory up front. TinyGo
// emits 2 initial pages; we rewrite the module's memory.min to 2100 pages
// (~137 MiB) before compiling. Matches coraza-proxy-wasm's patchWasm step.
const CORAZA_INITIAL_PAGES = 2100

export type WasmSource = ArrayBufferLike | Uint8Array | URL | string

async function resolveBytes(src: WasmSource): Promise<Uint8Array> {
  if (src instanceof Uint8Array) return src
  if (src instanceof ArrayBuffer) return new Uint8Array(src)
  if (src instanceof URL) {
    if (src.protocol === 'file:') return readFile(fileURLToPath(src))
    throw new Error(`unsupported URL protocol: ${src.protocol}`)
  }
  // string — treat as filesystem path.
  return readFile(src as string)
}

/**
 * Instantiate the Coraza WASM module with a Node WASI context.
 *
 * Caller responsibilities:
 *   - Pass a logger (or accept `console`) for `env.log` host imports.
 *   - Hold the returned Abi; disposal is by GC (WASM instance has no explicit close).
 *
 * When `precompiled` is supplied, skips the read+patch+compile step and
 * reuses the already-compiled module. `source` is ignored in that case.
 * Used by `WAFPool` to amortize WASM compilation across N workers — see
 * `compileWasmModule` below.
 */
export async function instantiate(
  source: WasmSource,
  logger: Logger,
  precompiled?: WebAssembly.Module,
): Promise<Abi> {
  let module: WebAssembly.Module
  if (precompiled) {
    module = precompiled
  } else {
    const bytes = await resolveBytes(source)
    const patched = patchInitialMemory(bytes, CORAZA_INITIAL_PAGES)
    module = await WebAssembly.compile(patched as unknown as BufferSource)
  }

  // Swap between node:wasi (full-featured, native binding) and our own
  // 120-line JS shim based on CORAZA_WASI=minimal. The minimal shim is
  // ~2-3× faster on hot WASI calls and drops a ~2 MB native dependency.
  let memRef: WebAssembly.Memory | null = null
  const minimal = useNativeWasi()
    ? null
    : createMinimalWasi({ logger, getMemory: () => memRef! })
  const wasi = minimal ?? new WASI({
    version: 'preview1',
    args: [],
    env: {},
  })

  // Shared host-regex state for the lifetime of this WASM instance.
  // Coraza calls `rx_compile` at WAF init for every CRS regex (~1300),
  // then `rx_match` on every request. V8's Irregexp JIT beats Go's regex
  // running inside WASM by a lot.
  //
  // Escape hatch: set `CORAZA_HOST_RX=off` to force every pattern to
  // fall back to Go's stdlib regex inside the WASM. Use this if you're
  // worried about V8's backtracking ReDoS surface — see docs/threat-model.md.
  const hostRxDisabled = process.env.CORAZA_HOST_RX === 'off'
  const hostRx = createHostRegex()

  const envImports = {
    log(level: number, ptr: number, len: number) {
      // `bytes()` pulled from the abi below once bound; we use a closure trick:
      if (!abi) return
      const msg = abi.readString(ptr, len)
      const fn: keyof Logger = level <= 0 ? 'debug' : level === 1 ? 'info' : level === 2 ? 'warn' : 'error'
      logger[fn](msg)
    },
    now_millis(): bigint {
      return BigInt(Date.now())
    },

    // Host-regex imports. Return 0 on compile failure so the Go side can
    // fall back to stdlib regex for PCRE features JS can't handle.
    rx_compile(patPtr: number, patLen: number): number {
      if (!abi || hostRxDisabled) return 0
      const pat = abi.readString(patPtr, patLen)
      return hostRx.compile(pat)
    },
    rx_match(handle: number, inputPtr: number, inputLen: number): number {
      if (!abi || hostRxDisabled) return 0
      const input = abi.readString(inputPtr, inputLen)
      return hostRx.match(handle, input) ? 1 : 0
    },
    rx_free(handle: number): void {
      hostRx.free(handle)
    },
  }

  const imports = {
    wasi_snapshot_preview1: wasi.wasiImport,
    env: envImports,
  }

  const instance = await WebAssembly.instantiate(module, imports)
  const exports = instance.exports as unknown as CorazaExports & { _start?: () => void }
  // Bind the shim's getMemory closure before any WASI import fires.
  memRef = exports.memory

  // WASI modules require _start for initialization.
  const startable = instance as never
  if (typeof exports._start === 'function') {
    ;(wasi.start as (_: never) => void)(startable)
  } else if (typeof (exports as { _initialize?: () => void })._initialize === 'function') {
    ;(wasi.initialize as (_: never) => void)(startable)
  }

  const abi = new Abi(exports)
  return abi
}

/**
 * Read + patch + compile the Coraza WASM once. Returns a `WebAssembly.Module`
 * that can be passed to `instantiate` via its `precompiled` argument as many
 * times as needed. Used by `WAFPool` to amortize the ~200-400 ms compile
 * across N workers — Node has no cross-worker code cache for local files
 * (https://github.com/nodejs/node/issues/36671), so without this each worker
 * would re-compile the same ~5 MB binary independently.
 */
export async function compileWasmModule(source: WasmSource): Promise<WebAssembly.Module> {
  const bytes = await resolveBytes(source)
  const patched = patchInitialMemory(bytes, CORAZA_INITIAL_PAGES)
  return WebAssembly.compile(patched as unknown as BufferSource)
}
