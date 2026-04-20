// WASM instantiation. Accepts Node paths, URLs, or raw buffers.
// The result is a ready-to-use Abi wrapper.

import { readFile } from 'node:fs/promises'
import { WASI } from 'node:wasi'
import { fileURLToPath } from 'node:url'
import { Abi, type CorazaExports } from './abi.js'
import { patchInitialMemory } from './wasmPatch.js'
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
 */
export async function instantiate(
  source: WasmSource,
  logger: Logger,
): Promise<Abi> {
  const bytes = await resolveBytes(source)
  const patched = patchInitialMemory(bytes, CORAZA_INITIAL_PAGES)
  const module = await WebAssembly.compile(patched as unknown as BufferSource)

  const wasi = new WASI({
    version: 'preview1',
    args: [],
    env: {},
  })

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
  }

  const imports = {
    wasi_snapshot_preview1: wasi.wasiImport,
    env: envImports,
  }

  const instance = await WebAssembly.instantiate(module, imports)
  const exports = instance.exports as unknown as CorazaExports & { _start?: () => void }

  // WASI modules require _start for initialization.
  if (typeof exports._start === 'function') {
    wasi.start(instance as unknown as Parameters<typeof wasi.start>[0])
  } else if (typeof (exports as { _initialize?: () => void })._initialize === 'function') {
    wasi.initialize(instance as unknown as Parameters<typeof wasi.initialize>[0])
  }

  const abi = new Abi(exports)
  return abi
}
