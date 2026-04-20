// @coraza/core/internal — low-level pieces exposed so adapter test suites
// (and other advanced callers) can mock or wire a custom ABI without
// going through the public WASM-loading path. NOT a stable public API:
// anything here can change between patch releases without a deprecation
// cycle. If you find yourself reaching for these in production code,
// open an issue so we can expose a real supported hook.

export { Abi, encodeHeaders, ABI_MAJOR } from './abi.js'
export { instantiate, type WasmSource } from './wasm.js'
export { patchInitialMemory } from './wasmPatch.js'
