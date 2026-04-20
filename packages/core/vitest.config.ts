import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov', 'json-summary'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/*.d.ts',
        'src/**/types.ts',
        'src/index.ts',
        // wasm.ts is pure Node/WASI I/O glue (file reading, WebAssembly.instantiate,
        // WASI lifecycle). It's exercised end-to-end by the adapter E2E suites which
        // boot with the real compiled WASM binary. Keeping it out of unit coverage
        // avoids brittle mocks of the WebAssembly + WASI globals.
        'src/wasm.ts',
        // pool.ts + pool-worker.ts are worker_threads glue. Unit-testing
        // Node's worker API reliably requires building the worker script
        // to disk; they're exercised by the pool integration test
        // (test/pool.integration.test.ts) and by E2E adapter benches.
        'src/pool.ts',
        'src/pool-worker.ts',
      ],
      thresholds: {
        lines: 98,
        functions: 98,
        statements: 98,
        branches: 95,
      },
    },
  },
})
