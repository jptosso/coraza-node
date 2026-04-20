import { defineConfig } from 'vitest/config'

export default defineConfig({
  resolve: {
    alias: {
      '@coraza/core': new URL('../core/src/index.ts', import.meta.url).pathname,
    },
  },
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    exclude: ['test/e2e/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov', 'json-summary'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.d.ts'],
      thresholds: {
        lines: 98,
        functions: 98,
        statements: 98,
        branches: 85,
      },
    },
  },
})
