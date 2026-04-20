import { defineConfig } from 'vitest/config'

export const baseConfig = defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov', 'json-summary'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.d.ts', 'src/**/index.ts', 'src/**/types.ts'],
      thresholds: {
        lines: 98,
        functions: 98,
        statements: 98,
        branches: 95,
      },
    },
  },
})

export default baseConfig
