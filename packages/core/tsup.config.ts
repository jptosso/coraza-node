import { defineConfig } from 'tsup'
import { cpSync, mkdirSync } from 'node:fs'

export default defineConfig({
  entry: ['src/index.ts', 'src/pool-worker.ts'],
  format: ['esm', 'cjs'],
  dts: { entry: ['src/index.ts'] },
  sourcemap: true,
  clean: true,
  target: 'node20',
  splitting: false,
  async onSuccess() {
    mkdirSync('dist/wasm', { recursive: true })
    cpSync('src/wasm/coraza.wasm', 'dist/wasm/coraza.wasm')
  },
})
