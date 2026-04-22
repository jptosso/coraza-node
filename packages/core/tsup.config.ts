import { defineConfig } from 'tsup'
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs'

export default defineConfig({
  entry: ['src/index.ts', 'src/internal.ts', 'src/pool-worker.ts'],
  format: ['esm', 'cjs'],
  dts: { entry: ['src/index.ts', 'src/internal.ts'] },
  sourcemap: true,
  clean: true,
  target: 'node22',
  splitting: false,
  async onSuccess() {
    mkdirSync('dist/wasm', { recursive: true })
    cpSync('src/wasm/coraza.wasm', 'dist/wasm/coraza.wasm')
    // Rename the ESM worker output to `.mjs` so Node unambiguously treats
    // it as ES module regardless of any bundler's `package.json` emission
    // choices. Turbopack in Next.js 16 dev mode is the canonical case where
    // `.js` would be re-emitted without a `"type":"module"` marker and fail
    // to load. See github.com/coraza-incubator/coraza-node#8. `pool.ts` references
    // `./pool-worker.mjs` at runtime; keeping the rename in lock-step with
    // that call site is what ships this fix.
    const renames: Array<[string, string]> = [
      ['dist/pool-worker.js', 'dist/pool-worker.mjs'],
      ['dist/pool-worker.js.map', 'dist/pool-worker.mjs.map'],
    ]
    for (const [from, to] of renames) {
      if (existsSync(from)) {
        if (existsSync(to)) rmSync(to)
        renameSync(from, to)
      }
    }
    // Patch the sourceMappingURL inside the renamed worker so debugger /
    // stack-trace tooling still finds the map.
    const mjs = 'dist/pool-worker.mjs'
    if (existsSync(mjs)) {
      const src = readFileSync(mjs, 'utf8')
      const patched = src.replace(
        /\/\/# sourceMappingURL=pool-worker\.js\.map/g,
        '//# sourceMappingURL=pool-worker.mjs.map',
      )
      if (patched !== src) writeFileSync(mjs, patched)
    }
    // Rewrite the `file` field inside the .map so DevTools doesn't complain.
    const mjsMap = 'dist/pool-worker.mjs.map'
    if (existsSync(mjsMap)) {
      try {
        const raw = readFileSync(mjsMap, 'utf8')
        const parsed = JSON.parse(raw) as { file?: string }
        if (parsed.file === 'pool-worker.js') {
          parsed.file = 'pool-worker.mjs'
          writeFileSync(mjsMap, JSON.stringify(parsed))
        }
      } catch {
        /* map may be absent or minified; best-effort */
      }
    }
  },
})
