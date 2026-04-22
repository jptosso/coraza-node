// Fail-fast guarantee for WAFPool worker bootstrap.
//
// Context: under Next.js 16 Turbopack dev mode, the bundler can emit the
// pool worker file with ESM syntax but no sibling `"type": "module"`
// marker. Node then refuses to load it — the worker never emits `online`,
// `error`, or `exit`, and the old pool bootstrap would await forever.
// That bug is what filed github.com/coraza-incubator/coraza-node#8.
//
// We now cap the init handshake with `readyTimeoutMs` and reject with an
// actionable error. This test proves the deadline fires and the error
// names the likely culprit — we don't try to reproduce the Turbopack
// repro (hard without an actual Next app); we just assert the defensive
// timeout flips hangs into loud rejections.

import { describe, it, expect } from 'vitest'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const distUrl = new URL('../dist/index.js', import.meta.url)
const distPath = fileURLToPath(distUrl)
const hasBuild = existsSync(distPath)

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let createWAFPool: any
if (hasBuild) {
  const mod = await import(distUrl.href)
  createWAFPool = mod.createWAFPool
}

const describeIfBuilt = hasBuild ? describe : describe.skip

describeIfBuilt('WAFPool ready timeout', () => {
  it(
    'rejects with an actionable error when workers do not init in time',
    async () => {
      // 1 ms is effectively impossible — even on a ramdisk, spawning a
      // worker_thread + compiling/instantiating Coraza's WASM takes tens
      // of ms. The rejection must carry a hint that names bundler/module
      // format as the likely cause.
      await expect(
        createWAFPool({
          rules: 'SecRuleEngine On\n',
          size: 1,
          mode: 'detect',
          readyTimeoutMs: 1,
        }),
      ).rejects.toThrow(/failed to initialize within 1ms/i)
    },
    10_000,
  )

  it('surfaces the bundler / module-format hint in the error message', async () => {
    // Explicitly check the copy — the hint is the reason this timeout
    // exists; losing it silently would regress the UX we're trying to
    // restore.
    let caught: Error | null = null
    try {
      await createWAFPool({
        rules: 'SecRuleEngine On\n',
        size: 1,
        mode: 'detect',
        readyTimeoutMs: 1,
      })
    } catch (err) {
      caught = err as Error
    }
    expect(caught).not.toBeNull()
    expect(caught!.message).toMatch(/ESM marker|type":"module"|\.mjs/i)
    expect(caught!.message).toMatch(/Turbopack|bundler/i)
  })
})
