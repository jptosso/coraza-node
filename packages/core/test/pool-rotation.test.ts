// Integration test for WAFPool worker rotation.
//
// Spins up the real pool-worker.js under worker_threads (no mocking — the
// point of this test is to confirm that a replacement worker actually gets
// a fresh Node worker_thread and is swapped in without dropping requests).
// The WAF rules are a no-op config so the worker just exercises the pool
// plumbing without the full CRS cost.

import { describe, it, expect } from 'vitest'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import type { Logger } from '../src/types.js'

// The pool spawns worker_threads that load the compiled `dist/pool-worker.js`.
// The test must therefore load the *built* pool (from dist/), not the raw
// src/ tree — otherwise `new URL('./pool-worker.js', import.meta.url)`
// resolves inside src/ where only the .ts source lives.
const distUrl = new URL('../dist/index.js', import.meta.url)
const distPath = fileURLToPath(distUrl)
const hasBuild = existsSync(distPath)

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let WAFPool: any
if (hasBuild) {
  const mod = await import(distUrl.href)
  WAFPool = mod.WAFPool
}

function captureLogger(): {
  logger: Logger
  lines: { level: string; msg: string; meta?: Record<string, unknown> }[]
} {
  const lines: { level: string; msg: string; meta?: Record<string, unknown> }[] = []
  const mk = (level: string) => (msg: string, meta?: Record<string, unknown>) =>
    lines.push({ level, msg, meta })
  return {
    logger: { debug: mk('debug'), info: mk('info'), warn: mk('warn'), error: mk('error') },
    lines,
  }
}

const RULES = 'SecRuleEngine On\n'

const d = hasBuild ? describe : describe.skip

d('WAFPool rotation', () => {
  it(
    'rotates the worker thread after maxRequestsPerWorker',
    async () => {
      const { logger, lines } = captureLogger()

      const pool = await WAFPool.create({
        rules: RULES,
        size: 1,
        maxRequestsPerWorker: 3,
        logger,
        mode: 'detect',
      })

      const observedThreadIds = new Set<number>(pool.threadIds())

      let anyFailed = false
      for (let i = 0; i < 10; i++) {
        try {
          const tx = await pool.newTransaction()
          try {
            await tx.processRequestBundle(
              {
                method: 'GET',
                url: `/t${i}`,
                protocol: 'HTTP/1.1',
                headers: [['host', 'example.test']],
                remoteAddr: '127.0.0.1',
                remotePort: 0,
                serverPort: 0,
              },
              undefined,
            )
          } finally {
            await tx.close()
          }
        } catch {
          anyFailed = true
        }
        for (const id of pool.threadIds()) observedThreadIds.add(id)
        // Small yield so a scheduled rotation can complete between tx's.
        await new Promise((r) => setTimeout(r, 20))
        for (const id of pool.threadIds()) observedThreadIds.add(id)
      }

      expect(anyFailed).toBe(false)

      // Let any trailing rotations finish.
      await new Promise((r) => setTimeout(r, 100))
      for (const id of pool.threadIds()) observedThreadIds.add(id)

      const rotations = lines.filter(
        (l) => l.level === 'info' && l.msg === 'coraza pool: rotating worker',
      )
      // 10 real txs @ threshold 3 trigger multiple rotations. The task's
      // assertion floor is "at least twice".
      expect(rotations.length).toBeGreaterThanOrEqual(2)

      // Distinct threadIds observed during the run — must include the
      // original + at least 2 replacements.
      expect(observedThreadIds.size).toBeGreaterThanOrEqual(3)

      await pool.destroy()
      expect(pool.destroyed).toBe(true)
    },
    20_000,
  )

  it('disables rotation when maxRequestsPerWorker is 0', async () => {
    const { logger, lines } = captureLogger()

    const pool = await WAFPool.create({
      rules: RULES,
      size: 1,
      maxRequestsPerWorker: 0,
      logger,
      mode: 'detect',
    })
    expect(pool.maxRequestsPerWorker).toBe(Infinity)

    for (let i = 0; i < 5; i++) {
      const tx = await pool.newTransaction()
      await tx.close()
    }
    const rotations = lines.filter(
      (l) => l.level === 'info' && l.msg === 'coraza pool: rotating worker',
    )
    expect(rotations).toEqual([])

    await pool.destroy()
  })

  it('defaults maxRequestsPerWorker to 50_000', async () => {
    const { logger } = captureLogger()
    const pool = await WAFPool.create({ rules: RULES, size: 1, logger, mode: 'detect' })
    expect(pool.maxRequestsPerWorker).toBe(50_000)
    await pool.destroy()
  })

  it('keeps in-flight transactions alive across a rotation', async () => {
    const { logger } = captureLogger()
    const pool = await WAFPool.create({
      rules: RULES,
      size: 1,
      maxRequestsPerWorker: 1,
      logger,
      mode: 'detect',
    })

    // Start a tx but don't close it yet — this keeps it pinned to the slot
    // we'll rotate out. The pinned tx must still be processable after the
    // swap.
    const pinned = await pool.newTransaction()
    const second = await pool.newTransaction()

    let ok1 = false
    try {
      await pinned.processRequestBundle(
        {
          method: 'GET',
          url: '/pinned',
          protocol: 'HTTP/1.1',
          headers: [['host', 'x']],
        },
        undefined,
      )
      ok1 = true
    } catch {
      ok1 = false
    }
    expect(ok1).toBe(true)
    await pinned.close()
    await second.close()

    await pool.destroy()
  })
})
