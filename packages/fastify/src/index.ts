// @coraza/fastify — Fastify plugin wrapping @coraza/core.
//
// Usage:
//
//   import fastify from 'fastify'
//   import { coraza } from '@coraza/fastify'
//   import { createWAF } from '@coraza/core'
//
//   const app = fastify()
//   await app.register(coraza, { waf })
//
// Design notes:
//   - Evaluates the full request (phases 1 + 2) in a single `preHandler`
//     hook using `processRequestBundle`. preHandler runs after Fastify's
//     body parser, so req.body is in hand. Running both phases together
//     matches the pattern used in @coraza/express — a separate onRequest
//     + preHandler sequence would miss CRS's phase-2 anomaly evaluator
//     on body-less requests, bypassing CRS's anomaly-score rule 949110.
//   - Fails closed on any WAF error (default `onWAFError: 'block'`).
//     Matches docs/threat-model.md's threat model.
//   - Logging: Fastify ships Pino. We forward to `request.log` (scoped)
//     for per-request log lines and fall back to `fastify.log` for
//     init-time messages.

import fp from 'fastify-plugin'
import type {
  AnyWAF,
  WAFLike,
  Transaction,
  WorkerTransaction,
  Interruption,
  SkipOptions,
} from '@coraza/core'
import { buildSkipPredicate, pathOf } from '@coraza/core'
import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify'

export interface CorazaFastifyOptions {
  /**
   * Single WAF or a WAFPool for multi-core scaling. Also accepts a
   * promise of either, so modules that can't do top-level await can
   * defer construction.
   */
  waf: WAFLike
  onBlock?: (
    interruption: Interruption,
    req: FastifyRequest,
    reply: FastifyReply,
  ) => void | Promise<void>
  /** Run phase 3+4 on the response. Default false; see @coraza/express docs. */
  inspectResponse?: boolean
  /** Bypass Coraza for static/media paths. See `SkipOptions`. */
  skip?: SkipOptions | false
  /**
   * What to do if the WAF throws mid-request.
   *   'block' (default) — respond 503 (fail-closed). A crash in the WAF
   *                       must not become a bypass.
   *   'allow'           — pass through. Only for availability-critical
   *                       setups; document why you flipped it.
   */
  onWAFError?: 'allow' | 'block'
}

const TX_SYMBOL = Symbol('coraza.tx')
type AnyTx = Transaction | WorkerTransaction
type WithTx = FastifyRequest & { [TX_SYMBOL]?: AnyTx }

const pluginImpl: FastifyPluginAsync<CorazaFastifyOptions> = async (fastify, opts) => {
  const {
    waf: wafOrPromise,
    onBlock = defaultBlock,
    inspectResponse = false,
    onWAFError = 'block',
  } = opts
  const shouldSkip = opts.skip === false ? () => false : buildSkipPredicate(opts.skip)

  // Resolve the (possibly deferred) WAF once, on plugin register — plugin
  // registration is already async so we can safely `await` here and every
  // subsequent hook sees a settled value.
  const waf: AnyWAF = await wafOrPromise

  fastify.decorateRequest(TX_SYMBOL as unknown as string, null)

  // One fused preHandler — body parser has run, so req.body is populated
  // (or explicitly empty for body-less verbs). Running phases 1+2 together
  // ensures CRS's anomaly evaluator at phase 2 always fires.
  fastify.addHook('preHandler', async (req, reply) => {
    if (reply.sent) return
    if (shouldSkip(pathOf(req.url))) return

    let tx: AnyTx
    try {
      tx = await waf.newTransaction()
    } catch (err) {
      ;(req.log ?? waf.logger).error(
        `coraza: newTransaction failed: ${(err as Error).message}`,
      )
      if (onWAFError === 'block' && !reply.sent) {
        await emitBlock(
          { ruleId: 0, action: 'deny', status: 503, data: 'WAF unavailable', source: 'waf-error' },
          req,
          reply,
          onBlock,
        )
      }
      return
    }
    ;(req as WithTx)[TX_SYMBOL] = tx

    try {
      if (await tx.isRuleEngineOff()) return

      const interrupted = await tx.processRequestBundle(
        {
          method: req.method,
          url: req.url,
          protocol: `HTTP/${req.raw.httpVersion ?? '1.1'}`,
          headers: headersOf(req.headers),
          remoteAddr: req.ip,
          remotePort: req.socket.remotePort ?? 0,
          serverPort: req.socket.localPort ?? 0,
        },
        serializeBody(req.body),
      )
      if (interrupted) {
        const it = await tx.interruption()
        if (it) {
          await emitBlock(it, req, reply, onBlock)
        }
      }
    } catch (err) {
      ;(req.log ?? waf.logger).error(
        `coraza: middleware error: ${(err as Error).message}`,
      )
      if (onWAFError === 'block' && !reply.sent) {
        await emitBlock(
          { ruleId: 0, action: 'deny', status: 503, data: 'WAF internal error', source: 'waf-error' },
          req,
          reply,
          onBlock,
        )
      }
    }
  })

  if (inspectResponse) {
    if (isPoolWAF(waf)) {
      // Fastify's onSend hook runs after the framework has decided the
      // serialised payload + headers; once we await a pool round-trip
      // (processResponse / processResponseBody) the reply's write path
      // can already be mid-flight, so `reply.code(...)` on a block
      // verdict triggers ERR_HTTP_HEADERS_SENT and crashes the whole
      // process. The Express adapter hit the same shape and resolved
      // it by skipping response-phase inspection when the WAF is a
      // pool; we mirror that here so inspectResponse: true is a no-op
      // (not an unsafe partial feature) under pools.
      waf.logger.warn(
        'coraza: inspectResponse=true is a no-op when using WAFPool; use a single WAF or drop response inspection',
      )
    } else {
      fastify.addHook('onSend', async (req, reply, payload) => {
        const tx = (req as WithTx)[TX_SYMBOL]
        if (!tx) return payload
        try {
          const rHdrInterrupted = await tx.processResponse({
            status: reply.statusCode,
            headers: headersOf(
              reply.getHeaders() as Record<string, string | string[]>,
            ),
            protocol: 'HTTP/1.1',
          })
          if (rHdrInterrupted) {
            const it = await tx.interruption()
            if (it) {
              reply.code(it.status || 403)
              return `Request blocked by Coraza (rule ${it.ruleId})\n`
            }
          }
          if (payload != null && (await tx.isResponseBodyProcessable())) {
            const buf = payloadToBytes(payload)
            if (buf && (await tx.processResponseBody(buf))) {
              const it = await tx.interruption()
              if (it) {
                reply.code(it.status || 403)
                return `Request blocked by Coraza (rule ${it.ruleId})\n`
              }
            }
          }
        } catch (err) {
          ;(req.log ?? waf.logger).error(
            `coraza: response inspection failed: ${(err as Error).message}`,
          )
          // Response phase errors don't turn into 503s — the response is
          // already mid-flight and we'd double-write. Log and let it through.
        }
        return payload
      })
    }
  }

  fastify.addHook('onResponse', async (req) => {
    const tx = (req as WithTx)[TX_SYMBOL]
    if (!tx) return
    try {
      await tx.processLogging()
    } finally {
      await tx.close()
    }
  })
}

function isPoolWAF(waf: AnyWAF): boolean {
  // WAFPool.newTransaction is declared `async`, so its constructor name is
  // 'AsyncFunction'; the sync WAF's newTransaction is a plain function.
  // Matches the same sync/async shape test used in @coraza/express.
  return (
    (waf.newTransaction as { constructor: { name: string } }).constructor.name ===
    'AsyncFunction'
  )
}

export const coraza = fp(pluginImpl, {
  fastify: '5.x',
  name: '@coraza/fastify',
})

export default coraza

export function defaultBlock(
  interruption: Interruption,
  _req: FastifyRequest,
  reply: FastifyReply,
): void {
  if (reply.sent) return
  reply
    .code(interruption.status || 403)
    .type('text/plain')
    .send(`Request blocked by Coraza (rule ${interruption.ruleId})\n`)
}

async function emitBlock(
  interruption: Interruption,
  req: FastifyRequest,
  reply: FastifyReply,
  onBlock: NonNullable<CorazaFastifyOptions['onBlock']>,
): Promise<void> {
  ;(req.log ?? (reply.server as { logger?: unknown }).logger as { warn?: (x: string) => void })?.warn?.(
    `coraza: request blocked (rule ${interruption.ruleId} status ${interruption.status})`,
  )
  await onBlock(interruption, req, reply)
}

import { headersOf, serializeBody, payloadToBytes } from './helpers.js'

export type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
