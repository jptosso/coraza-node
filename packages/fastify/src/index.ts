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
// Logging: Fastify ships Pino. We forward to `request.log` (scoped) for
// per-request log lines and fall back to `fastify.log` for init-time.

import fp from 'fastify-plugin'
import type { WAF, Interruption, Transaction, Logger, SkipOptions } from '@coraza/core'
import { buildSkipPredicate, pathOf } from '@coraza/core'
import type { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify'

export interface CorazaFastifyOptions {
  waf: WAF
  onBlock?: (interruption: Interruption, req: FastifyRequest, reply: FastifyReply) => void | Promise<void>
  inspectResponse?: boolean
  /** Bypass Coraza for static/media paths. See `SkipOptions`. */
  skip?: SkipOptions | false
}

const encoder = new TextEncoder()
const TX_SYMBOL = Symbol('coraza.tx')

type WithTx = FastifyRequest & { [TX_SYMBOL]?: Transaction }

const pluginImpl: FastifyPluginAsync<CorazaFastifyOptions> = async (fastify, opts) => {
  const { waf, onBlock = defaultBlock, inspectResponse = false } = opts
  const shouldSkip = opts.skip === false ? () => false : buildSkipPredicate(opts.skip)

  fastify.decorateRequest(TX_SYMBOL as unknown as string, null)

  fastify.addHook('onRequest', async (req, reply) => {
    if (shouldSkip(pathOf(req.url))) return
    const tx = waf.newTransaction()
    ;(req as WithTx)[TX_SYMBOL] = tx

    // Short-circuit if the rule engine is off — no headers, no body, no response.
    if (tx.isRuleEngineOff()) return

    if (tx.processRequest({
      method: req.method,
      url: req.url,
      protocol: `HTTP/${req.raw.httpVersion ?? '1.1'}`,
      headers: headersOf(req.headers),
      remoteAddr: req.ip,
      remotePort: req.socket.remotePort ?? 0,
      serverPort: req.socket.localPort ?? 0,
    })) {
      await doBlock(tx, req, reply, onBlock)
    }
  })

  fastify.addHook('preHandler', async (req, reply) => {
    const tx = (req as WithTx)[TX_SYMBOL]
    if (!tx || reply.sent) return
    if (!tx.isRequestBodyAccessible()) return
    const body = serializeBody(req.body)
    if (body && tx.processRequestBody(body)) {
      await doBlock(tx, req, reply, onBlock)
    }
  })

  if (inspectResponse) {
    fastify.addHook('onSend', async (req, reply, payload) => {
      const tx = (req as WithTx)[TX_SYMBOL]
      if (!tx) return payload
      try {
        if (tx.processResponse({
          status: reply.statusCode,
          headers: headersOf(reply.getHeaders() as Record<string, string | string[]>),
          protocol: 'HTTP/1.1',
        })) {
          const it = tx.interruption()
          if (it) {
            reply.code(it.status || 403)
            return `Request blocked by Coraza (rule ${it.ruleId})\n`
          }
        }
        if (payload != null && tx.isResponseBodyProcessable()) {
          const buf = payloadToBytes(payload)
          if (buf && tx.processResponseBody(buf)) {
            const it = tx.interruption()
            if (it) {
              reply.code(it.status || 403)
              return `Request blocked by Coraza (rule ${it.ruleId})\n`
            }
          }
        }
      } catch (err) {
        (req.log as Logger).error('coraza: response inspection failed', {
          err: (err as Error).message,
        })
      }
      return payload
    })
  }

  fastify.addHook('onResponse', async (req) => {
    const tx = (req as WithTx)[TX_SYMBOL]
    if (!tx) return
    try {
      tx.processLogging()
    } finally {
      tx.close()
    }
  })
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

async function doBlock(
  tx: Transaction,
  req: FastifyRequest,
  reply: FastifyReply,
  onBlock: NonNullable<CorazaFastifyOptions['onBlock']>,
): Promise<void> {
  const it = tx.interruption()
  if (!it) return
  ;(req.log as Logger).warn('coraza: request blocked', {
    ruleId: it.ruleId,
    status: it.status,
    action: it.action,
  })
  await onBlock(it, req, reply)
}

export function* headersOf(
  h: Record<string, string | string[] | number | undefined>,
): Iterable<[string, string]> {
  for (const [k, v] of Object.entries(h)) {
    if (v === undefined) continue
    if (Array.isArray(v)) {
      for (const item of v) yield [k, String(item)]
    } else {
      yield [k, String(v)]
    }
  }
}

export function serializeBody(body: unknown): Uint8Array | undefined {
  if (body === undefined || body === null) return undefined
  if (body instanceof Uint8Array) return body
  if (typeof body === 'string') return encoder.encode(body)
  try {
    return encoder.encode(JSON.stringify(body))
  } catch {
    return undefined
  }
}

export function payloadToBytes(payload: unknown): Uint8Array | undefined {
  if (payload instanceof Uint8Array) return payload
  if (typeof payload === 'string') return encoder.encode(payload)
  if (payload && typeof payload === 'object') {
    try {
      return encoder.encode(JSON.stringify(payload))
    } catch {
      return undefined
    }
  }
  return undefined
}

export type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
