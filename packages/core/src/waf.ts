import { Abi, utf8 } from './abi.js'
import { instantiate } from './wasm.js'
import { consoleLogger } from './logger.js'
import { Transaction } from './transaction.js'
import type { Logger, Mode, WAFConfig } from './types.js'

/**
 * A compiled WAF. Holds one WASM instance and one Coraza WAF configuration.
 * Create one per app (not per request). Thread-unsafe — if you want
 * concurrency, run multiple WAFs in worker_threads.
 */
export class WAF {
  readonly mode: Mode
  readonly logger: Logger

  #abi: Abi
  #id: number
  #destroyed = false

  private constructor(abi: Abi, id: number, mode: Mode, logger: Logger) {
    this.#abi = abi
    this.#id = id
    this.mode = mode
    this.logger = logger
  }

  static async create(config: WAFConfig): Promise<WAF> {
    const logger = config.logger ?? consoleLogger
    const mode: Mode = config.mode ?? 'detect'
    const source = config.wasmSource ?? defaultWasmPath()
    const abi = await instantiate(source, logger)
    return WAF.fromAbi(abi, config.rules, mode, logger)
  }

  /**
   * Build a WAF on top of an already-instantiated Abi. Exposed for:
   *   - Worker pools that instantiate the WASM once and hand Abi to many WAFs
   *   - Unit tests that inject a mock Abi
   */
  static fromAbi(abi: Abi, rules: string, mode: Mode, logger: Logger): WAF {
    const directives = wrapDirectives(rules, mode)
    const cfgBytes = utf8(directives)
    const ptr = abi.exports.host_malloc(cfgBytes.length)
    if (ptr === 0) throw new Error('coraza: OOM allocating config buffer')
    abi.writeAt(ptr, cfgBytes)
    try {
      const id = abi.exports.waf_create(ptr, cfgBytes.length)
      abi.check(id, 'waf_create')
      return new WAF(abi, id, mode, logger)
    } finally {
      abi.exports.host_free(ptr)
    }
  }

  /** Start a new transaction for an incoming request. Cheap; do one per request. */
  newTransaction(): Transaction {
    if (this.#destroyed) throw new Error('coraza: WAF is destroyed')
    const txId = this.#abi.exports.tx_create(this.#id)
    this.#abi.check(txId, 'tx_create')
    return new Transaction(this.#abi, txId)
  }

  /** Release the WAF. Pending transactions should be closed first. */
  destroy(): void {
    if (this.#destroyed) return
    this.#destroyed = true
    this.#abi.exports.waf_destroy(this.#id)
  }

  get destroyed(): boolean {
    return this.#destroyed
  }
}

/** Convenience factory mirroring the public API. */
export async function createWAF(config: WAFConfig): Promise<WAF> {
  return WAF.create(config)
}

function wrapDirectives(userRules: string, mode: Mode): string {
  // Ensure the engine is on in the chosen mode, regardless of what the
  // user-supplied SecLang says. We append ours last so they win.
  const engineLine = mode === 'block' ? 'SecRuleEngine On' : 'SecRuleEngine DetectionOnly'
  return `${userRules}\n${engineLine}\n`
}

function defaultWasmPath(): URL {
  // The compiled WASM ships alongside the JS bundle at dist/wasm/coraza.wasm.
  return new URL('./wasm/coraza.wasm', import.meta.url)
}

