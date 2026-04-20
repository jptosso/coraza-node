export type Mode = 'detect' | 'block'

export interface Logger {
  debug(msg: string, meta?: Record<string, unknown>): void
  info(msg: string, meta?: Record<string, unknown>): void
  warn(msg: string, meta?: Record<string, unknown>): void
  error(msg: string, meta?: Record<string, unknown>): void
}

export interface WAFConfig {
  /** SecLang directives. Typically the output of `recommended()` from `@coraza/coreruleset`. */
  rules: string
  /** 'detect' logs rule matches; 'block' returns a blocking verdict. Default: 'detect'. */
  mode?: Mode
  /** Custom logger. Defaults to `console`. */
  logger?: Logger
  /** Override the WASM binary (useful for tests / pinning a specific build). */
  wasmSource?: ArrayBufferLike | Uint8Array | URL | string
}

export interface RequestInfo {
  method: string
  url: string
  protocol?: string
  headers: Iterable<readonly [string, string]>
  remoteAddr?: string
  remotePort?: number
  serverPort?: number
}

export interface ResponseInfo {
  status: number
  protocol?: string
  headers: Iterable<readonly [string, string]>
}

export interface Interruption {
  ruleId: number
  action: string
  status: number
  data: string
  /**
   * Set to `'waf-error'` on interruptions synthesized by an adapter after
   * the WAF itself failed (bundle-encode crash, pool worker death, WASM
   * trap). Absent on genuine CRS rule hits. Use this to distinguish
   * availability failures from security blocks in your `onBlock` handler
   * and in logs/audits.
   */
  source?: 'waf-error'
}

export interface MatchedRule {
  id: number
  severity: number
  message: string
}
