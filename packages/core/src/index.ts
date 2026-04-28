export { createWAF, WAF } from './waf.js'
export { createWAFPool, WAFPool, WorkerTransaction, type WAFPoolOptions } from './pool.js'
export { Transaction } from './transaction.js'
export { consoleLogger, silentLogger } from './logger.js'

import type { WAF } from './waf.js'
import type { WAFPool } from './pool.js'

/**
 * A built WAF — either the single-instance `WAF` (sync, in-process)
 * or a `WAFPool` (async, worker_threads). Adapters accept either; use
 * this alias in consumer code so you can flip between the two without
 * re-threading the type.
 */
export type AnyWAF = WAF | WAFPool

/**
 * Shape every adapter accepts for the `waf` option. Accepting a Promise
 * lets middleware modules that can't do top-level await (e.g. Next's
 * CJS-transpiled middleware.ts) defer construction and still hand the
 * adapter a lazy handle.
 */
export type WAFLike = AnyWAF | Promise<AnyWAF>
export {
  buildSkipPredicate,
  pathOf,
  skipToIgnore,
  DEFAULT_SKIP_EXTENSIONS,
  DEFAULT_SKIP_PREFIXES,
  type SkipOptions,
} from './skip.js'
export {
  buildIgnoreMatcher,
  DEFAULT_IGNORE_EXTENSIONS,
  type IgnoreSpec,
  type IgnoreContext,
  type IgnoreVerdict,
  type IgnoreMatcher,
} from './ignore.js'
export type {
  Logger,
  Mode,
  WAFConfig,
  RequestInfo,
  ResponseInfo,
  Interruption,
  MatchedRule,
} from './types.js'
