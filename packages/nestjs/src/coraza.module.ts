import { DynamicModule, HttpException, Module, type Provider } from '@nestjs/common'
import {
  createWAF,
  type AnyWAF,
  type WAFLike,
  type WAFConfig,
  type SkipOptions,
  type IgnoreSpec,
  type Interruption,
} from '@coraza/core'
import { CorazaGuard, type CorazaBlockContext } from './coraza.guard.js'
import { CORAZA_OPTIONS, CORAZA_WAF } from './tokens.js'

/**
 * NestJS `CorazaModule.forRoot` options.
 *
 * Two shapes are accepted:
 *
 *   - **Built WAF**: pass `{ waf }` (a `WAF` or `WAFPool` from
 *     `@coraza/core`). Matches the Express / Fastify / Next adapter
 *     shape. Use this for production (almost certainly a `WAFPool`
 *     sized to `os.availableParallelism()`).
 *   - **Inline config**: pass a `WAFConfig` (rules / mode / logger /
 *     wasmSource) and the module constructs a single-threaded `WAF`
 *     internally. Convenient for tests and small services; not
 *     recommended for long-running HTTP servers — see the pool-mode
 *     note in the docs.
 */
export type CorazaNestOptions = CorazaNestCommonOptions &
  (CorazaNestBuiltOptions | WAFConfig)

interface CorazaNestCommonOptions {
  /**
   * When true, register CorazaGuard as APP_GUARD so every route is protected.
   * Default true.
   */
  globalGuard?: boolean
  /** Unified WAF-bypass spec. See README "Skipping the WAF". */
  ignore?: IgnoreSpec | false
  /**
   * @deprecated Use `ignore:` instead. Mapped at construction with a
   * one-shot deprecation warning. Removed at stable 0.1.
   */
  skip?: SkipOptions | false
  /**
   * Build the HttpException thrown on a block decision. Receives the
   * Coraza `Interruption`; defaults to `new HttpException('Request
   * blocked by Coraza (rule <id>)', interruption.status || 403)`.
   *
   * Also fires on WAF failure (with a synthesized 503 Interruption) when
   * `onWAFError: 'block'` — check `interruption.source === 'waf-error'`
   * to distinguish a rule hit from a WAF crash.
   *
   * The optional `ctx.matchedRules` (only populated when `verboseLog: true`)
   * lists every rule that matched in the transaction.
   */
  onBlock?: (interruption: Interruption, ctx?: CorazaBlockContext) => HttpException
  /**
   * What to do if the WAF throws mid-request. Default `'block'` (503).
   * `'allow'` lets the request through; see docs/threat-model.md.
   */
  onWAFError?: 'allow' | 'block'
  /**
   * Emit one `logger.warn` per matched rule on a block (ModSecurity
   * error.log style). Default `false`. The default block log always
   * includes `interruption.data`.
   */
  verboseLog?: boolean
  /**
   * Fires once when WAF construction (createWAF / promise) rejects.
   * The rejection still propagates out of the Nest provider factory
   * so app boot fails loudly; this hook lets you snapshot the error
   * first (healthchecks, external logger, etc.).
   */
  onWAFInit?: (err: Error) => void
}

interface CorazaNestBuiltOptions {
  /**
   * A pre-built `WAF` or `WAFPool`. Mutually exclusive with inline
   * `WAFConfig` fields (rules / mode / etc.) — if `waf` is set, those
   * are ignored.
   */
  waf: WAFLike
}

export interface CorazaNestAsyncOptions {
  useFactory: (...args: unknown[]) => Promise<CorazaNestOptions> | CorazaNestOptions
  inject?: readonly unknown[]
  globalGuard?: boolean
}

function hasBuiltWAF(opts: CorazaNestOptions): opts is CorazaNestCommonOptions & CorazaNestBuiltOptions {
  return 'waf' in opts && (opts as CorazaNestBuiltOptions).waf !== undefined
}

@Module({})
export class CorazaModule {
  static forRoot(opts: CorazaNestOptions): DynamicModule {
    const providers: Provider[] = [
      { provide: CORAZA_OPTIONS, useValue: opts },
      wafProvider(),
      CorazaGuard,
    ]
    if (opts.globalGuard ?? true) {
      providers.push(globalGuardProvider())
    }
    return {
      module: CorazaModule,
      global: true,
      providers,
      exports: [CORAZA_WAF, CorazaGuard],
    }
  }

  static forRootAsync(opts: CorazaNestAsyncOptions): DynamicModule {
    const providers: Provider[] = [
      {
        provide: CORAZA_OPTIONS,
        useFactory: opts.useFactory,
        inject: (opts.inject ?? []) as never[],
      },
      wafProvider(),
      CorazaGuard,
    ]
    if (opts.globalGuard ?? true) {
      providers.push(globalGuardProvider())
    }
    return {
      module: CorazaModule,
      global: true,
      providers,
      exports: [CORAZA_WAF, CorazaGuard],
    }
  }
}

function wafProvider(): Provider {
  return {
    provide: CORAZA_WAF,
    inject: [CORAZA_OPTIONS],
    useFactory: async (opts: CorazaNestOptions): Promise<AnyWAF> => {
      try {
        if (hasBuiltWAF(opts)) return await Promise.resolve(opts.waf)
        return await createWAF(opts as WAFConfig)
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err))
        // Surface the boot error via `onWAFInit` first (so healthcheck /
        // external logger code can capture it) before re-throwing —
        // otherwise the only signal is Nest's generic "DI factory
        // failed" error and the WASM-init stack is buried.
        try {
          opts.onWAFInit?.(e)
        } catch {
          // never let onWAFInit's own throw mask the original cause.
        }
        throw e
      }
    },
  }
}

function globalGuardProvider(): Provider {
  // Lazy-import APP_GUARD to avoid importing @nestjs/core at module top level
  // for consumers that already have it.
  return {
    provide: 'APP_GUARD',
    useExisting: CorazaGuard,
  }
}
