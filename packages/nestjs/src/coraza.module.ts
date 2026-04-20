import { DynamicModule, HttpException, Module, type Provider } from '@nestjs/common'
import { createWAF, type WAF, type WAFConfig, type SkipOptions, type Interruption } from '@coraza/core'
import { CorazaGuard } from './coraza.guard.js'
import { CORAZA_OPTIONS, CORAZA_WAF } from './tokens.js'

export interface CorazaNestOptions extends WAFConfig {
  /**
   * When true, register CorazaGuard as APP_GUARD so every route is protected.
   * Default true.
   */
  globalGuard?: boolean
  /** Bypass Coraza for static/media paths. See `SkipOptions`. */
  skip?: SkipOptions | false
  /**
   * Build the HttpException thrown on a block decision. Receives the
   * Coraza `Interruption`; defaults to `new HttpException('Request
   * blocked by Coraza (rule <id>)', interruption.status || 403)`.
   *
   * Also fires on WAF failure (with a synthesized 503 Interruption) when
   * `onWAFError: 'block'` — check `interruption.source === 'waf-error'`
   * to distinguish a rule hit from a WAF crash.
   */
  onBlock?: (interruption: Interruption) => HttpException
  /**
   * What to do if the WAF throws mid-request. Default `'block'` (503).
   * `'allow'` lets the request through; see docs/security.md.
   */
  onWAFError?: 'allow' | 'block'
}

export interface CorazaNestAsyncOptions {
  useFactory: (...args: unknown[]) => Promise<CorazaNestOptions> | CorazaNestOptions
  inject?: readonly unknown[]
  globalGuard?: boolean
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
    useFactory: async (opts: CorazaNestOptions): Promise<WAF> => createWAF(opts),
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
