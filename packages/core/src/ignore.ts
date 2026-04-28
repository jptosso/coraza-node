// Unified WAF-bypass matcher shared by every adapter.
//
// Replaces the older `SkipOptions { extensions, prefixes, patterns, custom }`
// with a single declarative spec covering every common bypass shape: file
// extensions, route globs/regex, HTTP methods, body-size cutoffs, header
// equality, plus an imperative `match` escape hatch.
//
// Verdicts: `false` = inspect, `true` = skip everything, `'skip-body'` =
// inspect URL + headers but no body. The order of restrictiveness when both
// declarative rules and `match` produce a verdict is `false > 'skip-body' >
// true` — most-restrictive wins, fail-closed.

const DEFAULT_EXTENSIONS: ReadonlySet<string> = new Set([
  // images
  'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg', 'ico', 'bmp', 'tiff',
  // stylesheets / scripts / sourcemaps
  'css', 'js', 'mjs', 'map',
  // fonts
  'woff', 'woff2', 'ttf', 'otf', 'eot',
  // media
  'mp4', 'webm', 'ogg', 'mp3', 'wav', 'flac',
  // misc static
  'pdf', 'txt', 'xml', 'wasm',
])

/**
 * Built-in static-mount prefixes. Kept on by default to preserve behavior
 * across upgrades: every framework adapter shipped these defaults under
 * `skip:` and removing them would silently start running the WAF over
 * `/_next/static/*` etc. Disable with `skipDefaults: true`.
 */
const DEFAULT_ROUTES: readonly string[] = [
  '/_next/static/*',
  '/_next/image*',
  '/_next/data/*',
  '/static/*',
  '/public/*',
  '/assets/*',
  '/favicon.ico*',
  '/robots.txt*',
]

/**
 * Read-only exposure of the built-in extension set, kept compatible with the
 * older `DEFAULT_SKIP_EXTENSIONS` export.
 */
export const DEFAULT_IGNORE_EXTENSIONS: ReadonlySet<string> = DEFAULT_EXTENSIONS

export type IgnoreVerdict = boolean | 'skip-body'

export type IgnoreContext = Readonly<{
  method: string
  url: URL
  headers: Readonly<Headers> | ReadonlyMap<string, string>
  contentLength: number | null
}>

export type IgnoreMatcher = (ctx: IgnoreContext) => IgnoreVerdict

export interface IgnoreSpec {
  /**
   * Path-suffix match against `URL.pathname`. A single token (`'css'`)
   * matches `'.css'`. A compound token (`'min.js'`) matches `'.min.js'` but
   * never the literal basename `'min.js'`. Case-insensitive.
   */
  extensions?: string[]

  /**
   * Glob string (`'/static/*'`, `'/api/healthz'`) or `RegExp`. Glob `*`
   * matches one or more path segments; `?` matches a single character.
   * String matches are anchored to the start of the pathname; regex are
   * applied verbatim.
   */
  routes?: Array<string | RegExp>

  /**
   * HTTP methods that bypass the WAF. Compared case-insensitively after
   * uppercasing both sides, so `['options']` works the same as `['OPTIONS']`.
   */
  methods?: string[]

  /**
   * Body-size cutoff. When `Content-Length` exceeds this byte count, the
   * matcher returns `'skip-body'` — URL + headers still inspected, only the
   * body phase is skipped. Non-numeric / missing `Content-Length` is treated
   * as 0 (we cannot exceed the cutoff if we don't know the size).
   */
  bodyLargerThan?: number

  /**
   * Skip when every listed header equals one of the given values (string
   * or `string[]`). Header names are case-insensitive. AND across keys; OR
   * within a single key's value array.
   */
  headerEquals?: Record<string, string | string[]>

  /**
   * Imperative escape hatch — runs LAST, after all declarative rules. Sees a
   * frozen framework-neutral context. May return `false`, `true`, or
   * `'skip-body'`. Sync only by design; async would force every adapter's
   * request loop to await per request. If the function throws, the error
   * is caught by `buildIgnoreMatcher`, logged via the WAF logger when
   * available, and treated as `false` (inspect normally) so a buggy
   * predicate cannot become a bypass.
   */
  match?: (ctx: IgnoreContext) => IgnoreVerdict

  /** Disable the built-in extension list. Default `false`. */
  skipDefaults?: boolean
}

const VERDICT_RANK: Record<string, number> = { 'true': 0, 'skip-body': 1, 'false': 2 }

function key(v: IgnoreVerdict): keyof typeof VERDICT_RANK {
  return v === true ? 'true' : v === false ? 'false' : 'skip-body'
}

/**
 * Combine two verdicts with most-restrictive-wins semantics:
 * `false` (inspect) beats `'skip-body'` beats `true` (full skip).
 */
function mostRestrictive(a: IgnoreVerdict, b: IgnoreVerdict): IgnoreVerdict {
  return VERDICT_RANK[key(a)]! >= VERDICT_RANK[key(b)]! ? a : b
}

/**
 * Compile a route glob string or RegExp into a path predicate. Globs use
 * `*` (zero-or-more characters) and `?` (a single character); everything
 * else is literal. Anchored to start of the path. Patterns without a
 * trailing `*` still match longer paths via `startsWith`-style semantics
 * so the legacy `prefixes` -> `routes + '*'` migration doesn't lose exact
 * matches like `'/favicon.ico'`.
 */
function compileRoute(spec: string | RegExp): (path: string) => boolean {
  if (spec instanceof RegExp) return (p) => spec.test(p)
  // Escape regex metachars except for our two glob ones, then translate.
  let out = '^'
  for (const ch of spec) {
    if (ch === '*') out += '.*'
    else if (ch === '?') out += '.'
    else if ('\\^$.|?*+()[]{}'.includes(ch)) out += '\\' + ch
    else out += ch
  }
  const re = new RegExp(out)
  return (p) => re.test(p)
}

function extensionMatches(pathname: string, extensions: ReadonlySet<string>): boolean {
  // `pathname` always begins with `/`. We match the longest suffix beginning
  // with `.` against the set so compound tokens like `'min.js'` work.
  const slash = pathname.lastIndexOf('/')
  const basename = slash === -1 ? pathname : pathname.slice(slash + 1)
  if (basename.length === 0) return false
  const lower = basename.toLowerCase()
  // Walk from each `.` boundary forward and test the suffix as a candidate.
  // This lets the user write `extensions: ['min.js']` and have it match
  // `app.min.js` via the `.min.js` boundary.
  for (let i = 0; i < lower.length; i++) {
    if (lower[i] === '.' && i + 1 < lower.length) {
      const suffix = lower.slice(i + 1)
      if (extensions.has(suffix)) return true
    }
  }
  return false
}

function headerGet(
  headers: Readonly<Headers> | ReadonlyMap<string, string>,
  name: string,
): string | undefined {
  // Headers#get is case-insensitive; Map#get is not. We can't distinguish
  // them by `typeof headers.get` (Map also has .get). Use the global Headers
  // identity check first; fall through to the case-insensitive iteration
  // path for everything else (Map / userland ReadonlyMap shapes).
  if (typeof Headers !== 'undefined' && headers instanceof Headers) {
    return (headers as Headers).get(name) ?? undefined
  }
  const map = headers as ReadonlyMap<string, string>
  const lower = name.toLowerCase()
  for (const [k, v] of map) {
    if (k.toLowerCase() === lower) return v
  }
  return undefined
}

/**
 * Build a fast per-request matcher from a spec. Compiles regex / globs once;
 * returns a closure the adapter calls per request.
 */
export function buildIgnoreMatcher(spec?: IgnoreSpec): IgnoreMatcher {
  const useDefaults = spec?.skipDefaults !== true

  const extensions = useDefaults
    ? new Set<string>([...DEFAULT_EXTENSIONS, ...(spec?.extensions ?? []).map((e) => e.toLowerCase())])
    : new Set<string>((spec?.extensions ?? []).map((e) => e.toLowerCase()))

  const routeStrings = useDefaults
    ? [...DEFAULT_ROUTES, ...(spec?.routes ?? [])]
    : (spec?.routes ?? [])
  const routes = routeStrings.map(compileRoute)

  const methods = new Set<string>((spec?.methods ?? []).map((m) => m.toUpperCase()))

  const bodyLargerThan = spec?.bodyLargerThan
  const hasBodyCutoff = typeof bodyLargerThan === 'number' && bodyLargerThan >= 0

  const headerEqualsEntries: Array<[string, Set<string>]> = []
  if (spec?.headerEquals) {
    for (const [name, val] of Object.entries(spec.headerEquals)) {
      const allowed = Array.isArray(val) ? new Set(val) : new Set([val])
      headerEqualsEntries.push([name.toLowerCase(), allowed])
    }
  }

  const match = spec?.match

  return function matcher(ctx: IgnoreContext): IgnoreVerdict {
    // `null` = no declarative rule matched yet. We can't use `false` as the
    // sentinel because `false` is also the most-restrictive verdict, which
    // would incorrectly poison `match`-only configs (per the brief: "If no
    // declarative rule matched, match runs. Whatever it returns is the
    // verdict.").
    let declarative: IgnoreVerdict | null = null

    if (methods.size > 0 && methods.has(ctx.method.toUpperCase())) {
      declarative = true
    } else if (extensions.size > 0 && extensionMatches(ctx.url.pathname, extensions)) {
      declarative = true
    } else if (routes.length > 0) {
      for (const r of routes) {
        if (r(ctx.url.pathname)) {
          declarative = true
          break
        }
      }
    }

    if (declarative !== true && hasBodyCutoff && ctx.contentLength !== null && ctx.contentLength > bodyLargerThan!) {
      declarative = 'skip-body'
    }

    if (declarative !== true && headerEqualsEntries.length > 0) {
      let allMatch = true
      for (const [name, allowed] of headerEqualsEntries) {
        const v = headerGet(ctx.headers, name)
        if (v === undefined || !allowed.has(v)) {
          allMatch = false
          break
        }
      }
      if (allMatch) declarative = true
    }

    if (!match) return declarative ?? false

    let imperative: IgnoreVerdict
    try {
      imperative = match(ctx)
    } catch {
      // Fail-closed: a buggy predicate must not become a bypass.
      return false
    }
    if (declarative === null) return imperative
    return mostRestrictive(declarative, imperative)
  }
}
