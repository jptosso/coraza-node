// URL skip-pattern helper shared by all framework adapters.
//
// Rationale: serving a 2 MB PNG through the WAF buys nothing — static media
// isn't user input and the request path is just a GET. We want a single
// authoritative bypass so every adapter behaves the same way.

/**
 * Extensions that are bypassed by default. Covers typical CDN-style static
 * assets: images, stylesheets, client-side scripts, fonts, source maps,
 * HTML5 media.
 */
export const DEFAULT_SKIP_EXTENSIONS: ReadonlySet<string> = new Set([
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
 * Prefix paths that are bypassed by default. These correspond to the
 * conventional static-asset mountpoints shipped by popular frameworks and
 * bundlers. Matched case-sensitively as a simple `startsWith`.
 */
export const DEFAULT_SKIP_PREFIXES: readonly string[] = [
  '/_next/static/',    // Next.js built assets
  '/_next/image',      // Next.js image optimizer
  '/_next/data/',      // Next.js ISR/data routes
  '/static/',          // Express / Fastify /static mount, CRA legacy
  '/public/',          // common public dir
  '/assets/',          // Vite, NestJS-Vite
  '/favicon.ico',      // everyone
  '/robots.txt',       // everyone
]

export interface SkipOptions {
  /**
   * Additional URL-path prefixes to bypass. Merged with
   * {@link DEFAULT_SKIP_PREFIXES} unless {@link skipDefaults} is `false`.
   */
  prefixes?: readonly string[]
  /**
   * Additional file extensions (without leading dot) to bypass. Merged with
   * {@link DEFAULT_SKIP_EXTENSIONS} unless {@link skipDefaults} is `false`.
   */
  extensions?: readonly string[]
  /**
   * Regexes to test against the URL path. A single match bypasses Coraza.
   * Evaluated after prefix/extension checks.
   */
  patterns?: readonly RegExp[]
  /**
   * Custom predicate. Receives the request path (and optionally the full URL
   * or method via the adapter). Returning `true` bypasses Coraza.
   */
  custom?: (path: string) => boolean
  /**
   * Disable the default prefix/extension lists entirely. Default: `false`.
   */
  skipDefaults?: boolean
}

/**
 * Build a single-path predicate that is cheap to call per request.
 * Compiled once; adapter middleware invokes it without re-parsing options.
 */
export function buildSkipPredicate(opts: SkipOptions | undefined): (path: string) => boolean {
  if (!opts) {
    const prefixes = DEFAULT_SKIP_PREFIXES
    const extensions = DEFAULT_SKIP_EXTENSIONS
    return (path) => matchesPrefix(path, prefixes) || matchesExtension(path, extensions)
  }

  const useDefaults = opts.skipDefaults !== true
  const prefixes = useDefaults
    ? [...DEFAULT_SKIP_PREFIXES, ...(opts.prefixes ?? [])]
    : [...(opts.prefixes ?? [])]
  const extensions = useDefaults
    ? new Set<string>([...DEFAULT_SKIP_EXTENSIONS, ...(opts.extensions ?? [])])
    : new Set<string>(opts.extensions ?? [])
  const patterns = opts.patterns ?? []
  const custom = opts.custom

  return (path) => {
    if (prefixes.length > 0 && matchesPrefix(path, prefixes)) return true
    if (extensions.size > 0 && matchesExtension(path, extensions)) return true
    for (const p of patterns) {
      if (p.test(path)) return true
    }
    if (custom && custom(path)) return true
    return false
  }
}

/** Extract the path from a URL string that may include query/hash. */
export function pathOf(url: string): string {
  const q = url.indexOf('?')
  const h = url.indexOf('#')
  const end = q === -1 ? (h === -1 ? url.length : h) : h === -1 ? q : Math.min(q, h)
  return url.slice(0, end)
}

function matchesPrefix(path: string, prefixes: readonly string[]): boolean {
  for (const p of prefixes) {
    if (path === p || path.startsWith(p)) return true
  }
  return false
}

function matchesExtension(path: string, extensions: ReadonlySet<string>): boolean {
  const dot = path.lastIndexOf('.')
  if (dot === -1 || dot === path.length - 1) return false
  // Don't match if the dot is in a directory (before the last /).
  const slash = path.lastIndexOf('/')
  if (dot < slash) return false
  const ext = path.slice(dot + 1).toLowerCase()
  return extensions.has(ext)
}
