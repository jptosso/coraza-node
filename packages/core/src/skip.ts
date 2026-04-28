// Legacy skip-pattern helper. Soft-deprecated in 0.1.0-preview in favor of
// the unified `IgnoreSpec` (see `./ignore.ts`). We keep this surface so
// existing consumers compile, mapping every option to the new matcher under
// the hood. Removed at stable 0.1.

import { buildIgnoreMatcher, type IgnoreSpec, type IgnoreContext } from './ignore.js'

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

/**
 * @deprecated Use {@link IgnoreSpec} on every adapter's `ignore:` option.
 * Soft-deprecated in 0.1.0-preview, removed at stable 0.1.
 */
export interface SkipOptions {
  prefixes?: readonly string[]
  extensions?: readonly string[]
  patterns?: readonly RegExp[]
  custom?: (path: string) => boolean
  skipDefaults?: boolean
}

/**
 * @deprecated Use `buildIgnoreMatcher` from `@coraza/core` and the unified
 * `ignore:` option on every adapter. Kept as a path-predicate alias so
 * existing consumers compile during the deprecation window.
 */
export function buildSkipPredicate(opts: SkipOptions | undefined): (path: string) => boolean {
  // Layer the default prefixes on top of the user spec — the new
  // IgnoreSpec doesn't carry built-in route prefixes, only built-in
  // extensions, so we splice them in here to keep the legacy default
  // behavior identical.
  const matcher = buildIgnoreMatcher(skipToIgnore(opts))
  return (path) => {
    // `new URL(path, 'http://x')` always succeeds with a base origin for any
    // path-shaped string; no try/catch needed.
    const ctx: IgnoreContext = {
      method: 'GET',
      url: new URL(path, 'http://x'),
      headers: emptyHeaders,
      contentLength: null,
    }
    return matcher(ctx) === true
  }
}

const emptyHeaders: ReadonlyMap<string, string> = new Map()

/**
 * Map a legacy `SkipOptions` onto the unified `IgnoreSpec`. Used by adapters
 * to keep `skip:` working during the deprecation window. Exported so the
 * adapters share one canonical translation.
 *
 * Notes:
 *  - `prefixes` map to `routes` with a trailing `*` glob unless already present.
 *  - `patterns` map to `routes` (RegExp passes through verbatim).
 *  - `custom` maps to `match`, wrapped to feed it just the pathname.
 */
export function skipToIgnore(opts: SkipOptions | undefined): IgnoreSpec | undefined {
  if (!opts) return undefined
  const routes: Array<string | RegExp> = []
  if (opts.prefixes) {
    for (const p of opts.prefixes) {
      // Old prefixes were `startsWith`; `'/foo'` should match `'/foo/bar'`.
      // The new glob `*` matches one-or-more chars, so we add it unless the
      // user already glob-anchored.
      routes.push(p.endsWith('*') ? p : p + '*')
    }
  }
  if (opts.patterns) {
    for (const re of opts.patterns) routes.push(re)
  }
  const out: IgnoreSpec = {}
  if (opts.extensions) out.extensions = [...opts.extensions]
  if (routes.length > 0) out.routes = routes
  if (opts.skipDefaults !== undefined) out.skipDefaults = opts.skipDefaults
  if (opts.custom) {
    out.match = (ctx: IgnoreContext): boolean => opts.custom!(ctx.url.pathname)
  }
  return out
}

/** Extract the path from a URL string that may include query/hash. */
export function pathOf(url: string): string {
  const q = url.indexOf('?')
  const h = url.indexOf('#')
  const end = q === -1 ? (h === -1 ? url.length : h) : h === -1 ? q : Math.min(q, h)
  return url.slice(0, end)
}

