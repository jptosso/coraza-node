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
   *
   * Matched case-sensitively as a simple `startsWith` against the URL path
   * (no query string, no fragment).
   */
  prefixes?: readonly string[]
  /**
   * Additional file extensions to bypass. Merged with
   * {@link DEFAULT_SKIP_EXTENSIONS} unless {@link skipDefaults} is `false`.
   *
   * Match semantics (see {@link buildSkipPredicate} for the full contract):
   *
   * - Match runs against the URL path only — query string and fragment are
   *   ignored. Pass paths via {@link pathOf} if your adapter hands you a
   *   full URL.
   * - Case-insensitive: list entries and the candidate path are both
   *   lowercased at match time. List entries are normalized once at
   *   build time, so `'PNG'` and `'png'` are equivalent.
   * - **Single-token entries** (no internal dot, e.g. `'css'`, `'png'`)
   *   match only the trailing `.foo` segment of the path's basename.
   *   `/static/foo.css/bar` does NOT match `'css'` because the last `.`
   *   is followed by a `/`.
   * - **Compound entries** (containing a dot, e.g. `'tar.gz'`, `'min.js'`)
   *   match as a `.<ext>` suffix on the path's basename. So `'tar.gz'`
   *   matches `/archive.tar.gz` but NOT a basename literally named
   *   `tar.gz` (no leading dot — that's the bare filename, not an
   *   extension), and not `/archive.tar.gz/extra` (the `/` after the
   *   match disqualifies it).
   * - Do NOT include a leading dot in entries: write `'png'`, not `'.png'`.
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
 *
 * The returned predicate runs four checks in order; the first hit wins:
 *
 * 1. Prefix match (`startsWith`) against {@link SkipOptions.prefixes}
 *    plus the defaults. Case-sensitive.
 * 2. Extension match against {@link SkipOptions.extensions} plus the
 *    defaults. See below.
 * 3. `RegExp.test` against each entry in {@link SkipOptions.patterns}.
 * 4. {@link SkipOptions.custom} if provided.
 *
 * ## Extension match contract
 *
 * The input is treated as a URL **path** — pre-strip query/fragment with
 * {@link pathOf} if the adapter hands you a full URL. The extension list
 * is normalized to lowercase once at build time.
 *
 * - **Single-token entries** (`'css'`, `'png'`, `'wasm'`): match the
 *   substring after the last `.` in the path, but only when no `/`
 *   appears between that `.` and the end of the string. So `/foo.css`
 *   matches but `/static/foo.css/bar` does not (the dot lives in a
 *   directory segment).
 * - **Compound entries** (`'tar.gz'`, `'min.js'`, `'d.ts'`): match
 *   `.<ext>` as a suffix on the path's basename (the part after the
 *   last `/`). The leading `.` is required, which is the boundary that
 *   makes a `'min.js'` entry skip `/bundle.min.js` while NOT skipping
 *   a request for a literal file named `min.js` (path `/min.js` —
 *   that's the bare filename, not a `.min.js` extension).
 *
 * Examples (assuming `extensions: ['css', 'tar.gz', 'min.js']`):
 *
 * | Path                       | Skip? | Why |
 * |----------------------------|-------|-----|
 * | `/foo.css`                 | yes   | trailing `.css` |
 * | `/Foo.CSS`                 | yes   | case-insensitive |
 * | `/static/foo.css/bar`      | no    | `/` after the `.` disqualifies |
 * | `/api/upload?name=evil.css`| no    | only the path is checked; pass via {@link pathOf} |
 * | `/archive.tar.gz`          | yes   | compound suffix `.tar.gz` |
 * | `/archive.tar.gz/extra`    | no    | `/` after the suffix disqualifies |
 * | `/bundle.min.js`           | yes   | compound suffix `.min.js` |
 * | `/bundle.js`               | no    | not `.min.js` |
 * | `/min.js`                  | no    | bare basename `min.js` has no leading `.min.js` |
 */
export function buildSkipPredicate(opts: SkipOptions | undefined): (path: string) => boolean {
  if (!opts) {
    const prefixes = DEFAULT_SKIP_PREFIXES
    const single = DEFAULT_SKIP_EXTENSIONS
    return (path) => matchesPrefix(path, prefixes) || matchesExtension(path, single, EMPTY_COMPOUND)
  }

  const useDefaults = opts.skipDefaults !== true
  const prefixes = useDefaults
    ? [...DEFAULT_SKIP_PREFIXES, ...(opts.prefixes ?? [])]
    : [...(opts.prefixes ?? [])]
  const merged = useDefaults
    ? [...DEFAULT_SKIP_EXTENSIONS, ...(opts.extensions ?? [])]
    : [...(opts.extensions ?? [])]
  const { single, compound } = partitionExtensions(merged)
  const patterns = opts.patterns ?? []
  const custom = opts.custom

  return (path) => {
    if (prefixes.length > 0 && matchesPrefix(path, prefixes)) return true
    if ((single.size > 0 || compound.length > 0) && matchesExtension(path, single, compound)) return true
    for (const p of patterns) {
      if (p.test(path)) return true
    }
    if (custom && custom(path)) return true
    return false
  }
}

const EMPTY_COMPOUND: readonly string[] = []

function partitionExtensions(list: readonly string[]): {
  single: ReadonlySet<string>
  compound: readonly string[]
} {
  const single = new Set<string>()
  const compound: string[] = []
  for (const raw of list) {
    const ext = raw.toLowerCase()
    if (ext.length === 0) continue
    if (ext.includes('.')) compound.push(ext)
    else single.add(ext)
  }
  return { single, compound }
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

function matchesExtension(
  path: string,
  single: ReadonlySet<string>,
  compound: readonly string[],
): boolean {
  const dot = path.lastIndexOf('.')
  if (dot === -1 || dot === path.length - 1) return false
  // Don't match if the dot is in a directory (before the last /).
  const slash = path.lastIndexOf('/')
  if (dot < slash) return false
  const lower = path.toLowerCase()
  if (single.size > 0 && single.has(lower.slice(dot + 1))) return true
  if (compound.length > 0) {
    // Compound entries match a `.ext.subext` suffix on the basename. The
    // leading dot is required so a request for a literal file named
    // `min.js` (path `/min.js`) does NOT match `extensions: ['min.js']`.
    const basenameStart = slash + 1
    for (const ext of compound) {
      // Need at least one character before `.<ext>` for the leading dot
      // boundary to exist within the basename. This is what excludes a
      // bare basename like `min.js` from matching `'min.js'`.
      if (lower.length - basenameStart <= ext.length) continue
      if (lower.endsWith('.' + ext)) return true
    }
  }
  return false
}
