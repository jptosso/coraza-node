// V8 RegExp-as-host-regex for the coraza-node WASM.
//
// CRS patterns use PCRE syntax with inline flags like `(?sm)` at the
// start. JavaScript RegExp doesn't accept `(?flags)` prefix literals (the
// `(?flags:subpattern)` *scoped* form is ES2018+, but the non-scoped one
// isn't valid JS). We parse the leading flag block ourselves and feed
// the pattern plus equivalent JS flags to `new RegExp()`.
//
// PCRE flag → JS flag mapping:
//   s  →  s   (dotall: `.` matches newline)
//   m  →  m   (multiline: `^` and `$` match at line boundaries)
//   i  →  i   (case-insensitive)
//   u  →  u   (unicode)
//   x  →  *no JS equivalent* — pattern is rejected, WASM falls back to Go
//
// CRS rules also lean on backreferences, atomic groups, and possessive
// quantifiers that JS doesn't support. We surface those as compile errors
// (return 0) and the Go side falls back transparently.

const INLINE_FLAG_RE = /^\(\?([a-z]+)\)/

export interface HostRegex {
  compile(pattern: string): number
  match(handle: number, input: string): boolean
  free(handle: number): void
  /** Number of patterns currently compiled in the host. Debug metric. */
  size(): number
  /** Number of patterns the host rejected (fell back to Go). Debug metric. */
  rejected(): number
}

export function createHostRegex(): HostRegex {
  const patterns = new Map<number, RegExp>()
  let nextHandle = 1
  let rejectedCount = 0

  function compile(raw: string): number {
    const { source, flags, ok } = translatePattern(raw)
    if (!ok) {
      rejectedCount++
      return 0
    }
    try {
      const re = new RegExp(source, flags)
      const h = nextHandle++
      patterns.set(h, re)
      return h
    } catch {
      // Unsupported PCRE feature (atomic groups, possessive quantifiers,
      // recursive patterns, some lookbehinds) → fall back to Go.
      rejectedCount++
      return 0
    }
  }

  function match(handle: number, input: string): boolean {
    const re = patterns.get(handle)
    if (!re) return false
    // Avoid stateful match bugs: `g`/`y` flags keep lastIndex. We never
    // emit those, but guard anyway.
    re.lastIndex = 0
    return re.test(input)
  }

  function free(handle: number): void {
    patterns.delete(handle)
  }

  return {
    compile,
    match,
    free,
    size: () => patterns.size,
    rejected: () => rejectedCount,
  }
}

/**
 * Translate a PCRE-style SecLang pattern to a JS-compatible one.
 * Handles the common inline flag prefix `(?flags)` that CRS emits via
 * our `(?sm)` wrapper.
 */
export function translatePattern(raw: string): { source: string; flags: string; ok: boolean } {
  let source = raw
  let jsFlags = ''
  const m = INLINE_FLAG_RE.exec(source)
  if (m) {
    const pcreFlags = m[1]!
    for (const f of pcreFlags) {
      switch (f) {
        case 's':
        case 'm':
        case 'i':
        case 'u':
          if (!jsFlags.includes(f)) jsFlags += f
          break
        case 'x':
          // `x` means "ignore whitespace and comments in pattern" — no JS
          // equivalent; we'd have to pre-strip the pattern, and the cost
          // of getting that right on CRS patterns (which do use `x` in a
          // few places) isn't worth it for v1.
          return { source: '', flags: '', ok: false }
        default:
          return { source: '', flags: '', ok: false }
      }
    }
    source = source.slice(m[0].length)
  }
  return { source, flags: jsFlags, ok: true }
}
