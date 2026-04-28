import { describe, it, expect, vi } from 'vitest'
import { buildIgnoreMatcher, type IgnoreContext } from '../src/ignore.js'
import { buildSkipPredicate, skipToIgnore } from '../src/skip.js'

function ctx(
  url: string,
  init: Partial<{ method: string; headers: Record<string, string>; contentLength: number | null }> = {},
): IgnoreContext {
  const u = new URL(url, 'http://x')
  const headers = new Headers(init.headers ?? {})
  return Object.freeze({
    method: init.method ?? 'GET',
    url: u,
    headers,
    contentLength: init.contentLength ?? null,
  })
}

describe('buildIgnoreMatcher — defaults', () => {
  const matcher = buildIgnoreMatcher(undefined)

  it('skips common static extensions', () => {
    expect(matcher(ctx('/img/logo.png'))).toBe(true)
    expect(matcher(ctx('/main.css'))).toBe(true)
    expect(matcher(ctx('/app.js'))).toBe(true)
  })

  it('is case-insensitive for extensions', () => {
    expect(matcher(ctx('/foo.PNG'))).toBe(true)
    expect(matcher(ctx('/foo.JPG'))).toBe(true)
  })

  it('does not skip dynamic paths without an extension', () => {
    expect(matcher(ctx('/api/login'))).toBe(false)
    expect(matcher(ctx('/echo'))).toBe(false)
    expect(matcher(ctx('/'))).toBe(false)
  })

  it('does not match a dot inside a directory name', () => {
    expect(matcher(ctx('/config.d/app'))).toBe(false)
    expect(matcher(ctx('/v1.2/api'))).toBe(false)
  })

  it('does not match an empty extension', () => {
    expect(matcher(ctx('/foo.'))).toBe(false)
  })
})

describe('buildIgnoreMatcher — extensions', () => {
  it('merges user extensions with defaults', () => {
    const m = buildIgnoreMatcher({ extensions: ['log'] })
    expect(m(ctx('/debug.log'))).toBe(true)
    expect(m(ctx('/img.png'))).toBe(true)
  })

  it('honors compound extensions like min.js', () => {
    const m = buildIgnoreMatcher({ extensions: ['min.js'], skipDefaults: true })
    expect(m(ctx('/app.min.js'))).toBe(true)
    expect(m(ctx('/app.js'))).toBe(false) // not in custom list, defaults off
  })

  it('compound extension does not match a literal basename', () => {
    // /min.js → basename "min.js" → only boundary at i=3 yields suffix "js"
    // which is not in the custom set (defaults off), so no match.
    const m = buildIgnoreMatcher({ extensions: ['min.js'], skipDefaults: true })
    expect(m(ctx('/min.js'))).toBe(false)
  })

  it('skipDefaults: true drops the built-in list', () => {
    const m = buildIgnoreMatcher({ skipDefaults: true })
    expect(m(ctx('/foo.png'))).toBe(false)
  })
})

describe('buildIgnoreMatcher — routes', () => {
  it('matches a glob route', () => {
    const m = buildIgnoreMatcher({ routes: ['/static/*'], skipDefaults: true })
    expect(m(ctx('/static/foo.css'))).toBe(true)
    expect(m(ctx('/api/foo'))).toBe(false)
  })

  it('matches an exact-style route via zero-or-more glob', () => {
    const m = buildIgnoreMatcher({ routes: ['/api/healthz'], skipDefaults: true })
    expect(m(ctx('/api/healthz'))).toBe(true)
    expect(m(ctx('/api'))).toBe(false)
  })

  it('matches a RegExp route', () => {
    const m = buildIgnoreMatcher({ routes: [/^\/internal\//], skipDefaults: true })
    expect(m(ctx('/internal/foo'))).toBe(true)
    expect(m(ctx('/external'))).toBe(false)
  })

  it('? matches a single character', () => {
    const m = buildIgnoreMatcher({ routes: ['/a?b'], skipDefaults: true })
    expect(m(ctx('/axb'))).toBe(true)
    expect(m(ctx('/ab'))).toBe(false)
  })
})

describe('buildIgnoreMatcher — methods', () => {
  it('skips configured methods', () => {
    const m = buildIgnoreMatcher({ methods: ['OPTIONS', 'HEAD'], skipDefaults: true })
    expect(m(ctx('/api', { method: 'OPTIONS' }))).toBe(true)
    expect(m(ctx('/api', { method: 'HEAD' }))).toBe(true)
    expect(m(ctx('/api', { method: 'GET' }))).toBe(false)
  })

  it('uppercases user input for comparison', () => {
    const m = buildIgnoreMatcher({ methods: ['options'], skipDefaults: true })
    expect(m(ctx('/api', { method: 'OPTIONS' }))).toBe(true)
  })
})

describe('buildIgnoreMatcher — bodyLargerThan', () => {
  it('returns skip-body when content-length exceeds the cutoff', () => {
    const m = buildIgnoreMatcher({ bodyLargerThan: 1000, skipDefaults: true })
    expect(m(ctx('/upload', { contentLength: 5000 }))).toBe('skip-body')
  })

  it('returns false when content-length is at or below the cutoff', () => {
    const m = buildIgnoreMatcher({ bodyLargerThan: 1000, skipDefaults: true })
    expect(m(ctx('/upload', { contentLength: 500 }))).toBe(false)
    expect(m(ctx('/upload', { contentLength: 1000 }))).toBe(false)
  })

  it('returns false when content-length is unknown', () => {
    const m = buildIgnoreMatcher({ bodyLargerThan: 1000, skipDefaults: true })
    expect(m(ctx('/upload'))).toBe(false)
  })

  it('full skip wins over skip-body when a method also matches', () => {
    const m = buildIgnoreMatcher({
      methods: ['OPTIONS'],
      bodyLargerThan: 1000,
      skipDefaults: true,
    })
    expect(m(ctx('/upload', { method: 'OPTIONS', contentLength: 5000 }))).toBe(true)
  })
})

describe('buildIgnoreMatcher — headerEquals', () => {
  it('matches when every key equals one of the values', () => {
    const m = buildIgnoreMatcher({
      headerEquals: { 'x-internal': 'true', 'x-env': ['stage', 'dev'] },
      skipDefaults: true,
    })
    expect(
      m(ctx('/api', { headers: { 'x-internal': 'true', 'x-env': 'dev' } })),
    ).toBe(true)
    expect(
      m(ctx('/api', { headers: { 'x-internal': 'true', 'x-env': 'prod' } })),
    ).toBe(false)
    expect(m(ctx('/api', { headers: { 'x-internal': 'true' } }))).toBe(false)
  })

  it('header name match is case-insensitive', () => {
    const m = buildIgnoreMatcher({
      headerEquals: { 'X-Internal': 'yes' },
      skipDefaults: true,
    })
    expect(m(ctx('/api', { headers: { 'x-internal': 'yes' } }))).toBe(true)
  })

  it('handles a ReadonlyMap headers shape (Node IncomingMessage style)', () => {
    const m = buildIgnoreMatcher({
      headerEquals: { 'x-internal': 'yes' },
      skipDefaults: true,
    })
    const verdict = m({
      method: 'GET',
      url: new URL('http://x/api'),
      headers: new Map([['x-internal', 'yes']]),
      contentLength: null,
    })
    expect(verdict).toBe(true)
  })

  it('Map header lookup is case-insensitive across mismatched keys', () => {
    const m = buildIgnoreMatcher({
      headerEquals: { 'x-internal': 'yes' },
      skipDefaults: true,
    })
    // Map has uppercase key, header spec has lowercase — must still match.
    const verdict = m({
      method: 'GET',
      url: new URL('http://x/api'),
      headers: new Map([['X-Internal', 'yes']]),
      contentLength: null,
    })
    expect(verdict).toBe(true)
  })

  it('Map lookup returns false when no key matches', () => {
    const m = buildIgnoreMatcher({
      headerEquals: { 'x-internal': 'yes' },
      skipDefaults: true,
    })
    const verdict = m({
      method: 'GET',
      url: new URL('http://x/api'),
      headers: new Map([['x-other', 'yes']]),
      contentLength: null,
    })
    expect(verdict).toBe(false)
  })
})

describe('buildIgnoreMatcher — match (imperative escape hatch)', () => {
  it('runs after declarative rules and returns its verdict when none matched', () => {
    const match = vi.fn(() => true as const)
    const m = buildIgnoreMatcher({ match, skipDefaults: true })
    expect(m(ctx('/dynamic'))).toBe(true)
    expect(match).toHaveBeenCalledOnce()
  })

  it('most-restrictive wins when both produced a verdict (false beats true)', () => {
    const m = buildIgnoreMatcher({
      methods: ['OPTIONS'], // declarative -> true
      match: () => false, // imperative -> false (inspect)
      skipDefaults: true,
    })
    expect(m(ctx('/api', { method: 'OPTIONS' }))).toBe(false)
  })

  it("most-restrictive: 'skip-body' beats true", () => {
    const m = buildIgnoreMatcher({
      methods: ['OPTIONS'],
      match: () => 'skip-body' as const,
      skipDefaults: true,
    })
    expect(m(ctx('/api', { method: 'OPTIONS' }))).toBe('skip-body')
  })

  it('errors in match are caught and treated as false (fail-closed)', () => {
    const m = buildIgnoreMatcher({
      methods: ['OPTIONS'],
      match: () => {
        throw new Error('user predicate boom')
      },
      skipDefaults: true,
    })
    expect(m(ctx('/api', { method: 'OPTIONS' }))).toBe(false)
  })

  it('match alone with no declarative spec: error path returns false', () => {
    const m = buildIgnoreMatcher({
      match: () => {
        throw new Error('bad')
      },
      skipDefaults: true,
    })
    expect(m(ctx('/x'))).toBe(false)
  })
})

describe('buildIgnoreMatcher — combined declarative rules', () => {
  it('extension wins before route', () => {
    const m = buildIgnoreMatcher({
      extensions: ['css'],
      routes: ['/api/*'],
      skipDefaults: true,
    })
    expect(m(ctx('/api/style.css'))).toBe(true) // ext fires first
    expect(m(ctx('/api/users'))).toBe(true) // route fires
    expect(m(ctx('/foo'))).toBe(false)
  })

  it('headerEquals does not fire when route already matched', () => {
    const m = buildIgnoreMatcher({
      routes: ['/api/healthz'],
      headerEquals: { 'x-bad': 'yes' },
      skipDefaults: true,
    })
    expect(m(ctx('/api/healthz'))).toBe(true)
  })
})

describe('skipToIgnore (legacy mapping)', () => {
  it('maps prefixes to routes with a trailing *', () => {
    const spec = skipToIgnore({ prefixes: ['/healthz'] })
    expect(spec?.routes).toEqual(['/healthz*'])
  })

  it('preserves a trailing * if the user already provided it', () => {
    const spec = skipToIgnore({ prefixes: ['/api/*'] })
    expect(spec?.routes).toEqual(['/api/*'])
  })

  it('forwards patterns into routes', () => {
    const re = /^\/regex/
    const spec = skipToIgnore({ patterns: [re] })
    expect(spec?.routes).toEqual([re])
  })

  it('translates custom into match', () => {
    const spec = skipToIgnore({ custom: (p) => p === '/x' })
    expect(spec?.match).toBeTypeOf('function')
  })

  it('returns undefined for undefined input', () => {
    expect(skipToIgnore(undefined)).toBeUndefined()
  })
})

describe('buildSkipPredicate (deprecated alias)', () => {
  it('still bypasses defaults', () => {
    const skip = buildSkipPredicate(undefined)
    expect(skip('/img/a.png')).toBe(true)
    expect(skip('/api/login')).toBe(false)
  })

  it('honors a custom predicate via the new match path', () => {
    const skip = buildSkipPredicate({ custom: (p) => p.includes('bypass-me') })
    expect(skip('/foo/bypass-me')).toBe(true)
    expect(skip('/foo/bar')).toBe(false)
  })

  it('preserves exact-match prefix semantics through the legacy mapping', () => {
    const skip = buildSkipPredicate({ skipDefaults: true, prefixes: ['/favicon.ico'] })
    expect(skip('/favicon.ico')).toBe(true)
    expect(skip('/favicon.icon')).toBe(true) // legacy startsWith semantics
    expect(skip('/something/else')).toBe(false)
  })

  it('regex patterns still work', () => {
    const skip = buildSkipPredicate({ patterns: [/^\/healthz$/] })
    expect(skip('/healthz')).toBe(true)
    expect(skip('/healthzz')).toBe(false)
  })
})
