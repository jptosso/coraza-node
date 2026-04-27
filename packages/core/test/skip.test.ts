import { describe, it, expect } from 'vitest'
import {
  buildSkipPredicate,
  pathOf,
  DEFAULT_SKIP_EXTENSIONS,
  DEFAULT_SKIP_PREFIXES,
} from '../src/skip.js'

// Helper: model the adapter convention of always running the predicate
// against `URL.pathname` (i.e. query/fragment pre-stripped).
const skipUrl = (pred: (p: string) => boolean, url: string) => pred(pathOf(url))

describe('pathOf', () => {
  it('returns path without query or hash', () => {
    expect(pathOf('/a/b')).toBe('/a/b')
    expect(pathOf('/a?q=1')).toBe('/a')
    expect(pathOf('/a#frag')).toBe('/a')
    expect(pathOf('/a?q=1#frag')).toBe('/a')
    expect(pathOf('/a#frag?q=1')).toBe('/a')
    expect(pathOf('')).toBe('')
  })
})

describe('buildSkipPredicate defaults', () => {
  const skip = buildSkipPredicate(undefined)

  it('bypasses common static extensions', () => {
    for (const ext of DEFAULT_SKIP_EXTENSIONS) {
      expect(skip(`/img/logo.${ext}`)).toBe(true)
    }
  })

  it('bypasses uppercase extensions', () => {
    expect(skip('/foo.PNG')).toBe(true)
    expect(skip('/foo.JPG')).toBe(true)
  })

  it('bypasses default prefixes', () => {
    for (const p of DEFAULT_SKIP_PREFIXES) {
      expect(skip(p)).toBe(true)
      expect(skip(p + 'anything')).toBe(true)
    }
  })

  it('does NOT bypass dynamic paths without an extension', () => {
    expect(skip('/api/login')).toBe(false)
    expect(skip('/echo')).toBe(false)
    expect(skip('/')).toBe(false)
  })

  it('does NOT treat dotfiles inside directories as extensions', () => {
    expect(skip('/config.d/app')).toBe(false)
  })

  it('does not match a path where the dot is only in a dir name', () => {
    expect(skip('/v1.2/api')).toBe(false)
  })

  it('ignores paths ending with a dot (no extension)', () => {
    expect(skip('/foo.')).toBe(false)
  })

  it('empty uses default', () => {
    const s = buildSkipPredicate({})
    expect(s('/foo.png')).toBe(true)
    expect(s('/api')).toBe(false)
  })
})

describe('buildSkipPredicate custom', () => {
  it('merges user prefixes with defaults', () => {
    const skip = buildSkipPredicate({ prefixes: ['/cdn/'] })
    expect(skip('/cdn/foo')).toBe(true)
    expect(skip('/_next/static/abc')).toBe(true)
  })

  it('merges user extensions with defaults', () => {
    const skip = buildSkipPredicate({ extensions: ['log'] })
    expect(skip('/debug.log')).toBe(true)
    expect(skip('/img.png')).toBe(true)
  })

  it('applies regex patterns', () => {
    const skip = buildSkipPredicate({ patterns: [/^\/healthz$/] })
    expect(skip('/healthz')).toBe(true)
    expect(skip('/healthzz')).toBe(false)
  })

  it('applies custom predicate', () => {
    const skip = buildSkipPredicate({ custom: (p) => p.includes('bypass-me') })
    expect(skip('/foo/bypass-me')).toBe(true)
    expect(skip('/foo/bar')).toBe(false)
  })

  it('skipDefaults: true omits built-in lists', () => {
    const skip = buildSkipPredicate({ skipDefaults: true, prefixes: ['/cdn/'] })
    expect(skip('/foo.png')).toBe(false) // png default dropped
    expect(skip('/_next/static/x')).toBe(false) // prefix default dropped
    expect(skip('/cdn/x')).toBe(true)
  })

  it('skipDefaults: true with no opts skips everything', () => {
    const skip = buildSkipPredicate({ skipDefaults: true })
    expect(skip('/foo.png')).toBe(false)
    expect(skip('/anything')).toBe(false)
  })

  it('favicon and robots.txt are bypassed', () => {
    const skip = buildSkipPredicate()
    expect(skip('/favicon.ico')).toBe(true)
    expect(skip('/robots.txt')).toBe(true)
  })
})

describe('buildSkipPredicate extension match contract', () => {
  it('single-segment entry still matches its own extension', () => {
    const skip = buildSkipPredicate({ skipDefaults: true, extensions: ['css'] })
    expect(skip('/foo.css')).toBe(true)
  })

  it('single-segment entry does not match when the dot is in a directory', () => {
    const skip = buildSkipPredicate({ skipDefaults: true, extensions: ['css'] })
    // The last `.` is inside a directory segment; the basename is `bar`.
    expect(skip('/static/foo.css/bar')).toBe(false)
  })

  it('case-insensitive: lowercase list entry matches uppercase path', () => {
    const skip = buildSkipPredicate({ skipDefaults: true, extensions: ['css'] })
    expect(skip('/foo.CSS')).toBe(true)
    expect(skip('/Foo.Css')).toBe(true)
  })

  it('case-insensitive: uppercase list entry is normalized at build time', () => {
    const skip = buildSkipPredicate({ skipDefaults: true, extensions: ['CSS'] })
    expect(skip('/foo.css')).toBe(true)
    expect(skip('/foo.CSS')).toBe(true)
  })

  it('query string is ignored when the caller pre-strips via pathOf', () => {
    const skip = buildSkipPredicate({ skipDefaults: true, extensions: ['css'] })
    expect(skipUrl(skip, '/foo.css?v=1')).toBe(true)
    expect(skipUrl(skip, '/foo.css#frag')).toBe(true)
  })

  it('does NOT match `evil.css` smuggled in a query string against the bare path', () => {
    // This pins issue #28's correctness check: pathname is `/api/upload`,
    // there is no extension to match, regardless of `?name=evil.css`.
    const skip = buildSkipPredicate({ skipDefaults: true, extensions: ['css'] })
    expect(skipUrl(skip, '/api/upload?name=evil.css')).toBe(false)
  })

  it('compound: tar.gz matches /archive.tar.gz', () => {
    const skip = buildSkipPredicate({ skipDefaults: true, extensions: ['tar.gz'] })
    expect(skip('/archive.tar.gz')).toBe(true)
    expect(skip('/dist/release-1.0.tar.gz')).toBe(true)
  })

  it('compound: min.js matches /bundle.min.js but not /bundle.js', () => {
    const skip = buildSkipPredicate({ skipDefaults: true, extensions: ['min.js'] })
    expect(skip('/bundle.min.js')).toBe(true)
    expect(skip('/bundle.js')).toBe(false)
  })

  it('compound: mixed-case input and entry both normalize', () => {
    const skip = buildSkipPredicate({ skipDefaults: true, extensions: ['Min.JS'] })
    expect(skip('/Bundle.MIN.js')).toBe(true)
    expect(skip('/Bundle.MIN.JS')).toBe(true)
  })

  it('compound: does NOT match a bare basename literally named `min.js`', () => {
    // The boundary case: a leading `.` is required in front of the entry,
    // otherwise we would skip a request for a literal file named `min.js`.
    // That file's basename is the entry itself, not the entry preceded
    // by `.`, so it must NOT skip.
    const skip = buildSkipPredicate({ skipDefaults: true, extensions: ['min.js'] })
    expect(skip('/min.js')).toBe(false)
    expect(skip('/sub/min.js')).toBe(false)
    expect(skip('min.js')).toBe(false)
  })

  it('compound: does NOT match a bare basename `tar.gz`', () => {
    const skip = buildSkipPredicate({ skipDefaults: true, extensions: ['tar.gz'] })
    expect(skip('/tar.gz')).toBe(false)
    expect(skip('/downloads/tar.gz')).toBe(false)
  })

  it('compound: does NOT match if the suffix is followed by another path segment', () => {
    const skip = buildSkipPredicate({ skipDefaults: true, extensions: ['tar.gz'] })
    expect(skip('/archive.tar.gz/extra')).toBe(false)
  })

  it('compound: does NOT match an unrelated basename ending with a different inner segment', () => {
    // /foo.bin.js must NOT be skipped under min.js
    const skip = buildSkipPredicate({ skipDefaults: true, extensions: ['min.js'] })
    expect(skip('/foo.bin.js')).toBe(false)
  })

  it('compound: does NOT skip `evil.min.js.exe` when `exe` is not in the list', () => {
    // Standard "skip if last bit matches" semantics. The literal trailing
    // segment is `exe`; `min.js` is not the suffix of the basename.
    const skip = buildSkipPredicate({ skipDefaults: true, extensions: ['min.js'] })
    expect(skip('/evil.min.js.exe')).toBe(false)
  })

  it('compound and single can coexist', () => {
    const skip = buildSkipPredicate({
      skipDefaults: true,
      extensions: ['css', 'tar.gz', 'min.js'],
    })
    expect(skip('/foo.css')).toBe(true)
    expect(skip('/x.tar.gz')).toBe(true)
    expect(skip('/x.min.js')).toBe(true)
    expect(skip('/x.js')).toBe(false)
    expect(skip('/min.js')).toBe(false) // boundary
  })

  it('empty / blank list entries are ignored', () => {
    const skip = buildSkipPredicate({ skipDefaults: true, extensions: ['', 'png'] })
    expect(skip('/foo.png')).toBe(true)
    expect(skip('/foo')).toBe(false)
    expect(skip('/foo.')).toBe(false)
  })
})
