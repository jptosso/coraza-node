import { describe, it, expect } from 'vitest'
import {
  buildSkipPredicate,
  pathOf,
  DEFAULT_SKIP_EXTENSIONS,
  DEFAULT_SKIP_PREFIXES,
} from '../src/skip.js'

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
