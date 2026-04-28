import { describe, it, expect } from 'vitest'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import {
  defaultWasmPath,
  defaultPoolWorkerPath,
  defaultWasmPathWithMetaUrl,
  defaultPoolWorkerPathWithMetaUrl,
  urlToFsPath,
} from '../src/wasmResolve.js'

describe('default WASM / pool-worker resolution', () => {
  it('returns a file:// URL via import.meta.url on a normal Node runtime', () => {
    const u = defaultWasmPath()
    expect(u).toBeInstanceOf(URL)
    expect(u.protocol).toBe('file:')
  })

  it('returns a file:// URL for the pool worker via import.meta.url', () => {
    const u = defaultPoolWorkerPath()
    expect(u.protocol).toBe('file:')
  })

  // These simulate the Next.js 15 middleware bundler which rewrites
  // `import.meta.url` to an empty string / sentinel. The URL constructor
  // throws, and we need to fall back through createRequire without taking
  // the process down.
  describe.each([
    ['empty string', ''],
    ['undefined', undefined as unknown as string],
    ['colon sentinel', ':'],
    ['opaque non-file protocol', 'webpack-internal:///./foo.js'],
  ])('when import.meta.url is %s', (_name, metaUrl) => {
    it('falls back via createRequire to a usable file:// URL (wasm)', () => {
      const u = defaultWasmPathWithMetaUrl(metaUrl)
      expect(u.protocol).toBe('file:')
      // The createRequire anchor walks up from @coraza/core/package.json;
      // the resulting path should end with dist/wasm/coraza.wasm.
      expect(fileURLToPath(u)).toMatch(/dist[\/\\]wasm[\/\\]coraza\.wasm$/)
    })

    it('falls back via createRequire to a usable file:// URL (pool worker)', () => {
      const u = defaultPoolWorkerPathWithMetaUrl(metaUrl)
      expect(u.protocol).toBe('file:')
      expect(fileURLToPath(u)).toMatch(/dist[\/\\]pool-worker\.mjs$/)
    })
  })

  // We expect the resolved file to actually exist once the package is
  // built — the fallback is useless if the path is wrong.
  it('resolves a wasm path that exists on disk (after build)', () => {
    const u = defaultWasmPathWithMetaUrl('')
    const p = fileURLToPath(u)
    // Build is a prerequisite for this test; if dist/wasm/coraza.wasm is
    // missing the fallback has returned the wrong path.
    expect(existsSync(p)).toBe(true)
  })

  it('resolves a pool-worker path that exists on disk (after build)', () => {
    const u = defaultPoolWorkerPathWithMetaUrl('')
    const p = fileURLToPath(u)
    expect(existsSync(p)).toBe(true)
  })

  it('honours a usable file:// import.meta.url without falling through', () => {
    // Hand it a known-good file URL; the new-URL branch should succeed
    // and we should get a file:// URL pointing at the same dir.
    const fakeMeta = new URL('fake-module.js', import.meta.url).href
    const u = defaultWasmPathWithMetaUrl(fakeMeta)
    expect(u.protocol).toBe('file:')
    expect(fileURLToPath(u)).toMatch(/wasm[\/\\]coraza\.wasm$/)
  })

  it('treats an http(s) anchor as unusable and falls through', () => {
    // Only file:// URLs are safe to hand to createRequire, so we should
    // fall back on the cwd anchor and still resolve successfully.
    const u = defaultWasmPathWithMetaUrl('https://example.invalid/app.js')
    expect(u.protocol).toBe('file:')
    expect(fileURLToPath(u)).toMatch(/dist[\/\\]wasm[\/\\]coraza\.wasm$/)
  })
})

describe('urlToFsPath', () => {
  // The reason this helper exists at all: under webpack/Turbopack a
  // bundle can ship a duplicate URL class, so the URL we hand
  // `fileURLToPath` is no longer `instanceof URL` from Node's POV. The
  // fallback path below is the one users actually run on Windows.
  function fakeBundlerUrl(href: string): { protocol: string; pathname: string; host: string; href: string } {
    const real = new URL(href)
    return {
      protocol: real.protocol,
      pathname: real.pathname,
      host: real.host,
      href: real.href,
    }
  }

  it('converts a POSIX file URL through fileURLToPath', () => {
    const u = new URL('file:///home/user/coraza.wasm')
    expect(urlToFsPath(u)).toBe('/home/user/coraza.wasm')
  })

  it('falls back when the URL is from a duplicated URL class (POSIX)', () => {
    // Real URL from Node's classes works on every platform.
    const u = fakeBundlerUrl('file:///home/user/coraza.wasm')
    expect(urlToFsPath(u as unknown as URL)).toBe('/home/user/coraza.wasm')
  })

  it('strips the leading slash from a Windows drive-letter file URL', () => {
    // Synthetic Windows file URL — `pathname` is `/C:/Users/me/coraza.wasm`
    // which Node.js readFile rejects on Windows. The helper must return
    // `C:/Users/me/coraza.wasm` regardless of which platform the unit
    // test runs on.
    const u = fakeBundlerUrl('file:///C:/Users/me/coraza.wasm')
    expect(urlToFsPath(u as unknown as URL)).toBe('C:/Users/me/coraza.wasm')
  })

  it('strips the leading slash from a Windows drive-letter file URL with a space', () => {
    const u = fakeBundlerUrl('file:///D:/Program%20Files/coraza/coraza.wasm')
    expect(urlToFsPath(u as unknown as URL)).toBe('D:/Program Files/coraza/coraza.wasm')
  })

  it('handles a Windows UNC file URL', () => {
    // file://server/share/path → //server/share/path
    const u = fakeBundlerUrl('file://server/share/coraza.wasm')
    expect(urlToFsPath(u as unknown as URL)).toBe('//server/share/coraza.wasm')
  })

  it('does not mangle a POSIX path whose first segment contains a colon later', () => {
    // A POSIX file at /a:b/c is legal. The drive-letter regex requires
    // exactly `/<letter>:/`, so a multi-character first segment must not
    // match.
    const u = fakeBundlerUrl('file:///foo:bar/coraza.wasm')
    expect(urlToFsPath(u as unknown as URL)).toBe('/foo:bar/coraza.wasm')
  })
})
